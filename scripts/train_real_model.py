#!/usr/bin/env python3
"""
Train a real transformer-backed detector and save loadable artifacts.

This script keeps runtime compatibility with the existing project by training
through TinyBERTForEmailSecurity(real_training=True) and exporting a model
directory that can be loaded by setting TINYBERT_MODEL_PATH.
"""

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import pandas as pd
from loguru import logger
from sklearn.model_selection import train_test_split

# Add project root to import path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.download_datasets import DatasetDownloader
from src.models.tinybert_model import TinyBERTForEmailSecurity, create_mini_dataset_for_quick_training


TEXT_COLUMN_CANDIDATES = [
    "text",
    "message",
    "email",
    "content",
    "body",
]

LABEL_COLUMN_CANDIDATES = [
    "label",
    "spam",
    "phishing",
    "fraud",
    "is_fraud",
    "target",
]

POSITIVE_LABEL_VALUES = {
    "1",
    "true",
    "yes",
    "spam",
    "phishing",
    "fraud",
    "malicious",
    "suspicious",
}


def _read_csv_if_available(path: Path) -> Optional[pd.DataFrame]:
    """Load CSV when path exists and has rows."""
    if not path.exists() or path.stat().st_size == 0:
        return None

    try:
        df = pd.read_csv(path)
        if df.empty:
            return None
        return df
    except Exception as e:
        logger.warning(f"Failed to read CSV at {path}: {e}")
        return None


def _normalize_labels(series: pd.Series) -> List[int]:
    """Map mixed label formats to binary integers."""
    if pd.api.types.is_numeric_dtype(series):
        return [1 if int(v) >= 1 else 0 for v in series.fillna(0).tolist()]

    labels: List[int] = []
    for raw in series.fillna("0").astype(str).str.strip().str.lower().tolist():
        labels.append(1 if raw in POSITIVE_LABEL_VALUES else 0)
    return labels


def _extract_text_and_labels(df: pd.DataFrame) -> Tuple[List[str], List[int]]:
    """Extract normalized texts and labels from a generic phishing dataset."""
    text_series: Optional[pd.Series] = None

    for col in TEXT_COLUMN_CANDIDATES:
        if col in df.columns:
            text_series = df[col].fillna("").astype(str)
            break

    if text_series is None and "subject" in df.columns and "body" in df.columns:
        text_series = (df["subject"].fillna("").astype(str) + " " + df["body"].fillna("").astype(str)).str.strip()

    if text_series is None and "subject" in df.columns and "body_plain" in df.columns:
        text_series = (df["subject"].fillna("").astype(str) + " " + df["body_plain"].fillna("").astype(str)).str.strip()

    if text_series is None:
        raise ValueError("No supported text column found in dataset")

    label_col = next((c for c in LABEL_COLUMN_CANDIDATES if c in df.columns), None)
    if not label_col:
        raise ValueError("No supported label column found in dataset")

    labels = _normalize_labels(df[label_col])
    texts = text_series.tolist()

    filtered_texts: List[str] = []
    filtered_labels: List[int] = []
    for t, y in zip(texts, labels):
        if t and t.strip():
            filtered_texts.append(t.strip())
            filtered_labels.append(int(y))

    return filtered_texts, filtered_labels


def _prepare_dataset(data_path: Path, sample_frac: float) -> Tuple[List[str], List[int], str]:
    """Load training data, generate if needed, then fallback to mini dataset."""
    source = str(data_path)

    df = _read_csv_if_available(data_path)

    if df is None:
        downloader = DatasetDownloader(ROOT / "data")
        generated = downloader.create_training_data(sample_frac=sample_frac)
        generated_df = _read_csv_if_available(generated)

        if generated_df is not None:
            # Keep user-selected dataset path as the training source when possible.
            # This lets the pipeline proceed even when remote raw sources are unavailable.
            try:
                data_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(generated, data_path)
                df = _read_csv_if_available(data_path)
                source = str(data_path)
                if df is None:
                    df = generated_df
                    source = str(generated)
            except Exception as e:
                logger.warning(f"Could not materialize generated dataset at {data_path}: {e}")
                df = generated_df
                source = str(generated)

    if df is not None:
        try:
            texts, labels = _extract_text_and_labels(df)
            if len(texts) >= 20 and len(set(labels)) >= 2:
                return texts, labels, source
            logger.warning("Dataset is too small or single-class; using mini dataset fallback")
        except Exception as e:
            logger.warning(f"Could not extract text/labels from dataset: {e}")

    texts, labels = create_mini_dataset_for_quick_training()
    return texts, labels, "mini_dataset"


def _compute_accuracy(model: TinyBERTForEmailSecurity, texts: List[str], labels: List[int]) -> float:
    """Compute quick validation accuracy."""
    if not texts or not labels:
        return 0.0

    preds = model.predict(texts)
    if isinstance(preds, dict):
        preds = [preds]

    pred_labels = [1 if p.get("threat_score", 0.0) >= 0.5 else 0 for p in preds]
    correct = sum(int(p == y) for p, y in zip(pred_labels, labels))
    return float(correct / len(labels))


def main():
    parser = argparse.ArgumentParser(description="Train and export a real transformer model artifact")
    parser.add_argument(
        "--data",
        type=Path,
        default=ROOT / "data" / "processed" / "training_data.csv",
        help="Training CSV path",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "models_saved" / "real_tinybert",
        help="Output model directory",
    )
    parser.add_argument("--sample", type=float, default=1.0, help="Sampling fraction when creating training data")
    parser.add_argument("--epochs", type=int, default=2, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=8, help="Batch size")
    parser.add_argument("--learning-rate", type=float, default=3e-5, help="Learning rate")
    parser.add_argument("--max-length", type=int, default=256, help="Token max length")
    parser.add_argument(
        "--base-model",
        type=str,
        default="distilbert-base-uncased",
        help="Transformer checkpoint for initialization",
    )
    parser.add_argument("--cpu", action="store_true", help="Force CPU training")
    args = parser.parse_args()

    logger.info("Preparing training data")
    texts, labels, source = _prepare_dataset(args.data, sample_frac=args.sample)

    logger.info(f"Dataset source: {source}")
    logger.info(f"Samples: {len(texts)}")
    logger.info(f"Label distribution: legit={labels.count(0)} phishing={labels.count(1)}")

    stratify = labels if len(set(labels)) > 1 else None
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=stratify,
    )

    logger.info("Initializing model backend")
    model = TinyBERTForEmailSecurity(
        model_name=args.base_model,
        max_length=args.max_length,
        use_gpu=not args.cpu,
        force_transformer=True,
    )

    logger.info(f"Selected backend: {model.backend}")

    history = model.train_quick(
        train_texts=train_texts,
        train_labels=train_labels,
        val_texts=val_texts,
        val_labels=val_labels,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        real_training=True,
        save_path=args.output,
    )

    val_acc = _compute_accuracy(model, val_texts, val_labels)

    args.output.mkdir(parents=True, exist_ok=True)
    with open(args.output / "training_history.json", "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

    with open(args.output / "training_summary.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "backend": model.backend,
                "base_model": args.base_model,
                "samples": len(texts),
                "train_samples": len(train_texts),
                "val_samples": len(val_texts),
                "epochs": args.epochs,
                "batch_size": args.batch_size,
                "learning_rate": args.learning_rate,
                "validation_accuracy": round(val_acc, 4),
                "data_source": source,
            },
            f,
            indent=2,
        )

    logger.success(f"Training complete. Backend={model.backend}")
    logger.success(f"Validation accuracy: {val_acc:.4f}")
    logger.success(f"Artifacts saved to: {args.output}")
    logger.info("Set TINYBERT_MODEL_PATH to this output directory for runtime loading")


if __name__ == "__main__":
    main()
