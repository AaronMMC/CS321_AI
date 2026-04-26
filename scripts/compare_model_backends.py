#!/usr/bin/env python3
"""
Compare heuristic and transformer backends on the same held-out dataset split.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from loguru import logger
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split

# Add project root to import path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.train_real_model import _prepare_dataset
from src.models.tinybert_model import TinyBERTForEmailSecurity


def _predict_scores(model: TinyBERTForEmailSecurity, texts: List[str]) -> List[float]:
    """Run model predictions and return threat scores."""
    preds = model.predict(texts)
    if isinstance(preds, dict):
        preds = [preds]
    return [float(p.get("threat_score", 0.0)) for p in preds]


def _compute_metrics(labels: List[int], scores: List[float], threshold: float) -> Dict[str, float]:
    """Compute standard binary classification metrics."""
    pred_labels = [1 if s >= threshold else 0 for s in scores]
    metrics: Dict[str, float] = {
        "accuracy": float(accuracy_score(labels, pred_labels)),
        "precision": float(precision_score(labels, pred_labels, zero_division=0)),
        "recall": float(recall_score(labels, pred_labels, zero_division=0)),
        "f1": float(f1_score(labels, pred_labels, zero_division=0)),
    }

    try:
        metrics["auc"] = float(roc_auc_score(labels, scores))
    except Exception:
        metrics["auc"] = 0.0

    return metrics


def _evaluate_backend(
    model: TinyBERTForEmailSecurity,
    labels: List[int],
    texts: List[str],
    threshold: float,
) -> Dict:
    """Evaluate a single backend and return summary."""
    scores = _predict_scores(model, texts)
    metrics = _compute_metrics(labels, scores, threshold)

    return {
        "backend": getattr(model, "backend", "unknown"),
        "source": getattr(model, "model_name", "unknown"),
        "metrics": metrics,
    }


def main():
    parser = argparse.ArgumentParser(description="Compare heuristic vs transformer backends")
    parser.add_argument(
        "--data",
        type=Path,
        default=ROOT / "data" / "raw" / "combined_fraud_detection_dataset.csv",
        help="Dataset CSV path",
    )
    parser.add_argument(
        "--transformer-model",
        type=Path,
        default=ROOT / "models_saved" / "real_tinybert_distilbert",
        help="Transformer artifact directory",
    )
    parser.add_argument("--sample", type=float, default=1.0, help="Sampling fraction for dataset preparation")
    parser.add_argument("--test-size", type=float, default=0.2, help="Held-out split fraction")
    parser.add_argument("--max-samples", type=int, default=2000, help="Max samples to evaluate")
    parser.add_argument("--threshold", type=float, default=0.5, help="Threat score threshold")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--cpu", action="store_true", help="Force CPU for transformer model")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "models_saved" / "backend_comparison.json",
        help="Output JSON path",
    )
    args = parser.parse_args()

    texts, labels, data_source = _prepare_dataset(args.data, sample_frac=args.sample)

    stratify = labels if len(set(labels)) > 1 else None
    _train_x, test_texts, _train_y, test_labels = train_test_split(
        texts,
        labels,
        test_size=args.test_size,
        random_state=args.seed,
        stratify=stratify,
    )

    if args.max_samples > 0 and len(test_texts) > args.max_samples:
        test_texts = test_texts[: args.max_samples]
        test_labels = test_labels[: args.max_samples]

    logger.info(f"Evaluation source: {data_source}")
    logger.info(f"Test samples: {len(test_texts)}")
    logger.info(f"Label distribution: legit={test_labels.count(0)} phishing={test_labels.count(1)}")

    heuristic_model = TinyBERTForEmailSecurity(use_gpu=False)
    transformer_model = TinyBERTForEmailSecurity(
        model_path=args.transformer_model,
        use_gpu=not args.cpu,
    )

    heuristic_result = _evaluate_backend(
        heuristic_model,
        labels=test_labels,
        texts=test_texts,
        threshold=args.threshold,
    )
    transformer_result = _evaluate_backend(
        transformer_model,
        labels=test_labels,
        texts=test_texts,
        threshold=args.threshold,
    )

    comparison = {
        "dataset": {
            "input_path": str(args.data),
            "resolved_source": data_source,
            "test_samples": len(test_texts),
            "threshold": args.threshold,
        },
        "heuristic": heuristic_result,
        "transformer": transformer_result,
        "delta": {
            "accuracy": transformer_result["metrics"]["accuracy"] - heuristic_result["metrics"]["accuracy"],
            "f1": transformer_result["metrics"]["f1"] - heuristic_result["metrics"]["f1"],
            "auc": transformer_result["metrics"]["auc"] - heuristic_result["metrics"]["auc"],
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2)

    logger.success("Backend comparison complete")
    logger.info(f"Heuristic metrics: {heuristic_result['metrics']}")
    logger.info(f"Transformer metrics: {transformer_result['metrics']}")
    logger.info(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
