"""
Shared model utilities: saving, loading, metrics helpers, and device management.
"""

import json
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import torch
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)
from loguru import logger


# ---------------------------------------------------------------------------
# Device helpers
# ---------------------------------------------------------------------------

def get_device(prefer_gpu: bool = True) -> torch.device:
    """Return the best available torch device."""
    if prefer_gpu and torch.cuda.is_available():
        device = torch.device("cuda")
        logger.info(f"Using GPU: {torch.cuda.get_device_name(0)}")
    else:
        device = torch.device("cpu")
        logger.info("Using CPU")
    return device


def count_parameters(model: torch.nn.Module) -> int:
    """Count the total number of trainable parameters."""
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


# ---------------------------------------------------------------------------
# Save / Load helpers
# ---------------------------------------------------------------------------

def save_model_metadata(path: Path, metadata: Dict[str, Any]):
    """Persist model metadata to a JSON file alongside the saved weights."""
    path.mkdir(parents=True, exist_ok=True)
    meta_path = path / "metadata.json"
    with open(meta_path, "w") as fh:
        json.dump(metadata, fh, indent=2, default=str)
    logger.info(f"Metadata saved → {meta_path}")


def load_model_metadata(path: Path) -> Dict[str, Any]:
    """Load metadata JSON from a model directory."""
    meta_path = path / "metadata.json"
    if not meta_path.exists():
        logger.warning(f"No metadata.json found in {path}")
        return {}
    with open(meta_path) as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------

def compute_metrics(
    true_labels: list,
    predicted_labels: list,
    predicted_probs: Optional[list] = None,
) -> Dict[str, float]:
    """
    Compute a standard set of classification metrics.

    Args:
        true_labels:       Ground-truth binary labels (0 / 1).
        predicted_labels:  Model hard predictions (0 / 1).
        predicted_probs:   Optional predicted probability for class 1 (used for AUC).

    Returns:
        Dict with accuracy, precision, recall, f1, and optionally auc.
    """
    metrics = {
        "accuracy": accuracy_score(true_labels, predicted_labels),
        "precision": precision_score(true_labels, predicted_labels, zero_division=0),
        "recall": recall_score(true_labels, predicted_labels, zero_division=0),
        "f1": f1_score(true_labels, predicted_labels, zero_division=0),
    }

    if predicted_probs is not None:
        try:
            metrics["auc"] = roc_auc_score(true_labels, predicted_probs)
        except ValueError:
            metrics["auc"] = 0.0

    cm = confusion_matrix(true_labels, predicted_labels)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        metrics["true_positives"] = int(tp)
        metrics["false_positives"] = int(fp)
        metrics["true_negatives"] = int(tn)
        metrics["false_negatives"] = int(fn)
        denom = tp + fn
        metrics["false_negative_rate"] = fn / denom if denom else 0.0

    return metrics


def print_metrics(metrics: Dict[str, float], title: str = "Evaluation Results"):
    """Pretty-print a metrics dict."""
    logger.info("=" * 50)
    logger.info(title)
    logger.info("=" * 50)
    for k, v in metrics.items():
        if isinstance(v, float):
            logger.info(f"  {k:<25} {v:.4f}")
        else:
            logger.info(f"  {k:<25} {v}")


def threshold_search(
    true_labels: list,
    predicted_probs: list,
    metric: str = "f1",
    thresholds: Optional[list] = None,
) -> Tuple[float, float]:
    """
    Find the probability threshold that maximises a given metric.

    Returns:
        (best_threshold, best_metric_value)
    """
    if thresholds is None:
        thresholds = [i / 100 for i in range(5, 96, 5)]

    best_thresh = 0.5
    best_score = 0.0

    for thresh in thresholds:
        preds = [1 if p >= thresh else 0 for p in predicted_probs]
        if metric == "f1":
            score = f1_score(true_labels, preds, zero_division=0)
        elif metric == "accuracy":
            score = accuracy_score(true_labels, preds)
        elif metric == "recall":
            score = recall_score(true_labels, preds, zero_division=0)
        else:
            score = f1_score(true_labels, preds, zero_division=0)

        if score > best_score:
            best_score = score
            best_thresh = thresh

    logger.info(f"Best threshold for {metric}: {best_thresh:.2f} → {metric}={best_score:.4f}")
    return best_thresh, best_score