"""
Standalone evaluation script.
Loads a saved model and evaluates it against a test CSV.
"""

from pathlib import Path
from typing import Dict, List, Optional
import pandas as pd
from loguru import logger

from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.models.utils import compute_metrics, print_metrics, threshold_search
from src.training.config import TrainingConfig


class ModelEvaluator:
    """
    Evaluate a TinyBERT model on a labelled dataset and produce a
    detailed metrics report.
    """

    def __init__(
        self,
        model: Optional[TinyBERTForEmailSecurity] = None,
        config: Optional[TrainingConfig] = None,
    ):
        self.config = config or TrainingConfig()
        self.model = model or TinyBERTForEmailSecurity(
            model_name=self.config.model_name,
            use_gpu=self.config.use_gpu,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_file(
        self,
        csv_path: Path,
        text_col: str = "text",
        label_col: str = "label",
    ) -> Dict:
        """Load a CSV and evaluate the model on it."""
        df = pd.read_csv(csv_path).dropna(subset=[text_col, label_col])
        texts = df[text_col].tolist()
        labels = df[label_col].astype(int).tolist()
        logger.info(f"Evaluating on {len(texts)} samples from {csv_path}")
        return self.evaluate(texts, labels)

    def evaluate(
        self,
        texts: List[str],
        true_labels: List[int],
        find_best_threshold: bool = True,
    ) -> Dict:
        """
        Run predictions and compute metrics.

        Args:
            texts:               Email text strings.
            true_labels:         Ground-truth labels (0=legit, 1=phishing).
            find_best_threshold: If True, also search for the optimal
                                 decision threshold.

        Returns:
            Dict of metrics (at default 0.5 threshold, and optionally the
            best threshold too).
        """
        logger.info("Running predictions …")
        predictions = self.model.predict(texts)
        if isinstance(predictions, dict):
            predictions = [predictions]

        pred_probs = [p.get("threat_score", 0.0) for p in predictions]
        pred_labels_05 = [1 if p >= 0.5 else 0 for p in pred_probs]

        metrics = compute_metrics(true_labels, pred_labels_05, pred_probs)
        print_metrics(metrics, title="Evaluation @ threshold=0.50")

        if find_best_threshold:
            best_thresh, best_f1 = threshold_search(
                true_labels, pred_probs, metric="f1"
            )
            pred_labels_best = [1 if p >= best_thresh else 0 for p in pred_probs]
            metrics_best = compute_metrics(true_labels, pred_labels_best, pred_probs)
            metrics["best_threshold"] = best_thresh
            metrics["best_threshold_f1"] = best_f1
            print_metrics(metrics_best, title=f"Evaluation @ threshold={best_thresh:.2f}")

        return metrics

    def evaluate_by_category(
        self,
        df: pd.DataFrame,
        text_col: str = "text",
        label_col: str = "label",
        category_col: str = "type",
    ) -> Dict[str, Dict]:
        """
        Break down metrics by a category column (e.g. 'type': legitimate / phishing / mixed).
        """
        results: Dict[str, Dict] = {}
        for category in df[category_col].unique():
            subset = df[df[category_col] == category]
            texts = subset[text_col].tolist()
            labels = subset[label_col].astype(int).tolist()
            if not texts:
                continue
            logger.info(f"Evaluating category '{category}' ({len(texts)} samples)")
            results[category] = self.evaluate(texts, labels, find_best_threshold=False)
        return results

    def generate_report(self, metrics: Dict, output_path: Optional[Path] = None) -> str:
        """
        Produce a human-readable markdown report.

        Args:
            metrics:     Metrics dict from ``evaluate()``.
            output_path: If provided, write the report to this file.

        Returns:
            Markdown string.
        """
        lines = [
            "# Model Evaluation Report",
            "",
            "## Performance Metrics",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
        ]

        display_keys = ["accuracy", "precision", "recall", "f1", "auc",
                        "true_positives", "false_positives", "true_negatives", "false_negatives",
                        "false_negative_rate", "best_threshold", "best_threshold_f1"]

        for k in display_keys:
            if k in metrics:
                v = metrics[k]
                if isinstance(v, float):
                    lines.append(f"| {k} | {v:.4f} |")
                else:
                    lines.append(f"| {k} | {v} |")

        report = "\n".join(lines)

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report)
            logger.info(f"Report saved → {output_path}")

        return report