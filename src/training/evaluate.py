"""
Model evaluation — loads a saved model and scores it against a labelled CSV.
"""

from pathlib import Path
from typing import Dict, List, Optional
import pandas as pd
from loguru import logger

from src.models.scratch_transformer import ScratchModelForEmailSecurity
from src.models.utils import compute_metrics, print_metrics, threshold_search
from src.training.config import TrainingConfig


class ModelEvaluator:
    """Evaluate a trained ScratchModelForEmailSecurity on a labelled dataset."""

    def __init__(
        self,
        model: Optional[ScratchModelForEmailSecurity] = None,
        config: Optional[TrainingConfig] = None,
        model_path: Optional[str] = None,
    ):
        self.config = config or TrainingConfig()

        if model is not None:
            self.model = model
        elif model_path:
            self.model = ScratchModelForEmailSecurity.load(model_path, use_gpu=self.config.use_gpu)
        else:
            raise ValueError(
                "Provide either a model instance or a model_path to a saved model directory."
            )

    def evaluate_file(self, csv_path: Path, text_col: str = "text", label_col: str = "label") -> Dict:
        df = pd.read_csv(csv_path).dropna(subset=[text_col, label_col])
        logger.info(f"Evaluating on {len(df)} samples from {csv_path}")
        return self.evaluate(df[text_col].tolist(), df[label_col].astype(int).tolist())

    def evaluate(
        self,
        texts: List[str],
        true_labels: List[int],
        find_best_threshold: bool = True,
    ) -> Dict:
        logger.info("Running predictions…")
        predictions = self.model.predict(texts)
        if isinstance(predictions, dict):
            predictions = [predictions]

        pred_probs    = [p.get("threat_score", 0.0) for p in predictions]
        pred_labels   = [1 if p >= 0.5 else 0 for p in pred_probs]
        metrics       = compute_metrics(true_labels, pred_labels, pred_probs)
        print_metrics(metrics, title="Evaluation @ threshold=0.50")

        if find_best_threshold:
            best_thresh, _ = threshold_search(true_labels, pred_probs, metric="f1")
            best_preds     = [1 if p >= best_thresh else 0 for p in pred_probs]
            best_metrics   = compute_metrics(true_labels, best_preds, pred_probs)
            metrics["best_threshold"]    = best_thresh
            metrics["best_threshold_f1"] = best_metrics["f1"]
            print_metrics(best_metrics, title=f"Evaluation @ threshold={best_thresh:.2f}")

        return metrics

    def generate_report(self, metrics: Dict, output_path: Optional[Path] = None) -> str:
        rows = ["# Model Evaluation Report\n", "| Metric | Value |", "|--------|-------|"]
        for k in ["accuracy", "precision", "recall", "f1", "auc",
                  "true_positives", "false_positives", "true_negatives", "false_negatives",
                  "false_negative_rate", "best_threshold", "best_threshold_f1"]:
            if k in metrics:
                v = metrics[k]
                rows.append(f"| {k} | {v:.4f} |" if isinstance(v, float) else f"| {k} | {v} |")
        report = "\n".join(rows)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report)
            logger.info(f"Report saved → {output_path}")
        return report