"""
K-fold cross-validation for model evaluation.
Provides reliable performance estimates on small datasets.
"""

from typing import Dict, List, Optional, Tuple
import numpy as np
from sklearn.model_selection import StratifiedKFold
from loguru import logger

from src.models.tinybert_model import TinyBERTForEmailSecurity, create_mini_dataset_for_quick_training
from src.models.utils import compute_metrics, print_metrics
from src.training.config import TrainingConfig


class CrossValidator:
    """
    Stratified k-fold cross-validation for TinyBERT.

    Trains *k* independent models and returns averaged metrics so you get
    an unbiased accuracy estimate without a large hold-out set.
    """

    def __init__(self, config: Optional[TrainingConfig] = None, n_folds: int = 5):
        self.config = config or TrainingConfig()
        self.n_folds = n_folds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        texts: List[str],
        labels: List[int],
    ) -> Dict:
        """
        Run stratified k-fold CV.

        Args:
            texts:  List of email text strings.
            labels: Corresponding binary labels (0=legit, 1=phishing).

        Returns:
            Dict with per-fold and averaged metrics.
        """
        skf = StratifiedKFold(n_splits=self.n_folds, shuffle=True, random_state=self.config.seed)
        texts_arr = np.array(texts)
        labels_arr = np.array(labels)

        fold_results: List[Dict] = []

        for fold_idx, (train_idx, val_idx) in enumerate(skf.split(texts_arr, labels_arr)):
            logger.info(f"--- Fold {fold_idx + 1}/{self.n_folds} ---")

            train_texts = texts_arr[train_idx].tolist()
            train_labels = labels_arr[train_idx].tolist()
            val_texts = texts_arr[val_idx].tolist()
            val_labels = labels_arr[val_idx].tolist()

            fold_metrics = self._train_and_eval_fold(
                train_texts, train_labels, val_texts, val_labels
            )
            fold_results.append(fold_metrics)
            logger.info(f"Fold {fold_idx + 1} F1: {fold_metrics.get('f1', 0):.4f}")

        averaged = self._average_metrics(fold_results)
        print_metrics(averaged, title=f"{self.n_folds}-Fold CV Results (averaged)")

        return {
            "fold_results": fold_results,
            "averaged": averaged,
            "n_folds": self.n_folds,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _train_and_eval_fold(
        self,
        train_texts: List[str],
        train_labels: List[int],
        val_texts: List[str],
        val_labels: List[int],
    ) -> Dict:
        """Train one fold and return evaluation metrics."""
        model = TinyBERTForEmailSecurity(
            model_name=self.config.model_name,
            max_length=self.config.max_length,
            use_gpu=self.config.use_gpu,
        )

        model.train_quick(
            train_texts=train_texts,
            train_labels=train_labels,
            val_texts=val_texts,
            val_labels=val_labels,
            epochs=self.config.epochs,
            batch_size=self.config.batch_size,
            learning_rate=self.config.learning_rate,
        )

        # Evaluate on validation fold
        predictions = model.predict(val_texts)
        if isinstance(predictions, dict):
            predictions = [predictions]

        pred_labels = [1 if p.get("threat_score", 0) >= 0.5 else 0 for p in predictions]
        pred_probs = [p.get("threat_score", 0.0) for p in predictions]

        return compute_metrics(val_labels, pred_labels, pred_probs)

    @staticmethod
    def _average_metrics(fold_results: List[Dict]) -> Dict:
        """Average numeric metrics across folds."""
        if not fold_results:
            return {}
        keys = [k for k, v in fold_results[0].items() if isinstance(v, float)]
        averaged = {}
        for k in keys:
            vals = [f[k] for f in fold_results if k in f]
            averaged[k] = float(np.mean(vals))
            averaged[f"{k}_std"] = float(np.std(vals))
        return averaged