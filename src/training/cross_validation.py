"""
K-fold cross-validation for model evaluation.
"""

from typing import Dict, List, Optional
import numpy as np
from sklearn.model_selection import StratifiedKFold
from loguru import logger

from src.models.scratch_transformer import ScratchModelForEmailSecurity
from src.models.utils import compute_metrics, print_metrics
from src.training.config import TrainingConfig


class CrossValidator:
    """Stratified k-fold cross-validation for the scratch Transformer."""

    def __init__(self, config: Optional[TrainingConfig] = None, n_folds: int = 5):
        self.config = config or TrainingConfig()
        self.n_folds = n_folds

    def run(self, texts: List[str], labels: List[int]) -> Dict:
        skf = StratifiedKFold(n_splits=self.n_folds, shuffle=True, random_state=self.config.seed)
        texts_arr  = np.array(texts)
        labels_arr = np.array(labels)
        fold_results: List[Dict] = []

        for fold_idx, (train_idx, val_idx) in enumerate(skf.split(texts_arr, labels_arr)):
            logger.info(f"--- Fold {fold_idx + 1}/{self.n_folds} ---")
            train_texts  = texts_arr[train_idx].tolist()
            train_labels = labels_arr[train_idx].tolist()
            val_texts    = texts_arr[val_idx].tolist()
            val_labels   = labels_arr[val_idx].tolist()

            fold_metrics = self._train_and_eval_fold(train_texts, train_labels, val_texts, val_labels)
            fold_results.append(fold_metrics)
            logger.info(f"Fold {fold_idx + 1} F1: {fold_metrics.get('f1', 0):.4f}")

        averaged = self._average_metrics(fold_results)
        print_metrics(averaged, title=f"{self.n_folds}-Fold CV Results (averaged)")
        return {"fold_results": fold_results, "averaged": averaged, "n_folds": self.n_folds}

    def _train_and_eval_fold(
        self,
        train_texts: List[str], train_labels: List[int],
        val_texts: List[str],   val_labels: List[int],
    ) -> Dict:
        model = ScratchModelForEmailSecurity(use_gpu=self.config.use_gpu)
        model.build_tokenizer(train_texts)
        model.train_quick(
            train_texts=train_texts, train_labels=train_labels,
            val_texts=val_texts,     val_labels=val_labels,
            epochs=self.config.epochs,
            batch_size=self.config.batch_size,
            learning_rate=self.config.learning_rate,
        )

        predictions = model.predict(val_texts)
        if isinstance(predictions, dict):
            predictions = [predictions]

        pred_labels = [1 if p.get("threat_score", 0) >= 0.5 else 0 for p in predictions]
        pred_probs  = [p.get("threat_score", 0.0) for p in predictions]
        return compute_metrics(val_labels, pred_labels, pred_probs)

    @staticmethod
    def _average_metrics(fold_results: List[Dict]) -> Dict:
        if not fold_results:
            return {}
        keys = [k for k, v in fold_results[0].items() if isinstance(v, float)]
        return {
            **{k: float(np.mean([f[k] for f in fold_results if k in f])) for k in keys},
            **{f"{k}_std": float(np.std([f[k] for f in fold_results if k in f])) for k in keys},
        }