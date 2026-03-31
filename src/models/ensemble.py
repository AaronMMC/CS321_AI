"""
Ensemble model that combines TinyBERT and BERT predictions
with optional external intelligence for improved accuracy.
"""

from typing import Dict, List, Optional, Union
import numpy as np
from loguru import logger

from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.models.bert_classifier import BERTPhishingClassifier, TinyBERTPhishingDetector
from src.features.external_intelligence import ThreatIntelligenceHub


class EnsemblePhishingDetector:
    """
    Weighted ensemble of multiple models.

    Strategy options:
        "average"   – weighted average of probability scores
        "max"       – take the maximum score (most conservative / safe)
        "vote"      – majority vote on binary label
    """

    def __init__(
        self,
        strategy: str = "average",
        use_gpu: bool = True,
        use_external: bool = True,
    ):
        if strategy not in ("average", "max", "vote"):
            raise ValueError(f"Unknown strategy '{strategy}'. Choose average, max or vote.")

        self.strategy = strategy
        self.use_external = use_external

        logger.info("Loading TinyBERT for ensemble …")
        self._tinybert = TinyBERTForEmailSecurity(use_gpu=use_gpu)

        logger.info("Loading pre-trained TinyBERT (HuggingFace) for ensemble …")
        try:
            self._hf_tinybert = TinyBERTPhishingDetector()
        except Exception as exc:
            logger.warning(f"Could not load HF TinyBERT: {exc} — will skip it.")
            self._hf_tinybert = None

        if use_external:
            self._threat_hub = ThreatIntelligenceHub()
        else:
            self._threat_hub = None

        # Default weights: (tinybert, hf_tinybert, external)
        self._weights = [0.55, 0.30, 0.15]

        logger.info(f"EnsemblePhishingDetector ready (strategy='{strategy}')")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict(
        self,
        text: str,
        urls: Optional[List[str]] = None,
    ) -> Dict:
        """
        Predict threat score for a single email text.

        Returns:
            {
                "threat_score": float,   # 0–1
                "risk_level": str,
                "model_scores": Dict[str, float],
                "confidence": float,
            }
        """
        scores: Dict[str, float] = {}

        # --- TinyBERT (fine-tuned) ---
        try:
            res = self._tinybert.predict(text)
            scores["tinybert"] = (
                res.get("threat_score", 0.0) if isinstance(res, dict) else float(res)
            )
        except Exception as exc:
            logger.error(f"TinyBERT prediction failed: {exc}")
            scores["tinybert"] = 0.0

        # --- HuggingFace TinyBERT ---
        if self._hf_tinybert is not None:
            try:
                res = self._hf_tinybert.predict(text)
                scores["hf_tinybert"] = res.get("threat_score", 0.0)
            except Exception as exc:
                logger.error(f"HF TinyBERT prediction failed: {exc}")
                scores["hf_tinybert"] = 0.0
        else:
            scores["hf_tinybert"] = scores["tinybert"]  # fallback

        # --- External intelligence ---
        if self._threat_hub and urls:
            try:
                feats = self._threat_hub.get_features_for_model(text, urls)
                scores["external"] = float(feats[0]) if len(feats) > 0 else 0.0
            except Exception as exc:
                logger.error(f"External intelligence failed: {exc}")
                scores["external"] = 0.0
        else:
            scores["external"] = 0.0

        combined = self._combine(scores)

        return {
            "threat_score": combined,
            "risk_level": self._risk_level(combined),
            "model_scores": scores,
            "confidence": self._confidence(scores),
        }

    def predict_batch(
        self, texts: List[str], urls_list: Optional[List[Optional[List[str]]]] = None
    ) -> List[Dict]:
        """Predict for a list of texts."""
        urls_list = urls_list or [None] * len(texts)
        return [self.predict(t, u) for t, u in zip(texts, urls_list)]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _combine(self, scores: Dict[str, float]) -> float:
        score_list = [scores["tinybert"], scores["hf_tinybert"], scores["external"]]
        weights = self._weights

        if self.strategy == "average":
            total_w = sum(weights)
            return min(sum(s * w for s, w in zip(score_list, weights)) / total_w, 1.0)
        elif self.strategy == "max":
            return max(score_list)
        else:  # vote
            positives = sum(1 for s in score_list if s >= 0.5)
            return 1.0 if positives >= 2 else 0.0

    @staticmethod
    def _confidence(scores: Dict[str, float]) -> float:
        """How much the models agree (1 = perfect agreement, 0 = total disagreement)."""
        vals = list(scores.values())
        if not vals:
            return 0.0
        spread = max(vals) - min(vals)
        return round(1.0 - spread, 3)

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 0.8:
            return "CRITICAL"
        if score >= 0.6:
            return "HIGH"
        if score >= 0.4:
            return "MEDIUM"
        if score >= 0.2:
            return "LOW"
        return "SAFE"