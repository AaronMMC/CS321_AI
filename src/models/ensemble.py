"""
Ensemble model combining two independently-initialised scratch Transformers
with optional external intelligence for improved accuracy.

Changes from original:
  - Replaced broken `from src.models.tinybert_model import TinyBERTForEmailSecurity`
    with `from src.models.scratch_transformer import ScratchModelForEmailSecurity`.
  - BERTPhishingClassifier secondary removed; both members now use the same
    scratch architecture (in a real deployment each would load a separately
    saved checkpoint).
"""

from typing import Dict, List, Optional
import numpy as np
from loguru import logger

from src.models.scratch_transformer import ScratchModelForEmailSecurity   # fixed
from src.features.external_intelligence import ThreatIntelligenceHub


class EnsemblePhishingDetector:
    """
    Weighted ensemble of two ScratchModelForEmailSecurity instances.

    strategy options:
        "average" – weighted average of probability scores
        "max"     – take the maximum score (most conservative)
        "vote"    – majority vote on binary label
    """

    def __init__(
        self,
        strategy:     str  = "average",
        use_gpu:      bool = True,
        use_external: bool = True,
        model_path:   str  = "models_saved/email_security_model",
    ):
        if strategy not in ("average", "max", "vote"):
            raise ValueError(f"Unknown strategy '{strategy}'")

        self.strategy     = strategy
        self.use_external = use_external

        logger.info("Loading primary model for ensemble …")
        self._primary = ScratchModelForEmailSecurity.load(model_path, use_gpu=use_gpu)

        # Second member: same checkpoint — in production load a different one
        logger.info("Loading secondary model for ensemble …")
        self._secondary = ScratchModelForEmailSecurity.load(model_path, use_gpu=use_gpu)

        self._threat_hub = ThreatIntelligenceHub() if use_external else None
        self._weights    = [0.55, 0.30, 0.15]   # primary, secondary, external

        logger.info(f"EnsemblePhishingDetector ready (strategy='{strategy}')")

    # ------------------------------------------------------------------

    def predict(self, text: str, urls: Optional[List[str]] = None) -> Dict:
        scores: Dict[str, float] = {}

        for name, mdl in (("primary", self._primary), ("secondary", self._secondary)):
            try:
                res       = mdl.predict(text)
                scores[name] = res.get("threat_score", 0.0) if isinstance(res, dict) else float(res)
            except Exception as exc:
                logger.error(f"Ensemble {name} prediction failed: {exc}")
                scores[name] = 0.0

        if self._threat_hub and urls:
            try:
                feats             = self._threat_hub.get_features_for_model(text, urls)
                scores["external"] = float(feats[0]) if feats else 0.0
            except Exception as exc:
                logger.error(f"External intel failed: {exc}")
                scores["external"] = 0.0
        else:
            scores["external"] = 0.0

        combined = self._combine(scores)
        return {
            "threat_score": combined,
            "risk_level":   self._risk_level(combined),
            "model_scores": scores,
            "confidence":   self._confidence(scores),
        }

    def predict_batch(
        self,
        texts:     List[str],
        urls_list: Optional[List[Optional[List[str]]]] = None,
    ) -> List[Dict]:
        urls_list = urls_list or [None] * len(texts)
        return [self.predict(t, u) for t, u in zip(texts, urls_list)]

    # ------------------------------------------------------------------

    def _combine(self, scores: Dict[str, float]) -> float:
        vals = [scores["primary"], scores["secondary"], scores["external"]]
        if self.strategy == "average":
            total = sum(self._weights)
            return min(sum(s * w for s, w in zip(vals, self._weights)) / total, 1.0)
        if self.strategy == "max":
            return max(vals)
        # vote
        return 1.0 if sum(1 for s in vals if s >= 0.5) >= 2 else 0.0

    @staticmethod
    def _confidence(scores: Dict[str, float]) -> float:
        vals   = list(scores.values())
        spread = max(vals) - min(vals) if vals else 0.0
        return round(1.0 - spread, 3)

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 0.8: return "CRITICAL"
        if score >= 0.6: return "HIGH"
        if score >= 0.4: return "MEDIUM"
        if score >= 0.2: return "LOW"
        return "SAFE"