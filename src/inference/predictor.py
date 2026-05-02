"""
High-level predictor: scratch Transformer + external intelligence + heuristics.
Requires a trained model saved to the path in settings.model.tinybert_path.
"""

from typing import Dict, List, Optional
from pathlib import Path
from loguru import logger

from src.models.scratch_transformer import ScratchModelForEmailSecurity
from src.features.external_intelligence import ThreatIntelligenceHub
from src.features.text_features import TextFeatureExtractor
from src.features.url_features import URLFeatureExtractor
from src.data.preprocessor import EmailPreprocessor
from src.utils.config import settings


class EmailThreatPredictor:
    """
    Combined threat scoring:
        model_score     × 0.60  (scratch Transformer trained on your data)
        external_score  × 0.30  (VirusTotal / WHOIS / Google SB)
        heuristic_score × 0.10  (rule-based text + URL features)
    """

    DEFAULT_WEIGHTS = {"model": 0.60, "external": 0.30, "heuristic": 0.10}

    def __init__(
        self,
        model: Optional[ScratchModelForEmailSecurity] = None,
        threat_hub: Optional[ThreatIntelligenceHub] = None,
        weights: Optional[Dict[str, float]] = None,
        use_gpu: bool = True,
    ):
        if model is not None:
            self.model = model
        else:
            saved = Path(str(settings.model.tinybert_path))
            if not saved.exists():
                raise RuntimeError(
                    f"No trained model at '{saved}'.\n"
                    "Run: python scripts/download_datasets.py --all\n"
                    "     python scripts/train_model.py"
                )
            self.model = ScratchModelForEmailSecurity.load(str(saved), use_gpu=use_gpu)
            logger.info(f"Model loaded from {saved}")

        self.threat_hub  = threat_hub or ThreatIntelligenceHub()
        self.weights     = weights or self.DEFAULT_WEIGHTS
        self._text_ext   = TextFeatureExtractor()
        self._url_ext    = URLFeatureExtractor()
        self._preprocessor = EmailPreprocessor()

    def predict(
        self,
        subject: str,
        body: str,
        urls: Optional[List[str]] = None,
        from_domain: Optional[str] = None,
    ) -> Dict:
        cleaned = self._preprocessor.prepare_for_model(subject, body)

        prediction   = self.model.predict(cleaned)
        model_score  = (
            prediction.get("threat_score", 0.0)
            if isinstance(prediction, dict) else float(prediction)
        )

        external_score = 0.0
        if urls:
            features = self.threat_hub.get_features_for_model(cleaned, urls)
            external_score = float(features[0]) if features else 0.0

        heuristic_score = self._heuristic(subject, body, urls or [])

        w = self.weights
        combined = min(
            model_score * w["model"]
            + external_score * w["external"]
            + heuristic_score * w["heuristic"],
            1.0,
        )

        return {
            "threat_score":    combined,
            "risk_level":      self._risk_level(combined),
            "model_score":     model_score,
            "external_score":  external_score,
            "heuristic_score": heuristic_score,
            "explanations":    self._explain(subject, body, urls or [], model_score, external_score),
        }

    def predict_from_parsed(self, email_data: Dict) -> Dict:
        return self.predict(
            subject=email_data.get("subject", ""),
            body=email_data.get("body_plain", "") or email_data.get("body", ""),
            urls=email_data.get("urls", []),
            from_domain=email_data.get("from_domain"),
        )

    def _heuristic(self, subject: str, body: str, urls: List[str]) -> float:
        tf = self._text_ext.extract(subject, body)
        us = self._url_ext.score(urls)
        ts = (
            tf.get("has_urgency",   0) * 0.25
            + tf.get("has_threat",  0) * 0.20
            + tf.get("has_verify",  0) * 0.20
            + tf.get("has_prize",   0) * 0.15
            + tf.get("has_sensitive", 0) * 0.20
        )
        return min(ts * 0.6 + us * 0.4, 1.0)

    def _explain(self, subject, body, urls, model_score, external_score) -> List[str]:
        tf = self._text_ext.extract(subject, body)
        reasons = []
        if model_score > 0.7:          reasons.append("AI model flagged suspicious language")
        if external_score > 0.5:       reasons.append("URLs have poor reputation")
        if tf.get("has_urgency"):      reasons.append("Contains urgency language")
        if tf.get("has_verify"):       reasons.append("Requests account verification")
        if tf.get("has_prize"):        reasons.append("Promises a prize or reward")
        if tf.get("has_sensitive"):    reasons.append("Requests sensitive information")
        if urls and self._url_ext.score(urls) > 0.6:
            reasons.append("Suspicious URL structure detected")
        return reasons or ["No obvious phishing indicators found"]

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 0.8: return "CRITICAL"
        if score >= 0.6: return "HIGH"
        if score >= 0.4: return "MEDIUM"
        if score >= 0.2: return "LOW"
        return "SAFE"