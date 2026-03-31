"""
High-level predictor that combines the ML model with external intelligence
and hand-crafted features into a single, consistent prediction interface.
"""

from typing import Dict, List, Optional, Union
import numpy as np
from loguru import logger

from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.features.external_intelligence import ThreatIntelligenceHub
from src.features.text_features import TextFeatureExtractor
from src.features.url_features import URLFeatureExtractor
from src.data.preprocessor import EmailPreprocessor


class EmailThreatPredictor:
    """
    Unified prediction interface.

    Combines:
        - TinyBERT text classification
        - External threat intelligence (VirusTotal, WHOIS, Google SB)
        - Hand-crafted text & URL features

    Score weighting (configurable):
        model_score    × 0.60
        external_score × 0.30
        heuristic_score × 0.10
    """

    DEFAULT_WEIGHTS = {
        "model": 0.60,
        "external": 0.30,
        "heuristic": 0.10,
    }

    def __init__(
        self,
        model: Optional[TinyBERTForEmailSecurity] = None,
        threat_hub: Optional[ThreatIntelligenceHub] = None,
        weights: Optional[Dict[str, float]] = None,
        use_gpu: bool = True,
    ):
        self.model = model or TinyBERTForEmailSecurity(use_gpu=use_gpu)
        self.threat_hub = threat_hub or ThreatIntelligenceHub()
        self.weights = weights or self.DEFAULT_WEIGHTS

        self._text_extractor = TextFeatureExtractor()
        self._url_extractor = URLFeatureExtractor()
        self._preprocessor = EmailPreprocessor()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict(
        self,
        subject: str,
        body: str,
        urls: Optional[List[str]] = None,
        from_domain: Optional[str] = None,
    ) -> Dict:
        """
        Predict threat level for a single email.

        Returns:
            {
                "threat_score": float,   # 0–1
                "risk_level": str,       # SAFE / LOW / MEDIUM / HIGH / CRITICAL
                "model_score": float,
                "external_score": float,
                "heuristic_score": float,
                "explanations": List[str],
            }
        """
        cleaned_text = self._preprocessor.prepare_for_model(subject, body)

        # 1. Model score
        prediction = self.model.predict(cleaned_text)
        model_score = (
            prediction.get("threat_score", 0.0)
            if isinstance(prediction, dict)
            else float(prediction)
        )

        # 2. External intelligence score
        external_score = 0.0
        if urls:
            features = self.threat_hub.get_features_for_model(cleaned_text, urls)
            external_score = float(features[0]) if len(features) > 0 else 0.0

        # 3. Heuristic score
        heuristic_score = self._heuristic_score(subject, body, urls or [])

        # 4. Weighted combination
        w = self.weights
        combined = (
            model_score * w["model"]
            + external_score * w["external"]
            + heuristic_score * w["heuristic"]
        )
        combined = min(combined, 1.0)

        explanations = self._build_explanations(
            subject, body, urls or [], model_score, external_score, heuristic_score
        )

        return {
            "threat_score": combined,
            "risk_level": self._risk_level(combined),
            "model_score": model_score,
            "external_score": external_score,
            "heuristic_score": heuristic_score,
            "explanations": explanations,
        }

    def predict_from_parsed(self, email_data: Dict) -> Dict:
        """
        Convenience wrapper that accepts a parsed email dict from EmailParser.
        """
        subject = email_data.get("subject", "")
        body = email_data.get("body_plain", "") or email_data.get("body", "")
        urls = email_data.get("urls", [])
        from_domain = email_data.get("from_domain")
        return self.predict(subject, body, urls=urls, from_domain=from_domain)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _heuristic_score(self, subject: str, body: str, urls: List[str]) -> float:
        """Simple rule-based score from text and URL features."""
        text_feats = self._text_extractor.extract(subject, body)
        url_score = self._url_extractor.score(urls)

        # Weighted sum of key text features
        text_score = (
            text_feats.get("has_urgency", 0) * 0.25
            + text_feats.get("has_threat", 0) * 0.20
            + text_feats.get("has_verify", 0) * 0.20
            + text_feats.get("has_prize", 0) * 0.15
            + text_feats.get("has_sensitive", 0) * 0.20
        )
        return min(text_score * 0.6 + url_score * 0.4, 1.0)

    def _build_explanations(
        self,
        subject: str,
        body: str,
        urls: List[str],
        model_score: float,
        external_score: float,
        heuristic_score: float,
    ) -> List[str]:
        reasons = []
        text_feats = self._text_extractor.extract(subject, body)

        if model_score > 0.7:
            reasons.append("AI model flagged suspicious language patterns")
        if external_score > 0.5:
            reasons.append("One or more URLs have poor reputation (VirusTotal/Google SB)")
        if text_feats.get("has_urgency"):
            reasons.append("Subject or body contains urgency language")
        if text_feats.get("has_verify"):
            reasons.append("Email requests account verification or login")
        if text_feats.get("has_prize"):
            reasons.append("Email promises a prize or unexpected reward")
        if text_feats.get("has_sensitive"):
            reasons.append("Email requests sensitive information (password, bank details)")
        if urls and self._url_extractor.score(urls) > 0.6:
            reasons.append("Suspicious URL structure detected (shortener / risky TLD)")

        return reasons if reasons else ["No obvious phishing indicators found"]

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