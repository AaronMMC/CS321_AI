"""
Explainability utilities for phishing predictions.
Produces human-readable explanations and simple feature-importance rankings.
"""

from typing import Dict, List, Optional, Tuple
from loguru import logger

from src.features.text_features import TextFeatureExtractor
from src.features.url_features import URLFeatureExtractor
from src.features.metadata_features import MetadataFeatureExtractor


class PredictionExplainer:
    """
    Generates plain-English explanations for a given threat prediction.

    Works purely from the feature scores produced by the extractor modules
    (no gradient-based attribution) so it runs on any device, instantly.
    """

    def __init__(self):
        self._text_ext = TextFeatureExtractor()
        self._url_ext = URLFeatureExtractor()
        self._meta_ext = MetadataFeatureExtractor()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def explain(
        self,
        subject: str,
        body: str,
        urls: Optional[List[str]] = None,
        email_data: Optional[Dict] = None,
        prediction: Optional[Dict] = None,
    ) -> Dict:
        """
        Build a full explanation report.

        Args:
            subject:    Email subject line.
            body:       Plain-text email body.
            urls:       List of URLs extracted from the email.
            email_data: Full parsed email dict (optional; enables metadata features).
            prediction: Existing prediction dict (optional); merged into output.

        Returns:
            {
                "risk_level": str,
                "threat_score": float,
                "top_reasons": List[str],
                "feature_scores": Dict[str, float],
                "recommendations": List[str],
            }
        """
        urls = urls or []

        text_feats = self._text_ext.extract(subject, body)
        url_feats = self._url_ext.extract_from_list(urls)
        meta_feats = self._meta_ext.extract(email_data) if email_data else {}

        all_feats = {**text_feats, **url_feats, **meta_feats}

        reasons = self._build_reasons(text_feats, url_feats, meta_feats, urls)
        recommendations = self._build_recommendations(reasons)

        threat_score = (
            prediction.get("threat_score", 0.0) if prediction else self._estimate_score(all_feats)
        )
        risk_level = (
            prediction.get("risk_level", self._risk_level(threat_score))
            if prediction
            else self._risk_level(threat_score)
        )

        return {
            "risk_level": risk_level,
            "threat_score": threat_score,
            "top_reasons": reasons[:5],          # surface the top 5
            "all_reasons": reasons,
            "feature_scores": {k: round(v, 3) for k, v in all_feats.items()},
            "recommendations": recommendations,
        }

    def top_features(self, subject: str, body: str, urls: Optional[List[str]] = None, n: int = 5) -> List[Tuple[str, float]]:
        """
        Return the *n* features with the highest scores, sorted descending.
        Useful for quick dashboard tooltips.
        """
        urls = urls or []
        text_feats = self._text_ext.extract(subject, body)
        url_feats = self._url_ext.extract_from_list(urls)
        all_feats = {**text_feats, **url_feats}
        ranked = sorted(all_feats.items(), key=lambda kv: kv[1], reverse=True)
        return ranked[:n]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_reasons(
        self,
        text_feats: Dict,
        url_feats: Dict,
        meta_feats: Dict,
        urls: List[str],
    ) -> List[str]:
        reasons: List[str] = []

        if text_feats.get("has_urgency"):
            reasons.append("Uses urgency language to pressure the recipient into acting immediately.")
        if text_feats.get("has_threat"):
            reasons.append("Mentions account suspension, deactivation or security breach.")
        if text_feats.get("has_verify"):
            reasons.append("Requests the recipient to verify or confirm account credentials.")
        if text_feats.get("has_prize"):
            reasons.append("Claims the recipient has won a prize or reward — a classic lure.")
        if text_feats.get("has_sensitive"):
            reasons.append("Asks for sensitive information such as passwords or bank details.")
        if text_feats.get("subject_all_caps", 0) > 0.5:
            reasons.append("Subject line is written entirely in capitals, a spam indicator.")
        if text_feats.get("exclamation_density", 0) > 0.3:
            reasons.append("Excessive use of exclamation marks detected.")

        if url_feats.get("is_shortener"):
            reasons.append("Email contains a shortened URL that hides the actual destination.")
        if url_feats.get("risky_tld"):
            reasons.append("URL uses a top-level domain commonly associated with phishing.")
        if url_feats.get("uses_ip_address"):
            reasons.append("URL uses a raw IP address instead of a domain name.")
        if url_feats.get("has_at_symbol"):
            reasons.append("URL contains '@' which can trick browsers into loading a different host.")
        if url_feats.get("suspicious_keyword_density", 0) > 0.3:
            reasons.append("URL contains keywords commonly used in phishing (e.g. 'verify', 'secure').")

        if meta_feats.get("reply_to_mismatch"):
            reasons.append("Reply-To address does not match the sender domain — a spoofing indicator.")
        if meta_feats.get("from_is_free_provider") and not meta_feats.get("from_is_gov"):
            reasons.append("Sent from a free email provider, which can be created anonymously.")
        if meta_feats.get("risky_attachment"):
            reasons.append("Email contains a potentially dangerous attachment type (e.g. .exe, macro).")
        if meta_feats.get("missing_message_id"):
            reasons.append("Email is missing the standard Message-ID header — unusual for legitimate mail.")

        return reasons if reasons else ["No specific phishing indicators were detected."]

    @staticmethod
    def _build_recommendations(reasons: List[str]) -> List[str]:
        recs = []
        if reasons and reasons[0] != "No specific phishing indicators were detected.":
            recs.append("Do NOT click any links or download attachments until verified.")
            recs.append("Contact the apparent sender through a known, trusted channel.")
            recs.append("Report this email to your IT security team immediately.")
            recs.append("If credentials may have been entered, change passwords without delay.")
        else:
            recs.append("Email appears legitimate, but always exercise caution with links.")
        return recs

    @staticmethod
    def _estimate_score(features: Dict) -> float:
        """Very rough heuristic score from features (fallback when no model result)."""
        positive = sum(1 for v in features.values() if v > 0.5)
        return min(positive / max(len(features), 1), 1.0)

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