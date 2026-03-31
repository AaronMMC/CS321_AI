"""
Hand-crafted text feature extraction for phishing detection.
These features complement the BERT embeddings with explicit signals.
"""

import re
from typing import Dict, List
from loguru import logger


class TextFeatureExtractor:
    """
    Extract numerical features from email text that are useful for
    phishing detection independent of deep-learning embeddings.
    """

    # --- Word lists ----------------------------------------------------------

    URGENCY_WORDS = {
        "urgent", "immediately", "asap", "right away", "now", "today",
        "final notice", "last chance", "expires", "expiring", "deadline",
        "act now", "don't delay", "time sensitive",
    }

    THREAT_WORDS = {
        "suspended", "deactivated", "blocked", "limited", "restricted",
        "unusual activity", "unauthorized", "breach", "compromised",
        "fraud", "suspicious",
    }

    VERIFY_WORDS = {
        "verify", "confirm", "validate", "authenticate", "update",
        "reactivate", "restore", "re-confirm", "sign in", "log in",
        "click here", "click the link", "follow the link",
    }

    PRIZE_WORDS = {
        "won", "winner", "prize", "lottery", "congratulations", "selected",
        "reward", "free gift", "claim", "jackpot",
    }

    FINANCIAL_WORDS = {
        "bank", "credit card", "account number", "routing", "wire transfer",
        "payment", "invoice", "refund", "tax", "irs", "revenue",
    }

    SENSITIVE_WORDS = {
        "password", "ssn", "social security", "pin", "otp",
        "one-time", "credit card", "cvv", "passport",
    }

    # -------------------------------------------------------------------------

    def extract(self, subject: str, body: str) -> Dict[str, float]:
        """
        Return a flat dict of named features, all in the range [0, 1]
        unless otherwise noted.
        """
        text = f"{subject} {body}".lower()
        words = set(re.findall(r"\b\w+\b", text))

        features: Dict[str, float] = {}

        # Keyword presence flags
        features["has_urgency"] = float(bool(self.URGENCY_WORDS & words))
        features["has_threat"] = float(bool(self.THREAT_WORDS & words))
        features["has_verify"] = float(bool(self.VERIFY_WORDS & words))
        features["has_prize"] = float(bool(self.PRIZE_WORDS & words))
        features["has_financial"] = float(bool(self.FINANCIAL_WORDS & words))
        features["has_sensitive"] = float(bool(self.SENSITIVE_WORDS & words))

        # Keyword density (count / total word count, capped at 1)
        total_words = max(len(re.findall(r"\b\w+\b", text)), 1)
        features["urgency_density"] = min(
            len(self.URGENCY_WORDS & words) / total_words * 10, 1.0
        )

        # Structural features
        features["subject_all_caps_ratio"] = self._caps_ratio(subject)
        features["body_all_caps_ratio"] = self._caps_ratio(body)
        features["exclamation_density"] = min(text.count("!") / total_words * 5, 1.0)
        features["question_density"] = min(text.count("?") / total_words * 5, 1.0)

        # Length features (normalised)
        features["subject_length_norm"] = min(len(subject) / 200, 1.0)
        features["body_length_norm"] = min(len(body) / 5000, 1.0)

        # Presence of dollar / peso signs (financial lure)
        features["has_currency_symbol"] = float(bool(re.search(r"[$₱€£]", text)))

        # Excessive punctuation
        features["has_excessive_punctuation"] = float(
            bool(re.search(r"[!?]{2,}", subject))
        )

        return features

    def extract_batch(
        self, subjects: List[str], bodies: List[str]
    ) -> List[Dict[str, float]]:
        """Extract features for a list of (subject, body) pairs."""
        if len(subjects) != len(bodies):
            raise ValueError("subjects and bodies must have the same length")
        return [self.extract(s, b) for s, b in zip(subjects, bodies)]

    def as_vector(self, subject: str, body: str) -> List[float]:
        """Return features as an ordered list (consistent across calls)."""
        feat = self.extract(subject, body)
        return [feat[k] for k in sorted(feat)]

    # --- Helpers -------------------------------------------------------------

    @staticmethod
    def _caps_ratio(text: str) -> float:
        """Fraction of alphabetic characters that are uppercase."""
        alpha = [c for c in text if c.isalpha()]
        if not alpha:
            return 0.0
        return sum(1 for c in alpha if c.isupper()) / len(alpha)