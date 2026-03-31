"""
Batch prediction utilities for processing large volumes of emails efficiently.
"""

import time
from typing import Dict, List, Optional, Iterator
from loguru import logger

from src.inference.predictor import EmailThreatPredictor
from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.features.external_intelligence import ThreatIntelligenceHub


class BatchEmailPredictor:
    """
    Processes lists of emails in configurable-size chunks to avoid
    memory exhaustion and provide progress feedback.
    """

    def __init__(
        self,
        predictor: Optional[EmailThreatPredictor] = None,
        chunk_size: int = 32,
    ):
        self.predictor = predictor or EmailThreatPredictor()
        self.chunk_size = chunk_size

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict_batch(self, emails: List[Dict]) -> List[Dict]:
        """
        Predict threat scores for a list of email dicts.

        Each element must have at least ``subject`` and ``body`` keys.
        The ``urls`` and ``from_domain`` keys are used if present.

        Returns a list of result dicts in the same order as the input.
        """
        results: List[Dict] = []
        total = len(emails)
        logger.info(f"BatchEmailPredictor: processing {total} emails in chunks of {self.chunk_size}")
        t0 = time.time()

        for chunk in self._chunks(emails):
            for email in chunk:
                try:
                    result = self.predictor.predict(
                        subject=email.get("subject", ""),
                        body=email.get("body", email.get("body_plain", "")),
                        urls=email.get("urls"),
                        from_domain=email.get("from_domain"),
                    )
                    result["input"] = {
                        "subject": email.get("subject", ""),
                        "from": email.get("from", ""),
                    }
                    results.append(result)
                except Exception as exc:
                    logger.error(f"Prediction failed for email '{email.get('subject', '')}': {exc}")
                    results.append(
                        {
                            "threat_score": 0.0,
                            "risk_level": "UNKNOWN",
                            "error": str(exc),
                        }
                    )

        elapsed = time.time() - t0
        logger.info(
            f"Batch complete: {total} emails in {elapsed:.1f}s "
            f"({total / max(elapsed, 0.01):.1f} emails/s)"
        )
        return results

    def predict_texts(self, subjects: List[str], bodies: List[str]) -> List[Dict]:
        """
        Convenience wrapper when you have parallel subject and body lists.
        """
        if len(subjects) != len(bodies):
            raise ValueError("subjects and bodies must have the same length")
        emails = [{"subject": s, "body": b} for s, b in zip(subjects, bodies)]
        return self.predict_batch(emails)

    def summary_stats(self, results: List[Dict]) -> Dict:
        """
        Compute aggregate statistics over a batch of prediction results.
        """
        if not results:
            return {}

        scores = [r.get("threat_score", 0.0) for r in results]
        levels = [r.get("risk_level", "UNKNOWN") for r in results]

        level_counts: Dict[str, int] = {}
        for lvl in levels:
            level_counts[lvl] = level_counts.get(lvl, 0) + 1

        return {
            "total": len(results),
            "mean_threat_score": sum(scores) / len(scores),
            "max_threat_score": max(scores),
            "min_threat_score": min(scores),
            "risk_level_distribution": level_counts,
            "threats_detected": sum(1 for s in scores if s >= 0.6),
            "critical_count": level_counts.get("CRITICAL", 0),
            "high_count": level_counts.get("HIGH", 0),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _chunks(self, lst: List) -> Iterator[List]:
        for i in range(0, len(lst), self.chunk_size):
            yield lst[i : i + self.chunk_size]