"""
General utility functions used across the application.
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from pathlib import Path
import pickle
from loguru import logger


def generate_email_hash(email_content: str) -> str:
    """
    Generate a unique hash for an email content.
    Used for deduplication and tracking.
    """
    # Normalize content (remove whitespace, lowercase)
    normalized = ' '.join(email_content.lower().split())
    return hashlib.sha256(normalized.encode()).hexdigest()


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse various timestamp formats to datetime object.
    """
    formats = [
        '%a, %d %b %Y %H:%M:%S %z',  # RFC 2822
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S%z',
        '%d/%b/%Y:%H:%M:%S %z',
    ]

    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except (ValueError, TypeError):
            continue

    logger.warning(f"Could not parse timestamp: {timestamp_str}")
    return None


class Cache:
    """Simple file-based cache for API responses"""

    def __init__(self, cache_dir: str = "cache", ttl_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)

    def _get_cache_path(self, key: str) -> Path:
        """Get filesystem path for cache key"""
        # Hash the key to create safe filename
        hashed = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{hashed}.pkl"

    def get(self, key: str) -> Optional[Any]:
        """Retrieve from cache if not expired"""
        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            return None

        try:
            with open(cache_path, 'rb') as f:
                data = pickle.load(f)

            # Check expiration
            if datetime.now() - data['timestamp'] < self.ttl:
                logger.debug(f"Cache hit for {key}")
                return data['value']
            else:
                logger.debug(f"Cache expired for {key}")
                cache_path.unlink()  # Delete expired cache
                return None

        except Exception as e:
            logger.warning(f"Cache read failed for {key}: {e}")
            return None

    def set(self, key: str, value: Any):
        """Store in cache with timestamp"""
        cache_path = self._get_cache_path(key)

        try:
            data = {
                'timestamp': datetime.now(),
                'value': value
            }
            with open(cache_path, 'wb') as f:
                pickle.dump(data, f)
            logger.debug(f"Cached {key}")
        except Exception as e:
            logger.warning(f"Cache write failed for {key}: {e}")

    def clear(self):
        """Clear all cache entries"""
        for cache_file in self.cache_dir.glob("*.pkl"):
            cache_file.unlink()
        logger.info("Cache cleared")


class ThreatScoreCalculator:
    """Calculate and normalize threat scores"""

    @staticmethod
    def combine_scores(scores: Dict[str, float], weights: Optional[Dict[str, float]] = None) -> float:
        """
        Combine multiple threat scores with optional weights.

        Args:
            scores: Dict of score_name -> score_value (0-1)
            weights: Dict of score_name -> weight (sum should be 1)

        Returns:
            Combined score (0-1)
        """
        if not scores:
            return 0.0

        if weights is None:
            # Equal weights if not specified
            weights = {k: 1.0 / len(scores) for k in scores}

        # Ensure weights sum to 1
        total_weight = sum(weights.values())
        if abs(total_weight - 1.0) > 0.001:
            # Normalize weights
            weights = {k: w / total_weight for k, w in weights.items()}

        combined = sum(scores.get(k, 0) * weights.get(k, 0) for k in scores)
        return min(1.0, max(0.0, combined))  # Clamp to [0,1]

    @staticmethod
    def calculate_risk_level(score: float) -> str:
        """Convert numerical score to risk level"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "SAFE"


def format_alert_message(threat_data: Dict) -> str:
    """Format threat data into readable alert message"""

    risk_level = ThreatScoreCalculator.calculate_risk_level(threat_data.get('score', 0))

    message = f"""
 {risk_level} RISK EMAIL DETECTED
━━━━━━━━━━━━━━━━━━━━━━━
 From: {threat_data.get('from', 'Unknown')}
 To: {threat_data.get('to', 'Unknown')}
 Subject: {threat_data.get('subject', 'No subject')}
️ Threat Score: {threat_data.get('score', 0):.1%}
 Risk Level: {risk_level}

 Suspicious Links: {threat_data.get('suspicious_links', 0)}
 Attachments: {threat_data.get('suspicious_attachments', 0)}

 Action Required: Investigate immediately if {risk_level} in ['CRITICAL', 'HIGH']
    """.strip()

    return message