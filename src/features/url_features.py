"""
URL-level feature extraction for phishing detection.
Analyses structural properties of URLs without external API calls.
"""

import re
import math
from typing import Dict, List, Optional
from urllib.parse import urlparse
from loguru import logger


# Well-known URL shorteners
_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "short.link", "rb.gy", "tiny.cc",
}

# TLDs commonly abused in phishing
_RISKY_TLDS = {
    "xyz", "top", "click", "link", "online", "site", "club",
    "info", "biz", "tk", "ml", "ga", "cf", "gq",
}

# Suspicious keywords inside URLs
_SUSPICIOUS_KEYWORDS = {
    "verify", "secure", "login", "signin", "update", "confirm",
    "account", "banking", "paypal", "amazon", "apple", "microsoft",
    "google", "facebook", "netflix", "gcash", "phishing",
}


class URLFeatureExtractor:
    """
    Extract hand-crafted features from a list of URLs in an email.
    All scores are normalised to [0, 1].
    """

    def extract_from_list(self, urls: List[str]) -> Dict[str, float]:
        """
        Aggregate features across all URLs in an email.

        Returns a flat feature dict.
        """
        if not urls:
            return self._empty_features()

        per_url = [self._extract_single(u) for u in urls]

        # Aggregate: take the max across URLs for each feature
        keys = per_url[0].keys()
        aggregated = {k: max(f[k] for f in per_url) for k in keys}

        # Extra aggregate features
        aggregated["url_count_norm"] = min(len(urls) / 10, 1.0)
        aggregated["shortener_ratio"] = sum(
            1 for f in per_url if f["is_shortener"]
        ) / len(per_url)

        return aggregated

    def _extract_single(self, url: str) -> Dict[str, float]:
        """Extract features for one URL."""
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
        except Exception:
            return self._empty_features()

        domain = parsed.netloc.lower().split(":")[0]  # strip port
        path = parsed.path.lower()
        full_url = url.lower()

        features: Dict[str, float] = {}

        # --- Shortener ---
        features["is_shortener"] = float(domain in _URL_SHORTENERS)

        # --- TLD risk ---
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        features["risky_tld"] = float(tld in _RISKY_TLDS)

        # --- Subdomain depth ---
        parts = domain.split(".")
        sub_depth = max(len(parts) - 2, 0)
        features["subdomain_depth_norm"] = min(sub_depth / 5, 1.0)

        # --- Suspicious keywords in URL ---
        kw_hits = sum(1 for kw in _SUSPICIOUS_KEYWORDS if kw in full_url)
        features["suspicious_keyword_density"] = min(kw_hits / 3, 1.0)

        # --- IP address used as domain ---
        features["uses_ip_address"] = float(bool(
            re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)
        ))

        # --- URL length (longer URLs are more suspicious) ---
        features["url_length_norm"] = min(len(url) / 200, 1.0)

        # --- Path depth ---
        path_depth = len([p for p in path.split("/") if p])
        features["path_depth_norm"] = min(path_depth / 8, 1.0)

        # --- Entropy of domain (high entropy → random-looking domain) ---
        features["domain_entropy"] = self._entropy(domain) / 5.0  # normalise

        # --- HTTPS ---
        features["is_https"] = float(parsed.scheme == "https")

        # --- @ symbol in URL (phishing trick) ---
        features["has_at_symbol"] = float("@" in url)

        # --- Double slash after path start ---
        features["has_double_slash"] = float("//" in path)

        return features

    # --- Helpers -------------------------------------------------------------

    @staticmethod
    def _entropy(text: str) -> float:
        """Shannon entropy of a string."""
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        n = len(text)
        return -sum((f / n) * math.log2(f / n) for f in freq.values())

    @staticmethod
    def _empty_features() -> Dict[str, float]:
        return {
            "is_shortener": 0.0,
            "risky_tld": 0.0,
            "subdomain_depth_norm": 0.0,
            "suspicious_keyword_density": 0.0,
            "uses_ip_address": 0.0,
            "url_length_norm": 0.0,
            "path_depth_norm": 0.0,
            "domain_entropy": 0.0,
            "is_https": 1.0,
            "has_at_symbol": 0.0,
            "has_double_slash": 0.0,
            "url_count_norm": 0.0,
            "shortener_ratio": 0.0,
        }

    def score(self, urls: List[str]) -> float:
        """
        Return a single [0, 1] suspicion score for a list of URLs.
        Useful as a quick feature for the model pipeline.
        """
        if not urls:
            return 0.0
        feats = self.extract_from_list(urls)
        weights = {
            "is_shortener": 0.25,
            "risky_tld": 0.15,
            "suspicious_keyword_density": 0.20,
            "uses_ip_address": 0.15,
            "has_at_symbol": 0.10,
            "domain_entropy": 0.10,
            "url_length_norm": 0.05,
        }
        return min(sum(feats.get(k, 0) * w for k, w in weights.items()), 1.0)