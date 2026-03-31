"""
Email header / metadata feature extraction.
Analyses sender, routing headers and structural anomalies.
"""

import re
from typing import Dict, List, Optional
from loguru import logger


# Philippine government domains considered trusted
_TRUSTED_GOV_DOMAINS = {
    "gov.ph", "deped.gov.ph", "dict.gov.ph", "doh.gov.ph",
    "dswd.gov.ph", "dilg.gov.ph", "dfa.gov.ph", "doj.gov.ph",
    "nbi.gov.ph", "pnp.gov.ph",
}

# Free email providers often abused in spoofing
_FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "tutanota.com", "yandex.com",
}


class MetadataFeatureExtractor:
    """
    Extract features from the parsed email metadata dict produced by
    ``EmailParser.parse_raw_email()``.
    """

    def extract(self, email_data: Dict) -> Dict[str, float]:
        """
        Return a flat feature dict with values in [0, 1].

        Args:
            email_data: Parsed email dictionary from EmailParser.
        """
        features: Dict[str, float] = {}

        from_domain = self._get_from_domain(email_data)
        reply_domain = self._get_reply_to_domain(email_data)

        # --- Sender trust ---
        features["from_is_gov"] = float(self._is_gov_domain(from_domain))
        features["from_is_free_provider"] = float(from_domain in _FREE_PROVIDERS)

        # --- Reply-To mismatch ---
        features["reply_to_mismatch"] = float(
            reply_domain is not None and reply_domain != from_domain
        )

        # --- Subject indicators ---
        subject = email_data.get("subject", "")
        features["subject_has_urgency"] = float(
            self._contains_urgency(subject)
        )
        features["subject_all_caps"] = float(subject == subject.upper() and len(subject) > 5)
        features["subject_length_norm"] = min(len(subject) / 200, 1.0)

        # --- Attachment risk ---
        attachments = email_data.get("attachments", [])
        features["has_attachments"] = float(bool(attachments))
        features["risky_attachment"] = float(
            any(self._is_risky_attachment(a) for a in attachments)
        )

        # --- URL count ---
        urls = email_data.get("urls", [])
        features["url_count_norm"] = min(len(urls) / 10, 1.0)

        # --- Missing headers (suspicious) ---
        features["missing_message_id"] = float(
            not bool(email_data.get("message_id"))
        )

        # --- Encoding / size anomalies ---
        size = email_data.get("size", 0)
        features["email_size_norm"] = min(size / 1_000_000, 1.0)  # norm to 1 MB

        return features

    def extract_batch(self, email_list: List[Dict]) -> List[Dict[str, float]]:
        """Extract features for a list of parsed email dicts."""
        return [self.extract(e) for e in email_list]

    def as_vector(self, email_data: Dict) -> List[float]:
        """Return features as a sorted, ordered list."""
        feat = self.extract(email_data)
        return [feat[k] for k in sorted(feat)]

    # --- Helpers -------------------------------------------------------------

    @staticmethod
    def _get_from_domain(email_data: Dict) -> str:
        """Safely extract the sender domain."""
        domain = email_data.get("from_domain", "")
        if not domain:
            frm = email_data.get("from", [])
            if isinstance(frm, list) and frm:
                addr = frm[0].get("email", "")
                domain = addr.split("@")[-1] if "@" in addr else ""
            elif isinstance(frm, str) and "@" in frm:
                domain = frm.split("@")[-1]
        return domain.lower().strip()

    @staticmethod
    def _get_reply_to_domain(email_data: Dict) -> Optional[str]:
        """Safely extract the Reply-To domain."""
        rt = email_data.get("reply_to", [])
        if isinstance(rt, list) and rt:
            addr = rt[0].get("email", "")
            if "@" in addr:
                return addr.split("@")[-1].lower().strip()
        return None

    @staticmethod
    def _is_gov_domain(domain: str) -> bool:
        return any(domain == d or domain.endswith("." + d) for d in _TRUSTED_GOV_DOMAINS)

    @staticmethod
    def _contains_urgency(text: str) -> bool:
        urgency_re = re.compile(
            r"\b(urgent|immediately|asap|suspended|verify|confirm|warning|alert|action required)\b",
            re.IGNORECASE,
        )
        return bool(urgency_re.search(text))

    @staticmethod
    def _is_risky_attachment(attachment: Dict) -> bool:
        """Flag executable or macro-capable attachment types."""
        risky_types = {
            "application/x-msdownload",
            "application/x-executable",
            "application/vnd.ms-excel.sheet.macroEnabled",
            "application/vnd.ms-word.document.macroEnabled",
        }
        risky_exts = {".exe", ".bat", ".cmd", ".vbs", ".js", ".jar", ".scr", ".pif"}

        ct = attachment.get("content_type", "").lower()
        fn = attachment.get("filename", "").lower()

        if ct in risky_types:
            return True
        return any(fn.endswith(ext) for ext in risky_exts)