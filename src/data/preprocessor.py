"""
Text preprocessing pipeline for email data.
Cleans, normalizes and prepares raw email text before tokenization.
"""

import re
import html
from typing import List, Optional
from loguru import logger


class EmailPreprocessor:
    """
    Clean and normalize raw email text so the model sees consistent input.

    Steps applied (in order):
        1. Unescape HTML entities
        2. Strip HTML tags
        3. Decode common URL-encoded characters
        4. Normalize whitespace
        5. Lower-case (optional)
        6. Remove / mask URLs
        7. Truncate to max_length tokens (by word count)
    """

    # Regex patterns
    _HTML_TAG = re.compile(r"<[^>]+>")
    _URL = re.compile(r"https?://\S+|www\.\S+")
    _MULTI_SPACE = re.compile(r"\s+")
    _EMAIL_ADDR = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    _REPEATED_PUNCT = re.compile(r"([!?.]){3,}")

    def __init__(
        self,
        lowercase: bool = True,
        mask_urls: bool = True,
        mask_emails: bool = True,
        max_words: int = 400,
    ):
        self.lowercase = lowercase
        self.mask_urls = mask_urls
        self.mask_emails = mask_emails
        self.max_words = max_words

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def clean(self, text: str) -> str:
        """Apply the full cleaning pipeline to a single string."""
        if not isinstance(text, str):
            text = str(text)

        text = html.unescape(text)
        text = self._HTML_TAG.sub(" ", text)
        text = self._decode_url_chars(text)

        if self.mask_emails:
            text = self._EMAIL_ADDR.sub("[EMAIL]", text)

        if self.mask_urls:
            text = self._URL.sub("[URL]", text)

        # Collapse repeated punctuation (e.g. "!!!!" → "!")
        text = self._REPEATED_PUNCT.sub(r"\1", text)

        text = self._MULTI_SPACE.sub(" ", text).strip()

        if self.lowercase:
            text = text.lower()

        # Word-count truncation
        words = text.split()
        if len(words) > self.max_words:
            text = " ".join(words[: self.max_words])

        return text

    def clean_batch(self, texts: List[str]) -> List[str]:
        """Clean a list of texts."""
        cleaned = [self.clean(t) for t in texts]
        logger.debug(f"Cleaned {len(cleaned)} texts")
        return cleaned

    def prepare_for_model(self, subject: str, body: str) -> str:
        """
        Combine subject and body into a single model input string.
        Subject is prepended with a [SUBJECT] marker so the model can
        pay more attention to it.
        """
        combined = f"[SUBJECT] {subject} [BODY] {body}"
        return self.clean(combined)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_url_chars(text: str) -> str:
        """Replace common URL-encoded sequences with readable text."""
        replacements = {
            "%20": " ",
            "%3A": ":",
            "%2F": "/",
            "%3F": "?",
            "%3D": "=",
            "%26": "&",
            "&amp;": "&",
            "&lt;": "<",
            "&gt;": ">",
            "&nbsp;": " ",
        }
        for encoded, decoded in replacements.items():
            text = text.replace(encoded, decoded)
        return text

    @staticmethod
    def extract_plain_from_html(html_body: str) -> str:
        """Strip HTML and return readable plain text."""
        text = re.sub(r"<br\s*/?>", "\n", html_body, flags=re.IGNORECASE)
        text = re.sub(r"<p[^>]*>", "\n", text, flags=re.IGNORECASE)
        text = re.sub(r"<[^>]+>", "", text)
        text = html.unescape(text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    @staticmethod
    def contains_urgency(text: str) -> bool:
        """Quick heuristic check for urgency language."""
        urgency_words = {
            "urgent", "immediately", "asap", "right away", "final notice",
            "last chance", "expires", "suspended", "deactivated", "verify now",
        }
        lower = text.lower()
        return any(w in lower for w in urgency_words)

    @staticmethod
    def contains_sensitive_request(text: str) -> bool:
        """Check if email requests sensitive information."""
        sensitive = {
            "password", "credit card", "bank account", "social security",
            "ssn", "pin", "one-time password", "otp", "cvv",
        }
        lower = text.lower()
        return any(w in lower for w in sensitive)