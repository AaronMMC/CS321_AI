"""
Data augmentation utilities for expanding training datasets.
Generates synthetic phishing / legitimate email variations.
"""

import random
import re
from typing import List, Tuple
from loguru import logger


# Word pools used to craft synthetic variations
_URGENT_PREFIXES = [
    "URGENT:", "IMPORTANT:", "ACTION REQUIRED:", "NOTICE:", "WARNING:",
    "ALERT:", "ATTENTION:", "CRITICAL:", "IMMEDIATE ACTION:", "FINAL NOTICE:",
]

_PHISHING_TEMPLATES = [
    "Your {service} account has been {action}. Click {link} to {verb} now.",
    "We detected unusual activity on your {service} account. Verify at {link}.",
    "Your {service} {item} is about to expire. Update here: {link}",
    "URGENT: Confirm your identity to restore {service} access. Go to {link}",
    "You have a pending {item} on {service}. Review it here: {link}",
]

_LEGITIMATE_TEMPLATES = [
    "Please find attached the {document} for your review.",
    "This is a reminder for the {event} scheduled on {date}.",
    "Your request for {item} has been {action}.",
    "Team update: {project} milestone reached. Details in the attached report.",
    "Monthly {report} is now available. Please review at your convenience.",
]

_SERVICES = ["GCash", "PayPal", "Netflix", "Spotify", "Google", "Microsoft", "bank"]
_ACTIONS = ["suspended", "limited", "flagged", "deactivated", "locked"]
_VERBS = ["verify", "confirm", "update", "restore", "reactivate"]
_LINKS = [
    "http://bit.ly/verify-now",
    "http://tinyurl.com/secure-login",
    "http://account-update.net/verify",
]
_DOCUMENTS = ["quarterly report", "monthly summary", "project update", "invoice"]
_EVENTS = ["team meeting", "project review", "training session", "board presentation"]
_PROJECTS = ["Alpha", "Phoenix", "Gateway", "NextGen"]
_REPORTS = ["performance report", "budget summary", "KPI dashboard"]


def _fill_template(template: str, is_phishing: bool) -> str:
    """Fill a template with random values."""
    replacements = {
        "{service}": random.choice(_SERVICES),
        "{action}": random.choice(_ACTIONS) if is_phishing else random.choice(["approved", "processed", "completed"]),
        "{link}": random.choice(_LINKS),
        "{verb}": random.choice(_VERBS),
        "{item}": random.choice(["subscription", "payment", "account", "order"]),
        "{document}": random.choice(_DOCUMENTS),
        "{event}": random.choice(_EVENTS),
        "{date}": f"April {random.randint(1, 30)}, 2024",
        "{project}": random.choice(_PROJECTS),
        "{report}": random.choice(_REPORTS),
    }
    result = template
    for placeholder, value in replacements.items():
        result = result.replace(placeholder, value)
    return result


class TextAugmenter:
    """
    Augment email text data to increase training set diversity.
    """

    def __init__(self, seed: int = 42):
        random.seed(seed)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def augment_dataset(
        self,
        texts: List[str],
        labels: List[int],
        augment_factor: int = 2,
    ) -> Tuple[List[str], List[int]]:
        """
        Augment every sample *augment_factor* additional times.

        Returns the original samples plus the generated ones.
        """
        augmented_texts = list(texts)
        augmented_labels = list(labels)

        for text, label in zip(texts, labels):
            for _ in range(augment_factor):
                aug = self._augment_single(text, is_phishing=bool(label))
                augmented_texts.append(aug)
                augmented_labels.append(label)

        logger.info(
            f"Augmented dataset: {len(texts)} → {len(augmented_texts)} samples "
            f"(factor ×{augment_factor + 1})"
        )
        return augmented_texts, augmented_labels

    def generate_synthetic_phishing(self, n: int = 50) -> List[str]:
        """Generate *n* synthetic phishing email texts."""
        samples = []
        for _ in range(n):
            prefix = random.choice(_URGENT_PREFIXES)
            template = random.choice(_PHISHING_TEMPLATES)
            body = _fill_template(template, is_phishing=True)
            samples.append(f"{prefix} {body}")
        return samples

    def generate_synthetic_legitimate(self, n: int = 50) -> List[str]:
        """Generate *n* synthetic legitimate email texts."""
        samples = []
        for _ in range(n):
            template = random.choice(_LEGITIMATE_TEMPLATES)
            body = _fill_template(template, is_phishing=False)
            samples.append(body)
        return samples

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _augment_single(self, text: str, is_phishing: bool) -> str:
        """Apply a random augmentation strategy to one sample."""
        strategy = random.choice([
            self._synonym_swap,
            self._case_variation,
            self._insert_noise,
            self._shuffle_sentences,
        ])
        try:
            return strategy(text, is_phishing)
        except Exception:
            return text  # Fall back to original on any error

    # --- Strategies ---

    def _synonym_swap(self, text: str, is_phishing: bool) -> str:
        """Replace some words with simple synonyms."""
        swaps = {
            "urgent": "immediate",
            "verify": "confirm",
            "suspended": "deactivated",
            "click": "tap",
            "account": "profile",
            "immediately": "right away",
            "meeting": "conference",
            "attached": "enclosed",
        }
        result = text
        for orig, replacement in swaps.items():
            if orig in result.lower() and random.random() < 0.4:
                result = re.sub(orig, replacement, result, flags=re.IGNORECASE, count=1)
        return result

    def _case_variation(self, text: str, _is_phishing: bool) -> str:
        """Randomly uppercase the first word of each sentence."""
        sentences = text.split(". ")
        varied = []
        for s in sentences:
            if s and random.random() < 0.3:
                s = s.upper()
            varied.append(s)
        return ". ".join(varied)

    def _insert_noise(self, text: str, is_phishing: bool) -> str:
        """Append a filler sentence to make the sample slightly longer."""
        fillers_phishing = [
            "Failure to act will result in permanent account closure.",
            "This is your final warning.",
            "Do not ignore this message.",
        ]
        fillers_legit = [
            "Please let us know if you have any questions.",
            "Thank you for your cooperation.",
            "We appreciate your prompt attention.",
        ]
        filler = random.choice(fillers_phishing if is_phishing else fillers_legit)
        return f"{text} {filler}"

    def _shuffle_sentences(self, text: str, _is_phishing: bool) -> str:
        """Shuffle the order of sentences (skipping very short texts)."""
        sentences = [s.strip() for s in text.split(".") if s.strip()]
        if len(sentences) > 2:
            middle = sentences[1:-1]
            random.shuffle(middle)
            sentences = [sentences[0]] + middle + [sentences[-1]]
        return ". ".join(sentences)