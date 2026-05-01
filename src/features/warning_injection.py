"""
Email Warning Injection Module.

Injects visual warnings into suspicious emails before delivery so that
recipients see a clear banner regardless of their email client.

Per the gateway design:
  - Subject line receives a [SUSPICIOUS] / [WARNING] / [CAUTION] prefix
    that survives forwarding and is visible in every mail client preview pane.
  - A plain-text warning banner is prepended to the email body with:
      • risk level and threat score
      • reasons the email was flagged
      • contextual Just-in-Time Training safety tips
  - X-Security-* headers are written for advanced mail clients.

CHANGES FROM ORIGINAL: none — this file is complete and correct as-is.
It is included here so the demo package is fully self-contained.
"""

from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Dict, List, Optional


class WarningLevel(IntEnum):
    """Warning severity levels ordered from safest to most dangerous."""
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class EmailWarningInjector:
    """
    Injects warnings into suspicious emails.

    Designed to work with ANY email client by:
      1. Modifying the subject line (visible in all clients' preview panes).
      2. Injecting a plain-text warning banner at the top of the body.
      3. Adding X-Security-* headers for advanced clients.
    """

    WARNING_PREFIXES: Dict[WarningLevel, str] = {
        WarningLevel.SAFE:     "[SAFE]",
        WarningLevel.LOW:      "[LOW RISK]",
        WarningLevel.MEDIUM:   "[CAUTION]",
        WarningLevel.HIGH:     "[WARNING]",
        WarningLevel.CRITICAL: "[SUSPICIOUS]",
    }

    SAFETY_TIPS: List[str] = [
        "Do NOT click links in this email",
        "Do NOT download attachments",
        "Do NOT reply with personal information",
        "Verify sender identity through official channels",
        "Report this email to your IT department",
        "When in doubt, contact the organisation directly using official contact information",
        "Government agencies will NEVER ask for passwords via email",
        "GCash / Landbank / BIR will NEVER send verification links via bit.ly",
    ]

    def __init__(self, min_warning_level: WarningLevel = WarningLevel.HIGH):
        """
        Args:
            min_warning_level: Minimum threat level that triggers modifications.
                               Default is HIGH — only HIGH and CRITICAL emails
                               are modified.  Set to MEDIUM to also warn on
                               medium-risk emails.
        """
        self.min_warning_level = min_warning_level

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inject_warning(
        self,
        email_data: Dict[str, Any],
        threat_level: WarningLevel,
        explanations: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Return a copy of email_data with warnings injected if the threat
        level meets or exceeds self.min_warning_level.

        Args:
            email_data:   Dict with at minimum 'subject', 'body', 'headers'
                          keys plus optional 'threat_score', 'risk_level'.
            threat_level: Severity of the detected threat.
            explanations: Human-readable reasons for flagging (shown in banner).

        Returns:
            Updated email_data dict with 'modified', 'modified_body',
            'warning_level', and 'warning_info' keys added / updated.
        """
        should_modify = threat_level >= self.min_warning_level
        threat_score: float = email_data.get("threat_score", 0.0)
        resolved_explanations: List[str] = (
            explanations if explanations is not None
            else email_data.get("explanations", [])
        )
        warning_prefix = self.WARNING_PREFIXES.get(threat_level, "[WARNING]")

        result: Dict[str, Any] = {
            **email_data,
            "headers": {**email_data.get("headers", {})},
            "modified": False,
            "modified_body": False,
            "warning_level": threat_level,
            "warning_info": {},
        }

        if should_modify:
            # Subject
            result["subject"] = self._modify_subject(
                email_data.get("subject", ""), warning_prefix
            )
            result["modified"] = True

            # Body
            body = email_data.get("body", email_data.get("body_plain", ""))
            if body:
                result["body"] = self._inject_body_warning(
                    body, threat_level, threat_score, resolved_explanations
                )
                result["modified_body"] = True

            # Headers
            self._add_security_headers(
                result["headers"], threat_level, threat_score, resolved_explanations
            )

        result["warning_info"] = {
            "warning_level": threat_level.name,
            "warning_prefix": warning_prefix,
            "threat_score": threat_score,
            "explanations": resolved_explanations,
            "safety_tips": self.SAFETY_TIPS[:3],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return result

    def determine_warning_level(self, threat_score: float) -> WarningLevel:
        """Map a numeric threat score to a WarningLevel enum value."""
        if threat_score >= 0.80:
            return WarningLevel.CRITICAL
        if threat_score >= 0.60:
            return WarningLevel.HIGH
        if threat_score >= 0.40:
            return WarningLevel.MEDIUM
        if threat_score >= 0.20:
            return WarningLevel.LOW
        return WarningLevel.SAFE

    # ------------------------------------------------------------------
    # Subject
    # ------------------------------------------------------------------

    def _modify_subject(self, subject: str, warning_prefix: str) -> str:
        if not subject or not subject.strip():
            return f"{warning_prefix} [No Subject]"
        # Avoid duplicate prefixes on retry
        for prefix in self.WARNING_PREFIXES.values():
            if subject.startswith(prefix):
                return subject.replace(prefix, warning_prefix, 1)
        return f"{warning_prefix} {subject}"

    # ------------------------------------------------------------------
    # Body
    # ------------------------------------------------------------------

    def _inject_body_warning(
        self,
        body: str,
        threat_level: WarningLevel,
        threat_score: float,
        explanations: List[str],
    ) -> str:
        banner = self._generate_warning_banner(threat_level, threat_score, explanations)
        return banner + body

    def _generate_warning_banner(
        self,
        threat_level: WarningLevel,
        threat_score: float,
        explanations: List[str],
    ) -> str:
        symbol = self._get_warning_symbol(threat_level)
        risk_name = threat_level.name

        explanations_text = ""
        if explanations:
            explanations_text = "\n! REASONS THIS EMAIL MAY BE SUSPICIOUS:\n"
            for exp in explanations[:5]:
                explanations_text += f"   * {exp}\n"

        relevant_tips = self._get_relevant_safety_tips(explanations)
        tips_text = "\n>>> SAFETY TIPS <<<\n" + "\n".join(
            f"   * {tip}" for tip in relevant_tips
        )

        return (
            f"\n{'=' * 70}\n"
            f"{symbol}  EMAIL SECURITY WARNING  {symbol}\n"
            f"{'=' * 70}\n"
            f"\n! RISK LEVEL: {risk_name}\n"
            f"! THREAT SCORE: {threat_score:.0%}\n"
            f"{'=' * 70}\n"
            f"{explanations_text}"
            f"{tips_text}\n"
            f"{'=' * 70}\n"
            f"! This warning was added by the Email Security Gateway.\n"
            f"  If you believe this is a false positive, contact your IT department.\n"
            f"{'=' * 70}\n\n"
            f"--- Original Email Below ---\n\n"
        )

    # ------------------------------------------------------------------
    # Headers
    # ------------------------------------------------------------------

    def _add_security_headers(
        self,
        headers: Dict[str, str],
        threat_level: WarningLevel,
        threat_score: float,
        explanations: List[str],
    ) -> None:
        headers["X-Security-Threat-Score"] = f"{threat_score:.2f}"
        headers["X-Security-Risk-Level"] = threat_level.name
        headers["X-Security-Warning"] = self.WARNING_PREFIXES.get(
            threat_level, "[WARNING]"
        )
        headers["X-Security-Analyzed"] = datetime.now(timezone.utc).isoformat()
        if explanations:
            headers["X-Security-Reasons"] = "; ".join(explanations[:3])

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_warning_symbol(level: WarningLevel) -> str:
        return {
            WarningLevel.SAFE:     "[OK]",
            WarningLevel.LOW:      "[i]",
            WarningLevel.MEDIUM:   "[!]",
            WarningLevel.HIGH:     "[!!]",
            WarningLevel.CRITICAL: "[!!!]",
        }.get(level, "[!]")

    def _get_relevant_safety_tips(self, explanations: List[str]) -> List[str]:
        """Return tips that are contextually relevant to the detected threat."""
        tips: List[str] = []
        text = " ".join(explanations).lower()

        if "url" in text or "link" in text:
            tips.append("Do NOT click any links in this email")
        if "urgency" in text or "suspended" in text or "urgent" in text:
            tips.append("Legitimate organisations never create artificial urgency")
        if "gcash" in text:
            tips.append("GCash never sends verification links via bit.ly or SMS")
        if "bank" in text or "landbank" in text:
            tips.append("Banks never ask for passwords via email")
        if "attachment" in text:
            tips.append("Do NOT open any attachments")

        if not tips:
            tips = [
                "Do NOT click links or download attachments",
                "Verify sender through official channels",
                "When in doubt, contact your IT department",
            ]
        return tips[:3]


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


def inject_warning_into_email(
    email_data: Dict[str, Any],
    threat_score: float,
    explanations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Convenience one-liner for callers that do not need to configure the injector.

    Uses default min_warning_level=HIGH so only HIGH/CRITICAL emails are modified.
    """
    injector = EmailWarningInjector()
    level = injector.determine_warning_level(threat_score)
    return injector.inject_warning(email_data, level, explanations)