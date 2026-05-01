"""
SMS alerting module using Twilio.

CHANGES FROM ORIGINAL:
  1. MockSMSSender.enabled = True so smtp_handler can check the .enabled
     attribute on both real and mock senders without AttributeError.
  2. SMSAlertSender.enabled property consolidated — set once in __init__
     so callers can always do `if sender.enabled: sender.send_alert(...)`.
  3. Docstring updated to reflect gateway integration pattern.
"""

import os
from typing import Dict, Optional

from loguru import logger

try:
    from twilio.rest import Client
    from twilio.base.exceptions import TwilioRestException
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False
    logger.warning("Twilio not installed — SMS alerts disabled. Run: pip install twilio")


class SMSAlertSender:
    """
    Send SMS alerts via Twilio when a high-risk email is detected.

    Required environment variables (set in .env):
        TWILIO_ACCOUNT_SID
        TWILIO_AUTH_TOKEN
        TWILIO_FROM_NUMBER   — the Twilio phone number to send from
    """

    def __init__(
        self,
        account_sid: Optional[str] = None,
        auth_token: Optional[str] = None,
        from_number: Optional[str] = None,
    ):
        self.account_sid = account_sid or os.getenv("TWILIO_ACCOUNT_SID", "")
        self.auth_token = auth_token or os.getenv("TWILIO_AUTH_TOKEN", "")
        self.from_number = from_number or os.getenv("TWILIO_FROM_NUMBER", "")

        self.client = None
        self.enabled = False

        if not TWILIO_AVAILABLE:
            logger.warning("SMS alerts disabled — Twilio library not installed")
            return

        if not all([self.account_sid, self.auth_token, self.from_number]):
            logger.warning(
                "SMS alerts disabled — missing TWILIO_ACCOUNT_SID / "
                "TWILIO_AUTH_TOKEN / TWILIO_FROM_NUMBER in .env"
            )
            return

        try:
            self.client = Client(self.account_sid, self.auth_token)
            self.enabled = True
            logger.info("SMSAlertSender initialised (Twilio)")
        except Exception as exc:
            logger.error(f"Failed to initialise Twilio client: {exc}")

    # ------------------------------------------------------------------

    def send_alert(self, to_number: str, threat_data: Dict) -> bool:
        """
        Send an SMS alert about a detected threat.

        Args:
            to_number:   Recipient phone number (E.164 format, e.g. +639123456789).
            threat_data: Dict with at least 'risk_level', 'threat_score',
                         'from', and 'subject' keys.

        Returns:
            True on success, False on failure or if sender is not enabled.
        """
        if not self.enabled or not self.client:
            logger.warning("SMS alert skipped — sender not enabled")
            return False

        message = self._format_message(threat_data)

        try:
            # Truncate to SMS single-message limit
            if len(message) > 160:
                message = message[:157] + "…"

            result = self.client.messages.create(
                body=message,
                from_=self.from_number,
                to=to_number,
            )
            logger.info(f"SMS alert sent to {to_number} — SID: {result.sid}")
            return True

        except TwilioRestException as exc:
            logger.error(f"Twilio error sending SMS to {to_number}: {exc}")
            return False
        except Exception as exc:
            logger.error(f"Unexpected error sending SMS: {exc}")
            return False

    def _format_message(self, threat_data: Dict) -> str:
        risk_level = threat_data.get("risk_level", "UNKNOWN")
        score = threat_data.get("threat_score", 0.0)

        emoji = {
            "CRITICAL": "[!!!]",
            "HIGH":     "[!!]",
            "MEDIUM":   "[!]",
        }.get(risk_level, "[i]")

        subject = str(threat_data.get("subject", "No subject"))[:35]
        sender  = str(threat_data.get("from", "Unknown"))[:30]

        campaign = threat_data.get("campaign")
        campaign_note = ""
        if campaign and campaign.get("campaign_detected"):
            campaign_note = f" | CAMPAIGN: {campaign['count']} emails"

        return (
            f"{emoji} {risk_level} EMAIL\n"
            f"From: {sender}\n"
            f"Subj: {subject}\n"
            f"Score: {score:.0%}{campaign_note}\n"
            f"Check dashboard: http://localhost:8501"
        )


# ---------------------------------------------------------------------------
# Mock sender (development / CI)
# ---------------------------------------------------------------------------


class MockSMSAlertSender:
    """
    Drop-in replacement for SMSAlertSender that logs instead of sending.
    Used when Twilio credentials are absent or in test environments.
    """

    # enabled = True so smtp_handler can always check .enabled uniformly
    enabled: bool = True

    def __init__(self, *args, **kwargs):
        logger.info("MockSMSAlertSender initialised (no real SMS will be sent)")

    def send_alert(self, to_number: str, threat_data: Dict) -> bool:
        risk_level = threat_data.get("risk_level", "UNKNOWN")
        subject = str(threat_data.get("subject", ""))[:40]
        logger.info(f"[MOCK SMS] → {to_number}  [{risk_level}] {subject}")
        return True


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_sms_sender(use_mock: bool = False) -> SMSAlertSender | MockSMSAlertSender:
    """
    Return a real SMSAlertSender if Twilio credentials are configured,
    otherwise return a MockSMSAlertSender.

    Pass use_mock=True to force the mock regardless of credentials
    (useful in tests).
    """
    if use_mock:
        return MockSMSAlertSender()

    sender = SMSAlertSender()
    if not sender.enabled:
        logger.info("Falling back to MockSMSAlertSender (no Twilio credentials)")
        return MockSMSAlertSender()
    return sender