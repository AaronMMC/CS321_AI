"""
SMS alerting module using Twilio.
Sends critical alerts to admin via SMS.
"""

from typing import Dict, Optional, List
from loguru import logger
import os

try:
    from twilio.rest import Client
    from twilio.base.exceptions import TwilioRestException
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False
    logger.warning("Twilio not installed - SMS alerts disabled")


class SMSAlertSender:
    """Send SMS alerts via Twilio"""

    def __init__(self, account_sid: Optional[str] = None, auth_token: Optional[str] = None, from_number: Optional[str] = None):
        self.account_sid = account_sid or os.getenv("TWILIO_ACCOUNT_SID")
        self.auth_token = auth_token or os.getenv("TWILIO_AUTH_TOKEN")
        self.from_number = from_number or os.getenv("TWILIO_FROM_NUMBER")

        self.client = None
        self.enabled = False

        if TWILIO_AVAILABLE and self.account_sid and self.auth_token and self.from_number:
            try:
                self.client = Client(self.account_sid, self.auth_token)
                self.enabled = True
                logger.info("SMS alert sender initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Twilio client: {e}")
        else:
            logger.warning("SMS alerts disabled - missing credentials or Twilio library")

    def send_alert(self, to_number: str, threat_data: Dict) -> bool:
        """Send SMS alert about a threat."""
        if not self.enabled or not self.client:
            logger.warning("SMS alerts not enabled - message not sent")
            return False

        message = self._format_alert_message(threat_data)

        try:
            if len(message) > 160:
                message = message[:157] + "..."

            result = self.client.messages.create(
                body=message,
                from_=self.from_number,
                to=to_number
            )

            logger.info(f"SMS alert sent to {to_number}: {result.sid}")
            return True

        except Exception as e:
            logger.error(f"Failed to send SMS: {e}")
            return False

    def _format_alert_message(self, threat_data: Dict) -> str:
        """Format threat data into SMS-friendly message"""
        risk_level = threat_data.get('risk_level', 'UNKNOWN')
        score = threat_data.get('threat_score', 0)

        if risk_level == 'CRITICAL':
            emoji = "🔴"
        elif risk_level == 'HIGH':
            emoji = "🟠"
        else:
            emoji = "🟡"

        return (
            f"{emoji} {risk_level} RISK EMAIL\n"
            f"From: {threat_data.get('from', 'Unknown')}\n"
            f"Subject: {threat_data.get('subject', 'No subject')[:30]}\n"
            f"Score: {score:.1%}\n"
            f"Check dashboard"
        )


class MockSMSAlertSender:
    """Mock SMS sender for development"""

    def __init__(self, *args, **kwargs):
        self.enabled = True
        logger.info("Mock SMS alert sender initialized")

    def send_alert(self, to_number: str, threat_data: Dict) -> bool:
        logger.info(f"[MOCK SMS] To: {to_number}")
        logger.info(f"[MOCK SMS] Alert: {threat_data.get('risk_level')} - {threat_data.get('subject', '')[:30]}")
        return True


def get_sms_sender(use_mock: bool = False):
    """Get SMS sender instance (real or mock)"""
    if use_mock:
        return MockSMSAlertSender()
    return SMSAlertSender()