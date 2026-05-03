"""
Alerting module — email (Gmail) only.

SMS (Twilio) and Telegram have been removed from the prototype.
All alerts are sent via src/alerting/email.py using Gmail App Passwords.
"""

from src.alerting.email import get_email_sender, EmailAlertSender, MockEmailAlertSender

__all__ = ["get_email_sender", "EmailAlertSender", "MockEmailAlertSender"]