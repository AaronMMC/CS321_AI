"""
Alerting module for multi-channel notifications.
"""

from src.alerting.sms import get_sms_sender
from src.alerting.email import get_email_sender
from src.alerting.telegram import get_telegram_bot

__all__ = ['get_sms_sender', 'get_email_sender', 'get_telegram_bot']