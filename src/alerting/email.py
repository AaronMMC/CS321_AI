"""
Email alerting module.
Sends detailed alerts via email with HTML formatting.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from loguru import logger
import os
from datetime import datetime


class EmailAlertSender:
    """Send email alerts with detailed threat information"""

    def __init__(
        self,
        smtp_server: Optional[str] = None,
        smtp_port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        from_email: Optional[str] = None,
        use_tls: bool = True
    ):
        self.smtp_server = smtp_server or os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = smtp_port or int(os.getenv("SMTP_PORT", "587"))
        self.username = username or os.getenv("SMTP_USERNAME")
        self.password = password or os.getenv("SMTP_PASSWORD")
        self.from_email = from_email or os.getenv("FROM_EMAIL", "alerts@email-security.local")
        self.use_tls = use_tls

        self.enabled = bool(self.username and self.password)

        if self.enabled:
            logger.info(f"Email alert sender initialized")
        else:
            logger.warning("Email alerts disabled - missing SMTP credentials")

    def send_alert(self, to_email: str, threat_data: Dict) -> bool:
        """Send email alert about a threat."""
        if not self.enabled:
            logger.warning("Email alerts not enabled")
            return False

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{threat_data.get('risk_level', 'ALERT')}] Suspicious Email Detected"
            msg['From'] = self.from_email
            msg['To'] = to_email

            html_content = self._create_html_content(threat_data)
            text_content = self._create_text_content(threat_data)

            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.send_message(msg)

            logger.info(f"Email alert sent to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

    def _create_html_content(self, threat_data: Dict) -> str:
        """Create HTML email content"""
        risk_level = threat_data.get('risk_level', 'UNKNOWN')
        score = threat_data.get('threat_score', 0)

        if risk_level == 'CRITICAL':
            color = '#DC2626'
            emoji = '🔴'
        elif risk_level == 'HIGH':
            color = '#F59E0B'
            emoji = '🟠'
        else:
            color = '#EAB308'
            emoji = '🟡'

        urls_html = ""
        if threat_data.get('urls'):
            urls_html = "<h3>Suspicious URLs:</h3><ul>"
            for url in threat_data['urls']:
                urls_html += f"<li><code>{url}</code></li>"
            urls_html += "</ul>"

        return f"""
        <html>
        <body style="font-family: Arial; padding: 20px;">
            <div style="background-color: {color}; color: white; padding: 20px; text-align: center;">
                <h1>{emoji} {risk_level} RISK EMAIL DETECTED</h1>
            </div>
            <div style="padding: 20px;">
                <h2>Email Details</h2>
                <p><strong>From:</strong> {threat_data.get('from', 'Unknown')}</p>
                <p><strong>To:</strong> {threat_data.get('to', 'Unknown')}</p>
                <p><strong>Subject:</strong> {threat_data.get('subject', 'No subject')}</p>
                <p><strong>Threat Score:</strong> {score:.1%}</p>
                {urls_html}
                <p><a href="http://localhost:8501" style="background-color: {color}; color: white; padding: 10px; text-decoration: none;">View in Dashboard</a></p>
            </div>
        </body>
        </html>
        """

    def _create_text_content(self, threat_data: Dict) -> str:
        """Create plain text email content"""
        risk_level = threat_data.get('risk_level', 'UNKNOWN')
        score = threat_data.get('threat_score', 0)

        return f"""
{risk_level} RISK EMAIL DETECTED
{'='*30}

From: {threat_data.get('from', 'Unknown')}
To: {threat_data.get('to', 'Unknown')}
Subject: {threat_data.get('subject', 'No subject')}
Threat Score: {score:.1%}

View in dashboard: http://localhost:8501
        """


class MockEmailAlertSender:
    """Mock email sender for development"""

    def __init__(self, *args, **kwargs):
        self.enabled = True
        logger.info("Mock email alert sender initialized")

    def send_alert(self, to_email: str, threat_data: Dict) -> bool:
        logger.info(f"[MOCK EMAIL] To: {to_email}")
        logger.info(f"[MOCK EMAIL] Subject: [{threat_data.get('risk_level')}] {threat_data.get('subject', '')[:50]}")
        return True


def get_email_sender(use_mock: bool = False):
    """Get email sender instance"""
    if use_mock:
        return MockEmailAlertSender()
    return EmailAlertSender()