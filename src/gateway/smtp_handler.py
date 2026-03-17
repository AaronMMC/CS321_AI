"""
SMTP handler module - intercepts emails before delivery.
Acts as a proxy between mail server and employees' inboxes.
"""

import asyncio
import smtplib
from email.message import EmailMessage
from typing import Optional, Callable, Awaitable, Dict
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from loguru import logger
from datetime import datetime
import json
from pathlib import Path

from src.gateway.email_parser import EmailParser
from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.features.external_intelligence import ThreatIntelligenceHub
from src.utils.config import settings


class EmailSecurityHandler(Message):
    """
    Custom SMTP handler that processes each email through the AI model.
    This is the core of the email gateway.
    """

    def __init__(self, model, threat_hub, alert_system=None):
        super().__init__()
        self.model = model
        self.threat_hub = threat_hub
        self.alert_system = alert_system
        self.parser = EmailParser()
        self.processed_count = 0
        self.threat_count = 0

    async def handle_DATA(self, server, session, envelope):
        """
        Handle incoming email data.
        This is called for each email that passes through the gateway.
        """
        # Get raw email content
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        data = envelope.content  # Raw email bytes

        logger.info(f"Received email from {mail_from} to {rcpt_tos}")

        try:
            # Parse the email
            email_data = self.parser.parse_raw_email(data)
            email_data['from'] = mail_from
            email_data['to'] = rcpt_tos

            # Analyze with AI model
            threat_score, alert = await self._analyze_email(email_data)

            # Process based on threat level
            action = self._determine_action(threat_score)

            if action['quarantine']:
                # Quarantine the email
                await self._quarantine_email(email_data, threat_score, alert)
                # Return 250 but don't deliver
                return '250 Message quarantined for security review'
            else:
                # Deliver normally but maybe add warning
                if action['warn']:
                    await self._add_warning_to_email(email_data)

                # Forward to actual mail server
                await self._forward_email(envelope)

                # Send alert if needed
                if alert and self.alert_system:
                    await self.alert_system.send_alert(alert)

                self.processed_count += 1
                return '250 Message accepted for delivery'

        except Exception as e:
            logger.error(f"Error processing email: {e}")
            # In case of error, deliver anyway to avoid blocking
            await self._forward_email(envelope)
            return '250 Message accepted'

    async def _analyze_email(self, email_data: Dict) -> tuple:
        """
        Analyze email using AI model and threat intelligence.

        Returns:
            Tuple of (threat_score, alert_dict)
        """
        # Extract URLs
        urls = email_data.get('urls', [])

        # Get external intelligence for URLs
        external_features = None
        if urls:
            external_features = self.threat_hub.get_features_for_model(
                email_data.get('body_plain', ''),
                urls
            )

        # Get text for model
        text_to_analyze = f"{email_data.get('subject', '')} {email_data.get('body_plain', '')}"

        # Get prediction from model
        if external_features is not None:
            # Use BERT model with external features (simplified for now)
            prediction = self.model.predict(text_to_analyze)
            threat_score = prediction['threat_score']
        else:
            # Use TinyBERT for quick inference
            prediction = self.model.predict(text_to_analyze)
            threat_score = prediction['threat_score'] if isinstance(prediction, dict) else prediction

        # Create alert if needed
        alert = None
        if threat_score > settings.alerts.email_alert_threshold:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'threat_score': threat_score,
                'from': email_data.get('from'),
                'to': email_data.get('to'),
                'subject': email_data.get('subject'),
                'urls': urls,
                'risk_level': self._get_risk_level(threat_score)
            }
            self.threat_count += 1

        return threat_score, alert

    def _determine_action(self, threat_score: float) -> Dict:
        """
        Determine what action to take based on threat score.
        """
        if threat_score >= 0.8:
            return {'quarantine': True, 'warn': False, 'block': True}
        elif threat_score >= 0.6:
            return {'quarantine': False, 'warn': True, 'block': False}
        elif threat_score >= 0.4:
            return {'quarantine': False, 'warn': True, 'block': False}
        else:
            return {'quarantine': False, 'warn': False, 'block': False}

    async def _quarantine_email(self, email_data: Dict, threat_score: float, alert: Dict):
        """
        Store quarantined email for admin review.
        """
        quarantine_dir = Path("quarantine")
        quarantine_dir.mkdir(exist_ok=True)

        # Save email with metadata
        quarantine_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + str(hash(email_data.get('subject', '')))[:8]

        # Save metadata
        metadata = {
            'id': quarantine_id,
            'timestamp': datetime.now().isoformat(),
            'threat_score': threat_score,
            'from': email_data.get('from'),
            'to': email_data.get('to'),
            'subject': email_data.get('subject'),
            'alert': alert
        }

        with open(quarantine_dir / f"{quarantine_id}.json", 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.warning(f"Email quarantined: {quarantine_id} with score {threat_score}")

    async def _add_warning_to_email(self, email_data: Dict):
        """
        Add warning header to suspicious emails.
        """
        # In a real implementation, you'd modify the email headers
        logger.info(f"Added warning to suspicious email from {email_data.get('from')}")

    async def _forward_email(self, envelope):
        """
        Forward email to the actual mail server.
        """
        # This is a simplified version - in production you'd use proper SMTP relay
        try:
            # Connect to real mail server (configured in settings)
            with smtplib.SMTP(settings.email_server.smtp_server, settings.email_server.smtp_port) as server:
                server.sendmail(
                    envelope.mail_from,
                    envelope.rcpt_tos,
                    envelope.content
                )
            logger.debug(f"Email forwarded to {envelope.rcpt_tos}")
        except Exception as e:
            logger.error(f"Failed to forward email: {e}")

    def _get_risk_level(self, score: float) -> str:
        """Convert score to risk level"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "SAFE"


class EmailGateway:
    """
    Main email gateway that runs the SMTP server and connects all components.
    """

    def __init__(self, host='0.0.0.0', port=10025):
        self.host = host
        self.port = port
        self.controller = None
        self.handler = None

    async def start(self, model, threat_hub, alert_system=None):
        """
        Start the email gateway server.
        """
        # Create handler
        self.handler = EmailSecurityHandler(model, threat_hub, alert_system)

        # Create SMTP controller
        self.controller = Controller(
            self.handler,
            hostname=self.host,
            port=self.port
        )

        # Start server
        self.controller.start()
        logger.info(f"Email gateway started on {self.host}:{self.port}")

        # Keep running
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await self.stop()

    async def stop(self):
        """Stop the email gateway"""
        if self.controller:
            self.controller.stop()
            logger.info("Email gateway stopped")

    def get_stats(self) -> Dict:
        """Get gateway statistics"""
        if self.handler:
            return {
                'processed_emails': self.handler.processed_count,
                'threats_detected': self.handler.threat_count
            }
        return {}


# Function to run gateway from command line
async def run_gateway():
    """Run the email gateway as a standalone service"""
    from src.models.tinybert_model import TinyBERTForEmailSecurity

    # Initialize components
    logger.info("Initializing Email Security Gateway...")

    # Load model
    model = TinyBERTForEmailSecurity()

    # Initialize threat hub
    threat_hub = ThreatIntelligenceHub()

    # Start gateway
    gateway = EmailGateway(host='localhost', port=10025)
    await gateway.start(model, threat_hub)


if __name__ == "__main__":
    asyncio.run(run_gateway())