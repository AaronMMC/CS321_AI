"""
SMTP handler module - intercepts emails before delivery.
Acts as a proxy between mail server and employees' inboxes.
"""

import asyncio
import smtplib
import time
from email import message_from_bytes
from email.policy import default
from typing import Optional, Dict, Any
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from loguru import logger
from datetime import datetime
import json
from pathlib import Path

from src.gateway.email_parser import EmailParser
from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.features.external_intelligence import ThreatIntelligenceHub
from src.features.warning_injection import EmailWarningInjector
from src.features.click_time_protection import ClickTimeProtection, rewrite_email_urls
from src.features.authentication_verification import verify_email_authentication
from src.features.performance_metrics import (
    record_email_processed, record_threat_detected, record_warning_added,
    record_url_rewritten, record_email_quarantined, record_authentication_failure,
    record_email_activity
)
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
        self.warning_injector = EmailWarningInjector()
        self.click_time_protector = ClickTimeProtection(threat_hub)
        self.auth_verifier = None  # Will be initialized when needed
        self.processed_count = 0
        self.threat_count = 0
        # Performance metrics will be accessed via global functions

    def handle_message(self, message):
        """
        Handle incoming email message (synchronous version).
        This method is called by aiosmtpd for each email.
        We'll delegate to our async handler.
        """
        # This is a synchronous wrapper - we'll call handle_DATA which is async
        # In a real implementation, we might need to handle this differently
        pass

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
            # Ensure data is bytes (should be from aiosmtpd)
            start_time = time.time()
            if data is None:
                # If no content, create minimal email data
                email_data = {
                    'headers': {},
                    'body_plain': '',
                    'body_html': '',
                    'subject': '',
                    'urls': []
                }
            elif isinstance(data, str):
                email_data = self.parser.parse_raw_email(data.encode('utf-8'))
            elif isinstance(data, bytes):
                email_data = self.parser.parse_raw_email(data)
            else:
                # Fallback: convert to bytes
                email_data = self.parser.parse_raw_email(str(data).encode('utf-8'))
            
            email_data['from'] = mail_from
            email_data['to'] = rcpt_tos
            
            # Record email processing started
            parse_time = time.time() - start_time

            # Perform email authentication verification (SPF/DKIM/DMARC)
            auth_result = None
            try:
                # Perform authentication verification
                auth_result = verify_email_authentication(email_data)
                logger.info(f"Email authentication: {auth_result.get('passed', False)} (score: {auth_result.get('score', 0.0):.2f})")
                
                # Record authentication failure if applicable
                if not auth_result.get('passed', False):
                    record_authentication_failure()
            except Exception as e:
                logger.warning(f"Authentication verification failed: {e}")
                auth_result = {'passed': False, 'score': 0.0, 'error': str(e)}
                record_authentication_failure()  # Count exceptions as failures too
            
            # Analyze with AI model
            analysis_start = time.time()
            threat_score, alert = await self._analyze_email(email_data)
            analysis_time = time.time() - analysis_start
            
            # Record threat detection
            record_threat_detected(threat_score, analysis_time)
            
            # If authentication failed completely, boost threat score
            if auth_result and not auth_result.get('passed', False) and auth_result.get('score', 0.0) < 0.3:
                # Boost threat score for failed authentication
                threat_score = min(1.0, threat_score + 0.3)
                if alert:
                    if 'authentication_failed' not in alert:
                        alert['authentication_failed'] = True
                    if 'auth_reasons' not in alert:
                        alert['auth_reasons'] = auth_result.get('reasons', [])

            # Persist model/auth outcomes on the working email payload
            email_data['threat_score'] = threat_score
            email_data['risk_level'] = self._get_risk_level(threat_score)
            if auth_result and not auth_result.get('passed', True):
                email_data['authentication_failed'] = True
                email_data['auth_reasons'] = auth_result.get('reasons', [])

            # Process based on threat level
            action = self._determine_action(threat_score)

            if action['quarantine']:
                # Quarantine the email
                quarantine_start = time.time()
                await self._quarantine_email(email_data, threat_score, alert)
                quarantine_time = time.time() - quarantine_start
                record_email_quarantined()
                
                # Record processing time for quarantined email
                total_time = time.time() - start_time
                record_email_processed(total_time)
                record_email_activity(email_data)
                
                # Return 250 but don't deliver
                return '250 Message quarantined for security review'
            else:
                # Deliver normally but maybe add warning
                if action['warn']:
                    warning_start = time.time()
                    await self._add_warning_to_email(email_data, alert)
                    warning_time = time.time() - warning_start
                    record_warning_added(warning_time)

                # Apply click-time protection to all delivered emails
                # This rewrites URLs to go through security proxy for real-time checking
                url_start = time.time()
                protected_email = rewrite_email_urls(email_data, self.threat_hub)
                url_time = time.time() - url_start
                # Count URLs rewritten for metrics
                url_count = 0
                if protected_email.get('url_mappings'):
                    url_count = len(protected_email['url_mappings'].get('subject', [])) + \
                             len(protected_email['url_mappings'].get('body_plain', [])) + \
                             len(protected_email['url_mappings'].get('body_html', []))
                record_url_rewritten(url_count, url_time)
                # Update email_data with protected version
                email_data.update(protected_email)

                # Forward to actual mail server
                await self._forward_email(envelope, email_data)

                # Send alert if needed
                if alert and self.alert_system:
                    await self.alert_system.send_alert(alert)

                # Record final email processing time
                total_time = time.time() - start_time
                record_email_processed(total_time)
                
                # Record email activity for dashboard
                record_email_activity(email_data)

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

    async def _add_warning_to_email(self, email_data: Dict, alert: Optional[Dict] = None):
        """
        Add warning header to suspicious emails using the warning injection module.
        """
        # Determine threat level from email data or use a default
        threat_score = email_data.get('threat_score', 0.5)
        threat_level = self.warning_injector.determine_warning_level(threat_score)

        # Build user-facing explanations for just-in-time guidance
        explanations = list(email_data.get('explanations', []))
        if not explanations:
            if threat_score >= 0.7:
                explanations.append('High threat score detected')
            urls = email_data.get('urls', [])
            if urls:
                explanations.append(f'Found {len(urls)} URL(s) in email')
            if email_data.get('authentication_failed'):
                explanations.append('Sender authentication checks failed')
            if alert and alert.get('auth_reasons'):
                explanations.extend(alert.get('auth_reasons', [])[:2])

        # The warning injector expects a generic body field.
        # Normalize from parsed fields so injected content is actually available for forwarding.
        normalized_body = (
            email_data.get('body_plain')
            or email_data.get('body_html')
            or email_data.get('body', '')
        )
        payload_for_warning = {
            **email_data,
            'body': normalized_body,
            'headers': {**email_data.get('headers', {})},
        }
        warned_email = self.warning_injector.inject_warning(
            payload_for_warning,
            threat_level,
            explanations=explanations,
        )

        # Sync warning output back to parser-friendly fields used by downstream mutation and forwarding.
        if warned_email.get('body'):
            if email_data.get('body_plain'):
                email_data['body_plain'] = warned_email['body']
            elif email_data.get('body_html'):
                email_data['body_html'] = warned_email['body']
            else:
                email_data['body_plain'] = warned_email['body']

        email_data['subject'] = warned_email.get('subject', email_data.get('subject', ''))
        email_data['headers'] = warned_email.get('headers', email_data.get('headers', {}))
        email_data['modified'] = warned_email.get('modified', False)
        email_data['modified_body'] = warned_email.get('modified_body', False)
        email_data['warning_info'] = warned_email.get('warning_info', {})

        logger.info(
            f"Added warning to suspicious email from {email_data.get('from')} - "
            f"Level: {email_data.get('warning_info', {}).get('warning_level', 'UNKNOWN')}"
        )

    async def _forward_email(self, envelope, email_data: Optional[Dict] = None):
        """
        Forward email to the actual mail server.
        """
        # This is a simplified version - in production you'd use proper SMTP relay
        try:
            outgoing_content = envelope.content
            if email_data:
                outgoing_content = self._build_outgoing_email_content(envelope.content, email_data)

            # Connect to real mail server (configured in settings)
            with smtplib.SMTP(settings.email_server.smtp_server, settings.email_server.smtp_port) as server:
                server.sendmail(
                    envelope.mail_from,
                    envelope.rcpt_tos,
                    outgoing_content
                )
            logger.debug(f"Email forwarded to {envelope.rcpt_tos}")
        except Exception as e:
            logger.error(f"Failed to forward email: {e}")

    def _build_outgoing_email_content(self, original_content: Any, email_data: Dict) -> bytes:
        """
        Apply subject/body/header mutations onto the outbound RFC822 message bytes.
        """
        try:
            if isinstance(original_content, bytes):
                original_bytes = original_content
            elif isinstance(original_content, str):
                original_bytes = original_content.encode('utf-8', errors='ignore')
            else:
                original_bytes = str(original_content).encode('utf-8', errors='ignore')

            message = message_from_bytes(original_bytes, policy=default)

            # Subject rewrite from warning injection + URL rewriting.
            if email_data.get('subject'):
                self._set_or_replace_header(message, 'Subject', email_data['subject'])

            # Add security headers if present.
            for key, value in email_data.get('headers', {}).items():
                if key.startswith('X-Security-'):
                    self._set_or_replace_header(message, key, str(value))

            # Apply rewritten/warned body content.
            self._apply_body_updates(
                message,
                plain_body=email_data.get('body_plain') or email_data.get('body'),
                html_body=email_data.get('body_html'),
            )

            return message.as_bytes(policy=default)
        except Exception as e:
            logger.warning(f"Failed to apply outbound content mutations, falling back to original message: {e}")
            if isinstance(original_content, bytes):
                return original_content
            if isinstance(original_content, str):
                return original_content.encode('utf-8', errors='ignore')
            return str(original_content).encode('utf-8', errors='ignore')

    @staticmethod
    def _set_or_replace_header(message, header_name: str, header_value: str):
        """Safely set or replace an RFC822 header."""
        if header_name in message:
            message.replace_header(header_name, header_value)
        else:
            message[header_name] = header_value

    def _apply_body_updates(self, message, plain_body: Optional[str], html_body: Optional[str]):
        """Replace existing text/plain and text/html parts with updated content when available."""
        if plain_body is None and html_body is None:
            return

        if not message.is_multipart():
            charset = message.get_content_charset() or 'utf-8'
            content_type = message.get_content_type()
            if content_type == 'text/html' and html_body is not None:
                message.set_content(html_body, subtype='html', charset=charset)
            elif plain_body is not None:
                message.set_content(plain_body, subtype='plain', charset=charset)
            elif html_body is not None:
                message.set_content(html_body, subtype='html', charset=charset)
            return

        plain_updated = False
        html_updated = False
        for part in message.walk():
            if part.get_content_maintype() != 'text':
                continue
            if part.get_content_disposition() == 'attachment':
                continue

            charset = part.get_content_charset() or 'utf-8'
            part_type = part.get_content_type()

            if part_type == 'text/plain' and plain_body is not None and not plain_updated:
                part.set_content(plain_body, subtype='plain', charset=charset)
                plain_updated = True
            elif part_type == 'text/html' and html_body is not None and not html_updated:
                part.set_content(html_body, subtype='html', charset=charset)
                html_updated = True

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