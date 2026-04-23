"""
SMTP handler module – intercepts emails before delivery.

BUG FIX: `verify_email_authentication` was a blocking DNS call being
awaited in an async context, which would stall the event loop for up to
5 seconds per email (the DNS resolver timeout).  It now uses the new
`verify_email_authentication_async` wrapper which runs DNS I/O in a
thread-pool executor, keeping the event loop free.
"""

import asyncio
import smtplib
import time
from email.message import EmailMessage
from typing import Optional, Dict
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
# BUG FIX: use the async wrapper to avoid blocking the event loop
from src.features.authentication_verification import verify_email_authentication_async
from src.features.performance_metrics import (
    record_email_processed, record_threat_detected, record_warning_added,
    record_url_rewritten, record_email_quarantined, record_authentication_failure,
    record_email_activity,
)
from src.utils.config import settings


class EmailSecurityHandler(Message):
    """
    Custom SMTP handler that processes each email through the AI model.
    """

    def __init__(self, model, threat_hub, alert_system=None):
        super().__init__()
        self.model                = model
        self.threat_hub           = threat_hub
        self.alert_system         = alert_system
        self.parser               = EmailParser()
        self.warning_injector     = EmailWarningInjector()
        self.click_time_protector = ClickTimeProtection(threat_hub)
        self.processed_count      = 0
        self.threat_count         = 0

    def handle_message(self, message):
        """Synchronous stub – actual work is done in handle_DATA."""
        pass

    async def handle_DATA(self, server, session, envelope):
        """Handle incoming email data."""
        mail_from = envelope.mail_from
        rcpt_tos  = envelope.rcpt_tos
        data      = envelope.content

        logger.info(f"Received email from {mail_from} to {rcpt_tos}")

        try:
            start_time = time.time()

            if data is None:
                email_data = {'headers': {}, 'body_plain': '', 'body_html': '',
                              'subject': '', 'urls': []}
            elif isinstance(data, str):
                email_data = self.parser.parse_raw_email(data.encode('utf-8'))
            elif isinstance(data, bytes):
                email_data = self.parser.parse_raw_email(data)
            else:
                email_data = self.parser.parse_raw_email(str(data).encode('utf-8'))

            email_data['from'] = mail_from
            email_data['to']   = rcpt_tos

            # BUG FIX: use async wrapper so DNS I/O runs in a thread pool
            # and does not block the event loop for other emails.
            auth_result = None
            try:
                auth_result = await verify_email_authentication_async(email_data)
                logger.info(
                    f"Auth: passed={auth_result.get('passed')} "
                    f"score={auth_result.get('score', 0):.2f}"
                )
                if not auth_result.get('passed'):
                    record_authentication_failure()
            except Exception as e:
                logger.warning(f"Authentication verification failed: {e}")
                auth_result = {'passed': False, 'score': 0.0, 'error': str(e)}
                record_authentication_failure()

            # AI analysis
            analysis_start = time.time()
            threat_score, alert = await self._analyze_email(email_data)
            record_threat_detected(threat_score, time.time() - analysis_start)

            # Boost score on auth failure
            if auth_result and not auth_result.get('passed') and auth_result.get('score', 0) < 0.3:
                threat_score = min(1.0, threat_score + 0.3)

            action = self._determine_action(threat_score)

            if action['quarantine']:
                await self._quarantine_email(email_data, threat_score, alert)
                record_email_quarantined()
                record_email_processed(time.time() - start_time)
                record_email_activity(email_data)
                return '250 Message quarantined for security review'
            else:
                if action['warn']:
                    warning_start = time.time()
                    await self._add_warning_to_email(email_data)
                    record_warning_added(time.time() - warning_start)

                url_start      = time.time()
                protected_email = rewrite_email_urls(email_data, self.threat_hub)
                url_count = (
                    len(protected_email.get('url_mappings', {}).get('subject', []))
                    + len(protected_email.get('url_mappings', {}).get('body_plain', []))
                    + len(protected_email.get('url_mappings', {}).get('body_html', []))
                )
                record_url_rewritten(url_count, time.time() - url_start)
                email_data.update(protected_email)

                await self._forward_email(envelope)

                if alert and self.alert_system:
                    await self.alert_system.send_alert(alert)

                record_email_processed(time.time() - start_time)
                record_email_activity(email_data)
                self.processed_count += 1
                return '250 Message accepted for delivery'

        except Exception as e:
            logger.error(f"Error processing email: {e}")
            await self._forward_email(envelope)
            return '250 Message accepted'

    async def _analyze_email(self, email_data: Dict) -> tuple:
        urls             = email_data.get('urls', [])
        text_to_analyze  = f"{email_data.get('subject', '')} {email_data.get('body_plain', '')}"

        prediction   = self.model.predict(text_to_analyze)
        threat_score = (
            prediction.get('threat_score', 0)
            if isinstance(prediction, dict) else prediction
        )

        alert = None
        if threat_score > settings.alerts.email_alert_threshold:
            alert = {
                'timestamp':   datetime.now().isoformat(),
                'threat_score': threat_score,
                'from':        email_data.get('from'),
                'to':          email_data.get('to'),
                'subject':     email_data.get('subject'),
                'urls':        urls,
                'risk_level':  self._get_risk_level(threat_score),
            }
            self.threat_count += 1

        return threat_score, alert

    def _determine_action(self, threat_score: float) -> Dict:
        if threat_score >= 0.8:
            return {'quarantine': True,  'warn': False}
        elif threat_score >= 0.4:
            return {'quarantine': False, 'warn': True}
        else:
            return {'quarantine': False, 'warn': False}

    async def _quarantine_email(self, email_data: Dict, threat_score: float, alert: Dict):
        quarantine_dir = Path("quarantine")
        quarantine_dir.mkdir(exist_ok=True)

        qid = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + str(
            hash(email_data.get('subject', ''))
        )[:8]
        meta = {
            'id':          qid,
            'timestamp':   datetime.now().isoformat(),
            'threat_score': threat_score,
            'from':        email_data.get('from'),
            'to':          email_data.get('to'),
            'subject':     email_data.get('subject'),
            'alert':       alert,
        }
        with open(quarantine_dir / f"{qid}.json", 'w') as f:
            json.dump(meta, f, indent=2)
        logger.warning(f"Email quarantined: {qid} with score {threat_score}")

    async def _add_warning_to_email(self, email_data: Dict):
        threat_score = email_data.get('threat_score', 0.5)
        level        = self.warning_injector.determine_warning_level(threat_score)
        warned       = self.warning_injector.inject_warning(email_data, level)
        email_data.update(warned)
        logger.info(f"Added warning to email from {email_data.get('from')}")

    async def _forward_email(self, envelope):
        try:
            with smtplib.SMTP(
                settings.email_server.smtp_server,
                settings.email_server.smtp_port,
            ) as server:
                server.sendmail(envelope.mail_from, envelope.rcpt_tos, envelope.content)
            logger.debug(f"Email forwarded to {envelope.rcpt_tos}")
        except Exception as e:
            logger.error(f"Failed to forward email: {e}")

    def _get_risk_level(self, score: float) -> str:
        if score >= 0.8:   return "CRITICAL"
        elif score >= 0.6: return "HIGH"
        elif score >= 0.4: return "MEDIUM"
        elif score >= 0.2: return "LOW"
        else:              return "SAFE"


class EmailGateway:
    """Main email gateway that runs the SMTP server."""

    def __init__(self, host='0.0.0.0', port=10025):
        self.host       = host
        self.port       = port
        self.controller = None
        self.handler    = None

    async def start(self, model, threat_hub, alert_system=None):
        self.handler    = EmailSecurityHandler(model, threat_hub, alert_system)
        self.controller = Controller(self.handler, hostname=self.host, port=self.port)
        self.controller.start()
        logger.info(f"Email gateway started on {self.host}:{self.port}")

        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await self.stop()

    async def stop(self):
        if self.controller:
            self.controller.stop()
            logger.info("Email gateway stopped")

    def get_stats(self) -> Dict:
        if self.handler:
            return {
                'processed_emails': self.handler.processed_count,
                'threats_detected': self.handler.threat_count,
            }
        return {}


async def run_gateway():
    """Run the email gateway as a standalone service."""
    model      = TinyBERTForEmailSecurity()
    threat_hub = ThreatIntelligenceHub()
    gateway    = EmailGateway(host='localhost', port=10025)
    await gateway.start(model, threat_hub)


if __name__ == "__main__":
    asyncio.run(run_gateway())