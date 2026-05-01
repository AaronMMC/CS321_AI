"""
SMTP handler module – intercepts emails before delivery.

CHANGES FROM ORIGINAL:
  1. _rebuild_envelope_with_warning() — re-serialises the modified email_data
     (subject prefix + body banner) back into the SMTP envelope bytes so the
     warning actually reaches the recipient's inbox.
  2. Campaign detection — EmailSecurityHandler now maintains a deque of recent
     senders and calls _check_campaign() on every message.  When ≥3 emails
     arrive from the same domain within 2 hours the threat score is boosted
     and a campaign alert is fired.
  3. SMS / Telegram alerting — SMSAlertSender and TelegramAlertBot are
     instantiated at handler startup and called directly (no more stub
     alert_system parameter needed).
  4. verify_email_authentication_async — already imported in original; usage
     is unchanged (runs DNS in thread-pool so the event loop stays free).
  5. All performance-metric helpers retained from original.
"""

import asyncio
import email as email_lib
import json
import smtplib
import time
from collections import deque
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from loguru import logger

from src.alerting.email import get_email_sender
from src.alerting.sms import get_sms_sender
from src.alerting.telegram import get_telegram_bot
from src.features.authentication_verification import verify_email_authentication_async
from src.features.click_time_protection import rewrite_email_urls
from src.features.external_intelligence import ThreatIntelligenceHub
from src.features.performance_metrics import (
    record_authentication_failure,
    record_email_activity,
    record_email_processed,
    record_email_quarantined,
    record_threat_detected,
    record_url_rewritten,
    record_warning_added,
)
from src.features.warning_injection import EmailWarningInjector
from src.gateway.email_parser import EmailParser
from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.utils.config import settings


# ---------------------------------------------------------------------------
# Helper — campaign window
# ---------------------------------------------------------------------------

_CAMPAIGN_WINDOW_HOURS = 2
_CAMPAIGN_THRESHOLD = 3          # same domain ≥ this many times → campaign


class EmailSecurityHandler(Message):
    """
    Custom aiosmtpd handler that processes every email through the AI model,
    external threat intelligence, authentication verification, warning injection,
    campaign detection, and alerting.
    """

    def __init__(self, model: TinyBERTForEmailSecurity, threat_hub: ThreatIntelligenceHub):
        super().__init__()
        self.model = model
        self.threat_hub = threat_hub
        self.parser = EmailParser()
        self.warning_injector = EmailWarningInjector()
        self.click_time_protector = rewrite_email_urls

        # Alerting senders (real or mock depending on .env configuration)
        self.sms_sender = get_sms_sender()
        self.telegram_bot = get_telegram_bot()
        self.email_sender = get_email_sender()

        # Campaign detection — sliding window of recent processed emails
        self._recent_senders: deque = deque(maxlen=500)

        # Simple counters for /stats endpoint
        self.processed_count = 0
        self.threat_count = 0

    # ------------------------------------------------------------------
    # aiosmtpd entry point
    # ------------------------------------------------------------------

    def handle_message(self, message):
        """Synchronous stub required by parent class — real work in handle_DATA."""
        pass

    async def handle_DATA(self, server, session, envelope):
        """
        Called once per incoming SMTP DATA command.

        Pipeline:
            parse → auth → AI score → campaign check →
            decide action (quarantine / warn / deliver) →
            forward → alert
        """
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        data = envelope.content

        logger.info(f"Received email from {mail_from} to {rcpt_tos}")

        try:
            start_time = time.time()

            # ── 1. Parse ────────────────────────────────────────────────────
            if data is None:
                email_data: Dict = {
                    "headers": {}, "body_plain": "", "body_html": "",
                    "subject": "", "urls": [], "from": mail_from, "to": rcpt_tos,
                }
            else:
                raw = data if isinstance(data, bytes) else data.encode("utf-8")
                email_data = self.parser.parse_raw_email(raw)

            email_data["from"] = mail_from
            email_data["to"] = rcpt_tos

            # ── 2. Authentication (SPF / DKIM / DMARC) ─────────────────────
            auth_result: Dict = {}
            try:
                auth_result = await verify_email_authentication_async(email_data)
                logger.info(
                    f"Auth: passed={auth_result.get('passed')} "
                    f"score={auth_result.get('score', 0):.2f}"
                )
                if not auth_result.get("passed"):
                    record_authentication_failure()
            except Exception as exc:
                logger.warning(f"Authentication verification failed: {exc}")
                auth_result = {"passed": False, "score": 0.0, "error": str(exc)}
                record_authentication_failure()

            email_data["auth"] = auth_result

            # ── 3. AI + external intelligence scoring ───────────────────────
            analysis_start = time.time()
            threat_score, alert_payload = await self._analyze_email(email_data)
            record_threat_detected(threat_score, time.time() - analysis_start)

            # Boost score when auth fails
            if not auth_result.get("passed") and auth_result.get("score", 1.0) < 0.3:
                threat_score = min(1.0, threat_score + 0.30)
                logger.info(f"Score boosted to {threat_score:.2f} (auth failed)")

            # ── 4. Campaign detection ───────────────────────────────────────
            campaign = self._check_campaign(email_data)
            if campaign:
                logger.warning(
                    f"Campaign: {campaign['count']} emails from {campaign['domain']} "
                    f"in {_CAMPAIGN_WINDOW_HOURS}h"
                )
                email_data["campaign"] = campaign
                threat_score = min(1.0, threat_score + 0.15)

            # ── 5. Decide action ────────────────────────────────────────────
            action = self._determine_action(threat_score)

            if action["quarantine"]:
                await self._quarantine_email(email_data, threat_score, alert_payload)
                record_email_quarantined()
                await self._fire_alerts(email_data, threat_score, campaign)
                record_email_processed(time.time() - start_time)
                record_email_activity({**email_data, "threat_score": threat_score,
                                       "risk_level": self._get_risk_level(threat_score),
                                       "quarantined": True})
                return "250 Message quarantined for security review"

            # ── 6. Warning injection ────────────────────────────────────────
            if action["warn"]:
                warn_start = time.time()
                email_data = await self._add_warning_to_email(email_data, threat_score, campaign)
                self._rebuild_envelope_with_warning(envelope, email_data)
                record_warning_added(time.time() - warn_start)

            # ── 7. Click-time URL rewriting ─────────────────────────────────
            url_start = time.time()
            protected = rewrite_email_urls(email_data, self.threat_hub)
            url_count = sum(
                len(protected.get("url_mappings", {}).get(k, []))
                for k in ("subject", "body_plain", "body_html")
            )
            record_url_rewritten(url_count, time.time() - url_start)
            email_data.update(protected)

            # ── 8. Forward ─────────────────────────────────────────────────
            await self._forward_email(envelope)

            # ── 9. Alerts ──────────────────────────────────────────────────
            if alert_payload or campaign:
                await self._fire_alerts(email_data, threat_score, campaign)

            record_email_processed(time.time() - start_time)
            record_email_activity({
                **email_data,
                "threat_score": threat_score,
                "risk_level": self._get_risk_level(threat_score),
                "modified": action["warn"],
                "url_mappings": email_data.get("url_mappings"),
            })
            self.processed_count += 1
            return "250 Message accepted for delivery"

        except Exception as exc:
            logger.error(f"Unhandled error in handle_DATA: {exc}", exc_info=True)
            # Fail-open: forward the original email so nothing is silently dropped
            try:
                await self._forward_email(envelope)
            except Exception:
                pass
            return "250 Message accepted (gateway error — forwarded unmodified)"

    # ------------------------------------------------------------------
    # AI / external intelligence
    # ------------------------------------------------------------------

    async def _analyze_email(self, email_data: Dict) -> Tuple[float, Optional[Dict]]:
        """Run model + external intelligence, return (threat_score, alert_dict)."""
        urls = email_data.get("urls", [])
        text = f"{email_data.get('subject', '')} {email_data.get('body_plain', '')}"

        prediction = self.model.predict(text)
        model_score = (
            prediction.get("threat_score", 0.0)
            if isinstance(prediction, dict)
            else float(prediction)
        )

        external_score = 0.0
        if urls:
            try:
                features = self.threat_hub.get_features_for_model(text, urls)
                external_score = float(features[0]) if len(features) > 0 else 0.0
            except Exception as exc:
                logger.warning(f"External intelligence failed: {exc}")

        combined = min(model_score * 0.6 + external_score * 0.4, 1.0)

        alert_payload = None
        if combined >= settings.alerts.email_alert_threshold:
            alert_payload = {
                "timestamp": datetime.now().isoformat(),
                "threat_score": combined,
                "model_score": model_score,
                "external_score": external_score,
                "from": email_data.get("from"),
                "to": email_data.get("to"),
                "subject": email_data.get("subject"),
                "urls": urls,
                "risk_level": self._get_risk_level(combined),
            }
            self.threat_count += 1

        return combined, alert_payload

    # ------------------------------------------------------------------
    # Campaign detection
    # ------------------------------------------------------------------

    def _check_campaign(self, email_data: Dict) -> Optional[Dict]:
        """
        Return a campaign dict when ≥ _CAMPAIGN_THRESHOLD emails have arrived
        from the same sender domain within _CAMPAIGN_WINDOW_HOURS hours.
        Otherwise return None.
        """
        domain = email_data.get("from_domain", "")
        if not domain:
            return None

        now = datetime.now()
        self._recent_senders.append({
            "from_domain": domain,
            "to": str(email_data.get("to", "")),
            "subject": email_data.get("subject", ""),
            "ts": now,
        })

        cutoff = now - timedelta(hours=_CAMPAIGN_WINDOW_HOURS)
        same_domain = [
            e for e in self._recent_senders
            if e["from_domain"] == domain and e["ts"] > cutoff
        ]

        if len(same_domain) >= _CAMPAIGN_THRESHOLD:
            recipients = list({e["to"] for e in same_domain})
            return {
                "campaign_detected": True,
                "domain": domain,
                "count": len(same_domain),
                "recipients": recipients,
                "window_hours": _CAMPAIGN_WINDOW_HOURS,
            }
        return None

    # ------------------------------------------------------------------
    # Action decision
    # ------------------------------------------------------------------

    def _determine_action(self, threat_score: float) -> Dict:
        if threat_score >= 0.80:
            return {"quarantine": True, "warn": False}
        elif threat_score >= 0.40:
            return {"quarantine": False, "warn": True}
        else:
            return {"quarantine": False, "warn": False}

    # ------------------------------------------------------------------
    # Warning injection
    # ------------------------------------------------------------------

    async def _add_warning_to_email(
        self,
        email_data: Dict,
        threat_score: float,
        campaign: Optional[Dict],
    ) -> Dict:
        """
        Build the explanation list (including campaign info if present),
        then delegate to EmailWarningInjector.  Returns the updated email_data.
        """
        explanations: List[str] = []

        if campaign:
            explanations.append(
                f"Part of a detected campaign: {campaign['count']} emails "
                f"from {campaign['domain']} in the last {campaign['window_hours']}h"
            )
            explanations.append(
                f"Other recipients: {', '.join(campaign['recipients'][:5])}"
            )

        auth = email_data.get("auth", {})
        if not auth.get("passed"):
            for reason in auth.get("reasons", []):
                explanations.append(reason)

        if not explanations:
            explanations.append(f"Threat score: {threat_score:.0%}")

        level = self.warning_injector.determine_warning_level(threat_score)
        result = self.warning_injector.inject_warning(
            {**email_data, "threat_score": threat_score},
            level,
            explanations,
        )
        email_data.update(result)
        logger.info(
            f"Warning injected: level={level.name} "
            f"subject='{email_data.get('subject', '')[:60]}'"
        )
        return email_data

    def _rebuild_envelope_with_warning(self, envelope, email_data: Dict) -> None:
        """
        Re-serialise the modified subject and body back into envelope.content
        so that the downstream MTA actually delivers the warned version.

        Handles both plain-text and multipart MIME messages.
        """
        try:
            raw = (
                envelope.content
                if isinstance(envelope.content, bytes)
                else envelope.content.encode("utf-8")
            )
            msg = email_lib.message_from_bytes(raw)

            # --- Rewrite subject ------------------------------------------
            new_subject = email_data.get("subject", msg.get("Subject", ""))
            if "Subject" in msg:
                del msg["Subject"]
            msg["Subject"] = new_subject

            # --- Rewrite body ---------------------------------------------
            new_body: str = email_data.get("body", email_data.get("body_plain", ""))

            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct == "text/plain" and not part.get_filename():
                        part.set_payload(new_body, charset="utf-8")
                        break
            else:
                msg.set_payload(new_body, charset="utf-8")

            envelope.content = msg.as_bytes()
            logger.debug("Envelope rebuilt with warning content")

        except Exception as exc:
            logger.error(f"_rebuild_envelope_with_warning failed: {exc}")
            # Leave envelope unchanged — email still forwarded (unmodified)

    # ------------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------------

    async def _quarantine_email(
        self,
        email_data: Dict,
        threat_score: float,
        alert_payload: Optional[Dict],
    ) -> None:
        """Write quarantine metadata JSON to the /quarantine directory."""
        quarantine_dir = Path("quarantine")
        quarantine_dir.mkdir(exist_ok=True)

        qid = (
            datetime.now().strftime("%Y%m%d_%H%M%S")
            + "_"
            + str(hash(email_data.get("subject", "")))[:8]
        )
        meta = {
            "id": qid,
            "timestamp": datetime.now().isoformat(),
            "threat_score": round(threat_score, 4),
            "risk_level": self._get_risk_level(threat_score),
            "from": str(email_data.get("from", "")),
            "to": str(email_data.get("to", "")),
            "subject": email_data.get("subject", ""),
            "urls": email_data.get("urls", []),
            "auth": email_data.get("auth", {}),
            "campaign": email_data.get("campaign"),
            "alert": alert_payload,
        }
        qfile = quarantine_dir / f"{qid}.json"
        qfile.write_text(json.dumps(meta, indent=2, default=str))
        logger.warning(f"Email quarantined → {qfile}  (score={threat_score:.2f})")

    # ------------------------------------------------------------------
    # Alerting
    # ------------------------------------------------------------------

    async def _fire_alerts(
        self,
        email_data: Dict,
        threat_score: float,
        campaign: Optional[Dict],
    ) -> None:
        """
        Send SMS + Telegram alerts to admin when score is above thresholds.
        Uses asyncio.create_task so alerting never blocks email processing.
        """
        threat_data = {
            "threat_score": threat_score,
            "risk_level": self._get_risk_level(threat_score),
            "from": str(email_data.get("from", "")),
            "to": str(email_data.get("to", "")),
            "subject": email_data.get("subject", ""),
            "urls": email_data.get("urls", []),
            "campaign": campaign,
        }

        # SMS — fires for HIGH and CRITICAL
        if (
            threat_score >= settings.alerts.sms_alert_threshold
            and settings.alerts.admin_phone
            and self.sms_sender.enabled
        ):
            try:
                self.sms_sender.send_alert(settings.alerts.admin_phone, threat_data)
            except Exception as exc:
                logger.error(f"SMS alert failed: {exc}")

        # Telegram — fires for MEDIUM and above
        if (
            threat_score >= settings.alerts.dashboard_alert_threshold
            and settings.alerts.admin_telegram
            and self.telegram_bot.enabled
        ):
            asyncio.create_task(
                self.telegram_bot.send_alert(settings.alerts.admin_telegram, threat_data)
            )

        # Email alert for CRITICAL
        if (
            threat_score >= settings.alerts.email_alert_threshold
            and settings.alerts.admin_email
            and self.email_sender.enabled
        ):
            try:
                self.email_sender.send_alert(settings.alerts.admin_email, threat_data)
            except Exception as exc:
                logger.error(f"Email alert failed: {exc}")

    # ------------------------------------------------------------------
    # Forward
    # ------------------------------------------------------------------

    async def _forward_email(self, envelope) -> None:
        """Forward (possibly modified) envelope to the real downstream SMTP."""
        try:
            with smtplib.SMTP(
                settings.email_server.smtp_server,
                settings.email_server.smtp_port,
                timeout=10,
            ) as server:
                server.sendmail(
                    envelope.mail_from,
                    envelope.rcpt_tos,
                    envelope.content,
                )
            logger.debug(f"Forwarded to {envelope.rcpt_tos}")
        except Exception as exc:
            logger.error(f"Forward failed: {exc}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_risk_level(score: float) -> str:
        if score >= 0.80:
            return "CRITICAL"
        if score >= 0.60:
            return "HIGH"
        if score >= 0.40:
            return "MEDIUM"
        if score >= 0.20:
            return "LOW"
        return "SAFE"


# ---------------------------------------------------------------------------
# EmailGateway — lifecycle manager
# ---------------------------------------------------------------------------


class EmailGateway:
    """Manages the lifecycle of the aiosmtpd Controller."""

    def __init__(self, host: str = "0.0.0.0", port: int = 10025):
        self.host = host
        self.port = port
        self.controller: Optional[Controller] = None
        self.handler: Optional[EmailSecurityHandler] = None

    async def start(
        self,
        model: TinyBERTForEmailSecurity,
        threat_hub: ThreatIntelligenceHub,
    ) -> None:
        self.handler = EmailSecurityHandler(model, threat_hub)
        self.controller = Controller(
            self.handler, hostname=self.host, port=self.port
        )
        self.controller.start()
        logger.info(f"Email gateway started on {self.host}:{self.port}")

        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await self.stop()

    async def stop(self) -> None:
        if self.controller:
            self.controller.stop()
            logger.info("Email gateway stopped")

    def get_stats(self) -> Dict:
        if self.handler:
            return {
                "processed_emails": self.handler.processed_count,
                "threats_detected": self.handler.threat_count,
            }
        return {}


# ---------------------------------------------------------------------------
# Stand-alone entry point
# ---------------------------------------------------------------------------


async def run_gateway(host: str = "localhost", port: int = 10025) -> None:
    model = TinyBERTForEmailSecurity()
    threat_hub = ThreatIntelligenceHub()
    gateway = EmailGateway(host=host, port=port)
    await gateway.start(model, threat_hub)


if __name__ == "__main__":
    asyncio.run(run_gateway())