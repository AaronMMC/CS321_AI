"""
SMTP handler module – intercepts emails before delivery.

Changes from original:
  - Replaced broken `from src.models.tinybert_model import TinyBERTForEmailSecurity`
    with `from src.models.scratch_transformer import ScratchModelForEmailSecurity`.
  - Removed SMS (Twilio) and Telegram imports and all call-sites.
  - Email alerting now routes through src/alerting/email.py (Gmail).
"""

import asyncio
import email as email_lib
import json
import smtplib
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message
from loguru import logger

from src.alerting.email import get_email_sender
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
from src.models.scratch_transformer import ScratchModelForEmailSecurity   # fixed
from src.utils.config import settings

_CAMPAIGN_WINDOW_HOURS = 2
_CAMPAIGN_THRESHOLD    = 3


class EmailSecurityHandler(Message):
    """
    aiosmtpd handler that runs every inbound email through:
      1. Parsing
      2. SPF / DKIM / DMARC authentication
      3. AI + external intelligence scoring
      4. Campaign detection
      5. Quarantine / warn / deliver decision
      6. Click-time URL rewriting
      7. Email alerting (Gmail)
    """

    def __init__(
        self,
        model:      ScratchModelForEmailSecurity,
        threat_hub: ThreatIntelligenceHub,
    ):
        super().__init__()
        self.model            = model
        self.threat_hub       = threat_hub
        self.parser           = EmailParser()
        self.warning_injector = EmailWarningInjector()
        self.email_sender     = get_email_sender()
        self._recent_senders: deque = deque(maxlen=500)
        self.processed_count  = 0
        self.threat_count     = 0

    def handle_message(self, message):
        pass

    async def handle_DATA(self, server, session, envelope):
        mail_from = envelope.mail_from
        rcpt_tos  = envelope.rcpt_tos
        data      = envelope.content

        logger.info(f"Received email from {mail_from} to {rcpt_tos}")

        try:
            start_time = time.time()

            # 1. Parse
            raw        = data if isinstance(data, bytes) else (data or b"").encode()
            email_data = self.parser.parse_raw_email(raw) if raw else {
                "headers": {}, "body_plain": "", "body_html": "",
                "subject": "", "urls": [], "from": mail_from, "to": rcpt_tos,
            }
            email_data["from"] = mail_from
            email_data["to"]   = rcpt_tos

            # 2. Authentication
            auth_result: Dict = {}
            try:
                auth_result = await verify_email_authentication_async(email_data)
                if not auth_result.get("passed"):
                    record_authentication_failure()
            except Exception as exc:
                logger.warning(f"Auth failed: {exc}")
                auth_result = {"passed": False, "score": 0.0}
                record_authentication_failure()
            email_data["auth"] = auth_result

            # 3. AI + external scoring
            analysis_start               = time.time()
            threat_score, alert_payload  = await self._analyze_email(email_data)
            record_threat_detected(threat_score, time.time() - analysis_start)

            if not auth_result.get("passed") and auth_result.get("score", 1.0) < 0.3:
                threat_score = min(1.0, threat_score + 0.30)

            # 4. Campaign detection
            campaign = self._check_campaign(email_data)
            if campaign:
                email_data["campaign"] = campaign
                threat_score = min(1.0, threat_score + 0.15)

            # 5. Decide
            action = self._determine_action(threat_score)

            if action["quarantine"]:
                await self._quarantine_email(email_data, threat_score, alert_payload)
                record_email_quarantined()
                await self._fire_alert(email_data, threat_score)
                record_email_processed(time.time() - start_time)
                return "250 Message quarantined for security review"

            # 6. Warning injection
            if action["warn"]:
                warn_start = time.time()
                email_data = await self._add_warning(email_data, threat_score, campaign)
                self._rebuild_envelope(envelope, email_data)
                record_warning_added(time.time() - warn_start)

            # 7. Click-time URL rewriting
            url_start = time.time()
            protected = rewrite_email_urls(email_data, self.threat_hub)
            url_count = sum(
                len(protected.get("url_mappings", {}).get(k, []))
                for k in ("subject", "body_plain", "body_html")
            )
            record_url_rewritten(url_count, time.time() - url_start)
            email_data.update(protected)

            # 8. Forward
            await self._forward_email(envelope)

            if alert_payload or campaign:
                await self._fire_alert(email_data, threat_score)

            record_email_processed(time.time() - start_time)
            record_email_activity({
                **email_data,
                "threat_score": threat_score,
                "risk_level":   self._get_risk_level(threat_score),
                "modified":     action["warn"],
                "url_mappings": email_data.get("url_mappings"),
            })
            self.processed_count += 1
            return "250 Message accepted for delivery"

        except Exception as exc:
            logger.error(f"handle_DATA error: {exc}", exc_info=True)
            try:
                await self._forward_email(envelope)
            except Exception:
                pass
            return "250 Message accepted (gateway error — forwarded unmodified)"

    # ------------------------------------------------------------------

    async def _analyze_email(self, email_data: Dict) -> Tuple[float, Optional[Dict]]:
        urls        = email_data.get("urls", [])
        text        = f"{email_data.get('subject', '')} {email_data.get('body_plain', '')}"
        prediction  = self.model.predict(text)
        model_score = (
            prediction.get("threat_score", 0.0)
            if isinstance(prediction, dict) else float(prediction)
        )
        external_score = 0.0
        if urls:
            try:
                features       = self.threat_hub.get_features_for_model(text, urls)
                external_score = float(features[0]) if features else 0.0
            except Exception as exc:
                logger.warning(f"External intel failed: {exc}")

        combined      = min(model_score * 0.6 + external_score * 0.4, 1.0)
        alert_payload = None
        if combined >= settings.alerts.email_alert_threshold:
            alert_payload = {
                "timestamp":  datetime.now().isoformat(),
                "threat_score": combined,
                "from":       email_data.get("from"),
                "to":         email_data.get("to"),
                "subject":    email_data.get("subject"),
                "urls":       urls,
                "risk_level": self._get_risk_level(combined),
            }
            self.threat_count += 1
        return combined, alert_payload

    def _check_campaign(self, email_data: Dict) -> Optional[Dict]:
        domain = email_data.get("from_domain", "")
        if not domain:
            return None
        now    = datetime.now()
        self._recent_senders.append({"from_domain": domain,
                                     "to": str(email_data.get("to", "")), "ts": now})
        cutoff = now - timedelta(hours=_CAMPAIGN_WINDOW_HOURS)
        same   = [e for e in self._recent_senders
                  if e["from_domain"] == domain and e["ts"] > cutoff]
        if len(same) >= _CAMPAIGN_THRESHOLD:
            return {
                "campaign_detected": True, "domain": domain,
                "count": len(same), "recipients": list({e["to"] for e in same}),
                "window_hours": _CAMPAIGN_WINDOW_HOURS,
            }
        return None

    def _determine_action(self, score: float) -> Dict:
        if score >= 0.80: return {"quarantine": True,  "warn": False}
        if score >= 0.40: return {"quarantine": False, "warn": True}
        return {"quarantine": False, "warn": False}

    async def _add_warning(self, email_data, threat_score, campaign) -> Dict:
        explanations: List[str] = []
        if campaign:
            explanations.append(
                f"Campaign: {campaign['count']} emails from "
                f"{campaign['domain']} in {campaign['window_hours']}h"
            )
        auth = email_data.get("auth", {})
        if not auth.get("passed"):
            explanations.extend(auth.get("reasons", []))
        if not explanations:
            explanations.append(f"Threat score: {threat_score:.0%}")
        level  = self.warning_injector.determine_warning_level(threat_score)
        result = self.warning_injector.inject_warning(
            {**email_data, "threat_score": threat_score}, level, explanations,
        )
        email_data.update(result)
        return email_data

    def _rebuild_envelope(self, envelope, email_data: Dict) -> None:
        try:
            raw = (envelope.content if isinstance(envelope.content, bytes)
                   else envelope.content.encode("utf-8"))
            msg         = email_lib.message_from_bytes(raw)
            new_subject = email_data.get("subject", msg.get("Subject", ""))
            if "Subject" in msg:
                del msg["Subject"]
            msg["Subject"] = new_subject
            new_body = email_data.get("body", email_data.get("body_plain", ""))
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain" and not part.get_filename():
                        part.set_payload(new_body, charset="utf-8")
                        break
            else:
                msg.set_payload(new_body, charset="utf-8")
            envelope.content = msg.as_bytes()
        except Exception as exc:
            logger.error(f"_rebuild_envelope failed: {exc}")

    async def _quarantine_email(self, email_data, threat_score, alert_payload) -> None:
        qdir = Path("quarantine")
        qdir.mkdir(exist_ok=True)
        qid  = (datetime.now().strftime("%Y%m%d_%H%M%S")
                + "_" + str(hash(email_data.get("subject", "")))[:8])
        meta = {
            "id": qid, "timestamp": datetime.now().isoformat(),
            "threat_score": round(threat_score, 4),
            "risk_level":   self._get_risk_level(threat_score),
            "from":         str(email_data.get("from", "")),
            "to":           str(email_data.get("to", "")),
            "subject":      email_data.get("subject", ""),
            "urls":         email_data.get("urls", []),
        }
        (qdir / f"{qid}.json").write_text(json.dumps(meta, indent=2, default=str))
        logger.warning(f"Quarantined → quarantine/{qid}.json  (score={threat_score:.2f})")

    async def _fire_alert(self, email_data: Dict, threat_score: float) -> None:
        if not self.email_sender.enabled:
            return
        if threat_score < settings.alerts.email_alert_threshold:
            return
        try:
            self.email_sender.send_alert(
                settings.alerts.admin_email,
                {
                    "threat_score": threat_score,
                    "risk_level":   self._get_risk_level(threat_score),
                    "from":         str(email_data.get("from", "")),
                    "to":           str(email_data.get("to", "")),
                    "subject":      email_data.get("subject", ""),
                    "urls":         email_data.get("urls", []),
                },
            )
        except Exception as exc:
            logger.error(f"Email alert failed: {exc}")

    async def _forward_email(self, envelope) -> None:
        try:
            with smtplib.SMTP(
                settings.email_server.smtp_server,
                settings.email_server.smtp_port,
                timeout=10,
            ) as server:
                server.sendmail(envelope.mail_from, envelope.rcpt_tos, envelope.content)
        except Exception as exc:
            logger.error(f"Forward failed: {exc}")

    @staticmethod
    def _get_risk_level(score: float) -> str:
        if score >= 0.80: return "CRITICAL"
        if score >= 0.60: return "HIGH"
        if score >= 0.40: return "MEDIUM"
        if score >= 0.20: return "LOW"
        return "SAFE"


class EmailGateway:
    def __init__(self, host: str = "0.0.0.0", port: int = 10025):
        self.host       = host
        self.port       = port
        self.controller = None
        self.handler    = None

    async def start(
        self,
        model:      ScratchModelForEmailSecurity,
        threat_hub: ThreatIntelligenceHub,
    ) -> None:
        self.handler    = EmailSecurityHandler(model, threat_hub)
        self.controller = Controller(self.handler, hostname=self.host, port=self.port)
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


async def run_gateway(host: str = "localhost", port: int = 10025) -> None:
    model      = ScratchModelForEmailSecurity.load(str(settings.model.tinybert_path))
    threat_hub = ThreatIntelligenceHub()
    gateway    = EmailGateway(host=host, port=port)
    await gateway.start(model, threat_hub)


if __name__ == "__main__":
    asyncio.run(run_gateway())