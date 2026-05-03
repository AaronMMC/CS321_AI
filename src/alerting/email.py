"""
Email alerting module — Gmail-capable.

Replaces the original generic EmailAlertSender with a Gmail-first
implementation using App Passwords (no OAuth needed for prototype demo).

Setup (one-time):
  1. Enable 2FA on your Google account.
  2. Go to https://myaccount.google.com/apppasswords
  3. Generate an App Password for "Mail" / "Other"
  4. Add to .env:
       GMAIL_ADDRESS=your.address@gmail.com
       GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
       ALERT_RECIPIENT=your.address@gmail.com   # defaults to GMAIL_ADDRESS
       GMAIL_ALERT_THRESHOLD=0.6
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Optional
from datetime import datetime
from loguru import logger


class EmailAlertSender:
    """
    Send HTML threat-alert emails via Gmail SMTP.

    Falls back gracefully to mock mode when credentials are absent so
    the rest of the gateway never crashes.
    """

    SMTP_HOST = "smtp.gmail.com"
    SMTP_PORT = 587

    def __init__(
        self,
        gmail_address: Optional[str] = None,
        app_password:  Optional[str] = None,
        recipient:     Optional[str] = None,
        threshold:     Optional[float] = None,
    ):
        self.gmail_address = (
            gmail_address or os.getenv("GMAIL_ADDRESS", "")
        ).strip()
        # Strip spaces that users copy from Google's app-password display
        self.app_password = (
            app_password or os.getenv("GMAIL_APP_PASSWORD", "")
        ).strip().replace(" ", "")
        self.recipient = (
            recipient
            or os.getenv("ALERT_RECIPIENT", self.gmail_address)
        ).strip()
        self.threshold = float(
            threshold if threshold is not None
            else os.getenv("GMAIL_ALERT_THRESHOLD", "0.6")
        )

        self.enabled = bool(self.gmail_address and self.app_password)

        if self.enabled:
            logger.info(
                f"EmailAlertSender ready (Gmail) — alerts → {self.recipient} "
                f"(threshold ≥ {self.threshold:.0%})"
            )
        else:
            logger.warning(
                "Email alerts disabled — set GMAIL_ADDRESS and "
                "GMAIL_APP_PASSWORD in .env to enable"
            )

    # ------------------------------------------------------------------

    def should_alert(self, threat_score: float) -> bool:
        return self.enabled and threat_score >= self.threshold

    def send_alert(self, to_email: str, threat_data: Dict) -> bool:
        """
        Send an HTML alert email.

        Args:
            to_email:    Recipient address (ignored if ALERT_RECIPIENT is set;
                         kept for backwards-compatibility with smtp_handler).
            threat_data: Dict with threat_score, risk_level, from, subject, urls.

        Returns:
            True on success, False on any failure.
        """
        if not self.enabled:
            logger.warning("Email alerts not enabled — skipping")
            return False

        recipient = self.recipient or to_email
        if not recipient:
            logger.warning("No recipient address configured — skipping alert")
            return False

        try:
            msg = self._build_message(recipient, threat_data)
            with smtplib.SMTP(self.SMTP_HOST, self.SMTP_PORT, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(self.gmail_address, self.app_password)
                server.send_message(msg)
            logger.info(
                f"[EmailAlert] Sent to {recipient} — "
                f"score={threat_data.get('threat_score', 0):.0%} "
                f"level={threat_data.get('risk_level')}"
            )
            return True
        except smtplib.SMTPAuthenticationError:
            logger.error(
                "[EmailAlert] Authentication failed. "
                "Use an App Password from https://myaccount.google.com/apppasswords"
            )
            return False
        except Exception as exc:
            logger.error(f"[EmailAlert] Failed to send: {exc}")
            return False

    # ------------------------------------------------------------------
    # Message builders
    # ------------------------------------------------------------------

    def _build_message(self, recipient: str, d: Dict) -> MIMEMultipart:
        risk  = d.get("risk_level", "UNKNOWN")
        score = d.get("threat_score", 0.0)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{risk}] Email Security Gateway — Threat Detected ({score:.0%})"
        msg["From"]    = f"Email Security Gateway <{self.gmail_address}>"
        msg["To"]      = recipient

        msg.attach(MIMEText(self._plain(d), "plain"))
        msg.attach(MIMEText(self._html(d),  "html"))
        return msg

    def _plain(self, d: Dict) -> str:
        score    = d.get("threat_score", 0.0)
        risk     = d.get("risk_level", "UNKNOWN")
        urls     = d.get("urls", [])
        url_block = "\n".join(f"  - {u}" for u in urls) if urls else "  (none)"
        return (
            f"[{risk}] THREAT DETECTED — {score:.0%}\n"
            f"{'='*50}\n"
            f"From   : {d.get('from', 'unknown')}\n"
            f"To     : {d.get('to', 'unknown')}\n"
            f"Subject: {d.get('subject', '(no subject)')}\n"
            f"Score  : {score:.0%}  |  Level: {risk}\n"
            f"\nSuspicious URLs:\n{url_block}\n"
            f"\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Dashboard: http://localhost:8501\n"
        )

    def _html(self, d: Dict) -> str:
        risk  = d.get("risk_level", "UNKNOWN")
        score = d.get("threat_score", 0.0)
        urls  = d.get("urls", [])

        colour = {
            "CRITICAL": "#DC2626",
            "HIGH":     "#F59E0B",
            "MEDIUM":   "#EAB308",
        }.get(risk, "#6B7280")

        url_rows = "".join(
            f"<li style='font-family:monospace;font-size:13px'>{u}</li>"
            for u in urls
        ) or "<li><em>None detected</em></li>"

        return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;background:#f3f4f6;padding:20px">
  <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;
              box-shadow:0 2px 8px rgba(0,0,0,.1);overflow:hidden">

    <div style="background:{colour};color:#fff;padding:20px;text-align:center">
      <h1 style="margin:0;font-size:22px">⚠️ {risk} RISK EMAIL DETECTED</h1>
      <p style="margin:6px 0 0;font-size:28px;font-weight:bold">{score:.0%}</p>
    </div>

    <div style="padding:24px">
      <table style="width:100%;border-collapse:collapse">
        <tr><td style="padding:8px;color:#6b7280;width:90px"><b>From</b></td>
            <td style="padding:8px">{d.get('from','unknown')}</td></tr>
        <tr style="background:#f9fafb">
            <td style="padding:8px;color:#6b7280"><b>To</b></td>
            <td style="padding:8px">{d.get('to','unknown')}</td></tr>
        <tr><td style="padding:8px;color:#6b7280"><b>Subject</b></td>
            <td style="padding:8px">{d.get('subject','(no subject)')}</td></tr>
        <tr style="background:#f9fafb">
            <td style="padding:8px;color:#6b7280"><b>Risk Level</b></td>
            <td style="padding:8px;color:{colour};font-weight:bold">{risk}</td></tr>
      </table>

      <h3 style="margin-top:20px;color:#374151">Suspicious URLs</h3>
      <ul style="margin:0;padding-left:20px">{url_rows}</ul>

      <div style="margin-top:24px;text-align:center">
        <a href="http://localhost:8501"
           style="background:{colour};color:#fff;padding:10px 20px;
                  border-radius:6px;text-decoration:none;font-weight:bold">
          View in Dashboard
        </a>
      </div>

      <p style="margin-top:20px;font-size:12px;color:#9ca3af;text-align:center">
        Email Security Gateway · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
      </p>
    </div>
  </div>
</body>
</html>"""


# ── Mock (used when credentials are absent) ───────────────────────────────────

class MockEmailAlertSender:
    """Logs alerts instead of sending — used in dev or when .env is unconfigured."""
    enabled = True

    def __init__(self, *args, **kwargs):
        logger.info("MockEmailAlertSender active (no real email will be sent)")

    def should_alert(self, score: float) -> bool:
        return score >= 0.6

    def send_alert(self, to_email: str, threat_data: Dict) -> bool:
        risk  = threat_data.get("risk_level", "?")
        subj  = str(threat_data.get("subject", ""))[:50]
        score = threat_data.get("threat_score", 0.0)
        logger.info(f"[MOCK EmailAlert] → {to_email}  [{risk}] {score:.0%}  {subj}")
        return True


# ── Factory ───────────────────────────────────────────────────────────────────

def get_email_sender(use_mock: bool = False):
    """Return a real EmailAlertSender if credentials are present, else Mock."""
    if use_mock:
        return MockEmailAlertSender()
    sender = EmailAlertSender()
    if not sender.enabled:
        logger.info("Falling back to MockEmailAlertSender (no credentials)")
        return MockEmailAlertSender()
    return sender