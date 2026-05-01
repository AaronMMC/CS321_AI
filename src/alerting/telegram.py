"""
Telegram bot alerting module.

CHANGES FROM ORIGINAL:
  1. enabled attribute added to MockTelegramBot so smtp_handler can check
     `.enabled` on both real and mock bots without AttributeError.
  2. send_alert() accepts the 'campaign' key in threat_data and adds
     campaign information to the Telegram message.
  3. get_telegram_bot() now auto-falls-back to MockTelegramBot when the
     token is missing (mirrors the pattern in sms.py).
  4. Async compatibility: send_alert is a coroutine so smtp_handler can
     fire it with asyncio.create_task() without wrapping.
"""

import os
from typing import Dict, List, Optional

from loguru import logger

try:
    from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import (
        Application,
        CallbackQueryHandler,
        CommandHandler,
        ContextTypes,
    )
    from telegram.error import TelegramError
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    logger.warning(
        "python-telegram-bot not installed — Telegram alerts disabled. "
        "Run: pip install python-telegram-bot"
    )


class TelegramAlertBot:
    """
    Telegram bot that sends threat alerts and accepts interactive commands.

    Required environment variables (set in .env):
        TELEGRAM_BOT_TOKEN
        TELEGRAM_ALLOWED_CHATS   — comma-separated chat IDs (optional)
    """

    def __init__(
        self,
        token: Optional[str] = None,
        allowed_chat_ids: Optional[List[str]] = None,
    ):
        self.token = token or os.getenv("TELEGRAM_BOT_TOKEN", "")
        raw_chats = os.getenv("TELEGRAM_ALLOWED_CHATS", "")
        self.allowed_chat_ids: List[str] = (
            allowed_chat_ids
            if allowed_chat_ids is not None
            else [c.strip() for c in raw_chats.split(",") if c.strip()]
        )

        self.bot: Optional[Bot] = None
        self.application = None
        self.enabled: bool = False

        if not TELEGRAM_AVAILABLE:
            logger.warning("Telegram alerts disabled — library not installed")
            return

        if not self.token:
            logger.warning(
                "Telegram alerts disabled — TELEGRAM_BOT_TOKEN not set in .env"
            )
            return

        try:
            self.bot = Bot(token=self.token)
            self.application = Application.builder().token(self.token).build()
            self._register_handlers()
            self.enabled = True
            logger.info("TelegramAlertBot initialised")
        except Exception as exc:
            logger.error(f"Failed to initialise Telegram bot: {exc}")

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def _register_handlers(self) -> None:
        if not self.application:
            return
        self.application.add_handler(CommandHandler("start", self._cmd_start))
        self.application.add_handler(CommandHandler("help", self._cmd_help))
        self.application.add_handler(CommandHandler("status", self._cmd_status))
        self.application.add_handler(CallbackQueryHandler(self._on_button))

    async def _cmd_start(self, update, context: "ContextTypes.DEFAULT_TYPE") -> None:
        chat_id = str(update.effective_chat.id)
        if not self._is_authorised(chat_id):
            await update.message.reply_text("⛔ Unauthorised chat.")
            return
        await update.message.reply_text(
            "🤖 *Email Security Gateway Alert Bot*\n\n"
            "I will notify you when suspicious emails are detected.\n\n"
            "Commands:\n"
            "/status — gateway status\n"
            "/help   — this message",
            parse_mode="Markdown",
        )

    async def _cmd_help(self, update, context: "ContextTypes.DEFAULT_TYPE") -> None:
        await update.message.reply_text(
            "Commands:\n"
            "/start  — initialise\n"
            "/status — check gateway status\n"
            "/help   — this message"
        )

    async def _cmd_status(self, update, context: "ContextTypes.DEFAULT_TYPE") -> None:
        import requests as _req
        try:
            r = _req.get("http://localhost:8000/api/v1/stats", timeout=3)
            stats = r.json()
            text = (
                f"✅ *Gateway operational*\n"
                f"Processed: {stats.get('emails_processed', 0):,}\n"
                f"Threats:   {stats.get('threats_detected', 0):,}\n"
                f"Quarantine:{stats.get('quarantine_count', 0):,}"
            )
        except Exception:
            text = "⚠️ Cannot reach gateway API (is uvicorn running?)"
        await update.message.reply_text(text, parse_mode="Markdown")

    async def _on_button(self, update, context: "ContextTypes.DEFAULT_TYPE") -> None:
        query = update.callback_query
        await query.answer()
        actions = {
            "ack": "✅ Alert acknowledged.",
            "fp":  "✅ Marked as false positive — thank you for the feedback.",
            "inv": "🔍 Escalated for investigation.",
        }
        await query.edit_message_text(
            actions.get(query.data, "Action recorded.")
        )

    # ------------------------------------------------------------------
    # Alert sender
    # ------------------------------------------------------------------

    async def send_alert(self, chat_id: str, threat_data: Dict) -> bool:
        """
        Send a Telegram alert message with inline action buttons.

        Args:
            chat_id:     Telegram chat ID (from ADMIN_TELEGRAM_CHAT_ID in .env).
            threat_data: Dict with risk_level, threat_score, from, subject,
                         and optionally campaign.

        Returns:
            True on success, False otherwise.
        """
        if not self.enabled or not self.bot:
            logger.warning("Telegram alert skipped — bot not enabled")
            return False

        if not self._is_authorised(chat_id):
            logger.warning(f"Telegram alert blocked — chat {chat_id} not authorised")
            return False

        try:
            risk_level = threat_data.get("risk_level", "UNKNOWN")
            score = threat_data.get("threat_score", 0.0)
            sender = str(threat_data.get("from", "Unknown"))[:50]
            subject = str(threat_data.get("subject", "No subject"))[:80]

            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(
                risk_level, "⚪"
            )

            text = (
                f"{emoji} *{risk_level} RISK EMAIL DETECTED*\n\n"
                f"*From:* `{sender}`\n"
                f"*Subject:* {subject}\n"
                f"*Score:* {score:.0%}"
            )

            # Campaign note
            campaign = threat_data.get("campaign")
            if campaign and campaign.get("campaign_detected"):
                count = campaign.get("count", 0)
                domain = campaign.get("domain", "")
                text += (
                    f"\n\n⚠️ *Campaign detected* — {count} emails from "
                    f"`{domain}` in the last 2 hours"
                )

            keyboard = InlineKeyboardMarkup(
                [
                    [
                        InlineKeyboardButton("✅ Acknowledge", callback_data="ack"),
                        InlineKeyboardButton("❌ False Positive", callback_data="fp"),
                    ],
                    [InlineKeyboardButton("🔍 Investigate", callback_data="inv")],
                ]
            )

            await self.bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode="Markdown",
                reply_markup=keyboard,
            )
            logger.info(f"Telegram alert sent to chat {chat_id}")
            return True

        except TelegramError as exc:
            logger.error(f"Telegram API error: {exc}")
            return False
        except Exception as exc:
            logger.error(f"Unexpected Telegram error: {exc}")
            return False

    # ------------------------------------------------------------------
    # Polling (optional — for interactive commands)
    # ------------------------------------------------------------------

    def run_polling(self) -> None:
        """
        Start the bot in long-polling mode to receive /status and /help commands.
        Call this in a background thread if you want interactive commands
        alongside the gateway.  Not required for alert-only operation.
        """
        if self.enabled and self.application:
            logger.info("Starting Telegram bot polling…")
            self.application.run_polling()
        else:
            logger.warning("Telegram bot not enabled — polling not started")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_authorised(self, chat_id: str) -> bool:
        """Return True if no allow-list is configured, or the chat is on it."""
        if not self.allowed_chat_ids:
            return True
        return chat_id in self.allowed_chat_ids


# ---------------------------------------------------------------------------
# Mock bot (development / CI)
# ---------------------------------------------------------------------------


class MockTelegramBot:
    """
    Drop-in async replacement for TelegramAlertBot.
    Logs the alert instead of sending it — no credentials required.
    """

    enabled: bool = True  # always True so smtp_handler can check uniformly

    def __init__(self, *args, **kwargs):
        logger.info("MockTelegramBot initialised (no real messages will be sent)")

    async def send_alert(self, chat_id: str, threat_data: Dict) -> bool:
        risk_level = threat_data.get("risk_level", "UNKNOWN")
        subject = str(threat_data.get("subject", ""))[:40]
        campaign = threat_data.get("campaign")
        campaign_note = (
            f" | CAMPAIGN({campaign['count']})" if campaign and campaign.get("campaign_detected") else ""
        )
        logger.info(
            f"[MOCK TELEGRAM] → {chat_id}  [{risk_level}] {subject}{campaign_note}"
        )
        return True

    def run_polling(self) -> None:
        logger.info("MockTelegramBot: polling not available in mock mode")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_telegram_bot(
    use_mock: bool = False,
) -> "TelegramAlertBot | MockTelegramBot":
    """
    Return a real TelegramAlertBot when a token is configured,
    otherwise return MockTelegramBot.

    Pass use_mock=True to force the mock (e.g. in tests).
    """
    if use_mock:
        return MockTelegramBot()

    bot = TelegramAlertBot()
    if not bot.enabled:
        logger.info("Falling back to MockTelegramBot (no token configured)")
        return MockTelegramBot()
    return bot