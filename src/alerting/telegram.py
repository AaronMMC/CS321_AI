"""
Telegram bot for alerts and interactive management.
"""

from typing import Dict, Optional, List
from loguru import logger
import os
import asyncio

try:
    from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    logger.warning("python-telegram-bot not installed - Telegram alerts disabled")


class TelegramAlertBot:
    """Telegram bot for sending alerts and receiving commands"""

    def __init__(self, token: Optional[str] = None, allowed_chat_ids: Optional[List[str]] = None):
        self.token = token or os.getenv("TELEGRAM_BOT_TOKEN")
        self.allowed_chat_ids = allowed_chat_ids or os.getenv("TELEGRAM_ALLOWED_CHATS", "").split(",")

        self.bot = None
        self.application = None
        self.enabled = False

        if TELEGRAM_AVAILABLE and self.token:
            try:
                self.bot = Bot(token=self.token)
                self.application = Application.builder().token(self.token).build()
                self._setup_handlers()
                self.enabled = True
                logger.info("Telegram bot initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Telegram bot: {e}")

    def _setup_handlers(self):
        """Setup command handlers"""
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CallbackQueryHandler(self.button_callback))

    async def start_command(self, update, context):
        """Handle /start command"""
        chat_id = str(update.effective_chat.id)

        if not self._is_authorized(chat_id):
            await update.message.reply_text("⛔ Unauthorized.")
            return

        await update.message.reply_text(
            "🤖 *Email Security Gateway Bot*\n\n"
            "I will send you alerts when suspicious emails are detected.\n\n"
            "Commands:\n"
            "/help - Show this help",
            parse_mode='Markdown'
        )

    async def help_command(self, update, context):
        """Handle /help command"""
        await update.message.reply_text(
            "Available commands:\n"
            "/start - Initialize bot\n"
            "/help - Show this help"
        )

    async def button_callback(self, update, context):
        """Handle inline button presses"""
        query = update.callback_query
        await query.answer()

        if query.data == "ack":
            await query.edit_message_text("✅ Alert acknowledged.")
        elif query.data == "fp":
            await query.edit_message_text("✅ Marked as false positive.")

    def _is_authorized(self, chat_id: str) -> bool:
        """Check if chat ID is authorized"""
        if not self.allowed_chat_ids or self.allowed_chat_ids == ['']:
            return True
        return chat_id in self.allowed_chat_ids

    async def send_alert(self, chat_id: str, threat_data: Dict) -> bool:
        """Send alert to specific Telegram chat."""
        if not self.enabled or not self.bot:
            return False

        if not self._is_authorized(chat_id):
            return False

        try:
            risk_level = threat_data.get('risk_level', 'UNKNOWN')
            score = threat_data.get('threat_score', 0)

            if risk_level == 'CRITICAL':
                emoji = "🔴"
            elif risk_level == 'HIGH':
                emoji = "🟠"
            else:
                emoji = "🟡"

            message = (
                f"{emoji} *{risk_level} RISK EMAIL*\n\n"
                f"*From:* {threat_data.get('from', 'Unknown')}\n"
                f"*Subject:* {threat_data.get('subject', 'No subject')}\n"
                f"*Score:* {score:.1%}"
            )

            keyboard = [[
                InlineKeyboardButton("✅ Acknowledge", callback_data="ack"),
                InlineKeyboardButton("❌ False Positive", callback_data="fp")
            ]]

            await self.bot.send_message(
                chat_id=chat_id,
                text=message,
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup(keyboard)
            )

            return True

        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
            return False

    def run_polling(self):
        """Start the bot in polling mode"""
        if self.enabled and self.application:
            logger.info("Starting Telegram bot polling...")
            self.application.run_polling()


class MockTelegramBot:
    """Mock Telegram bot for development"""

    def __init__(self, *args, **kwargs):
        self.enabled = True
        logger.info("Mock Telegram bot initialized")

    async def send_alert(self, chat_id: str, threat_data: Dict) -> bool:
        logger.info(f"[MOCK TELEGRAM] To: {chat_id}")
        logger.info(f"[MOCK TELEGRAM] Alert: {threat_data.get('risk_level')} - {threat_data.get('subject', '')[:30]}")
        return True

    def run_polling(self):
        logger.info("Mock Telegram bot polling started (press Ctrl+C to stop)")
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


def get_telegram_bot(use_mock: bool = False):
    """Get Telegram bot instance"""
    if use_mock:
        return MockTelegramBot()
    return TelegramAlertBot()