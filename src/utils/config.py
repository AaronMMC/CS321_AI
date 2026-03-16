"""
Configuration management module.
Loads environment variables and provides typed configuration objects.
"""

import os
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv
from loguru import logger

# Load environment variables from .env file
load_dotenv()


@dataclass
class APIConfig:
    """External API configuration"""
    virustotal_api_key: str = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", ""))
    google_safe_browsing_key: str = field(default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", ""))
    twilio_sid: str = field(default_factory=lambda: os.getenv("TWILIO_ACCOUNT_SID", ""))
    twilio_token: str = field(default_factory=lambda: os.getenv("TWILIO_AUTH_TOKEN", ""))
    telegram_token: str = field(default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", ""))

    def is_virustotal_configured(self) -> bool:
        return bool(self.virustotal_api_key)

    def is_google_safe_browsing_configured(self) -> bool:
        return bool(self.google_safe_browsing_key)


@dataclass
class EmailServerConfig:
    """Email server settings"""
    smtp_server: str = field(default_factory=lambda: os.getenv("SMTP_SERVER", "localhost"))
    smtp_port: int = int(os.getenv("SMTP_PORT", "25"))
    imap_server: str = field(default_factory=lambda: os.getenv("IMAP_SERVER", "localhost"))
    imap_port: int = int(os.getenv("IMAP_PORT", "143"))

    @property
    def smtp_address(self) -> str:
        return f"{self.smtp_server}:{self.smtp_port}"


@dataclass
class ModelConfig:
    """Model paths and settings"""
    model_path: Path = Path(os.getenv("MODEL_PATH", "models_saved/bert_phishing_detector_v1"))
    tinybert_path: Path = Path(os.getenv("TINYBERT_MODEL_PATH", "models_saved/tinybert_enron_spam"))
    confidence_threshold: float = 0.7  # Minimum confidence for flagging
    use_gpu: bool = True  # Will be auto-detected

    def __post_init__(self):
        # Auto-detect GPU availability
        import torch
        self.use_gpu = torch.cuda.is_available() if self.use_gpu else False


@dataclass
class AlertConfig:
    """Alert notification settings"""
    admin_phone: str = field(default_factory=lambda: os.getenv("ADMIN_PHONE", ""))
    admin_email: str = field(default_factory=lambda: os.getenv("ADMIN_EMAIL", ""))
    admin_telegram: str = field(default_factory=lambda: os.getenv("ADMIN_TELEGRAM_CHAT_ID", ""))

    # Alert thresholds
    sms_alert_threshold: float = 0.8  # Send SMS for threats >80%
    email_alert_threshold: float = 0.6  # Send email for threats >60%
    dashboard_alert_threshold: float = 0.4  # Show in dashboard for threats >40%


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    file: Path = Path(os.getenv("LOG_FILE", "logs/email_security.log"))

    def __post_init__(self):
        # Ensure log directory exists
        self.file.parent.mkdir(parents=True, exist_ok=True)


class Settings:
    """Main settings container"""

    def __init__(self):
        self.api = APIConfig()
        self.email_server = EmailServerConfig()
        self.model = ModelConfig()
        self.alerts = AlertConfig()
        self.logging = LoggingConfig()

        # Database
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///email_security.db")

        # Application settings
        self.debug = os.getenv("DEBUG", "False").lower() == "true"
        self.environment = os.getenv("ENVIRONMENT", "development")

    def validate(self) -> bool:
        """Validate critical configuration"""
        missing_keys = []

        # Check critical API keys (optional but warn)
        if not self.api.virustotal_api_key:
            logger.warning("VirusTotal API key not configured - external intelligence disabled")

        if not self.api.google_safe_browsing_key:
            logger.warning("Google Safe Browsing API key not configured - URL reputation disabled")

        # Check model paths
        if not self.model.model_path.exists() and not self.model.tinybert_path.exists():
            logger.error(f"No model found at {self.model.model_path} or {self.model.tinybert_path}")
            return False

        return True


# Global settings instance
settings = Settings()