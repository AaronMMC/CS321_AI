"""
FastAPI dependency injection for shared components.
"""

from fastapi import HTTPException, Header
from typing import Optional
from loguru import logger

from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.features.external_intelligence import ThreatIntelligenceHub
from src.gateway.queue_manager import EmailQueue

# --- Singleton instances ---
_model: Optional[TinyBERTForEmailSecurity] = None
_threat_hub: Optional[ThreatIntelligenceHub] = None
_email_queue: Optional[EmailQueue] = None


def get_model() -> TinyBERTForEmailSecurity:
    """Return the loaded model or raise 503."""
    global _model
    if _model is None:
        try:
            _model = TinyBERTForEmailSecurity()
        except Exception as e:
            logger.error(f"Failed to load model on demand: {e}")
            raise HTTPException(status_code=503, detail="Model not available")
    return _model


def get_threat_hub() -> ThreatIntelligenceHub:
    """Return the threat intelligence hub singleton."""
    global _threat_hub
    if _threat_hub is None:
        _threat_hub = ThreatIntelligenceHub()
    return _threat_hub


def get_email_queue() -> EmailQueue:
    """Return the email processing queue singleton."""
    global _email_queue
    if _email_queue is None:
        _email_queue = EmailQueue()
    return _email_queue


def verify_api_key(x_api_key: Optional[str] = Header(default=None)):
    """
    Optional API-key guard.

    Set the environment variable API_KEY to enable key checks.
    If API_KEY is not set, all requests are allowed (development mode).
    """
    import os
    expected = os.getenv("API_KEY", "")
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")