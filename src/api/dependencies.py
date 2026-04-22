"""
FastAPI dependency injection for shared components.
"""

import os
from dotenv import load_dotenv
from fastapi import HTTPException, Header, Request
from fastapi.security import APIKeyHeader
from typing import Optional
from loguru import logger

from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.features.external_intelligence import ThreatIntelligenceHub
from src.gateway.queue_manager import EmailQueue

# Load environment variables
load_dotenv()

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


def is_production() -> bool:
    """Check if running in production mode"""
    return os.getenv("ENVIRONMENT", "development").lower() == "production"


def verify_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")):
    """
    API-key guard for external API clients.

    - In DEVELOPMENT mode: API key is optional (all requests allowed)
    - In PRODUCTION mode: API key is required

    Set the environment variable API_KEY to enable key checks.
    """
    expected = os.getenv("API_KEY", "")

    # In development mode, skip API key check
    if not is_production():
        logger.debug("Development mode: API key check skipped")
        return True

    # In production mode, API key is required
    if not expected:
        logger.warning("Production mode: No API_KEY configured in environment!")
        raise HTTPException(
            status_code=500,
            detail="Server configuration error: API_KEY not set"
        )

    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Include 'X-API-Key' header."
        )

    if x_api_key != expected:
        logger.warning(f"Invalid API key attempt from client")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )

    logger.debug("API key validated successfully")
    return True


def get_client_ip(request: Request) -> str:
    """Extract client IP from request, handling proxies"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"