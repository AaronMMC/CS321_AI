"""
Transparent SMTP proxy server.
Sits between the mail transfer agent (MTA) and the internal mail server,
inspecting every message before it is delivered.

Architecture:
    Internet / MTA  →  [port 10025]  EmailProxyServer  →  [real SMTP port 25]
"""

import asyncio
import smtplib
from typing import Optional, Dict
from loguru import logger

from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.features.external_intelligence import ThreatIntelligenceHub
from src.gateway.email_parser import EmailParser
from src.gateway.smtp_handler import EmailGateway
from src.utils.config import settings


class EmailProxyServer:
    """
    Manages lifecycle of the SMTP proxy gateway.

    Usage::

        proxy = EmailProxyServer(listen_host="0.0.0.0", listen_port=10025)
        asyncio.run(proxy.run())
    """

    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 10025,
        forward_host: Optional[str] = None,
        forward_port: Optional[int] = None,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.forward_host = forward_host or settings.email_server.smtp_server
        self.forward_port = forward_port or settings.email_server.smtp_port

        self._model: Optional[TinyBERTForEmailSecurity] = None
        self._threat_hub: Optional[ThreatIntelligenceHub] = None
        self._gateway: Optional[EmailGateway] = None
        self._running = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self):
        """Initialise components and start the proxy (blocks until stopped)."""
        logger.info("Initialising Email Proxy Server …")
        await self._load_components()
        self._running = True
        logger.info(
            f"Email Proxy Server listening on {self.listen_host}:{self.listen_port} "
            f"→ forwarding to {self.forward_host}:{self.forward_port}"
        )
        await self._gateway.start(self._model, self._threat_hub)

    async def stop(self):
        """Gracefully stop the proxy."""
        self._running = False
        if self._gateway:
            await self._gateway.stop()
        logger.info("Email Proxy Server stopped.")

    def get_stats(self) -> Dict:
        """Return runtime statistics."""
        base = {
            "listen": f"{self.listen_host}:{self.listen_port}",
            "forward": f"{self.forward_host}:{self.forward_port}",
            "running": self._running,
        }
        if self._gateway:
            base.update(self._gateway.get_stats())
        return base

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _load_components(self):
        """Load AI model and threat hub (run in executor to avoid blocking)."""
        loop = asyncio.get_event_loop()

        logger.info("Loading TinyBERT model …")
        self._model = await loop.run_in_executor(None, TinyBERTForEmailSecurity)
        logger.info("Model loaded.")

        logger.info("Initialising Threat Intelligence Hub …")
        self._threat_hub = ThreatIntelligenceHub()
        logger.info("Threat hub ready.")

        self._gateway = EmailGateway(host=self.listen_host, port=self.listen_port)


# ---------------------------------------------------------------------------
# Stand-alone entry point
# ---------------------------------------------------------------------------

async def run_proxy(
    listen_host: str = "0.0.0.0",
    listen_port: int = 10025,
):
    """Start the proxy server (called from scripts or docker CMD)."""
    proxy = EmailProxyServer(listen_host=listen_host, listen_port=listen_port)
    try:
        await proxy.run()
    except KeyboardInterrupt:
        await proxy.stop()


if __name__ == "__main__":
    asyncio.run(run_proxy())