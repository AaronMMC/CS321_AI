"""
Main FastAPI application for the Email Security Gateway.

CHANGES FROM ORIGINAL:
  1. /api/v1/check-email now returns auth (SPF/DKIM/DMARC) and intel
     (VirusTotal, WHOIS, Google SB) fields in addition to threat_score.
  2. New GET /api/v1/quarantine endpoint reads the quarantine/ folder on disk
     and returns the metadata JSON files written by smtp_handler.
  3. EmailCheckResponse schema updated with optional intel and auth fields.
  4. Removed the duplicate email_queue.enqueue() that was processing every
     synchronous /check-email request a second time in the background.
  5. _get_risk_level() deduplicated — single copy used by all routes.
"""

import asyncio
import json as _json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from pydantic import BaseModel, Field

from src.features.authentication_verification import verify_email_authentication
from src.features.external_intelligence import ThreatIntelligenceHub
from src.gateway.email_parser import EmailParser
from src.gateway.queue_manager import AsyncProcessor, EmailQueue
from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.utils.config import settings

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Email Security Gateway API",
    description="AI-Powered Email Security for Philippine Government",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global singletons (initialised in startup event)
_model: Optional[TinyBERTForEmailSecurity] = None
_threat_hub: Optional[ThreatIntelligenceHub] = None
_email_queue: Optional[EmailQueue] = None
_processor: Optional[AsyncProcessor] = None
_email_parser = EmailParser()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class EmailCheckRequest(BaseModel):
    subject: str
    body: str
    from_email: Optional[str] = None
    to_email: Optional[str] = None
    urls: Optional[List[str]] = None


class EmailCheckResponse(BaseModel):
    threat_score: float = Field(..., ge=0, le=1)
    risk_level: str
    explanations: List[str]
    timestamp: datetime
    job_id: Optional[str] = None
    # NEW — threat-intelligence breakdown shown on the admin dashboard card
    intel: Optional[Dict[str, Any]] = None
    # NEW — SPF / DKIM / DMARC results
    auth: Optional[Dict[str, Any]] = None


class AlertResponse(BaseModel):
    id: str
    timestamp: datetime
    threat_score: float
    from_email: str
    to_email: str
    subject: str
    risk_level: str
    status: str = "new"


class WhitelistEntry(BaseModel):
    email: Optional[str] = None
    domain: Optional[str] = None
    reason: str
    added_by: str
    timestamp: datetime = Field(default_factory=datetime.now)


class BlacklistEntry(BaseModel):
    email: Optional[str] = None
    domain: Optional[str] = None
    reason: str
    added_by: str
    timestamp: datetime = Field(default_factory=datetime.now)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _build_intel(urls: List[str], threat_hub: ThreatIntelligenceHub) -> Dict[str, Any]:
    """
    Query VirusTotal, WHOIS, and Google Safe Browsing for the first URL
    found in the email.  Returns a flat dict suitable for JSON serialisation.
    """
    if not urls:
        return {}

    url = urls[0]
    intel: Dict[str, Any] = {"url_checked": url}

    try:
        vt = threat_hub.vt.check_url(url)
        intel["virustotal_score"] = round(vt.get("score", 0.0), 3)
        total = vt.get("total", 68)
        malicious = vt.get("malicious", 0)
        intel["virustotal_flags"] = f"{malicious}/{total} flags"
    except Exception:
        intel["virustotal_flags"] = "unavailable"

    try:
        domain = threat_hub.url_validator.extract_domain(url)
        if domain:
            whois_r = threat_hub.whois.check_domain(domain)
            age = whois_r.get("age_days")
            intel["domain_age_days"] = age
            intel["domain_age_label"] = (
                f"{age} days old" if age is not None else "unknown"
            )
            intel["registrar"] = whois_r.get("registrar", "unknown")
    except Exception:
        intel["domain_age_label"] = "unavailable"

    try:
        gsb = threat_hub.gsb.check_url(url)
        threat_types = gsb.get("threat_types", [])
        intel["google_safe_browsing"] = (
            ", ".join(threat_types) if threat_types else "Clean"
        )
    except Exception:
        intel["google_safe_browsing"] = "unavailable"

    return intel


def _build_auth(from_email: Optional[str]) -> Dict[str, Any]:
    """
    Run SPF / DKIM / DMARC checks for the sender domain.
    Returns a simplified dict for the API response.
    """
    if not from_email or "@" not in from_email:
        return {}

    domain = from_email.split("@")[1]
    try:
        result = verify_email_authentication({
            "from_domain": domain,
            "from": from_email,
            "headers": {},
            "body_raw": b"",
            "sender_ip": "127.0.0.1",
        })
        spf = result.get("spf", {})
        dkim = result.get("dkim", {})
        dmarc = result.get("dmarc", {})
        return {
            "passed": result.get("passed", False),
            "score": round(result.get("score", 0.0), 3),
            "spf": "Pass" if spf.get("passed") else "Fail",
            "dkim": "Pass" if dkim.get("passed") else "Fail",
            "dmarc": f"{dmarc.get('policy', 'unknown').capitalize()} policy — "
                     + ("pass" if dmarc.get("passed") else "fail"),
            "reasons": result.get("reasons", []),
        }
    except Exception as exc:
        logger.warning(f"Auth check failed for {domain}: {exc}")
        return {"passed": False, "score": 0.0, "error": str(exc)}


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def startup_event():
    global _model, _threat_hub, _email_queue, _processor

    logger.info("Starting Email Security Gateway API…")

    try:
        _model = TinyBERTForEmailSecurity()
        logger.info("Model loaded successfully")
    except Exception as exc:
        logger.error(f"Failed to load model: {exc}")

    _threat_hub = ThreatIntelligenceHub()
    _email_queue = EmailQueue()

    if _model:
        _processor = AsyncProcessor(_email_queue, _model, _threat_hub, num_workers=2)
        asyncio.create_task(_processor.start())
        logger.info("Async processor started (2 workers)")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down API…")
    if _processor:
        await _processor.stop()


# ---------------------------------------------------------------------------
# Routes — health
# ---------------------------------------------------------------------------


@app.get("/")
async def root():
    return {
        "service": "Email Security Gateway",
        "version": "1.0.0",
        "status": "operational",
        "model_loaded": _model is not None,
    }


# ---------------------------------------------------------------------------
# Routes — core email analysis
# ---------------------------------------------------------------------------


@app.post("/api/v1/check-email", response_model=EmailCheckResponse)
async def check_email(request: EmailCheckRequest):
    """
    Synchronous single-email threat check.

    Returns threat_score, risk_level, explanations PLUS the new
    intel (VirusTotal / WHOIS / Google SB) and auth (SPF/DKIM/DMARC) fields
    that the dashboard uses to populate the admin card.
    """
    if not _model:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        text = f"{request.subject} {request.body}"
        urls = request.urls or _email_parser._extract_urls(request.body)

        # --- External intelligence ----------------------------------------
        external_score = 0.0
        if urls and _threat_hub:
            try:
                features = _threat_hub.get_features_for_model(text, urls)
                external_score = float(features[0]) if len(features) > 0 else 0.0
            except Exception:
                pass

        # --- Model prediction ---------------------------------------------
        prediction = _model.predict(text)
        model_score = (
            prediction.get("threat_score", 0.0)
            if isinstance(prediction, dict)
            else float(prediction)
        )

        combined_score = min(model_score * 0.6 + external_score * 0.4, 1.0)

        # --- Explanations -------------------------------------------------
        explanations: List[str] = []
        if combined_score >= 0.7:
            explanations.append("High overall threat score detected")
        if model_score >= 0.6:
            explanations.append("AI model flagged suspicious language patterns")
        if urls:
            explanations.append(f"Found {len(urls)} URL(s) in email body")
        if external_score >= 0.5:
            explanations.append("One or more URLs have poor external reputation")
        subj_lower = request.subject.lower()
        if any(w in subj_lower for w in ("urgent", "verify", "suspended", "click")):
            explanations.append("Subject contains urgency or verification keywords")
        if not explanations:
            explanations.append("No obvious phishing indicators detected")

        # --- Intel breakdown (NEW) ----------------------------------------
        intel = _build_intel(urls, _threat_hub) if _threat_hub else {}

        # --- Auth (NEW) ---------------------------------------------------
        auth = _build_auth(request.from_email)

        # Auth failures raise the combined score
        if auth and not auth.get("passed") and auth.get("score", 1.0) < 0.3:
            combined_score = min(1.0, combined_score + 0.20)
            explanations.append("SPF / DKIM / DMARC authentication failed")

        return EmailCheckResponse(
            threat_score=round(combined_score, 4),
            risk_level=_get_risk_level(combined_score),
            explanations=explanations,
            timestamp=datetime.now(),
            job_id=None,
            intel=intel if intel else None,
            auth=auth if auth else None,
        )

    except Exception as exc:
        logger.error(f"check_email error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/v1/check-batch")
async def check_batch(emails: List[EmailCheckRequest], background_tasks: BackgroundTasks):
    """Queue multiple emails for background processing."""
    if not _model or not _email_queue:
        raise HTTPException(status_code=503, detail="Model or queue not ready")

    job_ids = []
    for email in emails:
        jid = _email_queue.enqueue({
            "subject": email.subject,
            "body": email.body,
            "from": email.from_email,
            "to": email.to_email,
        })
        job_ids.append(jid)

    return {
        "message": f"Queued {len(job_ids)} email(s) for processing",
        "job_ids": job_ids,
        "status_url": "/api/v1/job-status/{job_id}",
    }


@app.get("/api/v1/job-status/{job_id}")
async def get_job_status(job_id: str):
    if not _email_queue:
        raise HTTPException(status_code=503, detail="Queue not initialised")
    status = _email_queue.get_status(job_id)
    if not status:
        raise HTTPException(status_code=404, detail="Job not found")
    return status


# ---------------------------------------------------------------------------
# Routes — alerts
# ---------------------------------------------------------------------------


@app.get("/api/v1/alerts", response_model=List[AlertResponse])
async def get_alerts(status: Optional[str] = None, limit: int = 50):
    """Return recent alerts (mock data while no live gateway is running)."""
    mock = [
        {
            "id": "alert_001",
            "timestamp": datetime.now(),
            "threat_score": 0.94,
            "from_email": "support@gcash-verify.net",
            "to_email": "employee@deped.gov.ph",
            "subject": "URGENT: Account verification needed",
            "risk_level": "CRITICAL",
            "status": "new",
        },
        {
            "id": "alert_002",
            "timestamp": datetime.now(),
            "threat_score": 0.67,
            "from_email": "hr@company-ph.com",
            "to_email": "staff@dict.gov.ph",
            "subject": "Update your payroll information",
            "risk_level": "HIGH",
            "status": "acknowledged",
        },
    ]
    if status:
        mock = [a for a in mock if a["status"] == status]
    return mock[:limit]


# ---------------------------------------------------------------------------
# Routes — quarantine (NEW)
# ---------------------------------------------------------------------------


@app.get("/api/v1/quarantine")
async def get_quarantine(limit: int = 50):
    """
    Return quarantined email metadata by reading the quarantine/ folder that
    smtp_handler._quarantine_email() writes to.

    Each file is a JSON object created when an email scores ≥ 0.80.
    Falls back to an empty list when the folder does not yet exist (gateway
    not running).
    """
    quarantine_dir = Path("quarantine")
    if not quarantine_dir.exists():
        return []

    files = sorted(quarantine_dir.glob("*.json"), reverse=True)[:limit]
    results = []
    for f in files:
        try:
            results.append(_json.loads(f.read_text()))
        except Exception as exc:
            logger.warning(f"Could not read quarantine file {f}: {exc}")

    return results


@app.delete("/api/v1/quarantine/{quarantine_id}")
async def release_quarantine(quarantine_id: str):
    """Release (delete) a quarantined email by its ID."""
    quarantine_dir = Path("quarantine")
    target = quarantine_dir / f"{quarantine_id}.json"
    if not target.exists():
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    target.unlink()
    logger.info(f"Quarantine released: {quarantine_id}")
    return {"message": f"Released {quarantine_id}", "id": quarantine_id}


# ---------------------------------------------------------------------------
# Routes — whitelist / blacklist / feedback / stats
# ---------------------------------------------------------------------------


@app.post("/api/v1/whitelist")
async def add_to_whitelist(entry: WhitelistEntry):
    logger.info(f"Whitelist add: {entry.email or entry.domain}")
    return {"message": "Added to whitelist", "entry": entry.dict()}


@app.delete("/api/v1/whitelist/{identifier}")
async def remove_from_whitelist(identifier: str):
    logger.info(f"Whitelist remove: {identifier}")
    return {"message": f"Removed {identifier} from whitelist"}


@app.post("/api/v1/blacklist")
async def add_to_blacklist(entry: BlacklistEntry):
    logger.info(f"Blacklist add: {entry.email or entry.domain}")
    return {"message": "Added to blacklist", "entry": entry.dict()}


@app.delete("/api/v1/blacklist/{identifier}")
async def remove_from_blacklist(identifier: str):
    logger.info(f"Blacklist remove: {identifier}")
    return {"message": f"Removed {identifier} from blacklist"}


@app.post("/api/v1/feedback")
async def submit_feedback(
    job_id: str, is_threat: bool, admin_notes: Optional[str] = None
):
    logger.info(f"Feedback for {job_id}: is_threat={is_threat}")
    return {"message": "Feedback received", "job_id": job_id}


@app.get("/api/v1/stats")
async def get_stats():
    queue_stats = _email_queue.get_stats() if _email_queue else {}
    quarantine_count = len(list(Path("quarantine").glob("*.json"))) if Path("quarantine").exists() else 0
    return {
        "emails_processed": queue_stats.get("processed", 0),
        "threats_detected": queue_stats.get("threats", 0),
        "queue_size": queue_stats.get("queue_size", 0),
        "avg_processing_time": round(queue_stats.get("avg_wait_time", 0.0), 3),
        "model_loaded": _model is not None,
        "quarantine_count": quarantine_count,
        "timestamp": datetime.now(),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )