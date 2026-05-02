"""
FastAPI application for the Email Security Gateway.

Merged from: main.py + routes.py + schemas.py + dependencies.py
Those four files served a single app with no external consumers —
splitting them added indirection for no benefit.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import List, Optional
from datetime import datetime
from pathlib import Path
import re
import uvicorn
from loguru import logger
import asyncio

from src.models.scratch_transformer import ScratchModelForEmailSecurity
from src.features.external_intelligence import ThreatIntelligenceHub
from src.gateway.email_parser import EmailParser
from src.gateway.queue_manager import EmailQueue, AsyncProcessor
from src.utils.config import settings

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

# ── Globals ────────────────────────────────────────────────────────────────────
model: Optional[ScratchModelForEmailSecurity] = None
threat_hub: Optional[ThreatIntelligenceHub] = None
email_queue: Optional[EmailQueue] = None
processor: Optional[AsyncProcessor] = None
email_parser = EmailParser()


# ── Schemas ────────────────────────────────────────────────────────────────────

class EmailCheckRequest(BaseModel):
    subject: str = Field(..., min_length=1, max_length=500)
    body: str = Field(..., min_length=1)
    from_email: Optional[str] = None
    to_email: Optional[str] = None
    urls: Optional[List[str]] = None

    @field_validator("subject", "body")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()


class EmailCheckResponse(BaseModel):
    threat_score: float = Field(..., ge=0, le=1)
    risk_level: str
    explanations: List[str]
    timestamp: datetime
    job_id: Optional[str] = None


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
    reason: str = Field(..., min_length=3)
    added_by: str

    @model_validator(mode="after")
    def require_one(self) -> "WhitelistEntry":
        if not self.email and not self.domain:
            raise ValueError("Provide at least one of: email, domain")
        return self


class BlacklistEntry(BaseModel):
    email: Optional[str] = None
    domain: Optional[str] = None
    reason: str = Field(..., min_length=3)
    added_by: str

    @model_validator(mode="after")
    def require_one(self) -> "BlacklistEntry":
        if not self.email and not self.domain:
            raise ValueError("Provide at least one of: email, domain")
        return self


class FeedbackRequest(BaseModel):
    job_id: str
    is_threat: bool
    admin_notes: Optional[str] = None


# ── Startup / shutdown ─────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    global model, threat_hub, email_queue, processor

    logger.info("Starting Email Security Gateway API...")

    saved = Path(str(settings.model.tinybert_path))
    if saved.exists():
        try:
            model = ScratchModelForEmailSecurity.load(str(saved))
            logger.info(f"Model loaded from {saved}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            model = None
    else:
        logger.warning(
            f"No trained model found at '{saved}'. "
            "Prediction endpoints will return 503 until a model is trained.\n"
            "Run: python scripts/download_datasets.py --all  then  python scripts/train_model.py"
        )

    threat_hub = ThreatIntelligenceHub()
    email_queue = EmailQueue()

    if model:
        processor = AsyncProcessor(email_queue, model, threat_hub, num_workers=2)
        asyncio.create_task(processor.start())
        logger.info("Async processor started")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down...")
    if processor:
        await processor.stop()


# ── Helper ─────────────────────────────────────────────────────────────────────

def _risk_level(score: float) -> str:
    if score >= 0.8: return "CRITICAL"
    if score >= 0.6: return "HIGH"
    if score >= 0.4: return "MEDIUM"
    if score >= 0.2: return "LOW"
    return "SAFE"


def _require_model():
    if not model:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Model not loaded. Train one first:\n"
                f"  python scripts/download_datasets.py --all\n"
                f"  python scripts/train_model.py"
            ),
        )


# ── Email analysis ─────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "service": "Email Security Gateway",
        "version": "1.0.0",
        "status": "operational",
        "model_loaded": model is not None,
        "model_path": str(settings.model.tinybert_path),
    }


@app.post("/api/v1/check-email", response_model=EmailCheckResponse)
async def check_email(request: EmailCheckRequest):
    """Synchronously analyse a single email."""
    _require_model()
    try:
        text = f"{request.subject} {request.body}"
        urls = request.urls or email_parser._extract_urls(request.body)

        external_score = 0.0
        if urls:
            features = threat_hub.get_features_for_model(text, urls)
            external_score = float(features[0]) if features else 0.0

        prediction = model.predict(text)
        model_score = (
            prediction.get("threat_score", 0.0)
            if isinstance(prediction, dict) else float(prediction)
        )

        combined = model_score * 0.6 + external_score * 0.4

        explanations = []
        if combined > 0.7:
            explanations.append("High overall threat score")
        if urls:
            explanations.append(f"Found {len(urls)} URL(s) in email")
        if external_score > 0.5:
            explanations.append("URLs have poor reputation")
        if any(w in request.subject.lower() for w in ("urgent", "verify", "suspended")):
            explanations.append("Subject contains urgency/verification keywords")

        return EmailCheckResponse(
            threat_score=combined,
            risk_level=_risk_level(combined),
            explanations=explanations or ["No obvious threats detected"],
            timestamp=datetime.now(),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"check_email error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/check-batch")
async def check_batch(emails: List[EmailCheckRequest]):
    """Queue multiple emails for background processing."""
    _require_model()
    job_ids = [
        email_queue.enqueue({"subject": e.subject, "body": e.body,
                             "from": e.from_email, "to": e.to_email})
        for e in emails
    ]
    return {
        "message": f"Queued {len(job_ids)} emails",
        "job_ids": job_ids,
        "check_status_url": "/api/v1/job-status/{job_id}",
    }


@app.get("/api/v1/job-status/{job_id}")
async def get_job_status(job_id: str):
    if not email_queue:
        raise HTTPException(status_code=503, detail="Queue not initialised")
    status = email_queue.get_status(job_id)
    if not status:
        raise HTTPException(status_code=404, detail="Job not found")
    return status


# ── Alerts ─────────────────────────────────────────────────────────────────────

@app.get("/api/v1/alerts", response_model=List[AlertResponse])
async def get_alerts(status: Optional[str] = None, limit: int = 50):
    mock = [
        {
            "id": "alert_001", "timestamp": datetime.now(), "threat_score": 0.94,
            "from_email": "support@gcash-verify.net", "to_email": "employee@deped.gov.ph",
            "subject": "URGENT: Account verification needed",
            "risk_level": "CRITICAL", "status": "new",
        },
        {
            "id": "alert_002", "timestamp": datetime.now(), "threat_score": 0.67,
            "from_email": "hr@company-ph.com", "to_email": "staff@dict.gov.ph",
            "subject": "Update your payroll information",
            "risk_level": "HIGH", "status": "acknowledged",
        },
    ]
    if status:
        mock = [a for a in mock if a["status"] == status]
    return mock[:limit]


# ── Admin ──────────────────────────────────────────────────────────────────────

@app.post("/api/v1/whitelist")
async def add_whitelist(entry: WhitelistEntry):
    logger.info(f"Whitelist add: {entry.email or entry.domain}")
    return {"message": "Added to whitelist", "entry": entry.model_dump()}


@app.delete("/api/v1/whitelist/{identifier}")
async def remove_whitelist(identifier: str):
    return {"message": f"Removed {identifier} from whitelist"}


@app.post("/api/v1/blacklist")
async def add_blacklist(entry: BlacklistEntry):
    logger.info(f"Blacklist add: {entry.email or entry.domain}")
    return {"message": "Added to blacklist", "entry": entry.model_dump()}


@app.delete("/api/v1/blacklist/{identifier}")
async def remove_blacklist(identifier: str):
    return {"message": f"Removed {identifier} from blacklist"}


@app.post("/api/v1/feedback")
async def submit_feedback(payload: FeedbackRequest):
    logger.info(f"Feedback for {payload.job_id}: is_threat={payload.is_threat}")
    return {"message": "Feedback received", "job_id": payload.job_id}


@app.get("/api/v1/stats")
async def get_stats():
    q = email_queue.get_stats() if email_queue else {}
    return {
        "emails_processed": q.get("processed", 0),
        "threats_detected": q.get("threats", 0),
        "queue_size": q.get("queue_size", 0),
        "avg_processing_time": q.get("avg_wait_time", 0.0),
        "model_loaded": model is not None,
        "timestamp": datetime.now(),
    }


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


@app.get("/health/ready")
async def ready():
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")
    return {"status": "ready"}


if __name__ == "__main__":
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)