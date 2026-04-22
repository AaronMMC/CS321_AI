"""
Main FastAPI application for the Email Security Gateway.
Provides REST API endpoints for dashboard and external integration.
"""

import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uvicorn
from loguru import logger
import asyncio
import time

# Load environment variables
load_dotenv()

from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.features.external_intelligence import ThreatIntelligenceHub
from src.gateway.email_parser import EmailParser
from src.gateway.queue_manager import EmailQueue, AsyncProcessor
from src.utils.config import settings

# Initialize FastAPI
app = FastAPI(
    title="Email Security Gateway API",
    description="AI-Powered Email Security for Philippine Government",
    version="1.0.0"
)

# ============================================
# SECURITY: Configure CORS from environment
# ============================================
def get_cors_origins():
    """Get CORS allowed origins from environment variable"""
    cors_config = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:8501,http://localhost:8000")
    origins = [o.strip() for o in cors_config.split(",") if o.strip()]
    return origins

cors_origins = get_cors_origins()
logger.info(f"Configuring CORS for origins: {cors_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# SECURITY: Simple rate limiting for API endpoints
# ============================================
from collections import defaultdict
from datetime import datetime, timedelta

_rate_limit_storage = defaultdict(list)

def check_rate_limit(request: Request, requests_per_minute: int = 100) -> bool:
    """
    Simple rate limiting check.
    Returns True if request is allowed, raises HTTPException if rate limited.
    """
    # Skip if not enabled
    if os.getenv("RATE_LIMIT_ENABLED", "false").lower() != "true":
        return True

    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    current_time = datetime.now()

    # Clean old requests (older than 1 minute)
    _rate_limit_storage[client_ip] = [
        t for t in _rate_limit_storage[client_ip]
        if current_time - t < timedelta(minutes=1)
    ]

    # Check limit
    if len(_rate_limit_storage[client_ip]) >= requests_per_minute:
        logger.warning(f"Rate limit exceeded for {client_ip}")
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please try again later."
        )

    # Record this request
    _rate_limit_storage[client_ip].append(current_time)
    return True

# Global components
model = None
threat_hub = None
email_queue = None
processor = None
email_parser = EmailParser()


# Pydantic models for request/response
class EmailCheckRequest(BaseModel):
    """Request model for checking a single email"""
    subject: str
    body: str
    from_email: Optional[str] = None
    to_email: Optional[str] = None
    urls: Optional[List[str]] = None


class EmailCheckResponse(BaseModel):
    """Response model for email check"""
    threat_score: float = Field(..., ge=0, le=1)
    risk_level: str
    explanations: List[str]
    timestamp: datetime
    job_id: Optional[str] = None


class AlertResponse(BaseModel):
    """Alert information"""
    id: str
    timestamp: datetime
    threat_score: float
    from_email: str
    to_email: str
    subject: str
    risk_level: str
    status: str = "new"  # new, acknowledged, resolved


class WhitelistEntry(BaseModel):
    """Whitelist entry for trusted senders"""
    email: Optional[str] = None
    domain: Optional[str] = None
    reason: str = "manually added"
    added_by: str = "admin"
    timestamp: Optional[datetime] = None


class BlacklistEntry(BaseModel):
    """Blacklist entry for blocked senders"""
    email: Optional[str] = None
    domain: Optional[str] = None
    reason: str = "manually added"
    added_by: str = "admin"
    timestamp: Optional[datetime] = None


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize components on startup"""
    global model, threat_hub, email_queue, processor

    logger.info("Starting Email Security Gateway API...")

    # Load model
    try:
        model = TinyBERTForEmailSecurity()
        logger.info("Model loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        model = None

    # Initialize threat hub
    threat_hub = ThreatIntelligenceHub()

    # Initialize queue
    email_queue = EmailQueue()

    # Start processor if model loaded
    if model:
        processor = AsyncProcessor(email_queue, model, threat_hub, num_workers=2)
        asyncio.create_task(processor.start())
        logger.info("Processor started")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Clean shutdown"""
    global processor

    logger.info("Shutting down API...")
    if processor:
        await processor.stop()


# API Endpoints
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Email Security Gateway",
        "version": "1.0.0",
        "status": "operational",
        "model_loaded": model is not None
    }


@app.post("/api/v1/check-email", response_model=EmailCheckResponse)
async def check_email(request: EmailCheckRequest, http_request: Request, background_tasks: BackgroundTasks):
    """
    Check a single email for phishing threats.
    """
    # Apply rate limiting
    rate_limit = int(os.getenv("RATE_LIMIT_PER_MINUTE", "100"))
    check_rate_limit(http_request, rate_limit)

    # Log the request
    client_ip = http_request.client.host if http_request.client else "unknown"
    logger.info(f"Email check request from {client_ip}: subject='{request.subject[:50]}...'")

    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        # Prepare text for analysis
        text_to_analyze = f"{request.subject} {request.body}"

        # Get URLs from request or extract from body
        urls = request.urls or email_parser._extract_urls(request.body)

        # Get external intelligence
        external_score = 0
        if urls and threat_hub:
            features = threat_hub.get_features_for_model(text_to_analyze, urls)
            external_score = float(features[0]) if len(features) > 0 else 0

        # Get model prediction
        prediction = model.predict(text_to_analyze)
        if isinstance(prediction, dict):
            model_score = prediction.get('threat_score', 0)
        else:
            model_score = prediction

        # Combine scores (60% model, 40% external)
        combined_score = (model_score * 0.6) + (external_score * 0.4)

        # Generate explanations
        explanations = []
        if combined_score > 0.7:
            explanations.append("High threat score detected")
        if urls:
            explanations.append(f"Found {len(urls)} URL(s) in email")
        if external_score > 0.5:
            explanations.append("URLs have poor reputation")
        if "urgent" in request.subject.lower() or "verify" in request.subject.lower():
            explanations.append("Subject contains urgency/verification keywords")

        # Add to background processing queue
        job_id = email_queue.enqueue({
            "subject": request.subject,
            "body": request.body,
            "from": request.from_email,
            "to": request.to_email
        })

        return EmailCheckResponse(
            threat_score=combined_score,
            risk_level=_get_risk_level(combined_score),
            explanations=explanations or ["No obvious threats detected"],
            timestamp=datetime.now(),
            job_id=job_id
        )

    except Exception as e:
        logger.error(f"Error checking email: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/check-batch")
async def check_batch(emails: List[EmailCheckRequest], http_request: Request, background_tasks: BackgroundTasks):
    """
    Check multiple emails in batch.
    """
    # Apply rate limiting
    rate_limit = int(os.getenv("RATE_LIMIT_PER_MINUTE", "100"))
    check_rate_limit(http_request, rate_limit)

    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")

    job_ids = []
    for email in emails:
        job_id = email_queue.enqueue({
            "subject": email.subject,
            "body": email.body,
            "from": email.from_email,
            "to": email.to_email
        })
        job_ids.append(job_id)

    return {
        "message": f"Queued {len(job_ids)} emails for processing",
        "job_ids": job_ids,
        "check_status_url": "/api/v1/job-status/{job_id}"
    }


@app.get("/api/v1/job-status/{job_id}")
async def get_job_status(job_id: str):
    """
    Get status of a processing job.
    """
    if not email_queue:
        raise HTTPException(status_code=503, detail="Queue not initialized")

    status = email_queue.get_status(job_id)
    if not status:
        raise HTTPException(status_code=404, detail="Job not found")

    return status


@app.get("/api/v1/alerts", response_model=List[AlertResponse])
async def get_alerts(status: Optional[str] = None, limit: int = 50):
    """
    Get recent alerts.
    """
    # This would come from database in production
    # For now, return mock data
    mock_alerts = [
        {
            "id": "alert_001",
            "timestamp": datetime.now(),
            "threat_score": 0.94,
            "from_email": "support@gcash-verify.net",
            "to_email": "employee@deped.gov.ph",
            "subject": "URGENT: Account verification needed",
            "risk_level": "CRITICAL",
            "status": "new"
        },
        {
            "id": "alert_002",
            "timestamp": datetime.now(),
            "threat_score": 0.67,
            "from_email": "hr@company-ph.com",
            "to_email": "staff@dict.gov.ph",
            "subject": "Update your payroll information",
            "risk_level": "HIGH",
            "status": "acknowledged"
        }
    ]

    if status:
        mock_alerts = [a for a in mock_alerts if a["status"] == status]

    return mock_alerts[:limit]


@app.post("/api/v1/whitelist")
async def add_to_whitelist(entry: WhitelistEntry):
    """
    Add email/domain to whitelist.
    """
    # In production, store in database
    logger.info(f"Added to whitelist: {entry.email or entry.domain}")
    return {"message": "Added to whitelist", "entry": entry}


@app.delete("/api/v1/whitelist/{identifier}")
async def remove_from_whitelist(identifier: str):
    """
    Remove email/domain from whitelist.
    """
    logger.info(f"Removed from whitelist: {identifier}")
    return {"message": f"Removed {identifier} from whitelist"}


@app.post("/api/v1/blacklist")
async def add_to_blacklist(entry: BlacklistEntry):
    """
    Add email/domain to blacklist.
    """
    # In production, store in database
    logger.info(f"Added to blacklist: {entry.email or entry.domain}")
    return {"message": "Added to blacklist", "entry": entry}


@app.delete("/api/v1/blacklist/{identifier}")
async def remove_from_blacklist(identifier: str):
    """
    Remove email/domain from blacklist.
    """
    logger.info(f"Removed from blacklist: {identifier}")
    return {"message": f"Removed {identifier} from blacklist"}


@app.get("/api/v1/stats")
async def get_stats():
    """
    Get system statistics.
    """
    queue_stats = email_queue.get_stats() if email_queue else {}

    return {
        "emails_processed": queue_stats.get('processed', 0),
        "threats_detected": queue_stats.get('threats', 0),
        "queue_size": queue_stats.get('queue_size', 0),
        "avg_processing_time": queue_stats.get('avg_wait_time', 0),
        "model_loaded": model is not None,
        "timestamp": datetime.now()
    }


@app.post("/api/v1/feedback")
async def submit_feedback(job_id: str, is_threat: bool, admin_notes: Optional[str] = None):
    """
    Submit admin feedback for human-in-the-loop learning.
    """
    # In production, store feedback for model retraining
    logger.info(f"Feedback for {job_id}: is_threat={is_threat}, notes={admin_notes}")

    # Here you would update a feedback database and potentially trigger retraining

    return {"message": "Feedback received", "job_id": job_id}


def _get_risk_level(score: float) -> str:
    """Convert score to risk level"""
    if score >= 0.8:
        return "CRITICAL"
    elif score >= 0.6:
        return "HIGH"
    elif score >= 0.4:
        return "MEDIUM"
    elif score >= 0.2:
        return "LOW"
    else:
        return "SAFE"


# Run the application
if __name__ == "__main__":
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )