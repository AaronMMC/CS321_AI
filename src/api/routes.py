"""
Additional API route definitions.
Keeps main.py clean by splitting routes into logical groups.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from datetime import datetime
from loguru import logger

from src.api.dependencies import get_model, get_threat_hub, get_email_queue
from src.api.schemas import (
    EmailCheckRequest,
    EmailCheckResponse,
    FeedbackSchema,
    WhitelistEntrySchema,
    BlacklistEntrySchema,
)

# --- Routers ---
health_router = APIRouter(prefix="/health", tags=["Health"])
email_router = APIRouter(prefix="/api/v1", tags=["Email Analysis"])
admin_router = APIRouter(prefix="/api/v1/admin", tags=["Administration"])


# ---- Health ----------------------------------------------------------------

@health_router.get("/")
def health_check():
    """Simple liveness probe."""
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


@health_router.get("/ready")
def readiness_check(model=Depends(get_model)):
    """Readiness probe — confirms the model is loaded."""
    return {"status": "ready", "model": type(model).__name__}


# ---- Email analysis --------------------------------------------------------

@email_router.post("/analyze", response_model=EmailCheckResponse)
def analyze_email(
    request: EmailCheckRequest,
    model=Depends(get_model),
    threat_hub=Depends(get_threat_hub),
    queue=Depends(get_email_queue),
):
    """
    Analyze a single email and return a threat assessment.
    Alias for /check-email kept for backwards compatibility.
    """
    from src.gateway.email_parser import EmailParser

    parser = EmailParser()
    text = f"{request.subject} {request.body}"
    urls = request.urls or parser._extract_urls(request.body)

    # External intelligence
    external_score = 0.0
    if urls:
        features = threat_hub.get_features_for_model(text, urls)
        external_score = float(features[0]) if len(features) > 0 else 0.0

    # Model prediction
    prediction = model.predict(text)
    model_score = prediction.get("threat_score", 0.0) if isinstance(prediction, dict) else float(prediction)

    combined = model_score * 0.6 + external_score * 0.4

    explanations: List[str] = []
    if combined > 0.7:
        explanations.append("High overall threat score")
    if urls:
        explanations.append(f"Found {len(urls)} URL(s)")
    if external_score > 0.5:
        explanations.append("One or more URLs have poor reputation")
    if not explanations:
        explanations.append("No obvious threats detected")

    job_id = queue.enqueue({"subject": request.subject, "body": request.body})

    def _risk(s: float) -> str:
        if s >= 0.8:
            return "CRITICAL"
        if s >= 0.6:
            return "HIGH"
        if s >= 0.4:
            return "MEDIUM"
        if s >= 0.2:
            return "LOW"
        return "SAFE"

    return EmailCheckResponse(
        threat_score=combined,
        risk_level=_risk(combined),
        explanations=explanations,
        timestamp=datetime.now(),
        job_id=job_id,
    )


# ---- Administration --------------------------------------------------------

@admin_router.post("/whitelist")
def add_whitelist(entry: WhitelistEntrySchema):
    logger.info(f"Whitelist add: {entry.email or entry.domain}")
    return {"message": "Added to whitelist", "entry": entry.dict()}


@admin_router.delete("/whitelist/{identifier}")
def remove_whitelist(identifier: str):
    logger.info(f"Whitelist remove: {identifier}")
    return {"message": f"Removed {identifier} from whitelist"}


@admin_router.post("/blacklist")
def add_blacklist(entry: BlacklistEntrySchema):
    logger.info(f"Blacklist add: {entry.email or entry.domain}")
    return {"message": "Added to blacklist", "entry": entry.dict()}


@admin_router.delete("/blacklist/{identifier}")
def remove_blacklist(identifier: str):
    logger.info(f"Blacklist remove: {identifier}")
    return {"message": f"Removed {identifier} from blacklist"}


@admin_router.post("/feedback")
def submit_feedback(payload: FeedbackSchema):
    logger.info(f"Feedback for {payload.job_id}: is_threat={payload.is_threat}")
    return {"message": "Feedback received", "job_id": payload.job_id}