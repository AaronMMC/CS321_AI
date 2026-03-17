"""
Pydantic schemas for API request/response validation.
"""

from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import re


class EmailCheckRequest(BaseModel):
    """Request schema for checking a single email"""
    subject: str = Field(..., min_length=1, max_length=500)
    body: str = Field(..., min_length=1)
    from_email: Optional[EmailStr] = None
    to_email: Optional[EmailStr] = None
    urls: Optional[List[str]] = None

    @validator('subject')
    def subject_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Subject cannot be empty')
        return v.strip()

    @validator('body')
    def body_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Body cannot be empty')
        return v.strip()


class BatchCheckRequest(BaseModel):
    """Request schema for batch checking"""
    emails: List[EmailCheckRequest] = Field(..., max_items=100)
    priority: Optional[str] = Field("normal", regex="^(high|normal|low)$")


class EmailCheckResponse(BaseModel):
    """Response schema for email check"""
    threat_score: float = Field(..., ge=0, le=1, description="Threat score from 0 to 1")
    risk_level: str = Field(..., regex="^(SAFE|LOW|MEDIUM|HIGH|CRITICAL)$")
    explanations: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.now)
    job_id: Optional[str] = None
    processing_time_ms: Optional[float] = None


class AlertSchema(BaseModel):
    """Alert schema"""
    id: str
    timestamp: datetime
    threat_score: float = Field(..., ge=0, le=1)
    from_email: str
    to_email: str
    subject: str
    risk_level: str
    status: str = Field("new", regex="^(new|acknowledged|investigating|resolved|false_positive)$")
    urls: List[str] = Field(default_factory=list)
    attachments: List[Dict] = Field(default_factory=list)
    admin_notes: Optional[str] = None


class WhitelistEntrySchema(BaseModel):
    """Whitelist entry schema"""
    email: Optional[EmailStr] = None
    domain: Optional[str] = None
    reason: str = Field(..., min_length=3, max_length=200)
    added_by: str = Field(..., min_length=1)

    @validator('email', 'domain', always=True)
    def check_at_least_one(cls, v, values, **kwargs):
        if not values.get('email') and not v:
            raise ValueError('Either email or domain must be provided')
        return v

    @validator('domain')
    def validate_domain(cls, v):
        if v:
            # Simple domain validation
            pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
            if not re.match(pattern, v.lower()):
                raise ValueError('Invalid domain format')
        return v


class BlacklistEntrySchema(BaseModel):
    """Blacklist entry schema"""
    email: Optional[EmailStr] = None
    domain: Optional[str] = None
    reason: str = Field(..., min_length=3, max_length=200)
    added_by: str = Field(..., min_length=1)

    @validator('email', 'domain', always=True)
    def check_at_least_one(cls, v, values, **kwargs):
        if not values.get('email') and not v:
            raise ValueError('Either email or domain must be provided')
        return v


class FeedbackSchema(BaseModel):
    """Admin feedback schema"""
    job_id: str = Field(..., min_length=1)
    is_threat: bool
    admin_notes: Optional[str] = Field(None, max_length=500)
    action_taken: Optional[str] = Field(None, regex="^(quarantine|block|allow|investigate)$")


class StatsSchema(BaseModel):
    """System statistics schema"""
    emails_processed: int
    threats_detected: int
    queue_size: int
    avg_processing_time: float
    model_loaded: bool
    uptime_seconds: float
    alerts_today: int
    false_positive_rate: Optional[float]
    timestamp: datetime


class TrainingDataSchema(BaseModel):
    """Training data feedback schema"""
    email_text: str
    label: int = Field(..., ge=0, le=1)  # 0=legit, 1=phishing
    source: str = "admin_feedback"
    admin_id: str
    confidence: float = Field(1.0, ge=0, le=1)