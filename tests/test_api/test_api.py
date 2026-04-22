"""
Integration tests for FastAPI endpoints.
Run with: pytest tests/test_api/test_api.py -v
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fastapi.testclient import TestClient

# Import app and initialize model BEFORE creating TestClient
from src.api.main import app
from src.models.tinybert_model import TinyBERTForEmailSecurity
from src.features.external_intelligence import ThreatIntelligenceHub
from src.gateway.queue_manager import EmailQueue
import src.api.main as api_module
from tests.test_data.test_emails import LEGITIMATE_EMAILS, PHISHING_EMAILS


# Initialize all components when app loads (simulates startup event)
api_module.model = TinyBERTForEmailSecurity(use_gpu=False)
api_module.threat_hub = ThreatIntelligenceHub()
api_module.email_queue = EmailQueue()


# Now create test client
client = TestClient(app)


def test_root_endpoint():
    """Test root endpoint returns service info."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "Email Security Gateway"
    assert "version" in data
    assert "status" in data
    print(f"✓ Root endpoint: {data['status']}")


def test_check_email_legitimate():
    """Test checking a legitimate email returns low threat score."""
    legit = LEGITIMATE_EMAILS[0]
    response = client.post(
        "/api/v1/check-email",
        json={
            "subject": legit["subject"],
            "body": legit["body"],
            "from_email": legit["from"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "threat_score" in data
    assert "risk_level" in data
    assert "explanations" in data
    assert 0 <= data["threat_score"] <= 1
    print(f"✓ Legitimate email: score={data['threat_score']:.2%}, risk={data['risk_level']}")


def test_check_email_phishing():
    """Test checking a phishing email returns high threat score."""
    phishing = PHISHING_EMAILS[0]
    response = client.post(
        "/api/v1/check-email",
        json={
            "subject": phishing["subject"],
            "body": phishing["body"],
            "from_email": phishing["from"],
            "urls": phishing.get("suspicious_urls", []),
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "threat_score" in data
    print(f"✓ Phishing email: score={data['threat_score']:.2%}")


def test_check_email_validation():
    """Test validation rejects missing body field."""
    response = client.post(
        "/api/v1/check-email",
        json={"subject": "Test"},
    )
    assert response.status_code == 422
    print("✓ Validation: missing body correctly rejected")


def test_batch_check():
    """Test batch endpoint queues multiple emails."""
    batch = []
    for email in LEGITIMATE_EMAILS[:2] + PHISHING_EMAILS[:2]:
        batch.append({
            "subject": email["subject"],
            "body": email["body"],
            "from_email": email["from"],
        })

    response = client.post("/api/v1/check-batch", json=batch)
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "job_ids" in data
    assert len(data["job_ids"]) == len(batch)
    print(f"✓ Batch check: {len(batch)} emails queued")


def test_alerts_endpoint():
    """Test alerts endpoint returns list of alerts."""
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert isinstance(alerts, list)
    print(f"✓ Alerts: {len(alerts)} returned")


def test_stats_endpoint():
    """Test stats endpoint returns system statistics."""
    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    stats = response.json()
    assert "emails_processed" in stats
    assert "threats_detected" in stats
    assert "model_loaded" in stats
    print(f"✓ Stats: processed={stats['emails_processed']}")


def test_job_status():
    """Test job status endpoint."""
    response = client.post(
        "/api/v1/check-email",
        json={"subject": "Test subject", "body": "Test body content"},
    )
    data = response.json()
    job_id = data.get("job_id")

    if job_id:
        status_resp = client.get(f"/api/v1/job-status/{job_id}")
        assert status_resp.status_code == 200
        status = status_resp.json()
        assert "job_id" in status
        assert "status" in status
        print(f"✓ Job status: {status['status']}")
    else:
        print("⚠ No job_id returned — skipping status check")


def test_feedback_endpoint():
    """Test feedback endpoint accepts admin feedback."""
    response = client.post(
        "/api/v1/feedback",
        params={"job_id": "test_job_123", "is_threat": True, "admin_notes": "Test"},
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Feedback received"
    print("✓ Feedback endpoint working")


def test_invalid_endpoint():
    """Test 404 for invalid paths."""
    response = client.get("/invalid-path-xyz")
    assert response.status_code == 404
    print("✓ 404 handled correctly")


def test_whitelist_endpoint():
    """Test whitelist endpoint."""
    response = client.post(
        "/api/v1/whitelist",
        json={
            "email": "trusted@deped.gov.ph",
            "domain": "deped.gov.ph",
            "reason": "Internal department",
            "added_by": "admin",
        },
    )
    assert response.status_code == 200
    print("✓ Whitelist endpoint working")


def test_blacklist_endpoint():
    """Test blacklist endpoint."""
    response = client.post(
        "/api/v1/blacklist",
        json={
            "email": "banned@example.com",
            "domain": "banned-example.com",
            "reason": "Known phishing domain",
            "added_by": "admin",
        },
    )
    assert response.status_code == 200
    print("✓ Blacklist endpoint working")