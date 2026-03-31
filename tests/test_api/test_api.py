"""
Integration tests for FastAPI endpoints.
Run with: pytest tests/test_api/test_api.py -v
"""

import pytest
import sys
from pathlib import Path
import httpx
import asyncio

sys.path.append(str(Path(__file__).parent.parent.parent))

from src.api.main import app
from tests.test_data.test_emails import LEGITIMATE_EMAILS, PHISHING_EMAILS


class TestAPI:
    """Test FastAPI endpoints."""

    @pytest.fixture
    async def client(self):
        async with httpx.AsyncClient(app=app, base_url="http://test") as client:
            yield client

    @pytest.mark.asyncio
    async def test_root_endpoint(self, client):
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "Email Security Gateway"
        assert "version" in data
        assert "status" in data
        print(f"✓ Root endpoint: {data['status']}")

    @pytest.mark.asyncio
    async def test_check_email_legitimate(self, client):
        legit = LEGITIMATE_EMAILS[0]
        response = await client.post(
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

    @pytest.mark.asyncio
    async def test_check_email_phishing(self, client):
        phishing = PHISHING_EMAILS[0]
        response = await client.post(
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

    @pytest.mark.asyncio
    async def test_check_email_validation(self, client):
        # Missing body → validation error
        response = await client.post(
            "/api/v1/check-email",
            json={"subject": "Test"},
        )
        assert response.status_code == 422
        print("✓ Validation: missing body correctly rejected")

    @pytest.mark.asyncio
    async def test_batch_check(self, client):
        """Test batch endpoint — payload is a list of email objects."""
        batch = []
        for email in LEGITIMATE_EMAILS[:2] + PHISHING_EMAILS[:2]:
            batch.append({
                "subject": email["subject"],
                "body": email["body"],
                "from_email": email["from"],
            })

        # /api/v1/check-batch expects a JSON array (List[EmailCheckRequest])
        response = await client.post("/api/v1/check-batch", json=batch)
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "job_ids" in data
        assert len(data["job_ids"]) == len(batch)
        print(f"✓ Batch check: {len(batch)} emails queued")

    @pytest.mark.asyncio
    async def test_alerts_endpoint(self, client):
        response = await client.get("/api/v1/alerts")
        assert response.status_code == 200
        alerts = response.json()
        assert isinstance(alerts, list)
        print(f"✓ Alerts: {len(alerts)} returned")

    @pytest.mark.asyncio
    async def test_stats_endpoint(self, client):
        response = await client.get("/api/v1/stats")
        assert response.status_code == 200
        stats = response.json()
        assert "emails_processed" in stats
        assert "threats_detected" in stats
        assert "model_loaded" in stats
        print(f"✓ Stats: processed={stats['emails_processed']}")

    @pytest.mark.asyncio
    async def test_job_status(self, client):
        # Create a job first
        response = await client.post(
            "/api/v1/check-email",
            json={"subject": "Test subject", "body": "Test body content"},
        )
        data = response.json()
        job_id = data.get("job_id")

        if job_id:
            status_resp = await client.get(f"/api/v1/job-status/{job_id}")
            assert status_resp.status_code == 200
            status = status_resp.json()
            assert "job_id" in status
            assert "status" in status
            print(f"✓ Job status: {status['status']}")
        else:
            print("⚠ No job_id returned — skipping status check")

    @pytest.mark.asyncio
    async def test_feedback_endpoint(self, client):
        response = await client.post(
            "/api/v1/feedback",
            params={"job_id": "test_job_123", "is_threat": True, "admin_notes": "Test"},
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Feedback received"
        print("✓ Feedback endpoint working")


class TestAPIErrorHandling:
    """Test API error handling."""

    @pytest.fixture
    async def client(self):
        async with httpx.AsyncClient(app=app, base_url="http://test") as client:
            yield client

    @pytest.mark.asyncio
    async def test_invalid_endpoint(self, client):
        response = await client.get("/invalid-path-xyz")
        assert response.status_code == 404
        print("✓ 404 handled correctly")

    @pytest.mark.asyncio
    async def test_missing_fields(self, client):
        response = await client.post(
            "/api/v1/check-email",
            json={"subject": "Only subject"},
        )
        assert response.status_code == 422
        print("✓ Missing fields validation working")

    @pytest.mark.asyncio
    async def test_invalid_json(self, client):
        response = await client.post(
            "/api/v1/check-email",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 422
        print("✓ Invalid JSON handling working")


async def run_api_tests():
    """Run API tests manually (without pytest)."""
    print("\n" + "=" * 50)
    print("RUNNING API TESTS")
    print("=" * 50)

    test_api = TestAPI()
    test_errors = TestAPIErrorHandling()

    async with httpx.AsyncClient(app=app, base_url="http://test") as client:
        await test_api.test_root_endpoint(client)
        await test_api.test_check_email_legitimate(client)
        await test_api.test_check_email_phishing(client)
        await test_api.test_check_email_validation(client)
        await test_api.test_alerts_endpoint(client)
        await test_api.test_stats_endpoint(client)
        await test_errors.test_invalid_endpoint(client)

    print("\n" + "=" * 50)
    print("API TESTS COMPLETED")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(run_api_tests())