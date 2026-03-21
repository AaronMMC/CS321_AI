"""
Integration tests for FastAPI endpoints.
Run with: pytest tests/test_api.py -v
"""

import pytest
import sys
from pathlib import Path
import httpx
import asyncio

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from src.api.main import app
from tests.test_data.test_emails import LEGITIMATE_EMAILS, PHISHING_EMAILS


class TestAPI:
    """Test FastAPI endpoints"""

    @pytest.fixture
    async def client(self):
        """Create async test client"""
        async with httpx.AsyncClient(app=app, base_url="http://test") as client:
            yield client

    @pytest.mark.asyncio
    async def test_root_endpoint(self, client):
        """Test root endpoint"""
        response = await client.get("/")
        assert response.status_code == 200

        data = response.json()
        assert data['service'] == "Email Security Gateway"
        assert 'version' in data
        assert 'status' in data
        print(f"✓ Root endpoint: {data['status']}")

    @pytest.mark.asyncio
    async def test_check_email_legitimate(self, client):
        """Test legitimate email check"""
        legit = LEGITIMATE_EMAILS[0]

        response = await client.post(
            "/api/v1/check-email",
            json={
                "subject": legit['subject'],
                "body": legit['body'],
                "from_email": legit['from']
            }
        )

        assert response.status_code == 200

        data = response.json()
        assert 'threat_score' in data
        assert 'risk_level' in data
        assert 'explanations' in data
        assert 0 <= data['threat_score'] <= 1

        print(f"✓ Legitimate email check: score={data['threat_score']:.2%}, risk={data['risk_level']}")

    @pytest.mark.asyncio
    async def test_check_email_phishing(self, client):
        """Test phishing email check"""
        phishing = PHISHING_EMAILS[0]

        response = await client.post(
            "/api/v1/check-email",
            json={
                "subject": phishing['subject'],
                "body": phishing['body'],
                "from_email": phishing['from'],
                "urls": phishing.get('suspicious_urls', [])
            }
        )

        assert response.status_code == 200

        data = response.json()
        assert 'threat_score' in data

        print(f"✓ Phishing email check: score={data['threat_score']:.2%}")

    @pytest.mark.asyncio
    async def test_check_email_validation(self, client):
        """Test email validation"""
        # Empty subject
        response = await client.post(
            "/api/v1/check-email",
            json={
                "subject": "",
                "body": "Some body"
            }
        )
        assert response.status_code == 422  # Validation error

        # Empty body
        response = await client.post(
            "/api/v1/check-email",
            json={
                "subject": "Test",
                "body": ""
            }
        )
        assert response.status_code == 422

        print("✓ Validation working correctly")

    @pytest.mark.asyncio
    async def test_batch_check(self, client):
        """Test batch email checking"""
        batch_emails = []
        for email in LEGITIMATE_EMAILS[:2] + PHISHING_EMAILS[:2]:
            batch_emails.append({
                "subject": email['subject'],
                "body": email['body'],
                "from_email": email['from']
            })

        response = await client.post(
            "/api/v1/check-batch",
            json={"emails": batch_emails}
        )

        assert response.status_code == 200

        data = response.json()
        assert 'message' in data
        assert 'job_ids' in data
        assert len(data['job_ids']) == len(batch_emails)

        print(f"✓ Batch check: {len(batch_emails)} emails queued")

    @pytest.mark.asyncio
    async def test_alerts_endpoint(self, client):
        """Test alerts endpoint"""
        response = await client.get("/api/v1/alerts")
        assert response.status_code == 200

        alerts = response.json()
        assert isinstance(alerts, list)

        print(f"✓ Alerts endpoint: {len(alerts)} alerts returned")

    @pytest.mark.asyncio
    async def test_stats_endpoint(self, client):
        """Test stats endpoint"""
        response = await client.get("/api/v1/stats")
        assert response.status_code == 200

        stats = response.json()
        assert 'emails_processed' in stats
        assert 'threats_detected' in stats
        assert 'model_loaded' in stats

        print(f"✓ Stats endpoint: processed={stats['emails_processed']}")

    @pytest.mark.asyncio
    async def test_job_status(self, client):
        """Test job status endpoint"""
        # First create a job
        response = await client.post(
            "/api/v1/check-email",
            json={
                "subject": "Test",
                "body": "Test content"
            }
        )

        data = response.json()
        job_id = data.get('job_id')

        if job_id:
            # Check status
            response = await client.get(f"/api/v1/job-status/{job_id}")
            assert response.status_code == 200

            status = response.json()
            assert 'job_id' in status
            assert 'status' in status

            print(f"✓ Job status: {status['status']}")
        else:
            print("⚠ No job_id returned")

    @pytest.mark.asyncio
    async def test_feedback_endpoint(self, client):
        """Test feedback endpoint"""
        response = await client.post(
            "/api/v1/feedback",
            json={
                "job_id": "test_job_123",
                "is_threat": True,
                "admin_notes": "Test feedback"
            }
        )

        assert response.status_code == 200

        data = response.json()
        assert data['message'] == "Feedback received"

        print("✓ Feedback endpoint working")


class TestAPIErrorHandling:
    """Test API error handling"""

    @pytest.fixture
    async def client(self):
        async with httpx.AsyncClient(app=app, base_url="http://test") as client:
            yield client

    @pytest.mark.asyncio
    async def test_invalid_endpoint(self, client):
        """Test invalid endpoint"""
        response = await client.get("/invalid")
        assert response.status_code == 404
        print("✓ 404 handled correctly")

    @pytest.mark.asyncio
    async def test_missing_fields(self, client):
        """Test missing required fields"""
        response = await client.post(
            "/api/v1/check-email",
            json={"subject": "Only subject"}
        )
        assert response.status_code == 422

        print("✓ Missing fields validation working")

    @pytest.mark.asyncio
    async def test_invalid_json(self, client):
        """Test invalid JSON"""
        response = await client.post(
            "/api/v1/check-email",
            content="not json"
        )
        assert response.status_code == 422

        print("✓ Invalid JSON handling working")


async def run_api_tests():
    """Run API tests manually"""
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