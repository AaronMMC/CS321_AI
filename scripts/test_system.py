#!/usr/bin/env python3
"""
End-to-end system test for Email Security Gateway.
Tests all components working together.
"""

import sys
import time
import requests
import asyncio
from pathlib import Path
from datetime import datetime
from loguru import logger

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

# Configure logger
logger.add(sys.stdout, level="INFO")

API_BASE_URL = "http://localhost:8000/api/v1"
DASHBOARD_URL = "http://localhost:8501"
GATEWAY_PORT = 10025


def test_api():
    """Test API endpoints"""
    logger.info("=" * 50)
    logger.info("TESTING API")
    logger.info("=" * 50)

    # Test root
    try:
        response = requests.get("http://localhost:8000/", timeout=5)
        if response.status_code == 200:
            logger.success("✓ API root endpoint accessible")
        else:
            logger.error(f"✗ API root failed: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"✗ API not reachable: {e}")
        return False

    # Test check email
    test_email = {
        "subject": "URGENT: Account Verification Required",
        "body": "Click here to verify: http://bit.ly/verify",
        "from_email": "support@phishing.net"
    }

    try:
        response = requests.post(
            f"{API_BASE_URL}/check-email",
            json=test_email,
            timeout=10
        )

        if response.status_code == 200:
            result = response.json()
            logger.success(f"✓ Email check working: threat_score={result.get('threat_score', 'N/A')}")
        else:
            logger.error(f"✗ Email check failed: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"✗ Email check error: {e}")
        return False

    # Test alerts
    try:
        response = requests.get(f"{API_BASE_URL}/alerts", timeout=5)
        if response.status_code == 200:
            alerts = response.json()
            logger.success(f"✓ Alerts endpoint working: {len(alerts)} alerts")
        else:
            logger.error(f"✗ Alerts failed: {response.status_code}")
    except Exception as e:
        logger.error(f"✗ Alerts error: {e}")

    # Test stats
    try:
        response = requests.get(f"{API_BASE_URL}/stats", timeout=5)
        if response.status_code == 200:
            stats = response.json()
            logger.success(f"✓ Stats endpoint working: processed={stats.get('emails_processed', 0)}")
        else:
            logger.error(f"✗ Stats failed: {response.status_code}")
    except Exception as e:
        logger.error(f"✗ Stats error: {e}")

    return True


def test_dashboard():
    """Test dashboard accessibility"""
    logger.info("\n" + "=" * 50)
    logger.info("TESTING DASHBOARD")
    logger.info("=" * 50)

    try:
        response = requests.get(DASHBOARD_URL, timeout=5)
        if response.status_code == 200:
            logger.success("✓ Dashboard accessible")
            return True
        else:
            logger.error(f"✗ Dashboard not accessible: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"✗ Dashboard not reachable: {e}")
        return False


def test_model():
    """Test model loading and prediction"""
    logger.info("\n" + "=" * 50)
    logger.info("TESTING MODEL")
    logger.info("=" * 50)

    try:
        from src.models.tinybert_model import TinyBERTForEmailSecurity

        logger.info("Loading model...")
        model = TinyBERTForEmailSecurity(use_gpu=False)
        logger.success("✓ Model loaded")

        # Test legitimate email
        legit_text = "Meeting agenda for tomorrow at 10am"
        result = model.predict(legit_text)
        score = result['threat_score'] if isinstance(result, dict) else result

        if score < 0.4:
            logger.success(f"✓ Legitimate email correctly scored: {score:.2%}")
        else:
            logger.warning(f"⚠ Legitimate email got high score: {score:.2%}")

        # Test phishing email
        phish_text = "URGENT: Your account will be suspended! Click here to verify"
        result = model.predict(phish_text)
        score = result['threat_score'] if isinstance(result, dict) else result

        if score > 0.4:
            logger.success(f"✓ Phishing email detected: {score:.2%}")
        else:
            logger.warning(f"⚠ Phishing email got low score: {score:.2%}")

        return True

    except Exception as e:
        logger.error(f"✗ Model test failed: {e}")
        return False


def test_gateway():
    """Test gateway port is listening"""
    logger.info("\n" + "=" * 50)
    logger.info("TESTING GATEWAY")
    logger.info("=" * 50)

    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', GATEWAY_PORT))
        sock.close()

        if result == 0:
            logger.success(f"✓ Gateway listening on port {GATEWAY_PORT}")
            return True
        else:
            logger.warning(f"⚠ Gateway not listening on port {GATEWAY_PORT}")
            return False
    except Exception as e:
        logger.error(f"✗ Gateway test failed: {e}")
        return False


def test_threat_intelligence():
    """Test threat intelligence integration"""
    logger.info("\n" + "=" * 50)
    logger.info("TESTING THREAT INTELLIGENCE")
    logger.info("=" * 50)

    try:
        from src.features.external_intelligence import ThreatIntelligenceHub

        threat_hub = ThreatIntelligenceHub()
        logger.success("✓ Threat Intelligence Hub initialized")

        # Test URL reputation
        test_url = "http://bit.ly/test-phishing"
        vt_result = threat_hub.vt.check_url(test_url)
        logger.info(f"  VirusTotal score: {vt_result.get('score', 0):.2%}")

        # Test WHOIS
        test_domain = "deped.gov.ph"
        whois_result = threat_hub.whois.check_domain(test_domain)
        logger.info(f"  WHOIS: {test_domain} - age: {whois_result.get('age_days', 'unknown')} days")

        return True

    except Exception as e:
        logger.error(f"✗ Threat intelligence test failed: {e}")
        return False


def run_all_tests():
    """Run all system tests"""
    logger.info("\n" + "=" * 50)
    logger.info("EMAIL SECURITY GATEWAY - SYSTEM TEST")
    logger.info("=" * 50)
    logger.info(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    results = {}

    # Run tests
    results['api'] = test_api()
    results['dashboard'] = test_dashboard()
    results['model'] = test_model()
    results['gateway'] = test_gateway()
    results['threat_intel'] = test_threat_intelligence()

    # Summary
    logger.info("\n" + "=" * 50)
    logger.info("TEST SUMMARY")
    logger.info("=" * 50)

    all_passed = True
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        logger.info(f"  {test_name.upper()}: {status}")
        if not passed:
            all_passed = False

    logger.info("=" * 50)

    if all_passed:
        logger.success("\n✅ All tests passed! System is ready.")
        return 0
    else:
        logger.error("\n❌ Some tests failed. Please check the logs.")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())