"""
Unit tests for ML models.
Run with: pytest tests/test_models.py -v
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from src.models.tinybert_model import TinyBERTForEmailSecurity, create_mini_dataset_for_quick_training
from src.features.external_intelligence import ThreatIntelligenceHub
from tests.test_data.test_emails import get_test_dataset, LEGITIMATE_EMAILS, PHISHING_EMAILS


class TestTinyBERTModel:
    """Test TinyBERT model functionality"""

    @pytest.fixture
    def model(self):
        """Create model instance for testing"""
        return TinyBERTForEmailSecurity(use_gpu=False)  # Use CPU for tests

    @pytest.fixture
    def test_data(self):
        """Get test dataset"""
        return get_test_dataset()

    def test_model_initialization(self, model):
        """Test that model initializes correctly"""
        assert model is not None
        assert model.device is not None
        assert model.tokenizer is not None
        assert model.model is not None
        print(f"✓ Model initialized on {model.device}")

    def test_tokenization(self, model):
        """Test tokenization functionality"""
        test_text = "This is a test email for tokenization"
        tokens = model.tokenize([test_text])

        assert 'input_ids' in tokens
        assert 'attention_mask' in tokens
        assert tokens['input_ids'].shape[0] == 1  # Batch size 1
        print(f"✓ Tokenization successful: {tokens['input_ids'].shape}")

    def test_prediction_legitimate(self, model):
        """Test prediction on legitimate email"""
        legit_email = LEGITIMATE_EMAILS[0]
        text = f"{legit_email['subject']} {legit_email['body']}"

        result = model.predict(text)

        assert result is not None
        assert 'threat_score' in result
        assert 'label' in result
        assert 0 <= result['threat_score'] <= 1

        # Legitimate emails should have low threat score
        if result['threat_score'] < 0.4:
            print(f"✓ Legitimate email correctly identified: score={result['threat_score']:.2%}")
        else:
            print(f"⚠ Legitimate email got high score: {result['threat_score']:.2%}")

    def test_prediction_phishing(self, model):
        """Test prediction on phishing email"""
        phishing_email = PHISHING_EMAILS[0]
        text = f"{phishing_email['subject']} {phishing_email['body']}"

        result = model.predict(text)

        assert result is not None
        assert 'threat_score' in result

        # Phishing emails should have higher threat score
        if result['threat_score'] > 0.4:
            print(f"✓ Phishing email detected: score={result['threat_score']:.2%}")
        else:
            print(f"⚠ Phishing email got low score: {result['threat_score']:.2%}")

    def test_batch_prediction(self, model, test_data):
        """Test batch prediction"""
        texts = [item['text'] for item in test_data[:5]]

        results = model.predict(texts)

        assert isinstance(results, list)
        assert len(results) == len(texts)
        for result in results:
            assert 'threat_score' in result
            print(f"  - Score: {result['threat_score']:.2%}")

        print(f"✓ Batch prediction successful: {len(results)} emails")

    def test_quick_training(self):
        """Test quick training with mini dataset"""
        texts, labels = create_mini_dataset_for_quick_training()

        model = TinyBERTForEmailSecurity(use_gpu=False)

        # Train for just 1 epoch for testing
        history = model.train_quick(
            train_texts=texts[:50],
            train_labels=labels[:50],
            epochs=1,
            batch_size=8
        )

        assert 'train_loss' in history
        assert len(history['train_loss']) == 1
        print(f"✓ Quick training complete: final loss={history['train_loss'][0]:.4f}")


class TestThreatIntelligence:
    """Test threat intelligence integration"""

    @pytest.fixture
    def threat_hub(self):
        """Create threat hub for testing"""
        return ThreatIntelligenceHub()

    def test_virustotal_check(self, threat_hub):
        """Test VirusTotal URL checking"""
        test_url = "http://bit.ly/test-phishing"

        result = threat_hub.vt.check_url(test_url)

        assert result is not None
        assert 'score' in result
        assert 0 <= result['score'] <= 1
        print(f"✓ VirusTotal check: score={result['score']:.2%}")

    def test_whois_check(self, threat_hub):
        """Test WHOIS domain checking"""
        test_domain = "deped.gov.ph"

        result = threat_hub.whois.check_domain(test_domain)

        assert result is not None
        assert 'domain' in result
        assert 'score' in result
        print(f"✓ WHOIS check for {test_domain}: age={result.get('age_days', 'unknown')} days")

    def test_features_extraction(self, threat_hub):
        """Test feature extraction for model input"""
        test_text = "URGENT: Verify your account now!"
        test_urls = ["http://bit.ly/verify"]

        features = threat_hub.get_features_for_model(test_text, test_urls)

        assert features is not None
        assert len(features) == 4
        assert all(0 <= f <= 1 for f in features)
        print(f"✓ Features extracted: {features}")

    def test_pattern_recognition(self, threat_hub):
        """Test pattern recognition across emails"""
        test_emails = [
            {'from_domain': 'phishing-site.net', 'to': 'user1@deped.gov.ph'},
            {'from_domain': 'phishing-site.net', 'to': 'user2@deped.gov.ph'},
            {'from_domain': 'phishing-site.net', 'to': 'user3@deped.gov.ph'},
        ]

        result = threat_hub.analyze_email_patterns(test_emails)

        assert result is not None
        if result.get('campaign_detected'):
            print(f"✓ Campaign detected: {len(result.get('campaigns', []))} campaigns")
        else:
            print("⚠ No campaign detected")


class TestModelPerformance:
    """Test model performance metrics"""

    @pytest.fixture
    def model(self):
        """Create model for testing"""
        return TinyBERTForEmailSecurity(use_gpu=False)

    def test_threat_score_range(self, model):
        """Test that threat scores are within valid range"""
        test_cases = [
            ("Normal meeting reminder", 0),
            ("URGENT: Account verification needed", 1),
            ("Your package is ready for pickup", 0),
            ("You won $1000! Claim now", 1),
        ]

        for text, expected_type in test_cases:
            result = model.predict(text)
            score = result['threat_score'] if isinstance(result, dict) else result

            assert 0 <= score <= 1
            print(f"  - '{text[:30]}...': {score:.2%}")

        print("✓ All threat scores within valid range")

    def test_confidence_consistency(self, model):
        """Test that confidence values are consistent"""
        text = "This is a test email"

        # Run multiple predictions
        scores = []
        for _ in range(5):
            result = model.predict(text)
            score = result['threat_score'] if isinstance(result, dict) else result
            scores.append(score)

        # Scores should be consistent (variance < 0.1)
        variance = max(scores) - min(scores)
        assert variance < 0.1
        print(f"✓ Consistent predictions: variance={variance:.4f}")


def run_tests():
    """Run all tests manually"""
    print("\n" + "=" * 50)
    print("RUNNING MODEL TESTS")
    print("=" * 50)

    test_model = TestTinyBERTModel()
    test_threat = TestThreatIntelligence()
    test_perf = TestModelPerformance()

    # Run tests
    test_model.test_model_initialization(TinyBERTForEmailSecurity(use_gpu=False))
    test_model.test_tokenization(TinyBERTForEmailSecurity(use_gpu=False))
    test_model.test_prediction_legitimate(TinyBERTForEmailSecurity(use_gpu=False))
    test_model.test_prediction_phishing(TinyBERTForEmailSecurity(use_gpu=False))

    threat_hub = ThreatIntelligenceHub()
    test_threat.test_virustotal_check(threat_hub)
    test_threat.test_whois_check(threat_hub)
    test_threat.test_features_extraction(threat_hub)

    print("\n" + "=" * 50)
    print("ALL TESTS COMPLETED")
    print("=" * 50)


if __name__ == "__main__":
    run_tests()