"""
Unit tests for Email Warning Injection module.
Run with: pytest tests/test_features/test_warning_injection.py -v
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.features.warning_injection import EmailWarningInjector, WarningLevel


class TestEmailWarningInjector:
    """Test email warning injection functionality."""

    @pytest.fixture
    def injector(self):
        """Create warning injector instance."""
        return EmailWarningInjector()

    @pytest.fixture
    def legitimate_email(self):
        """Sample legitimate email."""
        return {
            'from': 'john.doe@deped.gov.ph',
            'to': 'maria.santos@deped.gov.ph',
            'subject': 'Meeting Agenda for Tomorrow',
            'body': 'Hi Team,\n\nPlease find attached the agenda.',
            'headers': {}
        }

    @pytest.fixture
    def suspicious_email(self):
        """Sample suspicious email."""
        return {
            'from': 'support@gcash-verify.net',
            'to': 'employee@deped.gov.ph',
            'subject': 'URGENT: Your GCash Account Will Be Suspended',
            'body': 'Click here to verify: http://bit.ly/gcash-verify',
            'headers': {},
            'threat_score': 0.85,
            'risk_level': 'CRITICAL',
            'explanations': ['High threat score', 'Suspicious URL detected']
        }

    def test_suspicious_prefix_in_subject(self, injector, suspicious_email):
        """Test that [SUSPICIOUS] prefix is added to subject."""
        result = injector.inject_warning(suspicious_email, WarningLevel.CRITICAL)
        assert '[SUSPICIOUS]' in result['subject']
        assert 'URGENT' in result['subject']

    def test_warning_prefix_for_high_level(self, injector, suspicious_email):
        """Test that [WARNING] prefix is added for HIGH risk."""
        result = injector.inject_warning(suspicious_email, WarningLevel.HIGH)
        assert '[WARNING]' in result['subject']

    def test_no_modification_for_safe_email(self, injector, legitimate_email):
        """Test that safe emails are NOT modified."""
        legitimate_email['threat_score'] = 0.1
        result = injector.inject_warning(legitimate_email, WarningLevel.SAFE)
        assert not result['modified']
        assert result['subject'] == legitimate_email['subject']

    def test_preserves_original_subject_content(self, injector, suspicious_email):
        """Test that original subject content is preserved after modification."""
        result = injector.inject_warning(suspicious_email, WarningLevel.CRITICAL)
        assert 'URGENT' in result['subject']
        assert 'GCash' in result['subject']
        assert 'Suspended' in result['subject']

    def test_inject_warning_banner_in_body(self, injector, suspicious_email):
        """Test that warning banner is injected into body."""
        result = injector.inject_warning(suspicious_email, WarningLevel.CRITICAL)
        assert result['modified_body']
        assert 'WARNING' in result['body']

    def test_body_warning_contains_explanations(self, injector, suspicious_email):
        """Test that warning explains WHY email is suspicious."""
        result = injector.inject_warning(suspicious_email, WarningLevel.CRITICAL)
        assert '! REASONS' in result['body']

    def test_body_warning_contains_safety_tips(self, injector, suspicious_email):
        """Test that warning includes safety tips."""
        result = injector.inject_warning(suspicious_email, WarningLevel.CRITICAL)
        assert 'SAFETY TIPS' in result['body']
        assert 'Do NOT click' in result['body']

    def test_add_x_security_headers(self, injector, suspicious_email):
        """Test that X-Security-* headers are added."""
        result = injector.inject_warning(suspicious_email, WarningLevel.CRITICAL)
        headers = result['headers']
        assert 'X-Security-Threat-Score' in headers
        assert 'X-Security-Risk-Level' in headers
        assert 'X-Security-Analyzed' in headers

    def test_header_contains_threat_score(self, injector, suspicious_email):
        """Test that threat score is in headers."""
        result = injector.inject_warning(suspicious_email, WarningLevel.CRITICAL)
        headers = result['headers']
        assert headers['X-Security-Threat-Score'] == '0.85'

    def test_critical_level_threshold(self, injector, suspicious_email):
        """Test CRITICAL level for very high threat scores."""
        suspicious_email['threat_score'] = 0.9
        result = injector.inject_warning(suspicious_email, WarningLevel.CRITICAL)
        assert result['warning_level'] == WarningLevel.CRITICAL
        assert result['modified']

    def test_medium_level_warning(self, injector, suspicious_email):
        """Test CAUTION prefix for MEDIUM level."""
        med_injector = EmailWarningInjector(min_warning_level=WarningLevel.MEDIUM)
        result = med_injector.inject_warning(suspicious_email, WarningLevel.MEDIUM)
        assert result['modified']
        assert '[CAUTION]' in result['subject']

    def test_empty_subject_handling(self, injector):
        """Test handling of empty subject."""
        email = {
            'subject': '',
            'body': 'Test body',
            'headers': {}
        }
        result = injector.inject_warning(email, WarningLevel.CRITICAL)
        assert result['modified']
        assert '[SUSPICIOUS]' in result['subject']

    def test_determine_warning_level(self, injector):
        """Test warning level determination from score."""
        assert injector.determine_warning_level(0.85) == WarningLevel.CRITICAL
        assert injector.determine_warning_level(0.65) == WarningLevel.HIGH
        assert injector.determine_warning_level(0.45) == WarningLevel.MEDIUM
        assert injector.determine_warning_level(0.25) == WarningLevel.LOW
        assert injector.determine_warning_level(0.15) == WarningLevel.SAFE

    def test_warning_level_enum_order(self):
        """Test that warning levels are ordered correctly."""
        assert WarningLevel.SAFE < WarningLevel.LOW
        assert WarningLevel.LOW < WarningLevel.MEDIUM
        assert WarningLevel.MEDIUM < WarningLevel.HIGH
        assert WarningLevel.HIGH < WarningLevel.CRITICAL

    def test_minimum_warning_level_config(self):
        """Test minimum warning level configuration."""
        config_injector = EmailWarningInjector(min_warning_level=WarningLevel.MEDIUM)
        email = {'subject': 'Test', 'body': 'Test', 'headers': {}, 'threat_score': 0.8}
        
        assert config_injector.inject_warning(email, WarningLevel.MEDIUM)['modified']
        assert not config_injector.inject_warning(email, WarningLevel.LOW)['modified']

    def test_gcash_specific_tips(self, injector):
        """Test GCash-specific safety tips."""
        gcash_email = {
            'subject': 'GCash Verify',
            'body': 'Verify now',
            'headers': {},
            'threat_score': 0.85,
            'explanations': ['GCash impersonation', 'Suspicious URL']
        }
        result = injector.inject_warning(gcash_email, WarningLevel.CRITICAL)
        assert 'GCash never sends' in result['body']


class TestWarningLevels:
    """Test all warning level configurations."""

    def test_all_levels_defined(self):
        """Test that all expected warning levels are defined."""
        assert hasattr(WarningLevel, 'SAFE')
        assert hasattr(WarningLevel, 'LOW')
        assert hasattr(WarningLevel, 'MEDIUM')
        assert hasattr(WarningLevel, 'HIGH')
        assert hasattr(WarningLevel, 'CRITICAL')

    def test_level_order(self):
        """Test warning level ordering."""
        assert WarningLevel.SAFE < WarningLevel.LOW
        assert WarningLevel.LOW < WarningLevel.MEDIUM
        assert WarningLevel.MEDIUM < WarningLevel.HIGH
        assert WarningLevel.HIGH < WarningLevel.CRITICAL


class TestEdgeCases:
    """Test edge case handling."""

    def test_multiple_explanations(self):
        """Test handling of multiple explanations."""
        injector = EmailWarningInjector()
        email = {
            'subject': 'Test',
            'body': 'Test',
            'headers': {},
            'threat_score': 0.9,
            'explanations': ['Reason 1', 'Reason 2', 'Reason 3', 'Reason 4', 'Reason 5']
        }
        result = injector.inject_warning(email, WarningLevel.CRITICAL)
        assert result['modified']
        assert result['modified_body']

    def test_warning_info_metadata(self):
        """Test warning info metadata is populated correctly."""
        injector = EmailWarningInjector()
        email = {
            'subject': 'Test',
            'body': 'Test',
            'headers': {},
            'threat_score': 0.85,
            'explanations': ['Test reason']
        }
        result = injector.inject_warning(email, WarningLevel.CRITICAL)
        assert result['warning_info']['warning_level'] == 'CRITICAL'
        assert result['warning_info']['threat_score'] == 0.85
        assert len(result['warning_info']['explanations']) == 1
