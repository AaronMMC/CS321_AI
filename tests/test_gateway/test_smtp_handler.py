"""
Regression tests for SMTP handler content mutation logic.
"""

from email import message_from_bytes
from email.message import EmailMessage
from email.policy import default

import pytest

from src.gateway.smtp_handler import EmailSecurityHandler


class _DummyThreatHub:
    """Minimal threat hub stub for handler construction in unit tests."""


def _build_handler() -> EmailSecurityHandler:
    return EmailSecurityHandler(model=None, threat_hub=_DummyThreatHub())


def test_build_outgoing_email_content_updates_plain_message_fields():
    handler = _build_handler()
    original = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Original Subject\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"Original body"
    )

    email_data = {
        'subject': '[WARNING] Original Subject',
        'body_plain': 'Updated body with rewritten URL: http://proxy/check?x=1',
        'headers': {
            'X-Security-Risk-Level': 'HIGH',
            'X-Security-Threat-Score': '0.75',
        },
    }

    updated = handler._build_outgoing_email_content(original, email_data)
    parsed = message_from_bytes(updated, policy=default)

    assert parsed['Subject'] == '[WARNING] Original Subject'
    assert parsed['X-Security-Risk-Level'] == 'HIGH'
    assert parsed['X-Security-Threat-Score'] == '0.75'
    assert 'Updated body with rewritten URL' in parsed.get_content()


def test_build_outgoing_email_content_updates_multipart_plain_and_html():
    handler = _build_handler()

    msg = EmailMessage()
    msg['From'] = 'sender@example.com'
    msg['To'] = 'recipient@example.com'
    msg['Subject'] = 'Original Subject'
    msg.set_content('Original plain body')
    msg.add_alternative('<html><body><p>Original html body</p></body></html>', subtype='html')

    email_data = {
        'subject': '[CAUTION] Original Subject',
        'body_plain': 'Updated plain body',
        'body_html': '<html><body><p>Updated html body</p></body></html>',
        'headers': {
            'X-Security-Risk-Level': 'MEDIUM',
        },
    }

    updated = handler._build_outgoing_email_content(msg.as_bytes(policy=default), email_data)
    parsed = message_from_bytes(updated, policy=default)

    assert parsed['Subject'] == '[CAUTION] Original Subject'
    assert parsed['X-Security-Risk-Level'] == 'MEDIUM'

    plain_part = None
    html_part = None
    for part in parsed.walk():
        if part.get_content_disposition() == 'attachment':
            continue
        if part.get_content_type() == 'text/plain':
            plain_part = part.get_content()
        if part.get_content_type() == 'text/html':
            html_part = part.get_content()

    assert plain_part is not None
    assert html_part is not None
    assert 'Updated plain body' in plain_part
    assert 'Updated html body' in html_part


@pytest.mark.asyncio
async def test_add_warning_to_email_uses_parsed_body_plain_field():
    handler = _build_handler()

    email_data = {
        'from': 'attacker@example.net',
        'subject': 'Urgent account verification',
        'body_plain': 'Please verify now: http://bit.ly/verify-me',
        'body_html': '',
        'headers': {},
        'threat_score': 0.72,
        'urls': ['http://bit.ly/verify-me'],
    }

    await handler._add_warning_to_email(email_data)

    assert email_data['subject'].startswith('[WARNING]')
    assert 'EMAIL SECURITY WARNING' in email_data['body_plain']
    assert email_data['headers'].get('X-Security-Risk-Level') == 'HIGH'
