"""
Email parsing module - extracts relevant information from raw emails.
Handles RFC 822 email format and extracts text, headers, URLs, and attachments.
"""

import email
from email.policy import default
from email.utils import parsedate_to_datetime
from typing import Dict, Optional, List, Tuple
import re
from pathlib import Path
import quopri
import base64
from loguru import logger
from src.utils.validators import URLValidator
from src.utils.helpers import generate_email_hash


class EmailParser:
    """Parse raw email messages and extract structured information"""

    def __init__(self):
        self.url_validator = URLValidator()

    def parse_raw_email(self, raw_email: bytes) -> Dict:
        """
        Parse raw email bytes into structured format.

        Args:
            raw_email: Raw email content as bytes

        Returns:
            Dictionary with parsed email components
        """
        try:
            # Parse email using policy to preserve structure
            msg = email.message_from_bytes(raw_email, policy=default)

            # Extract basic headers
            email_data = {
                'message_id': msg.get('Message-ID', generate_email_hash(raw_email.decode('utf-8', errors='ignore'))),
                'from': self._parse_address_field(msg.get('From', '')),
                'to': self._parse_address_field(msg.get('To', '')),
                'cc': self._parse_address_field(msg.get('Cc', '')),
                'subject': msg.get('Subject', ''),
                'date': self._parse_date(msg.get('Date', '')),
                'reply_to': self._parse_address_field(msg.get('Reply-To', '')),
                'return_path': msg.get('Return-Path', ''),

                # Content
                'body_plain': '',
                'body_html': '',
                'urls': [],
                'attachments': [],

                # Metadata
                'size': len(raw_email),
                'has_attachments': False,
                'content_type': msg.get_content_type(),
            }

            # Extract body and attachments
            self._extract_content(msg, email_data)

            # Extract URLs from body
            email_data['urls'] = self._extract_urls(email_data['body_plain'] + ' ' + email_data['body_html'])

            # Generate hash for deduplication
            email_data['hash'] = generate_email_hash(email_data['body_plain'] + email_data['subject'])

            # Extract domain from sender
            if email_data['from']:
                from_email = email_data['from'][0].get('email', '')
                if '@' in from_email:
                    email_data['from_domain'] = from_email.split('@')[1].lower()
                else:
                    email_data['from_domain'] = None

            logger.debug(f"Parsed email: {email_data['subject']} from {email_data['from_domain']}")
            return email_data

        except Exception as e:
            logger.error(f"Failed to parse email: {e}")
            # Return minimal structure on error
            return {
                'error': str(e),
                'raw_preview': raw_email[:500].decode('utf-8', errors='ignore'),
                'hash': generate_email_hash(raw_email.decode('utf-8', errors='ignore'))
            }

    def _parse_address_field(self, field: str) -> List[Dict]:
        """
        Parse email address field (From, To, Cc) into structured format.

        Returns:
            List of dicts with 'name' and 'email' keys
        """
        if not field:
            return []

        addresses = []
        # Simple regex for email extraction
        email_pattern = r'([^<]*?)\s*<([^>]+)>|([^,\s]+@[^,\s]+)'

        for match in re.finditer(email_pattern, field):
            if match.group(1) and match.group(2):
                # Format: "Name <email>"
                name = match.group(1).strip()
                email_addr = match.group(2).strip()
            else:
                # Format: "email@domain.com"
                name = ''
                email_addr = match.group(3).strip()

            addresses.append({
                'name': name,
                'email': email_addr
            })

        return addresses

    def _parse_date(self, date_str: str) -> Optional[str]:
        """Parse email date string to ISO format"""
        try:
            dt = parsedate_to_datetime(date_str)
            return dt.isoformat()
        except:
            return None

    def _extract_content(self, msg, email_data: Dict):
        """
        Recursively extract content from email message parts.
        """
        if msg.is_multipart():
            for part in msg.iter_parts():
                self._extract_content(part, email_data)
        else:
            content_type = msg.get_content_type()
            content_disposition = str(msg.get('Content-Disposition', ''))

            # Check if it's an attachment
            if 'attachment' in content_disposition.lower():
                attachment = self._extract_attachment(msg)
                if attachment:
                    email_data['attachments'].append(attachment)
                    email_data['has_attachments'] = True
            else:
                # Extract body text
                payload = msg.get_payload(decode=True)
                if payload:
                    try:
                        decoded = payload.decode('utf-8', errors='ignore')

                        if content_type == 'text/plain':
                            email_data['body_plain'] += decoded
                        elif content_type == 'text/html':
                            email_data['body_html'] += decoded
                    except:
                        pass

    def _extract_attachment(self, msg) -> Optional[Dict]:
        """Extract attachment information"""
        try:
            filename = msg.get_filename()
            if not filename:
                return None

            content_type = msg.get_content_type()
            size = len(msg.get_payload(decode=True) or b'')

            # Don't store actual content for security/size reasons
            return {
                'filename': filename,
                'content_type': content_type,
                'size': size,
                'hash': generate_email_hash(filename + str(size))
            }
        except Exception as e:
            logger.warning(f"Failed to extract attachment: {e}")
            return None

    def _extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from text"""
        return self.url_validator.extract_all_urls(text)

    def extract_features(self, email_data: Dict) -> Dict:
        """
        Extract numerical features from parsed email for model input.
        """
        features = {
            'url_count': len(email_data.get('urls', [])),
            'has_attachments': 1 if email_data.get('has_attachments') else 0,
            'subject_length': len(email_data.get('subject', '')),
            'body_length': len(email_data.get('body_plain', '')),

            # Suspicious patterns
            'has_urgent_words': self._check_urgent_words(email_data),
            'has_verify_words': self._check_verify_words(email_data),
            'has_sensitive_words': self._check_sensitive_words(email_data),

            # Sender indicators
            'from_domain_trusted': self._check_trusted_domain(email_data),
            'reply_to_mismatch': self._check_reply_to_mismatch(email_data),
        }

        return features

    def _check_urgent_words(self, email_data: Dict) -> int:
        """Check for urgency words in subject and body"""
        urgent_words = ['urgent', 'immediate', 'asap', 'critical', 'warning', 'alert']
        text = (email_data.get('subject', '') + ' ' + email_data.get('body_plain', '')).lower()

        for word in urgent_words:
            if word in text:
                return 1
        return 0

    def _check_verify_words(self, email_data: Dict) -> int:
        """Check for verification-related words"""
        verify_words = ['verify', 'confirm', 'validate', 'update', 'reactivate', 'restore']
        text = (email_data.get('subject', '') + ' ' + email_data.get('body_plain', '')).lower()

        for word in verify_words:
            if word in text:
                return 1
        return 0

    def _check_sensitive_words(self, email_data: Dict) -> int:
        """Check for sensitive information requests"""
        sensitive_words = ['password', 'credit card', 'ssn', 'social security', 'bank account', 'login']
        text = (email_data.get('subject', '') + ' ' + email_data.get('body_plain', '')).lower()

        for word in sensitive_words:
            if word in text:
                return 1
        return 0

    def _check_trusted_domain(self, email_data: Dict) -> int:
        """Check if sender domain is from trusted sources"""
        trusted_domains = ['gov.ph', 'dict.gov.ph', 'deped.gov.ph', 'doh.gov.ph', 'dswd.gov.ph']
        from_domain = email_data.get('from_domain', '')

        for domain in trusted_domains:
            if from_domain.endswith(domain):
                return 1
        return 0

    def _check_reply_to_mismatch(self, email_data: Dict) -> int:
        """Check if Reply-To domain mismatches From domain"""
        from_domain = email_data.get('from_domain', '')

        if email_data.get('reply_to'):
            reply_to_email = email_data['reply_to'][0].get('email', '') if email_data['reply_to'] else ''
            if '@' in reply_to_email:
                reply_domain = reply_to_email.split('@')[1].lower()
                if reply_domain != from_domain:
                    return 1
        return 0


# Simple test function
def test_parser():
    """Test the email parser with sample emails"""
    parser = EmailParser()

    # Sample legitimate email
    legit_email = b"""From: "HR Department" <hr@deped.gov.ph>
To: employee@deped.gov.ph
Subject: Meeting Reminder
Date: Mon, 1 Jan 2024 10:00:00 +0800

Dear Employee,

This is a reminder for our meeting tomorrow at 10 AM.

Best regards,
HR Department"""

    # Sample phishing email
    phishing_email = b"""From: "GCash Support" <support@gcash-verify.net>
To: employee@deped.gov.ph
Subject: URGENT: Account Verification Required
Date: Mon, 1 Jan 2024 10:00:00 +0800

Dear User,

Your GCash account has been limited. Click here to verify: http://bit.ly/gcash-verify

Immediate action required!
"""

    print("=== Parsing Legitimate Email ===")
    legit_data = parser.parse_raw_email(legit_email)
    print(f"Subject: {legit_data['subject']}")
    print(f"From: {legit_data['from']}")
    print(f"From Domain: {legit_data.get('from_domain')}")
    print(f"Features: {parser.extract_features(legit_data)}")

    print("\n=== Parsing Phishing Email ===")
    phish_data = parser.parse_raw_email(phishing_email)
    print(f"Subject: {phish_data['subject']}")
    print(f"From: {phish_data['from']}")
    print(f"URLs: {phish_data['urls']}")
    print(f"Features: {parser.extract_features(phish_data)}")


if __name__ == "__main__":
    test_parser()