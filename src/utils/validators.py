"""
Input validation utilities for emails, URLs, and domains.
"""

import re
import ipaddress
from typing import Optional, Tuple
from urllib.parse import urlparse
from email_validator import validate_email, EmailNotValidError
from loguru import logger


class EmailValidator:
    """Validate and normalize email addresses"""

    @staticmethod
    def validate(email: str) -> Tuple[bool, Optional[str]]:
        """
        Validate email address format.

        Returns:
            Tuple[bool, Optional[str]]: (is_valid, normalized_email or error message)
        """
        try:
            # Validate and get info
            email_info = validate_email(email, check_deliverability=False)

            # Normalize the email address
            normalized = email_info.normalized
            return True, normalized

        except EmailNotValidError as e:
            return False, str(e)

    @staticmethod
    def extract_domain(email: str) -> Optional[str]:
        """Extract domain from email address"""
        try:
            return email.split('@')[1].lower()
        except (IndexError, AttributeError):
            return None


class URLValidator:
    """Validate and analyze URLs"""

    @staticmethod
    def validate(url: str) -> bool:
        """Check if string is a valid URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path

            # Remove port if present
            domain = domain.split(':')[0]

            # Remove www prefix
            if domain.startswith('www.'):
                domain = domain[4:]

            return domain.lower() if domain else None
        except Exception as e:
            logger.debug(f"Failed to extract domain from URL {url}: {e}")
            return None

    @staticmethod
    def is_ip_address(domain: str) -> bool:
        """Check if domain is actually an IP address"""
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False

    @staticmethod
    def extract_all_urls(text: str) -> list:
        """Extract all URLs from text using regex"""
        # Simple URL regex pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)


class DomainValidator:
    """Validate and analyze domains"""

    @staticmethod
    def validate(domain: str) -> bool:
        """Basic domain format validation"""
        # Simple domain regex
        pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        return bool(re.match(pattern, domain.lower()))

    @staticmethod
    def get_tld(domain: str) -> Optional[str]:
        """Extract top-level domain"""
        try:
            return domain.split('.')[-1]
        except (AttributeError, IndexError):
            return None

    @staticmethod
    def count_subdomains(domain: str) -> int:
        """Count number of subdomains (excluding the main domain)"""
        parts = domain.split('.')
        return len(parts) - 2  # Subtract main domain and TLD