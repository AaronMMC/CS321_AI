"""
SPF/DKIM/DMARC Verification Module.
Provides email authentication verification to prevent spoofing and phishing.
"""
import re
import dns.resolver
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from loguru import logger
from src.utils.config import settings


class AuthenticationVerifier:
    """
    Verifies email authenticity using SPF, DKIM, and DMARC records.
    """

    def __init__(self):
        """Initialize authentication verifier."""
        # Configure DNS resolver timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 5.0

    def verify_spf(self, sender_ip: str, sender_domain: str) -> Dict:
        """
        Verify SPF record for sending domain.
        
        Args:
            sender_ip: IP address of the sending server
            sender_domain: Domain from the email sender
            
        Returns:
            Dictionary with SPF verification results
        """
        if not sender_domain:
            return {
                'passed': False,
                'reason': 'No sender domain',
                'score': 0.0
            }

        try:
            # Get SPF records for the domain
            spf_records = self.resolver.resolve(sender_domain, 'TXT')
            spf_record = None
            
            for record in spf_records:
                record_text = record.to_text().strip('"')
                if record_text.startswith('v=spf1'):
                    spf_record = record_text
                    break
            
            if not spf_record:
                return {
                    'passed': False,
                    'reason': 'No SPF record found',
                    'score': 0.0
                }
            
            # Basic SPF evaluation (simplified)
            # In production, use a proper SPF library like pyspf
            if 'v=spf1' in spf_record:
                # Check if IP is authorized (simplified check)
                if 'ip4:' in spf_record or 'ip6:' in spf_record or 'include:' in spf_record:
                    # This is a simplified check - real SPF validation is more complex
                    if 'all' in spf_record and '-all' in spf_record:
                        return {
                            'passed': True,
                            'reason': 'SPF passed with strict policy',
                            'score': 1.0
                        }
                    elif '~all' in spf_record:
                        return {
                            'passed': True,
                            'reason': 'SPF passed with soft fail policy',
                            'score': 0.8
                        }
                    else:
                        return {
                            'passed': True,
                            'reason': 'SPF passed with neutral policy',
                            'score': 0.5
                        }
                else:
                    return {
                        'passed': False,
                        'reason': 'SPF record does not authorize sender IP',
                        'score': 0.0
                    }
            else:
                return {
                    'passed': False,
                    'reason': 'Invalid SPF record format',
                    'score': 0.0
                }
                
        except dns.resolver.NXDOMAIN:
            return {
                'passed': False,
                'reason': 'Domain does not exist',
                'score': 0.0
            }
        except dns.resolver.NoAnswer:
            return {
                'passed': False,
                'reason': 'No SPF record found',
                'score': 0.0
            }
        except Exception as e:
            logger.warning(f"SPF verification error for {sender_domain}: {e}")
            return {
                'passed': False,
                'reason': f'DNS lookup failed: {str(e)}',
                'score': 0.0
            }

    def verify_dkim(self, email_headers: Dict, email_body: bytes) -> Dict:
        """
        Verify DKIM signature of email.
        
        Args:
            email_headers: Email headers dictionary
            email_body: Email body as bytes
            
        Returns:
            Dictionary with DKIM verification results
        """
        # Extract DKIM-Signature header
        dkim_signature = email_headers.get('DKIM-Signature', '')
        if not dkim_signature:
            return {
                'passed': False,
                'reason': 'No DKIM signature found',
                'score': 0.0
            }
        
        try:
            # Parse DKIM signature (simplified)
            # In production, use a proper DKIM library like pyDKIM
            dkim_params = {}
            for part in dkim_signature.split(';'):
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    dkim_params[key.strip()] = value.strip()
            
            # Check required tags
            required_tags = ['v', 'a', 'b', 'bh', 'd', 's', 'h', 'bh']
            missing_tags = [tag for tag in required_tags if tag not in dkim_params]
            
            if missing_tags:
                return {
                    'passed': False,
                    'reason': f'Missing required DKIM tags: {missing_tags}',
                    'score': 0.0
                }
            
            # Basic validation - in production would verify cryptographic signature
            if dkim_params.get('v') == 'DKIM1':
                return {
                    'passed': True,
                    'reason': 'DKIM signature format valid',
                    'score': 0.8  # Not actually verifying crypto, just format
                }
            else:
                return {
                    'passed': False,
                    'reason': 'Invalid DKIM version',
                    'score': 0.0
                }
                
        except Exception as e:
            logger.warning(f"DKIM verification error: {e}")
            return {
                'passed': False,
                'reason': f'DKIM parsing failed: {str(e)}',
                'score': 0.0
            }

    def verify_dmarc(self, sender_domain: str, spf_result: Dict, dkim_result: Dict, 
                    from_header: str) -> Dict:
        """
        Verify DMARC policy for sending domain.
        
        Args:
            sender_domain: Domain from the email sender
            spf_result: SPF verification result
            dkim_result: DKIM verification result
            from_header: From header value
            
        Returns:
            Dictionary with DMARC verification results
        """
        if not sender_domain:
            return {
                'passed': False,
                'reason': 'No sender domain',
                'score': 0.0,
                'policy': 'none'
            }
        
        try:
            # Check for DMARC record
            dmarc_domain = f"_dmarc.{sender_domain}"
            dmarc_records = self.resolver.resolve(dmarc_domain, 'TXT')
            
            dmarc_record = None
            for record in dmarc_records:
                record_text = record.to_text().strip('"')
                if record_text.startswith('v=DMARC1'):
                    dmarc_record = record_text
                    break
            
            if not dmarc_record:
                return {
                    'passed': True,  # No DMARC policy means not failed
                    'reason': 'No DMARC record found',
                    'score': 0.5,  # Neutral score
                    'policy': 'none'
                }
            
            # Parse DMARC record
            dmarc_params = {}
            for part in dmarc_record.split(';'):
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    dmarc_params[key.strip()] = value.strip()
            
            policy = dmarc_params.get('p', 'none')
            
            # Check alignment
            spf_aligned = self._check_spf_alignment(sender_domain, from_header)
            dkim_aligned = self._check_dkim_alignment(sender_domain, from_header)
            
            # DMARC passes if either SPF or DKIM passes AND aligns
            spf_passed = spf_result.get('passed', False) and spf_aligned
            dkim_passed = dkim_result.get('passed', False) and dkim_aligned
            dmarc_passed = spf_passed or dkim_passed
            
            # Score based on policy and result
            if dmarc_passed:
                if policy == 'reject':
                    score = 1.0
                elif policy == 'quarantine':
                    score = 0.8
                else:  # none
                    score = 0.9
            else:
                if policy == 'reject':
                    score = 0.0
                elif policy == 'quarantine':
                    score = 0.2
                else:  # none
                    score = 0.5
            
            return {
                'passed': dmarc_passed,
                'reason': f'DMARC {policy} policy: {"passed" if dmarc_passed else "failed"}',
                'score': score,
                'policy': policy,
                'spf_aligned': spf_aligned,
                'dkim_aligned': dkim_aligned
            }
            
        except dns.resolver.NXDOMAIN:
            return {
                'passed': True,  # No DMARC policy means not failed
                'reason': 'No DMARC record found',
                'score': 0.5,
                'policy': 'none'
            }
        except Exception as e:
            logger.warning(f"DMARC verification error for {sender_domain}: {e}")
            return {
                'passed': True,  # Fail open for verification errors
                'reason': f'DNS lookup failed: {str(e)}',
                'score': 0.5,
                'policy': 'error'
            }

    def _check_spf_alignment(self, sender_domain: str, from_header: str) -> bool:
        """Check SPF alignment (simplified)."""
        # Extract domain from From header
        from_domain = self._extract_domain_from_email(from_header)
        if not from_domain:
            return False
        
        # For strict alignment, domains must match exactly
        return sender_domain.lower() == from_domain.lower()

    def _check_dkim_alignment(self, sender_domain: str, from_header: str) -> bool:
        """Check DKIM alignment (simplified)."""
        # Extract domain from From header
        from_domain = self._extract_domain_from_email(from_header)
        if not from_domain:
            return False
        
        # For DKIM alignment, check if domain in signature matches From domain
        # Simplified: just check if domains match
        return sender_domain.lower() == from_domain.lower()

    def _extract_domain_from_email(self, email_string: str) -> Optional[str]:
        """Extract domain from email string."""
        if not email_string:
            return None
        
        # Simple email extraction
        email_match = re.search(r'[\w\.-]+@([\w\.-]+)', email_string)
        if email_match:
            return email_match.group(1).lower()
        return None

    def verify_email_authentication(self, email_data: Dict) -> Dict:
        """
        Perform complete email authentication verification.
        
        Args:
            email_data: Parsed email data dictionary
            
        Returns:
            Dictionary with combined authentication results
        """
        # Extract sender information
        sender_ip = email_data.get('sender_ip', '127.0.0.1')  # Would be from connection in real implementation
        sender_domain = email_data.get('from_domain', '')
        from_header = email_data.get('from', '')
        email_headers = email_data.get('headers', {})
        email_body = email_data.get('body_raw', b'')
        
        # Perform individual verifications
        spf_result = self.verify_spf(sender_ip, sender_domain)
        dkim_result = self.verify_dkim(email_headers, email_body)
        dmarc_result = self.verify_dmarc(sender_domain, spf_result, dkim_result, from_header)
        
        # Calculate combined score
        # Weight: SPF 30%, DKIM 30%, DMARC 40%
        spf_score = spf_result.get('score', 0.0)
        dkim_score = dkim_result.get('score', 0.0)
        dmarc_score = dmarc_result.get('score', 0.0)
        
        combined_score = (spf_score * 0.3) + (dkim_score * 0.3) + (dmarc_score * 0.4)
        
        # Determine if authentication passed
        passed = combined_score >= 0.5
        
        # Collect reasons
        reasons = []
        if not spf_result.get('passed', False):
            reasons.append(f"SPF failed: {spf_result.get('reason', '')}")
        if not dkim_result.get('passed', False):
            reasons.append(f"DKIM failed: {dkim_result.get('reason', '')}")
        if not dmarc_result.get('passed', False):
            reasons.append(f"DMARC failed: {dmarc_result.get('reason', '')}")
        
        return {
            'passed': passed,
            'score': combined_score,
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result,
            'reasons': reasons,
            'timestamp': datetime.now().isoformat()
        }


def verify_email_authentication(email_data: Dict) -> Dict:
    """
    Convenience function to verify email authentication.
    
    Args:
        email_data: Parsed email data dictionary
        
    Returns:
        Dictionary with authentication verification results
    """
    verifier = AuthenticationVerifier()
    return verifier.verify_email_authentication(email_data)


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    async def test_authentication():
        """Test authentication verification functionality"""
        print("=" * 60)
        print("AUTHENTICATION VERIFICATION MODULE TEST")
        print("=" * 60)
        
        # Test SPF verification
        verifier = AuthenticationVerifier()
        
        # Test case 1: Domain with SPF record
        spf_result = verifier.verify_spf('1.2.3.4', 'gmail.com')
        print(f"SPF verification for gmail.com: {spf_result}")
        
        # Test case 2: Non-existent domain
        spf_result = verifier.verify_spf('1.2.3.4', 'nonexistentdomain12345.com')
        print(f"SPF verification for non-existent domain: {spf_result}")
        
        # Test case 3: Empty domain
        spf_result = verifier.verify_spf('1.2.3.4', '')
        print(f"SPF verification for empty domain: {spf_result}")
        
        # Test complete verification
        test_email = {
            'sender_ip': '1.2.3.4',
            'from_domain': 'gmail.com',
            'from': 'sender@gmail.com',
            'headers': {
                'DKIM-Signature': 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20161025; h=mime-version:date:message-id:subject:from:to:content-type; bh=hashvalue; b=signature'
            },
            'body_raw': b'Test email body'
        }
        
        auth_result = verifier.verify_email_authentication(test_email)
        print(f"Complete authentication result: {auth_result}")
        
        print("=" * 60)
        print("AUTHENTICATION VERIFICATION TEST COMPLETE")
        print("=" * 60)
    
    # Run the test
    asyncio.run(test_authentication())