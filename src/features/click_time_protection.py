"""
Click-Time Protection Module.

Provides real-time URL protection by rewriting URLs in emails to go through
a security proxy that can block malicious clicks after delivery.
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, quote_plus
from src.features.external_intelligence import ThreatIntelligenceHub
from src.utils.config import settings


class ClickTimeProtection:
    """
    Provides click-time protection by rewriting URLs in emails to route
    through a security checking proxy.
    """
    
    def __init__(self, threat_hub: ThreatIntelligenceHub):
        """
        Initialize click-time protection.
        
        Args:
            threat_hub: Threat intelligence hub for URL checking
        """
        self.threat_hub = threat_hub
        self.proxy_base_url = getattr(settings, 'click_time_proxy_url', 'http://localhost:8080/check')
        self.enabled = getattr(settings, 'click_time_protection_enabled', True)
        
        # URL patterns that should NOT be rewritten (trusted domains)
        self.trusted_patterns = [
            r'https?://(www\.)?deped\.gov\.ph',
            r'https?://(www\.)?dict\.gov\.ph',
            r'https?://(www\.)?doh\.gov\.ph',
            r'https?://(www\.)?dswd\.gov\.ph',
            r'https?://(www\.)?gov\.ph',
            r'https?://(www\.)?google\.com',
            r'https?://(www\.)?microsoft\.com',
        ]
    
    def should_rewrite_url(self, url: str) -> bool:
        """
        Determine if a URL should be rewritten for click-time protection.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL should be rewritten, False otherwise
        """
        if not self.enabled:
            return False
            
        # Skip trusted domains
        for pattern in self.trusted_patterns:
            if re.match(pattern, url, re.IGNORECASE):
                return False
                
        # Rewrite all other HTTP/HTTPS URLs
        return url.lower().startswith(('http://', 'https://'))
    
    def rewrite_url(self, url: str, email_id: str = "") -> str:
        """
        Rewrite a URL to route through the security proxy.
        
        Args:
            url: Original URL
            email_id: Optional email identifier for tracking
            
        Returns:
            Rewritten URL that goes through security proxy
        """
        if not self.should_rewrite_url(url):
            return url
            
        # Create a unique identifier for tracking
        if not email_id:
            email_id = hashlib.md5(url.encode()).hexdigest()[:16]
            
        # Encode the original URL for safe transmission
        encoded_url = quote_plus(url)
        
        # Build proxy URL
        params = {
            'url': encoded_url,
            'email_id': email_id,
            'ts': str(int(hashlib.md5(url.encode()).hexdigest()[:8], 16))  # Simple timestamp-ish
        }
        
        return f"{self.proxy_base_url}?{urlencode(params)}"
    
    def extract_and_rewrite_urls(self, text: str, email_id: str = "") -> Tuple[str, List[Dict[str, str]]]:
        """
        Find all URLs in text and rewrite them for click-time protection.
        
        Args:
            text: Text containing URLs
            email_id: Optional email identifier
            
        Returns:
            Tuple of (text_with_rewritten_urls, list_of_url_mappings)
        """
        if not text:
            return text, []
            
        # Extract URLs using regex (simple approach)
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        
        # Rewrite each URL
        rewritten_text = text
        url_mappings = []
        
        for url in urls:
            rewritten_url = self.rewrite_url(url, email_id)
            if rewritten_url != url:  # Only if actually rewritten
                rewritten_text = rewritten_text.replace(url, rewritten_url, 1)  # Replace first occurrence
                url_mappings.append({
                    'original': url,
                    'rewritten': rewritten_url,
                    'email_id': email_id or hashlib.md5(url.encode()).hexdigest()[:16]
                })
                
        return rewritten_text, url_mappings
    
    async def check_url_safety(self, url: str) -> Dict:
        """
        Check if a URL is safe using threat intelligence.
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with safety assessment
        """
        # Decode the URL if it's been encoded for the proxy
        original_url = url
        if 'url=' in url:
            try:
                # Extract the url parameter
                import urllib.parse
                parsed = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed.query)
                if 'url' in query_params:
                    original_url = urllib.parse.unquote_plus(query_params['url'][0])
            except:
                pass  # If decoding fails, use the URL as-is
        
        # Check URL safety
        safety_result = await self._check_url_with_threat_intel(original_url)
        
        return {
            'url': original_url,
            'safe': safety_result.get('safe', False),
            'threat_score': safety_result.get('threat_score', 0.0),
            'reasons': safety_result.get('reasons', []),
            'action': 'block' if not safety_result.get('safe', True) else 'allow'
        }
    
    async def _check_url_with_threat_intel(self, url: str) -> Dict:
        """
        Check URL safety using threat intelligence services.
        
        Args:
            url: URL to check
            
        Returns:
            Safety assessment dictionary
        """
        # Initialize result
        result = {
            'safe': True,
            'threat_score': 0.0,
            'reasons': []
        }
        
        # Check with VirusTotal (if available)
        try:
            vt_result = self.threat_hub.vt.check_url(url)
            if vt_result and vt_result.get('score', 0) > 0.5:
                result['safe'] = False
                result['threat_score'] = max(result['threat_score'], vt_result['score'])
                result['reasons'].append(f"VirusTotal flagged as malicious (score: {vt_result['score']:.2f})")
        except Exception as e:
            # VirusTotal might not be configured or have rate limits
            pass
            
        # Check URL patterns for obvious threats
        threat_indicators = [
            (r'bit\.ly|tinyurl|tco|goo\.gl|ow\.ly', 'URL shortener often used for phishing'),
            (r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', 'IP address in URL (suspicious)'),
            (r'(paypal|ebay|amazon|bank|secure).*\.tk|.*\.ml|.*\.ga', 'Suspicious TLD for brand'),
            (r'(login|signin|verify|update|confirm).*[0-9]', 'Login-related with numbers'),
            (r'@.*@', 'Multiple @ symbols (common in phishing)'),
        ]
        
        for pattern, reason in threat_indicators:
            if re.search(pattern, url, re.IGNORECASE):
                result['reasons'].append(reason)
                result['threat_score'] = max(result['threat_score'], 0.7)
                
        # Check for suspicious domains
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.win', '.click', '.band']
        for tld in suspicious_tlds:
            if tld in url.lower():
                result['reasons'].append(f"Suspicious TLD: {tld}")
                result['threat_score'] = max(result['threat_score'], 0.6)
                
        # Normalize threat score
        result['threat_score'] = min(result['threat_score'], 1.0)
        
        # Determine if safe based on threshold
        result['safe'] = result['threat_score'] < 0.5
        
        return result
    
    def generate_block_page_html(self, url: str, reasons: List[str]) -> str:
        """
        Generate HTML block page for malicious URLs.
        
        Args:
            url: The blocked URL
            reasons: List of reasons for blocking
            
        Returns:
            HTML string for block page
        """
        reasons_html = ''.join(f'<li>{reason}</li>' for reason in reasons)
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Access Blocked - Email Security Gateway</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f8f9fa; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background-color: #dc3545; color: white; padding: 20px; border-radius: 6px; text-align: center; }}
        .content {{ margin: 30px 0; }}
        .url-box {{ background-color: #f8f9fa; padding: 15px; border-radius: 4px; font-family: monospace; word-break: break-all; }}
        .reasons {{ margin: 20px 0; }}
        .reasons ul {{ padding-left: 20px; }}
        .footer {{ margin-top: 30px; text-align: center; color: #6c757d; font-size: 14px; }}
        .btn {{ display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 10px 5px; }}
        .btn-secondary {{ background-color: #6c757d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>&#128274; Access Blocked</h1>
            <p>This URL has been blocked by the Email Security Gateway</p>
        </div>
        
        <div class="content">
            <h2>Blocked URL:</h2>
            <div class="url-box">{url}</div>
            
            <div class="reasons">
                <h3>Reasons for Blocking:</h3>
                <ul>
                    {reasons_html}
                </ul>
            </div>
            
            <div>
                <p>This link was detected in an email that passed through the Email Security Gateway.</p>
                <p>If you believe this is a mistake, please contact your IT department with the details above.</p>
            </div>
            
            <div style="margin-top: 30px;">
                <a href="javascript:history.back()" class="btn btn-secondary">Go Back</a>
            </div>
        </div>
        
        <div class="footer">
            Email Security Gateway &copy; 2026<br>
            For security assistance, contact your IT department
        </div>
    </div>
</body>
</html>
        """.strip()


def rewrite_email_urls(email_data: Dict, threat_hub: ThreatIntelligenceHub) -> Dict:
    """
    Convenience function to rewrite URLs in an email for click-time protection.
    
    Args:
        email_data: Email data dictionary
        threat_hub: Threat intelligence hub
        
    Returns:
        Email data with URLs rewritten for click-time protection
    """
    protector = ClickTimeProtection(threat_hub)
    
    # Create a copy to avoid modifying original
    protected_email = email_data.copy()
    
    # Initialize URL mappings
    subject_mappings = []
    plain_mappings = []
    html_mappings = []
    
    # Rewrite URLs in subject
    if protected_email.get('subject'):
        protected_email['subject'], subject_mappings = protector.extract_and_rewrite_urls(
            protected_email['subject']
        )
    
    # Rewrite URLs in body (both plain text and HTML)
    if protected_email.get('body_plain'):
        protected_email['body_plain'], plain_mappings = protector.extract_and_rewrite_urls(
            protected_email['body_plain']
        )
    
    if protected_email.get('body_html'):
        protected_email['body_html'], html_mappings = protector.extract_and_rewrite_urls(
            protected_email['body_html']
        )
    
    # Store URL mappings for tracking (would normally go to database)
    protected_email['url_mappings'] = {
        'subject': subject_mappings,
        'body_plain': plain_mappings,
        'body_html': html_mappings
    }
    
    # Generate a simple email ID if not present
    if 'email_id' not in protected_email:
        protected_email['email_id'] = hashlib.md5(
            (protected_email.get('subject', '') + protected_email.get('body_plain', '')).encode()
        ).hexdigest()[:16]
        
    return protected_email


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    from src.features.external_intelligence import ThreatIntelligenceHub
    
    async def test_click_time_protection():
        """Test click-time protection functionality"""
        print("=" * 60)
        print("CLICK-TIME PROTECTION MODULE TEST")
        print("=" * 60)
        
        # Initialize threat hub
