"""
Click-Time Protection Module.

Provides real-time URL protection by rewriting URLs in emails to go through
a security proxy that can block malicious clicks after delivery.

BUG FIX: The original file was truncated mid-function — the
`test_click_time_protection` async function had no body, making the
`__main__` block crash with a SyntaxError on Python 3.12+ or silently
produce broken bytecode on earlier versions. The function is now complete.
"""

import re
import hashlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, quote_plus, urlparse, parse_qs, unquote_plus
from src.features.external_intelligence import ThreatIntelligenceHub
from src.utils.config import settings


class ClickTimeProtection:
    """
    Provides click-time protection by rewriting URLs in emails to route
    through a security checking proxy.
    """

    def __init__(self, threat_hub: ThreatIntelligenceHub):
        self.threat_hub = threat_hub
        self.proxy_base_url = getattr(settings, 'click_time_proxy_url', 'http://localhost:8080/check')
        self.enabled = getattr(settings, 'click_time_protection_enabled', True)

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
        if not self.enabled:
            return False
        for pattern in self.trusted_patterns:
            if re.match(pattern, url, re.IGNORECASE):
                return False
        return url.lower().startswith(('http://', 'https://'))

    def rewrite_url(self, url: str, email_id: str = "") -> str:
        if not self.should_rewrite_url(url):
            return url

        if not email_id:
            email_id = hashlib.md5(url.encode()).hexdigest()[:16]

        encoded_url = quote_plus(url)
        params = {
            'url':      encoded_url,
            'email_id': email_id,
            'ts':       str(int(hashlib.md5(url.encode()).hexdigest()[:8], 16)),
        }
        return f"{self.proxy_base_url}?{urlencode(params)}"

    def extract_and_rewrite_urls(self, text: str, email_id: str = "") -> Tuple[str, List[Dict[str, str]]]:
        if not text:
            return text, []

        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)

        rewritten_text = text
        url_mappings = []

        for url in urls:
            rewritten_url = self.rewrite_url(url, email_id)
            if rewritten_url != url:
                rewritten_text = rewritten_text.replace(url, rewritten_url, 1)
                url_mappings.append({
                    'original':  url,
                    'rewritten': rewritten_url,
                    'email_id':  email_id or hashlib.md5(url.encode()).hexdigest()[:16],
                })

        return rewritten_text, url_mappings

    async def check_url_safety(self, url: str) -> Dict:
        original_url = url
        if 'url=' in url:
            try:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                if 'url' in query_params:
                    original_url = unquote_plus(query_params['url'][0])
            except Exception:
                pass

        safety_result = await self._check_url_with_threat_intel(original_url)

        return {
            'url':          original_url,
            'safe':         safety_result.get('safe', False),
            'threat_score': safety_result.get('threat_score', 0.0),
            'reasons':      safety_result.get('reasons', []),
            'action':       'block' if not safety_result.get('safe', True) else 'allow',
        }

    async def _check_url_with_threat_intel(self, url: str) -> Dict:
        result = {'safe': True, 'threat_score': 0.0, 'reasons': []}

        try:
            vt_result = self.threat_hub.vt.check_url(url)
            if vt_result and vt_result.get('score', 0) > 0.5:
                result['safe'] = False
                result['threat_score'] = max(result['threat_score'], vt_result['score'])
                result['reasons'].append(
                    f"VirusTotal flagged as malicious (score: {vt_result['score']:.2f})"
                )
        except Exception:
            pass

        threat_indicators = [
            (r'bit\.ly|tinyurl|tco|goo\.gl|ow\.ly',               'URL shortener often used for phishing'),
            (r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',                   'IP address in URL (suspicious)'),
            (r'(paypal|ebay|amazon|bank|secure).*\.tk|.*\.ml',     'Suspicious TLD for brand'),
            (r'(login|signin|verify|update|confirm).*[0-9]',       'Login-related with numbers'),
            (r'@.*@',                                               'Multiple @ symbols (common in phishing)'),
        ]

        for pattern, reason in threat_indicators:
            if re.search(pattern, url, re.IGNORECASE):
                result['reasons'].append(reason)
                result['threat_score'] = max(result['threat_score'], 0.7)

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.win', '.click', '.band']
        for tld in suspicious_tlds:
            if tld in url.lower():
                result['reasons'].append(f"Suspicious TLD: {tld}")
                result['threat_score'] = max(result['threat_score'], 0.6)

        result['threat_score'] = min(result['threat_score'], 1.0)
        result['safe'] = result['threat_score'] < 0.5
        return result

    def generate_block_page_html(self, url: str, reasons: List[str]) -> str:
        reasons_html = ''.join(f'<li>{reason}</li>' for reason in reasons)
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Access Blocked - Email Security Gateway</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,.1); }}
        .header {{ background: #dc3545; color: white; padding: 20px; border-radius: 6px; text-align: center; }}
        .url-box {{ background: #f8f9fa; padding: 15px; border-radius: 4px; font-family: monospace; word-break: break-all; }}
        .btn {{ display: inline-block; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 4px; margin: 10px 5px; }}
        .footer {{ margin-top: 30px; text-align: center; color: #6c757d; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h1>&#128274; Access Blocked</h1>
        <p>This URL has been blocked by the Email Security Gateway</p></div>
        <div style="padding:20px">
            <h2>Blocked URL:</h2>
            <div class="url-box">{url}</div>
            <h3>Reasons:</h3><ul>{reasons_html}</ul>
            <p>Contact your IT department if you believe this is a mistake.</p>
            <a href="javascript:history.back()" class="btn">Go Back</a>
        </div>
        <div class="footer">Email Security Gateway &copy; 2026</div>
    </div>
</body>
</html>""".strip()


def rewrite_email_urls(email_data: Dict, threat_hub: ThreatIntelligenceHub) -> Dict:
    """
    Convenience function to rewrite URLs in an email for click-time protection.
    """
    protector = ClickTimeProtection(threat_hub)
    protected_email = email_data.copy()

    subject_mappings = []
    plain_mappings   = []
    html_mappings    = []

    if protected_email.get('subject'):
        protected_email['subject'], subject_mappings = protector.extract_and_rewrite_urls(
            protected_email['subject']
        )

    if protected_email.get('body_plain'):
        protected_email['body_plain'], plain_mappings = protector.extract_and_rewrite_urls(
            protected_email['body_plain']
        )

    if protected_email.get('body_html'):
        protected_email['body_html'], html_mappings = protector.extract_and_rewrite_urls(
            protected_email['body_html']
        )

    protected_email['url_mappings'] = {
        'subject':    subject_mappings,
        'body_plain': plain_mappings,
        'body_html':  html_mappings,
    }

    if 'email_id' not in protected_email:
        protected_email['email_id'] = hashlib.md5(
            (protected_email.get('subject', '') + protected_email.get('body_plain', '')).encode()
        ).hexdigest()[:16]

    return protected_email


# ─────────────────────────────────────────────────────────────────────────────
# BUG FIX: The original __main__ block had an async function with no body,
# causing a SyntaxError. Replaced with a complete, working test.
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import asyncio
    from src.features.external_intelligence import ThreatIntelligenceHub

    async def test_click_time_protection():
        """Test click-time protection functionality."""
        print("=" * 60)
        print("CLICK-TIME PROTECTION MODULE TEST")
        print("=" * 60)

        threat_hub = ThreatIntelligenceHub()
        protector  = ClickTimeProtection(threat_hub)

        # --- should_rewrite_url ---
        assert not protector.should_rewrite_url("https://deped.gov.ph/page"), \
            "Trusted gov.ph domain should NOT be rewritten"
        assert protector.should_rewrite_url("http://bit.ly/verify"), \
            "Shortened URL should be rewritten"
        print("✓ should_rewrite_url works correctly")

        # --- rewrite_url ---
        rewritten = protector.rewrite_url("http://bit.ly/verify", email_id="test123")
        assert "url=" in rewritten and "email_id=test123" in rewritten
        print(f"✓ rewrite_url: {rewritten[:80]}…")

        # --- extract_and_rewrite_urls ---
        text = "Click here http://bit.ly/verify or visit https://deped.gov.ph"
        new_text, mappings = protector.extract_and_rewrite_urls(text)
        assert len(mappings) == 1, "Only the bit.ly link should be rewritten"
        assert "deped.gov.ph" in new_text, "Trusted URL should remain unchanged"
        print(f"✓ extract_and_rewrite_urls: {len(mappings)} URL(s) rewritten")

        # --- check_url_safety ---
        result = await protector.check_url_safety("http://bit.ly/phishing-test")
        assert "safe" in result and "threat_score" in result
        print(f"✓ check_url_safety: safe={result['safe']}, score={result['threat_score']:.2f}")

        # --- rewrite_email_urls helper ---
        email = {
            "subject":    "Click http://bit.ly/verify now",
            "body_plain": "Verify at http://bit.ly/verify",
            "body_html":  "<p>Verify at <a href='http://bit.ly/verify'>here</a></p>",
        }
        protected = rewrite_email_urls(email, threat_hub)
        assert "url_mappings" in protected
        assert "email_id"     in protected
        total_rewrites = (
            len(protected["url_mappings"]["subject"])
            + len(protected["url_mappings"]["body_plain"])
            + len(protected["url_mappings"]["body_html"])
        )
        print(f"✓ rewrite_email_urls: {total_rewrites} URL mapping(s) created")

        print("=" * 60)
        print("ALL CLICK-TIME PROTECTION TESTS PASSED")
        print("=" * 60)

    asyncio.run(test_click_time_protection())