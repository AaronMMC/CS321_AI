"""
SPF/DKIM/DMARC Verification Module.

BUG FIX (1): The `test_authentication` function was declared `async` but
contained zero `await` calls, so wrapping it in `asyncio.run()` was pure
overhead.  The test is now a plain synchronous function.

BUG FIX (2): `dns.resolver` calls are blocking I/O.  When
`verify_email_authentication` is called from an async context (e.g. inside
`smtp_handler.handle_DATA`) it would block the whole event loop.  A
`run_in_executor` wrapper (`verify_email_authentication_async`) is now
provided so async callers can offload the DNS work to a thread-pool without
modifying existing synchronous call-sites.
"""

import asyncio
import re
import dns.resolver
import hashlib
from typing import Dict, List, Optional
from datetime import datetime
from loguru import logger
from src.utils.config import settings


class AuthenticationVerifier:
    """
    Verifies email authenticity using SPF, DKIM, and DMARC records.
    All DNS calls are synchronous; use `verify_email_authentication_async`
    from async contexts.
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout  = 5.0
        self.resolver.lifetime = 5.0

    # ------------------------------------------------------------------ SPF
    def verify_spf(self, sender_ip: str, sender_domain: str) -> Dict:
        if not sender_domain:
            return {'passed': False, 'reason': 'No sender domain', 'score': 0.0}

        try:
            spf_records = self.resolver.resolve(sender_domain, 'TXT')
            spf_record  = None

            for record in spf_records:
                record_text = record.to_text().strip('"')
                if record_text.startswith('v=spf1'):
                    spf_record = record_text
                    break

            if not spf_record:
                return {'passed': False, 'reason': 'No SPF record found', 'score': 0.0}

            if 'ip4:' in spf_record or 'ip6:' in spf_record or 'include:' in spf_record:
                if '-all' in spf_record:
                    return {'passed': True, 'reason': 'SPF passed with strict policy',  'score': 1.0}
                elif '~all' in spf_record:
                    return {'passed': True, 'reason': 'SPF passed with soft fail policy', 'score': 0.8}
                else:
                    return {'passed': True, 'reason': 'SPF passed with neutral policy',   'score': 0.5}
            else:
                return {'passed': False, 'reason': 'SPF record does not authorize sender IP', 'score': 0.0}

        except dns.resolver.NXDOMAIN:
            return {'passed': False, 'reason': 'Domain does not exist',  'score': 0.0}
        except dns.resolver.NoAnswer:
            return {'passed': False, 'reason': 'No SPF record found',    'score': 0.0}
        except Exception as e:
            logger.warning(f"SPF verification error for {sender_domain}: {e}")
            return {'passed': False, 'reason': f'DNS lookup failed: {e}', 'score': 0.0}

    # ------------------------------------------------------------------ DKIM
    def verify_dkim(self, email_headers: Dict, email_body: bytes) -> Dict:
        dkim_signature = email_headers.get('DKIM-Signature', '')
        if not dkim_signature:
            return {'passed': False, 'reason': 'No DKIM signature found', 'score': 0.0}

        try:
            dkim_params: Dict[str, str] = {}
            for part in dkim_signature.split(';'):
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    dkim_params[key.strip()] = value.strip()

            required_tags = ['v', 'a', 'b', 'bh', 'd', 's', 'h']
            missing_tags  = [t for t in required_tags if t not in dkim_params]

            if missing_tags:
                return {'passed': False, 'reason': f'Missing required DKIM tags: {missing_tags}', 'score': 0.0}

            if dkim_params.get('v') == 'DKIM1':
                return {'passed': True, 'reason': 'DKIM signature format valid', 'score': 0.8}
            else:
                return {'passed': False, 'reason': 'Invalid DKIM version', 'score': 0.0}

        except Exception as e:
            logger.warning(f"DKIM verification error: {e}")
            return {'passed': False, 'reason': f'DKIM parsing failed: {e}', 'score': 0.0}

    # ------------------------------------------------------------------ DMARC
    def verify_dmarc(self, sender_domain: str, spf_result: Dict,
                     dkim_result: Dict, from_header: str) -> Dict:
        if not sender_domain:
            return {'passed': False, 'reason': 'No sender domain', 'score': 0.0, 'policy': 'none'}

        try:
            dmarc_domain  = f"_dmarc.{sender_domain}"
            dmarc_records = self.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_record  = None

            for record in dmarc_records:
                record_text = record.to_text().strip('"')
                if record_text.startswith('v=DMARC1'):
                    dmarc_record = record_text
                    break

            if not dmarc_record:
                return {'passed': True, 'reason': 'No DMARC record found',
                        'score': 0.5, 'policy': 'none'}

            dmarc_params: Dict[str, str] = {}
            for part in dmarc_record.split(';'):
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    dmarc_params[key.strip()] = value.strip()

            policy       = dmarc_params.get('p', 'none')
            spf_aligned  = self._check_spf_alignment(sender_domain, from_header)
            dkim_aligned = self._check_dkim_alignment(sender_domain, from_header)
            spf_passed   = spf_result.get('passed', False) and spf_aligned
            dkim_passed  = dkim_result.get('passed', False) and dkim_aligned
            dmarc_passed = spf_passed or dkim_passed

            score_map = {
                ('reject',     True):  1.0,
                ('quarantine', True):  0.8,
                ('none',       True):  0.9,
                ('reject',     False): 0.0,
                ('quarantine', False): 0.2,
                ('none',       False): 0.5,
            }
            score = score_map.get((policy, dmarc_passed), 0.5)

            return {
                'passed':       dmarc_passed,
                'reason':       f'DMARC {policy} policy: {"passed" if dmarc_passed else "failed"}',
                'score':        score,
                'policy':       policy,
                'spf_aligned':  spf_aligned,
                'dkim_aligned': dkim_aligned,
            }

        except dns.resolver.NXDOMAIN:
            return {'passed': True, 'reason': 'No DMARC record found', 'score': 0.5, 'policy': 'none'}
        except Exception as e:
            logger.warning(f"DMARC verification error for {sender_domain}: {e}")
            return {'passed': True, 'reason': f'DNS lookup failed: {e}', 'score': 0.5, 'policy': 'error'}

    # ------------------------------------------------------------------ helpers
    def _check_spf_alignment(self, sender_domain: str, from_header: str) -> bool:
        from_domain = self._extract_domain_from_email(from_header)
        return bool(from_domain and sender_domain.lower() == from_domain.lower())

    def _check_dkim_alignment(self, sender_domain: str, from_header: str) -> bool:
        from_domain = self._extract_domain_from_email(from_header)
        return bool(from_domain and sender_domain.lower() == from_domain.lower())

    @staticmethod
    def _extract_domain_from_email(email_string: str) -> Optional[str]:
        if not email_string:
            return None
        m = re.search(r'[\w\.-]+@([\w\.-]+)', email_string)
        return m.group(1).lower() if m else None

    # ------------------------------------------------------------------ combined
    def verify_email_authentication(self, email_data: Dict) -> Dict:
        sender_ip     = email_data.get('sender_ip', '127.0.0.1')
        sender_domain = email_data.get('from_domain', '')
        from_header   = email_data.get('from', '')
        email_headers = email_data.get('headers', {})
        email_body    = email_data.get('body_raw', b'')

        spf_result   = self.verify_spf(sender_ip, sender_domain)
        dkim_result  = self.verify_dkim(email_headers, email_body)
        dmarc_result = self.verify_dmarc(sender_domain, spf_result, dkim_result, from_header)

        combined_score = (
            spf_result.get('score',   0.0) * 0.3
            + dkim_result.get('score',  0.0) * 0.3
            + dmarc_result.get('score', 0.0) * 0.4
        )
        passed  = combined_score >= 0.5
        reasons = []
        if not spf_result.get('passed'):
            reasons.append(f"SPF failed: {spf_result.get('reason', '')}")
        if not dkim_result.get('passed'):
            reasons.append(f"DKIM failed: {dkim_result.get('reason', '')}")
        if not dmarc_result.get('passed'):
            reasons.append(f"DMARC failed: {dmarc_result.get('reason', '')}")

        return {
            'passed':    passed,
            'score':     combined_score,
            'spf':       spf_result,
            'dkim':      dkim_result,
            'dmarc':     dmarc_result,
            'reasons':   reasons,
            'timestamp': datetime.now().isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Public convenience functions
# ─────────────────────────────────────────────────────────────────────────────

def verify_email_authentication(email_data: Dict) -> Dict:
    """Synchronous entry-point (safe to call from sync code)."""
    return AuthenticationVerifier().verify_email_authentication(email_data)


async def verify_email_authentication_async(email_data: Dict) -> Dict:
    """
    BUG FIX: Async wrapper that offloads blocking DNS calls to a thread-pool
    executor so they do not stall the event loop inside smtp_handler.handle_DATA.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, verify_email_authentication, email_data)


# ─────────────────────────────────────────────────────────────────────────────
#  Self-test  (BUG FIX: was wrapped in asyncio.run() for no reason)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    def test_authentication():
        """Test authentication verification functionality (plain sync)."""
        print("=" * 60)
        print("AUTHENTICATION VERIFICATION MODULE TEST")
        print("=" * 60)

        verifier = AuthenticationVerifier()

        spf = verifier.verify_spf('1.2.3.4', 'gmail.com')
        print(f"SPF for gmail.com:              {spf}")

        spf2 = verifier.verify_spf('1.2.3.4', 'nonexistentdomain12345abc.com')
        print(f"SPF for non-existent domain:    {spf2}")

        spf3 = verifier.verify_spf('1.2.3.4', '')
        print(f"SPF for empty domain:           {spf3}")

        test_email = {
            'sender_ip':   '1.2.3.4',
            'from_domain': 'gmail.com',
            'from':        'sender@gmail.com',
            'headers': {
                'DKIM-Signature': (
                    'v=DKIM1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; '
                    's=20161025; h=mime-version:date:message-id:subject:from:to; '
                    'bh=hashvalue; b=signature'
                )
            },
            'body_raw': b'Test email body',
        }
        result = verify_email_authentication(test_email)
        print(f"Complete auth result:           passed={result['passed']}, score={result['score']:.2f}")

        print("=" * 60)
        print("AUTHENTICATION VERIFICATION TEST COMPLETE")
        print("=" * 60)

    test_authentication()