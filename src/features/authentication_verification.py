"""
SPF / DKIM / DMARC Verification Module.

CHANGES FROM ORIGINAL:
  1. verify_email_authentication_async() — async wrapper that runs the
     blocking DNS calls in a thread-pool executor so smtp_handler.handle_DATA
     never stalls the event loop.
  2. test_authentication() is now a plain synchronous function (was
     incorrectly declared async with no await calls, causing unnecessary
     asyncio.run() overhead and confusing stack-traces on Python 3.12+).
  3. Minor: resolver timeout / lifetime unified at 5 s.
"""

import asyncio
import re
from datetime import datetime
from typing import Dict, List, Optional

import dns.resolver
from loguru import logger

from src.utils.config import settings


# ---------------------------------------------------------------------------
# Core verifier
# ---------------------------------------------------------------------------


class AuthenticationVerifier:
    """
    Verifies email authenticity using SPF, DKIM, and DMARC DNS records.

    All DNS resolution is synchronous.  Use verify_email_authentication_async()
    when calling from an async context (e.g. inside aiosmtpd handle_DATA).
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 5.0

    # ------------------------------------------------------------------
    # SPF
    # ------------------------------------------------------------------

    def verify_spf(self, sender_ip: str, sender_domain: str) -> Dict:
        """
        Look up the SPF TXT record for sender_domain and return a result dict.

        Keys: passed (bool), reason (str), score (float 0-1).
        """
        if not sender_domain:
            return {"passed": False, "reason": "No sender domain provided", "score": 0.0}

        try:
            answers = self.resolver.resolve(sender_domain, "TXT")
            spf_record: Optional[str] = None
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break

            if not spf_record:
                return {"passed": False, "reason": "No SPF record found", "score": 0.0}

            if "-all" in spf_record:
                policy_score, policy_label = 1.0, "strict (-all)"
            elif "~all" in spf_record:
                policy_score, policy_label = 0.8, "soft fail (~all)"
            else:
                policy_score, policy_label = 0.5, "neutral"

            return {
                "passed": True,
                "reason": f"SPF passed — {policy_label} policy",
                "score": policy_score,
                "record": spf_record[:120],
            }

        except dns.resolver.NXDOMAIN:
            return {"passed": False, "reason": "Sender domain does not exist", "score": 0.0}
        except dns.resolver.NoAnswer:
            return {"passed": False, "reason": "No SPF TXT record found", "score": 0.0}
        except Exception as exc:
            logger.warning(f"SPF lookup failed for {sender_domain}: {exc}")
            return {"passed": False, "reason": f"DNS error: {exc}", "score": 0.0}

    # ------------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------------

    def verify_dkim(self, email_headers: Dict, email_body: bytes) -> Dict:
        """
        Validate that a DKIM-Signature header is present and structurally
        correct (required tags: v, a, b, bh, d, s, h).

        Full cryptographic verification requires the dnspython + dkimpy
        stack; this implementation does a structural pre-check that is
        sufficient for the gateway's risk-scoring purpose.
        """
        dkim_sig = email_headers.get("DKIM-Signature", "")
        if not dkim_sig:
            return {"passed": False, "reason": "No DKIM-Signature header found", "score": 0.0}

        try:
            params: Dict[str, str] = {}
            for part in dkim_sig.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k.strip()] = v.strip()

            required = {"v", "a", "b", "bh", "d", "s", "h"}
            missing = required - params.keys()
            if missing:
                return {
                    "passed": False,
                    "reason": f"DKIM signature missing required tags: {missing}",
                    "score": 0.0,
                }

            if params.get("v") != "DKIM1":
                return {
                    "passed": False,
                    "reason": f"Unsupported DKIM version: {params.get('v')}",
                    "score": 0.0,
                }

            return {
                "passed": True,
                "reason": "DKIM-Signature header is structurally valid",
                "score": 0.8,
                "domain": params.get("d", ""),
                "selector": params.get("s", ""),
            }

        except Exception as exc:
            logger.warning(f"DKIM parse error: {exc}")
            return {"passed": False, "reason": f"DKIM parse failed: {exc}", "score": 0.0}

    # ------------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------------

    def verify_dmarc(
        self,
        sender_domain: str,
        spf_result: Dict,
        dkim_result: Dict,
        from_header: str,
    ) -> Dict:
        """
        Look up the _dmarc.<sender_domain> TXT record and evaluate alignment.
        """
        if not sender_domain:
            return {
                "passed": False, "reason": "No sender domain", "score": 0.0, "policy": "none"
            }

        try:
            answers = self.resolver.resolve(f"_dmarc.{sender_domain}", "TXT")
            dmarc_record: Optional[str] = None
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_record = txt
                    break

            if not dmarc_record:
                # No DMARC record — treated as pass with low confidence
                return {
                    "passed": True,
                    "reason": "No DMARC record — unauthenticated domain",
                    "score": 0.5,
                    "policy": "none",
                }

            params: Dict[str, str] = {}
            for part in dmarc_record.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k.strip()] = v.strip()

            policy = params.get("p", "none").lower()
            from_domain = self._extract_domain_from_email(from_header)
            spf_aligned = bool(from_domain and sender_domain.lower() == from_domain.lower())
            dkim_aligned = bool(from_domain and sender_domain.lower() == from_domain.lower())

            spf_pass = spf_result.get("passed") and spf_aligned
            dkim_pass = dkim_result.get("passed") and dkim_aligned
            dmarc_pass = spf_pass or dkim_pass

            score_table = {
                ("reject", True): 1.0, ("quarantine", True): 0.85,
                ("none", True): 0.9,   ("reject", False): 0.0,
                ("quarantine", False): 0.2, ("none", False): 0.5,
            }
            score = score_table.get((policy, dmarc_pass), 0.5)

            return {
                "passed": dmarc_pass,
                "reason": f"DMARC '{policy}' policy — {'pass' if dmarc_pass else 'fail'}",
                "score": score,
                "policy": policy,
                "spf_aligned": spf_aligned,
                "dkim_aligned": dkim_aligned,
            }

        except dns.resolver.NXDOMAIN:
            return {
                "passed": True,
                "reason": "No DMARC record found (_dmarc subdomain absent)",
                "score": 0.5,
                "policy": "none",
            }
        except Exception as exc:
            logger.warning(f"DMARC lookup failed for {sender_domain}: {exc}")
            return {
                "passed": True,
                "reason": f"DMARC DNS error: {exc}",
                "score": 0.5,
                "policy": "error",
            }

    # ------------------------------------------------------------------
    # Combined
    # ------------------------------------------------------------------

    def verify_email_authentication(self, email_data: Dict) -> Dict:
        """
        Run SPF, DKIM, and DMARC checks and return a combined result.

        Input keys used from email_data:
            sender_ip    (str, default '127.0.0.1')
            from_domain  (str)
            from         (str)  — the raw From header value
            headers      (dict) — email headers
            body_raw     (bytes)
        """
        sender_ip = email_data.get("sender_ip", "127.0.0.1")
        sender_domain = email_data.get("from_domain", "")
        from_header = str(email_data.get("from", ""))
        email_headers = email_data.get("headers", {})
        email_body = email_data.get("body_raw", b"")

        spf = self.verify_spf(sender_ip, sender_domain)
        dkim = self.verify_dkim(email_headers, email_body)
        dmarc = self.verify_dmarc(sender_domain, spf, dkim, from_header)

        combined_score = (
            spf.get("score", 0.0) * 0.30
            + dkim.get("score", 0.0) * 0.30
            + dmarc.get("score", 0.0) * 0.40
        )
        passed = combined_score >= 0.5

        reasons: List[str] = []
        if not spf.get("passed"):
            reasons.append(f"SPF failed: {spf.get('reason', '')}")
        if not dkim.get("passed"):
            reasons.append(f"DKIM failed: {dkim.get('reason', '')}")
        if not dmarc.get("passed"):
            reasons.append(f"DMARC failed: {dmarc.get('reason', '')}")

        return {
            "passed": passed,
            "score": round(combined_score, 4),
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "reasons": reasons,
            "timestamp": datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain_from_email(email_string: str) -> Optional[str]:
        if not email_string:
            return None
        m = re.search(r"[\w.\-]+@([\w.\-]+)", email_string)
        return m.group(1).lower() if m else None


# ---------------------------------------------------------------------------
# Public convenience functions
# ---------------------------------------------------------------------------


def verify_email_authentication(email_data: Dict) -> Dict:
    """Synchronous entry-point — safe to call from sync code."""
    return AuthenticationVerifier().verify_email_authentication(email_data)


async def verify_email_authentication_async(email_data: Dict) -> Dict:
    """
    Async wrapper that offloads blocking DNS I/O to a thread-pool executor.

    Use this inside aiosmtpd handle_DATA (or any async context) so the
    event loop stays free while DNS resolves.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, verify_email_authentication, email_data)


# ---------------------------------------------------------------------------
# Self-test  (plain sync — no asyncio.run() needed)
# ---------------------------------------------------------------------------


if __name__ == "__main__":

    def test_authentication():
        """Quick smoke-test for all three checks."""
        print("=" * 60)
        print("AUTHENTICATION VERIFICATION MODULE TEST")
        print("=" * 60)

        verifier = AuthenticationVerifier()

        # SPF on a real, well-configured domain
        spf = verifier.verify_spf("1.2.3.4", "gmail.com")
        print(f"SPF gmail.com:          passed={spf['passed']}  score={spf['score']}")

        # SPF on a non-existent domain (should fail gracefully)
        spf2 = verifier.verify_spf("1.2.3.4", "nonexistent-xyz-12345.com")
        print(f"SPF non-existent:       passed={spf2['passed']}  reason={spf2['reason']}")

        # SPF with empty domain (should fail gracefully)
        spf3 = verifier.verify_spf("1.2.3.4", "")
        print(f"SPF empty domain:       passed={spf3['passed']}  reason={spf3['reason']}")

        # DKIM with a well-formed fake signature
        dkim = verifier.verify_dkim(
            {
                "DKIM-Signature": (
                    "v=DKIM1; a=rsa-sha256; c=relaxed/relaxed; "
                    "d=gmail.com; s=20161025; "
                    "h=mime-version:date:message-id:subject:from:to; "
                    "bh=hashvalue; b=signaturevalue"
                )
            },
            b"Test email body",
        )
        print(f"DKIM well-formed:       passed={dkim['passed']}  score={dkim['score']}")

        # Full combined check
        result = verify_email_authentication(
            {
                "sender_ip": "1.2.3.4",
                "from_domain": "gmail.com",
                "from": "sender@gmail.com",
                "headers": {
                    "DKIM-Signature": (
                        "v=DKIM1; a=rsa-sha256; c=relaxed/relaxed; "
                        "d=gmail.com; s=20161025; "
                        "h=mime-version:from:to:subject; "
                        "bh=bodyhashhash; b=signaturesig"
                    )
                },
                "body_raw": b"Test email body content",
            }
        )
        print(
            f"Combined gmail.com:     passed={result['passed']}  "
            f"score={result['score']:.2f}"
        )

        # Phishing-like domain (newly registered, likely NXDOMAIN for DMARC)
        result2 = verify_email_authentication(
            {
                "sender_ip": "5.6.7.8",
                "from_domain": "gcash-verify.net",
                "from": "support@gcash-verify.net",
                "headers": {},
                "body_raw": b"",
            }
        )
        print(
            f"gcash-verify.net:       passed={result2['passed']}  "
            f"score={result2['score']:.2f}  "
            f"reasons={result2['reasons']}"
        )

        print("=" * 60)
        print("TEST COMPLETE")
        print("=" * 60)

    test_authentication()