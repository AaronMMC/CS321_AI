"""
External intelligence integration module.
Connects to VirusTotal, Google Safe Browsing, WHOIS, and other threat databases.
"""
import numpy as np
import requests
import whois
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
from urllib.parse import urlparse
import asyncio
import aiohttp
from loguru import logger
from src.utils.helpers import Cache
from src.utils.validators import URLValidator, DomainValidator
from src.utils.config import settings


class VirusTotalChecker:
    """Check URLs and domains against VirusTotal database"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.api.virustotal_api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}
        self.cache = Cache(cache_dir="cache/virustotal", ttl_hours=6)

        if not self.api_key:
            logger.warning("VirusTotal API key not configured - will use mock data")

    def check_url(self, url: str) -> Dict:
        """
        Check URL reputation against VirusTotal.

        Returns:
            Dict with:
                - malicious: int (number of vendors flagging as malicious)
                - suspicious: int
                - harmless: int
                - undetected: int
                - score: float (normalized threat score 0-1)
        """
        # Check cache first
        cache_key = f"vt_url_{url}"
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug(f"Cache hit for VirusTotal URL: {url}")
            return cached

        if not self.api_key:
            # Return mock data for development
            mock_result = self._mock_virustotal_result(url)
            self.cache.set(cache_key, mock_result)
            return mock_result

        try:
            # URL encode the URL
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            response = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']

                result = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total': sum(stats.values()),
                    'score': self._calculate_threat_score(stats)
                }

                self.cache.set(cache_key, result)
                return result
            else:
                logger.error(f"VirusTotal API error: {response.status_code}")
                return self._mock_virustotal_result(url)

        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
            return self._mock_virustotal_result(url)

    def _calculate_threat_score(self, stats: Dict) -> float:
        """Calculate normalized threat score from VirusTotal stats"""
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = max(sum(stats.values()), 1)  # Avoid division by zero

        # Weight malicious more than suspicious
        score = (malicious * 1.0 + suspicious * 0.5) / total
        return min(1.0, score)

    def _mock_virustotal_result(self, url: str) -> Dict:
        """Generate mock VirusTotal data for development"""
        # Make it realistic based on URL patterns
        suspicious_patterns = ['bit.ly', 'tinyurl', 'verify', 'secure', 'account']

        malicious = 0
        suspicious = 0

        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if pattern in url_lower:
                malicious += 2
                suspicious += 3

        # Add randomness
        import random
        malicious = min(15, malicious + random.randint(0, 3))
        suspicious = min(20, suspicious + random.randint(0, 5))

        total = 60  # Typical total vendors

        return {
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': total - malicious - suspicious - 5,
            'undetected': 5,
            'total': total,
            'score': (malicious * 1.0 + suspicious * 0.5) / total
        }


class GoogleSafeBrowsingChecker:
    """Check URLs against Google Safe Browsing"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.api.google_safe_browsing_key
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.cache = Cache(cache_dir="cache/googlesb", ttl_hours=12)

        if not self.api_key:
            logger.warning("Google Safe Browsing API key not configured")

    def check_url(self, url: str) -> Dict:
        """Check if URL is in Google's threat list"""
        cache_key = f"gsb_{url}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        if not self.api_key:
            result = self._mock_google_result(url)
            self.cache.set(cache_key, result)
            return result

        try:
            payload = {
                'client': {
                    'clientId': 'email-security-gateway',
                    'clientVersion': '1.0.0'
                },
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }

            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                has_match = 'matches' in data

                result = {
                    'threat_detected': has_match,
                    'threat_types': [m['threatType'] for m in data.get('matches', [])],
                    'score': 0.9 if has_match else 0.0
                }

                self.cache.set(cache_key, result)
                return result
            else:
                logger.error(f"Google SB API error: {response.status_code}")
                return self._mock_google_result(url)

        except Exception as e:
            logger.error(f"Google Safe Browsing check failed: {e}")
            return self._mock_google_result(url)

    def _mock_google_result(self, url: str) -> Dict:
        """Mock Google Safe Browsing response"""
        suspicious = any(p in url.lower() for p in ['bit.ly', 'verify', 'secure'])
        return {
            'threat_detected': suspicious,
            'threat_types': ['SOCIAL_ENGINEERING'] if suspicious else [],
            'score': 0.85 if suspicious else 0.0
        }


class WHOISChecker:
    """Check domain registration details"""

    def __init__(self):
        self.cache = Cache(cache_dir="cache/whois", ttl_hours=24)

    def check_domain(self, domain: str) -> Dict:
        """
        Get WHOIS information for domain.

        Returns:
            Dict with:
                - creation_date: datetime
                - expiration_date: datetime
                - registrar: str
                - age_days: int
                - is_new: bool (created in last 30 days)
                - score: float (threat score based on domain age)
        """
        cache_key = f"whois_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        try:
            # Remove protocol and path if URL was passed
            if domain.startswith('http'):
                domain = urlparse(domain).netloc

            w = whois.whois(domain)

            # Parse creation date
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]

            if creation:
                age_days = (datetime.now() - creation).days
                is_new = age_days < 30

                # New domains are more suspicious
                if age_days < 7:
                    score = 0.9
                elif age_days < 30:
                    score = 0.7
                elif age_days < 90:
                    score = 0.4
                else:
                    score = 0.1
            else:
                age_days = None
                is_new = False
                score = 0.3  # Unknown is somewhat suspicious

            result = {
                'domain': domain,
                'creation_date': creation.isoformat() if creation else None,
                'expiration_date': w.expiration_date.isoformat() if w.expiration_date else None,
                'registrar': w.registrar,
                'age_days': age_days,
                'is_new': is_new,
                'score': score
            }

            self.cache.set(cache_key, result)
            return result

        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {e}")

            # Return mock data
            return {
                'domain': domain,
                'creation_date': None,
                'expiration_date': None,
                'registrar': 'Unknown',
                'age_days': None,
                'is_new': False,
                'score': 0.5  # Medium threat for lookup failures
            }


class ThreatIntelligenceHub:
    """
    Central hub combining all external intelligence sources.
    This is the "multi-source intelligence" core of the system.
    """

    def __init__(self):
        self.vt = VirusTotalChecker()
        self.gsb = GoogleSafeBrowsingChecker()
        self.whois = WHOISChecker()
        self.url_validator = URLValidator()
        self.domain_validator = DomainValidator()

        # Pattern recognition cache
        self.pattern_cache = Cache(cache_dir="cache/patterns", ttl_hours=48)

        logger.info("Threat Intelligence Hub initialized")

    async def analyze_urls_async(self, urls: List[str]) -> Dict[str, Dict]:
        """Analyze multiple URLs asynchronously"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in urls:
                # For simplicity, we're not actually making async API calls here
                # but this structure allows for future optimization
                tasks.append(self._analyze_single_url(url))

            results = await asyncio.gather(*tasks)
            return dict(zip(urls, results))

    async def _analyze_single_url(self, url: str) -> Dict:
        """Analyze a single URL using all sources"""
        # Extract domain
        domain = self.url_validator.extract_domain(url)

        # Get intelligence from all sources
        vt_result = self.vt.check_url(url)
        gsb_result = self.gsb.check_url(url)
        whois_result = self.whois.check_domain(domain) if domain else None

        # Calculate combined score
        scores = []

        if vt_result:
            scores.append(vt_result.get('score', 0) * 0.4)  # 40% weight

        if gsb_result:
            scores.append(gsb_result.get('score', 0) * 0.3)  # 30% weight

        if whois_result:
            scores.append(whois_result.get('score', 0) * 0.3)  # 30% weight

        combined_score = sum(scores) if scores else 0.0

        return {
            'url': url,
            'domain': domain,
            'combined_threat_score': combined_score,
            'virustotal': vt_result,
            'google_safe_browsing': gsb_result,
            'whois': whois_result,
            'threat_level': self._get_threat_level(combined_score)
        }

    def analyze_email_patterns(self, email_batch: List[Dict]) -> Dict:
        """
        Analyze patterns across multiple emails to detect campaigns.
        This is the "pattern recognition across time" feature.
        """
        if len(email_batch) < 2:
            return {'campaign_detected': False, 'similar_emails': 0}

        # Group by sender domain
        domains = {}
        for email in email_batch:
            domain = email.get('from_domain', 'unknown')
            if domain not in domains:
                domains[domain] = []
            domains[domain].append(email)

        # Check for coordinated attacks
        campaigns = []
        for domain, emails in domains.items():
            if len(emails) >= 3:  # Same domain sending to multiple recipients
                campaigns.append({
                    'domain': domain,
                    'count': len(emails),
                    'recipients': [e.get('to') for e in emails],
                    'threat_level': 'HIGH' if len(emails) > 5 else 'MEDIUM'
                })

        return {
            'campaign_detected': len(campaigns) > 0,
            'campaigns': campaigns,
            'total_emails_analyzed': len(email_batch)
        }

    def _get_threat_level(self, score: float) -> str:
        """Convert numerical score to threat level"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "SAFE"

    def get_features_for_model(self, email_text: str, urls: List[str]) -> np.ndarray:
        """
        Extract numerical features from intelligence sources for model input.
        Returns a 4-dimensional feature vector.
        """
        features = [0.0, 0.0, 0.0, 0.0]

        if urls:
            # Analyze first URL (simplified for now)
            url = urls[0]
            domain = self.url_validator.extract_domain(url)

            # Feature 1: URL reputation
            vt_result = self.vt.check_url(url)
            features[0] = vt_result.get('score', 0)

            # Feature 2: Domain age
            if domain:
                whois_result = self.whois.check_domain(domain)
                features[1] = whois_result.get('score', 0.5)

            # Feature 3: External DB hits
            gsb_result = self.gsb.check_url(url)
            features[2] = gsb_result.get('score', 0)

        # Feature 4: Placeholder for pattern matching
        # This would be updated with campaign detection results
        features[3] = 0.0

        return np.array(features, dtype=np.float32)