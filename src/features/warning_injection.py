"""
Email Warning Injection Module.

Injects visual warnings into suspicious emails before delivery.
Per documentation: Marks emails with [SUSPICIOUS] prefix that survives delivery to any device.

Features:
- Modifies email subject with warning prefix
- Injects warning banner into email body
- Adds X-Security-* headers for email clients
- Provides Just-in-Time training explanations
"""

from enum import IntEnum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone


class WarningLevel(IntEnum):
    """Warning severity levels, ordered from safest to most dangerous."""
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class EmailWarningInjector:
    """
    Injects warnings into suspicious emails.
    
    Designed to work with ANY email client by:
    1. Modifying subject line (visible in all clients)
    2. Injecting warning banner at top of body
    3. Adding X-Security headers (for advanced clients)
    """
    
    # Warning prefixes for different levels
    WARNING_PREFIXES = {
        WarningLevel.SAFE: '[SAFE]',
        WarningLevel.LOW: '[LOW RISK]',
        WarningLevel.MEDIUM: '[CAUTION]',
        WarningLevel.HIGH: '[WARNING]',
        WarningLevel.CRITICAL: '[SUSPICIOUS]',
    }
    
    # Explanation templates
    EXPLANATION_TEMPLATES = {
        'high_threat_score': 'High threat score detected ({score:.0%})',
        'suspicious_url': 'Contains suspicious URL(s): {urls}',
        'urgency_tactics': 'Uses urgency/pressure tactics',
        'spoofed_domain': 'Sender domain may be impersonating legitimate organization',
        'suspicious_keywords': 'Contains suspicious keywords: {keywords}',
        'attachment_warning': 'Contains potentially dangerous attachment',
        'new_domain': 'Sender domain is newly registered',
        'free_email_provider': 'Uses free email provider (not typical for official communication)',
    }
    
    # Safety tips for user education (Just-in-Time Training)
    SAFETY_TIPS = [
        'Do NOT click links in this email',
        'Do NOT download attachments',
        'Do NOT reply with personal information',
        'Verify sender identity through official channels',
        'Report this email to your IT department',
        'When in doubt, contact the organization directly using official contact information',
        'Government agencies will NEVER ask for passwords via email',
        'GCash/Landbank/BIR will NEVER send verification links via bit.ly',
    ]
    
    def __init__(self, min_warning_level: WarningLevel = WarningLevel.HIGH):
        """
        Initialize the warning injector.
        
        Args:
            min_warning_level: Minimum threat level to trigger warnings.
                              Default is HIGH - only HIGH/CRITICAL get warnings.
        """
        self.min_warning_level = min_warning_level
    
    def inject_warning(
        self,
        email_data: Dict[str, Any],
        threat_level: WarningLevel,
        explanations: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Inject warning into email.
        
        Args:
            email_data: Email data dict with keys:
                - from: Sender email address
                - to: Recipient email address
                - subject: Email subject
                - body: Email body (plain text or HTML)
                - headers: Optional existing headers dict
                - threat_score: Optional threat score (0-1)
                - risk_level: Optional risk level string
            threat_level: Warning level based on threat assessment
            explanations: Optional list of explanations for why email is suspicious
            
        Returns:
            Modified email data dict with:
                - subject: Modified with warning prefix
                - body: Modified with warning banner
                - headers: Added X-Security-* headers
                - modified: Boolean indicating if email was modified
                - warning_level: The applied warning level
                - warning_info: Additional warning details
        """
        # Check if modification is needed
        should_modify = threat_level >= self.min_warning_level
        
        # Get threat score and explanations from email_data if not provided
        threat_score = email_data.get('threat_score', 0.0)
        _explanations = explanations if explanations is not None else email_data.get('explanations', [])
        explanations: List[str] = _explanations  # Type narrowing
        
        # Determine warning prefix
        warning_prefix = self.WARNING_PREFIXES.get(threat_level, '[WARNING]')
        
        # Start with copy of original email
        result = {
            **email_data,
            'headers': {**email_data.get('headers', {})},
            'modified': False,
            'modified_body': False,
            'warning_level': threat_level,
            'warning_info': {}
        }
        
        # Apply subject modification
        if should_modify:
            original_subject = email_data.get('subject', '')
            result['subject'] = self._modify_subject(original_subject, warning_prefix)
            result['modified'] = True
        
        # Apply body modification
        if should_modify and email_data.get('body'):
            result['body'] = self._inject_body_warning(
                email_data['body'],
                threat_level,
                threat_score,
                explanations
            )
            result['modified_body'] = True
        
        # Add security headers
        if should_modify:
            self._add_security_headers(result['headers'], threat_level, threat_score, explanations)
        
        # Add warning info
        result['warning_info'] = {
            'warning_level': threat_level.name,
            'warning_prefix': warning_prefix,
            'threat_score': threat_score,
            'explanations': explanations,
            'safety_tips': self.SAFETY_TIPS[:3],  # Include top 3 tips
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return result
    
    def _modify_subject(self, subject: str, warning_prefix: str) -> str:
        """
        Add warning prefix to subject line.
        
        Args:
            subject: Original subject line
            warning_prefix: Warning prefix to add (e.g., '[SUSPICIOUS]')
            
        Returns:
            Modified subject line with warning prefix
        """
        # Handle empty subject
        if not subject or not subject.strip():
            return f"{warning_prefix} [No Subject]"
        
        # Check if warning already present (avoid duplicates)
        for prefix in self.WARNING_PREFIXES.values():
            if subject.startswith(prefix):
                # Replace existing warning with new one
                return subject.replace(prefix, warning_prefix, 1)
        
        # Add warning prefix at the beginning
        return f"{warning_prefix} {subject}"
    
    def _inject_body_warning(
        self,
        body: str,
        threat_level: WarningLevel,
        threat_score: float,
        explanations: List[str]
    ) -> str:
        """
        Inject warning banner into email body.
        
        The warning is designed to be visible in ALL email clients.
        
        Args:
            body: Original email body
            threat_level: Warning level
            threat_score: Threat score
            explanations: List of explanations
            
        Returns:
            Body with warning banner prepended
        """
        explanations = explanations or []
        warning_banner = self._generate_warning_banner(
            threat_level,
            threat_score,
            explanations
        )
        
        # Check content type (HTML vs plain text)
        is_html = body.strip().startswith('<') and '<html' in body.lower()
        
        if is_html:
            # For HTML emails, add warning at the beginning of body
            return warning_banner + body
        else:
            # For plain text, add warning at the beginning
            return warning_banner + body
    
    def _generate_warning_banner(
        self,
        threat_level: WarningLevel,
        threat_score: float,
        explanations: List[str]
    ) -> str:
        """
        Generate warning banner content with visual indicators.
        
        Uses emoji symbols for better visual impact while maintaining
        ASCII fallback for email clients that don't support emojis.
        """
        warning_symbol = self._get_warning_symbol(threat_level)
        risk_name = threat_level.name
        
        # Build explanations section
        explanations_text = ""
        if explanations:
            explanations_text = "\n! REASONS THIS EMAIL MAY BE SUSPICIOUS:\n"
            for exp in explanations[:5]:  # Limit to 5 explanations
                explanations_text += f"   * {exp}\n"
        
        # Get relevant safety tips
        relevant_tips = self._get_relevant_safety_tips(explanations)
        tips_text = "\n>>> SAFETY TIPS <<<\n" + "\n".join(f"   * {tip}" for tip in relevant_tips)
        
        banner = f"""
{'='*70}
{warning_symbol}  EMAIL SECURITY WARNING  {warning_symbol}
{'='*70}

! RISK LEVEL: {risk_name}
! THREAT SCORE: {threat_score:.0%}
{'='*70}
{explanations_text}
{tips_text}
{'='*70}
! This warning was added by the Email Security Gateway.
    If you believe this is a false positive, contact your IT department.
{'='*70}

--- Original Email Below ---

"""
        return banner
    
    def _get_warning_symbol(self, level: WarningLevel) -> str:
        """Get warning symbol based on threat level."""
        symbols = {
            WarningLevel.SAFE: '[OK]',
            WarningLevel.LOW: '[i]',
            WarningLevel.MEDIUM: '[!]',
            WarningLevel.HIGH: '[!!]',
            WarningLevel.CRITICAL: '[!!!]',
        }
        return symbols.get(level, '[!]')
    
    def _get_relevant_safety_tips(self, explanations: List[str]) -> List[str]:
        """
        Get relevant safety tips based on explanations.
        
        This provides Just-in-Time Training by tailoring tips to the specific threat.
        """
        tips = []
        explanations_text = ' '.join(explanations).lower()
        
        # Prioritize tips based on detected issues
        if 'url' in explanations_text or 'link' in explanations_text:
            tips.append("Do NOT click any links in this email")
        
        if 'urgency' in explanations_text or 'suspended' in explanations_text:
            tips.append("Legitimate organizations don't create artificial urgency")
        
        if 'gcash' in explanations_text or 'gcash' in explanations_text:
            tips.append("GCash never sends verification links via bit.ly or SMS")
        
        if 'bank' in explanations_text or 'landbank' in explanations_text:
            tips.append("Banks never ask for passwords via email")
        
        if 'attachment' in explanations_text:
            tips.append("Do NOT open any attachments")
        
        if not tips:
            # Default tips
            tips = [
                "Do NOT click links or download attachments",
                "Verify sender through official channels",
                "When in doubt, contact your IT department"
            ]
        
        return tips[:3]  # Return top 3 most relevant tips
    
    def _add_security_headers(
        self,
        headers: Dict[str, str],
        threat_level: WarningLevel,
        threat_score: float,
        explanations: List[str]
    ) -> None:
        """
        Add X-Security-* headers for email clients that support them.
        
        These headers are recognized by some email clients for display.
        """
        headers['X-Security-Threat-Score'] = f'{threat_score:.2f}'
        headers['X-Security-Risk-Level'] = threat_level.name
        headers['X-Security-Warning'] = self.WARNING_PREFIXES.get(threat_level, '[WARNING]')
        headers['X-Security-Analyzed'] = datetime.now(timezone.utc).isoformat()
        
        if explanations:
            # Include first 3 explanations in header (headers have length limits)
            headers['X-Security-Reasons'] = '; '.join(explanations[:3])
    
    def determine_warning_level(self, threat_score: float) -> WarningLevel:
        """
        Determine appropriate warning level based on threat score.
        
        Args:
            threat_score: Threat score between 0.0 and 1.0
            
        Returns:
            Appropriate WarningLevel enum value
        """
        if threat_score >= 0.8:
            return WarningLevel.CRITICAL
        elif threat_score >= 0.6:
            return WarningLevel.HIGH
        elif threat_score >= 0.4:
            return WarningLevel.MEDIUM
        elif threat_score >= 0.2:
            return WarningLevel.LOW
        else:
            return WarningLevel.SAFE


def inject_warning_into_email(
    email_data: Dict[str, Any],
    threat_score: float,
    explanations: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Convenience function to inject warning into email.
    
    Args:
        email_data: Email data dict
        threat_score: Threat score (0-1)
        explanations: Optional list of explanations
        
    Returns:
        Modified email data with warnings
    """
    injector = EmailWarningInjector()
    level = injector.determine_warning_level(threat_score)
    return injector.inject_warning(email_data, level, explanations)
