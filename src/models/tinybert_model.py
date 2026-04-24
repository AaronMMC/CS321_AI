"""
Email Security Model - Lightweight heuristic-based threat detection.
This module provides a fast, reliable threat detection without external model dependencies.
"""

import re
from typing import Dict, List, Union
from loguru import logger


class TinyBERTForEmailSecurity:
    """
    Email threat detection model using heuristic-based approach.
    Fast, reliable, and doesn't require downloading external models.
    """
    
    def __init__(self, use_gpu: bool = False):
        """Initialize the threat detection model"""
        self.device = "cpu"  # Always use CPU for reliability
        self.model_loaded = True
        logger.info("Initialized heuristic-based threat detection model")
    
    def predict(self, text: Union[str, List[str]]) -> Union[Dict, List[Dict]]:
        """
        Predict threat scores for one or more texts.
        
        Args:
            text: Single email text or list of texts
            
        Returns:
            Dictionary or list of dictionaries with predictions
        """
        # Handle single input
        if isinstance(text, str):
            return self._heuristic_predict(text)
        else:
            return [self._heuristic_predict(t) for t in text]
    
    def _heuristic_predict(self, text: str) -> Dict:
        """
        Heuristic-based prediction for email threat detection.
        
        Analyzes text for common phishing patterns and assigns a threat score.
        """
        text_lower = text.lower()
        threat_score = 0.0
        
        # High-risk phishing keywords (strong indicators)
        high_risk_keywords = [
            'urgent', 'immediately', 'suspended', 'account limited', 
            'verify now', 'click here', 'confirm identity', 'unauthorized',
            'locked', 'compromised', 'breach', 'terminate', 'closed'
        ]
        
        # Medium-risk keywords
        medium_risk_keywords = [
            'verify', 'update', 'confirm', 'suspended', 'limited',
            'winner', 'prize', 'claim', 'gift', 'free', 'bonus',
            'discount', 'offer', 'expire', 'deadline', 'action required'
        ]
        
        # Check for high-risk keywords
        for keyword in high_risk_keywords:
            if keyword in text_lower:
                threat_score += 0.20
        
        # Check for medium-risk keywords
        for keyword in medium_risk_keywords:
            if keyword in text_lower:
                threat_score += 0.10
        
        # Check for suspicious URLs/domains
        suspicious_domains = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'is.gd']
        for domain in suspicious_domains:
            if domain in text_lower:
                threat_score += 0.15
        
        # Check for suspicious TLDs often used in phishing
        if re.search(r'https?://[^\s]+\.(xyz|tk|ml|ga|cf|gq|top|work|click)', text_lower):
            threat_score += 0.25
        
        # Check for financial keywords
        financial_keywords = ['bank', 'gcash', 'paypal', 'netflix', 'credit card', 
                           'banking', 'wallet', 'invoice', 'payment', 'billing',
                           'payroll', 'salary', 'refund', 'tax']
        for keyword in financial_keywords:
            if keyword in text_lower:
                threat_score += 0.08
        
        # Check for threat/urgency patterns
        urgency_patterns = [
            r'24\s*hours?',
            r'48\s*hours?',
            r'immediate',
            r'within\s*\d+\s*hours?',
            r'last\s*chance',
            r'don\'t\s*miss',
            r'only\s*\d+\s*left'
        ]
        
        for pattern in urgency_patterns:
            if re.search(pattern, text_lower):
                threat_score += 0.12
        
        # Cap the threat score at 1.0
        threat_score = min(1.0, threat_score)
        
        # Determine label based on score
        if threat_score >= 0.7:
            label = "PHISHING"
        elif threat_score >= 0.4:
            label = "SUSPICIOUS"
        else:
            label = "LEGITIMATE"
        
        return {
            'threat_score': threat_score,
            'label': label,
            'confidence': 0.7 + (0.3 * min(threat_score, 1.0))
        }
    
    def train_quick(self, *args, **kwargs):
        """Training not needed for heuristic model"""
        logger.info("Training not needed for heuristic-based model")
        return {'train_loss': [], 'val_accuracy': []}
    
    def save_model(self, path: str):
        """Save not needed for heuristic model"""
        logger.info(f"Model save to {path} (not implemented for heuristic model)")
    
    @classmethod
    def load_model(cls, path: str):
        """Load the model"""
        return cls()


def create_mini_dataset_for_quick_training():
    """
    Create a small dataset for testing.
    Returns (texts, labels) where 0=legit, 1=phishing
    """
    legitimate = [
        "Meeting agenda for tomorrow's project review",
        "Please find attached the quarterly financial report",
        "Your leave request has been approved for next week",
        "Reminder: Team building event this Friday",
        "Project update: All milestones achieved on time",
        "Invoice #12345 for services rendered",
        "Welcome to the team! Here's your onboarding schedule",
        "System maintenance scheduled for Sunday 2 AM",
        "Your password reset request has been processed",
        "Thank you for your application. We'll be in touch",
    ]
    
    phishing = [
        "URGENT: Your account will be suspended in 24 hours. Click here to verify",
        "You have won $1,000,000! Claim your prize now by providing bank details",
        "GCash: Your account has been limited. Verify immediately",
        "Security Alert: Unusual login detected. Confirm your identity",
        "Your Netflix subscription is expiring. Update payment method",
        "DICT: Your email requires immediate verification. Click link",
        "Paypal: Transaction disputed. Sign in to review",
        "Apple ID: Your account has been locked. Unlock now",
        "Tax refund available. Submit form to receive payment",
        "HR Department: Update your payroll information immediately",
    ]
    
    texts = []
    labels = []
    
    for email in legitimate:
        texts.append(email)
        labels.append(0)
    
    for email in phishing:
        texts.append(email)
        labels.append(1)
    
    return texts, labels
