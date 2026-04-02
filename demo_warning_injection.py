#!/usr/bin/env python3
"""
Demonstration script for Email Warning Injection Feature #1
Shows how suspicious emails are marked with visual warnings
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.features.warning_injection import EmailWarningInjector, WarningLevel
from tests.test_data.test_emails import LEGITIMATE_EMAILS, PHISHING_EMAILS, MIXED_EMAILS

def demonstrate_warning_injection():
    """Demonstrate the email warning injection functionality"""
    
    print("=" * 80)
    print("EMAIL SECURITY GATEWAY - FEATURE #1 DEMONSTRATION")
    print("Email Warning Injection Module")
    print("=" * 80)
    print()
    
    # Create injector (default warns on HIGH and CRITICAL levels)
    injector = EmailWarningInjector()
    
    # Test categories
    test_categories = [
        ("LEGITIMATE EMAILS", LEGITIMATE_EMAILS, False),
        ("PHISHING EMAILS", PHISHING_EMAILS, True),
        ("MIXED/BORDERLINE EMAILS", MIXED_EMAILS, True)  # Some will be flagged
    ]
    
    total_processed = 0
    total_warned = 0
    
    for category_name, emails, expect_warnings in test_categories:
        print(f"\n{category_name}:")
        print("-" * 50)
        
        for i, email_data in enumerate(emails, 1):
            total_processed += 1
            
            # Prepare email for processing
            email_to_process = {
                'from': email_data['from'],
                'to': 'recipient@deped.gov.ph',  # Default recipient
                'subject': email_data['subject'],
                'body': email_data['body'],
                'headers': {},
                'threat_score': 0.9 if 'phishing' in email_data.get('note', '').lower() or i <= len(PHISHING_EMAILS) else 0.1,
                'explanations': []  # Would normally come from threat analysis
            }
            
            # Add some realistic explanations for phishing emails
            if i <= len(PHISHING_EMAILS) or 'suspended' in email_data['subject'].lower():
                email_to_process['explanations'] = [
                    'Sender domain impersonates legitimate organization',
                    'Contains suspicious URL shortener (bit.ly)',
                    'Uses urgency/pressure tactics'
                ]
            
            # Determine warning level based on threat score
            threat_score = email_to_process['threat_score']
            warning_level = injector.determine_warning_level(threat_score)
            
            # Process email
            result = injector.inject_warning(email_to_process, warning_level, email_to_process['explanations'])
            
            # Track statistics
            if result['modified']:
                total_warned += 1
                
            # Display results
            status = "WARNING" if result['modified'] else "SAFE"
            print(f"  [{i:2d}] {status} | Score: {threat_score:.2f} | {email_data['subject'][:40]}...")
            
            if result['modified']:
                print(f"      Subject: {result['subject']}")
                if result['modified_body']:
                    # Show first 200 chars of body with warning
                    body_preview = result['body'][:200].replace('\n', ' ') + "..."
                    print(f"      Body:  {body_preview}")
                print(f"      Headers: {list(result['headers'].keys())}")
            print()
    
    # Summary
    print("=" * 80)
    print("DEMONSTRATION SUMMARY")
    print("=" * 80)
    print(f"Total emails processed: {total_processed}")
    print(f"Emails with warnings added: {total_warned}")
    print(f"Percentage warned: {total_warned/total_processed*100:.1f}%")
    print()
    print("KEY FEATURES DEMONSTRATED:")
    print("[OK] Subject line modification with [SUSPICIOUS]/[WARNING]/[CAUTION] prefixes")
    print("[OK] Warning banner injection into email body")
    print("[OK] X-Security-* headers for advanced email clients")
    print("[OK] Just-in-Time training via contextual safety tips")
    print("[OK] Configurable warning thresholds")
    print("[OK] Threat explanation inclusion")
    print()
    print("NEXT STEPS FOR FULL DEPLOYMENT:")
    print("1. Integrate with SMTP handler (smtp_handler.py)")
    print("2. Implement Click-Time Protection (URL rewriting)")
    print("3. Add SPF/DKIM/DMARC verification")
    print("4. Add performance metrics framework")
    print("5. Implement persistence layer (database)")
    print("6. Add authentication and rate limiting")
    print("=" * 80)

if __name__ == "__main__":
    demonstrate_warning_injection()