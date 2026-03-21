"""
Test email data for unit and integration tests.
Contains legitimate and phishing email samples.
"""

# Legitimate email samples
LEGITIMATE_EMAILS = [
    {
        "subject": "Meeting Agenda for Tomorrow",
        "body": """Hi Team,

Please find attached the agenda for tomorrow's 10 AM meeting.

Topics:
1. Project status update
2. Q2 planning
3. Resource allocation

Best regards,
John Doe
Project Manager""",
        "from": "john.doe@deped.gov.ph",
        "expected_label": 0
    },
    {
        "subject": "Quarterly Report - Q1 2024",
        "body": """Dear Stakeholders,

Please review the attached quarterly report for Q1 2024.

Highlights:
- 15% increase in efficiency
- 3 new projects launched
- Budget utilization at 78%

Let me know if you have any questions.

Regards,
Finance Department
finance@dict.gov.ph""",
        "from": "finance@dict.gov.ph",
        "expected_label": 0
    },
    {
        "subject": "Leave Request Approved",
        "body": """Hello Maria,

Your leave request for May 15-20, 2024 has been approved.

Remaining leave credits: 12 days
Please ensure your tasks are handed over before your leave.

Best,
HR Department
hr@deped.gov.ph""",
        "from": "hr@deped.gov.ph",
        "expected_label": 0
    },
    {
        "subject": "System Maintenance Notice",
        "body": """Dear Users,

The email system will undergo maintenance on Sunday, April 7, 2024 from 2:00 AM to 4:00 AM.

During this period, email services may be temporarily unavailable.

Thank you for your patience.

IT Support Team
it@dict.gov.ph""",
        "from": "it@dict.gov.ph",
        "expected_label": 0
    },
    {
        "subject": "Training Invitation: Cybersecurity Awareness",
        "body": """Good day!

You are invited to attend the Cybersecurity Awareness Training on April 10, 2024 at 10:00 AM.

Venue: Conference Room A
Duration: 2 hours

Please confirm your attendance by replying to this email.

Best regards,
Training Committee
training@dict.gov.ph""",
        "from": "training@dict.gov.ph",
        "expected_label": 0
    }
]

# Phishing email samples
PHISHING_EMAILS = [
    {
        "subject": "URGENT: Your GCash Account Will Be Suspended",
        "body": """Dear Valued Customer,

Your GCash account has been flagged for unusual activity. To avoid permanent suspension, please verify your account immediately.

Click here to verify: http://bit.ly/gcash-verify-urgent

Failure to verify within 24 hours will result in account closure.

Thank you,
GCash Support Team
support@gcash-security.net""",
        "from": "support@gcash-security.net",
        "expected_label": 1,
        "suspicious_urls": ["http://bit.ly/gcash-verify-urgent"],
        "suspicious_domain": "gcash-security.net"
    },
    {
        "subject": "DICT: Your Email Requires Immediate Verification",
        "body": """ATTENTION:

Your email account has been selected for mandatory verification. Click the link below to complete verification:

http://bit.ly/dict-verify-now

If not verified within 48 hours, your account will be deactivated.

Department of Information and Communications Technology
admin@dict-verify.com""",
        "from": "admin@dict-verify.com",
        "expected_label": 1,
        "suspicious_urls": ["http://bit.ly/dict-verify-now"],
        "suspicious_domain": "dict-verify.com"
    },
    {
        "subject": "You Won $1,000,000! Claim Your Prize",
        "body": """CONGRATULATIONS!

You have been selected as the winner of our $1,000,000 lottery draw!

To claim your prize, please provide:
- Full name
- Bank account details
- Contact number

Click here to claim: http://bit.ly/claim-prize

This is a limited time offer!

Best regards,
International Lottery Commission
prize@lottery-winner.net""",
        "from": "prize@lottery-winner.net",
        "expected_label": 1,
        "suspicious_urls": ["http://bit.ly/claim-prize"],
        "suspicious_domain": "lottery-winner.net"
    },
    {
        "subject": "PayPal: Transaction Disputed - Action Required",
        "body": """Dear Customer,

A recent transaction on your account has been disputed. Please sign in to review:

http://bit.ly/paypal-dispute

If you do not verify within 24 hours, your account will be limited.

Secure your account now!

PayPal Security Center
security@paypal-verify.net""",
        "from": "security@paypal-verify.net",
        "expected_label": 1,
        "suspicious_urls": ["http://bit.ly/paypal-dispute"],
        "suspicious_domain": "paypal-verify.net"
    },
    {
        "subject": "Netflix Subscription Expiring - Update Payment",
        "body": """Dear Netflix Member,

Your payment method needs to be updated to continue enjoying Netflix.

Update now: http://bit.ly/netflix-update

If not updated within 3 days, your subscription will be canceled.

Thank you,
Netflix Billing Team
billing@netflix-support.com""",
        "from": "billing@netflix-support.com",
        "expected_label": 1,
        "suspicious_urls": ["http://bit.ly/netflix-update"],
        "suspicious_domain": "netflix-support.com"
    },
    {
        "subject": "HR: Update Your Payroll Information",
        "body": """Dear Employee,

We are updating our payroll system. Please verify your information:

http://bit.ly/payroll-update

Failure to update may delay your next salary.

HR Department
hr@company-payroll.com""",
        "from": "hr@company-payroll.com",
        "expected_label": 1,
        "suspicious_urls": ["http://bit.ly/payroll-update"],
        "suspicious_domain": "company-payroll.com"
    }
]

# Mixed emails (borderline cases)
MIXED_EMAILS = [
    {
        "subject": "Your Package is Delayed",
        "body": """Dear Customer,

Your package is delayed due to weather conditions.

Track your package here: http://bit.ly/track-package-123

Estimated delivery: April 5, 2024

Thank you for your patience,
Logistics Team
tracking@logistics-ph.com""",
        "from": "tracking@logistics-ph.com",
        "expected_label": 0,  # Legitimate tracking
        "note": "Legitimate tracking link"
    },
    {
        "subject": "Your Package is Delayed - Verify Account",
        "body": """Dear Customer,

Your package is delayed. Please verify your account to receive updates:

http://bit.ly/verify-account

Logistics Department
support@logistics-verify.com""",
        "from": "support@logistics-verify.com",
        "expected_label": 1,  # Phishing variant
        "note": "Phishing version of tracking email"
    }
]


# Test dataset for model evaluation
def get_test_dataset():
    """Return combined test dataset with labels"""
    dataset = []

    for email in LEGITIMATE_EMAILS:
        dataset.append({
            'text': f"{email['subject']} {email['body']}",
            'label': email['expected_label'],
            'type': 'legitimate'
        })

    for email in PHISHING_EMAILS:
        dataset.append({
            'text': f"{email['subject']} {email['body']}",
            'label': email['expected_label'],
            'type': 'phishing',
            'urls': email.get('suspicious_urls', [])
        })

    for email in MIXED_EMAILS:
        dataset.append({
            'text': f"{email['subject']} {email['body']}",
            'label': email['expected_label'],
            'type': 'mixed',
            'note': email.get('note', '')
        })

    return dataset


def get_phishing_urls():
    """Return list of suspicious URLs for testing"""
    return [
        "http://bit.ly/gcash-verify",
        "http://bit.ly/dict-verify",
        "http://bit.ly/paypal-verify",
        "http://phishing-site.com/verify",
        "http://secure-login.net/update",
        "http://account-verify.com",
        "http://bit.ly/suspicious-link",
        "http://tinyurl.com/fake-login"
    ]


def get_legitimate_urls():
    """Return list of legitimate URLs for testing"""
    return [
        "http://deped.gov.ph",
        "http://dict.gov.ph",
        "http://doh.gov.ph",
        "http://dswd.gov.ph",
        "http://mail.google.com",
        "http://office.com",
        "http://github.com"
    ]


def get_test_email_strings():
    """Return raw email strings for parser testing"""

    legit_email_str = """From: "John Doe" <john.doe@deped.gov.ph>
To: maria.santos@deped.gov.ph
Subject: Meeting Agenda for Tomorrow
Date: Mon, 1 Apr 2024 10:00:00 +0800

Hi Maria,

Please find attached the agenda for tomorrow's 10 AM meeting.

Best regards,
John"""

    phishing_email_str = """From: "GCash Support" <support@gcash-verify.net>
To: employee@deped.gov.ph
Subject: URGENT: Account Verification Required
Date: Mon, 1 Apr 2024 14:30:00 +0800

Dear User,

Your GCash account has been limited. Click here to verify: http://bit.ly/gcash-verify

Immediate action required!
"""

    return {
        'legitimate': legit_email_str,
        'phishing': phishing_email_str
    }