"""
Standalone test runner for Email Warning Injection module.
Run with: python tests/test_features/run_warning_tests.py
"""

import sys
import importlib.util

# Import only what we need, bypassing src/__init__.py
spec = importlib.util.spec_from_file_location('warning_injection', 'src/features/warning_injection.py')
warning_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(warning_mod)

EmailWarningInjector = warning_mod.EmailWarningInjector
WarningLevel = warning_mod.WarningLevel

print('=' * 60)
print('RUNNING EMAIL WARNING INJECTION TESTS')
print('=' * 60)

# Create injector
injector = EmailWarningInjector()

# Test data
suspicious_email = {
    'from': 'support@gcash-verify.net',
    'to': 'employee@deped.gov.ph',
    'subject': 'URGENT: Your GCash Account Will Be Suspended',
    'body': 'Click here to verify: http://bit.ly/gcash-verify',
    'headers': {},
    'threat_score': 0.85,
    'risk_level': 'CRITICAL',
    'explanations': ['High threat score', 'Suspicious URL detected', 'Urgency tactics']
}

legitimate_email = {
    'from': 'john.doe@deped.gov.ph',
    'to': 'maria.santos@deped.gov.ph',
    'subject': 'Meeting Agenda for Tomorrow',
    'body': 'Hi Team,\n\nPlease find attached the agenda.',
    'headers': {},
    'threat_score': 0.1
}

tests_passed = 0
tests_failed = 0

def test(name, condition, error_msg=""):
    global tests_passed, tests_failed
    if condition:
        print(f"  PASS: {name}")
        tests_passed += 1
    else:
        print(f"  FAIL: {name} - {error_msg}")
        tests_failed += 1

# Test 1: Inject SUSPICIOUS prefix
print("\n1. Subject modification for CRITICAL level:")
result = injector.inject_warning(suspicious_email, WarningLevel.CRITICAL)
print(f"   Original: {suspicious_email['subject']}")
print(f"   Modified: {result['subject']}")
test("SUSPICIOUS prefix added", '[SUSPICIOUS]' in result['subject'])
test("Original content preserved", 'URGENT' in result['subject'] and 'GCash' in result['subject'])

# Test 2: No modification for safe email
print("\n2. Safe email handling:")
result_safe = injector.inject_warning(legitimate_email, WarningLevel.SAFE)
print(f"   Modified: {result_safe['modified']}")
test("Safe email NOT modified", not result_safe['modified'])

# Test 3: Body modification
print("\n3. Body modification:")
print(f"   Body starts with warning: {result['body'][:50]}...")
test("Body warning added", 'WARNING' in result['body'])
test("Explanations included", '! REASONS' in result['body'])

# Test 4: Safety tips
print("\n4. Safety tips (Just-in-Time Training):")
test("Safety tips included", '>>> SAFETY TIPS <<<' in result['body'])
test("Tips are actionable", 'Do NOT click' in result['body'])

# Test 5: Security headers
print("\n5. Security headers:")
headers_list = list(result['headers'].keys())
print(f"   Headers: {headers_list}")
test("Threat score header", 'X-Security-Threat-Score' in result['headers'])
test("Risk level header", 'X-Security-Risk-Level' in result['headers'])
test("Analyzed timestamp", 'X-Security-Analyzed' in result['headers'])

# Test 6: Warning info dict
print("\n6. Warning info metadata:")
test("Warning level correct", result['warning_info']['warning_level'] == 'CRITICAL')
test("Threat score recorded", result['warning_info']['threat_score'] == 0.85)
test("Explanations recorded", len(result['warning_info']['explanations']) == 3)

# Test 7: HIGH level
print("\n7. HIGH level warning:")
result_high = injector.inject_warning(suspicious_email.copy(), WarningLevel.HIGH)
print(f"   Subject: {result_high['subject'][:40]}...")
test("WARNING prefix for HIGH", '[WARNING]' in result_high['subject'])

# Test 8: MEDIUM level
print("\n8. MEDIUM level warning:")
# Create injector that allows MEDIUM level modifications
med_injector = EmailWarningInjector(min_warning_level=WarningLevel.MEDIUM)
result_med = med_injector.inject_warning(suspicious_email.copy(), WarningLevel.MEDIUM)
print(f"   Subject: {result_med['subject'][:40]}...")
test("CAUTION prefix for MEDIUM", '[CAUTION]' in result_med['subject'])

# Test 9: Empty subject handling
print("\n9. Edge cases:")
empty_subj_email = {'subject': '', 'body': 'Test', 'headers': {}, 'threat_score': 0.8}
result_empty = injector.inject_warning(empty_subj_email, WarningLevel.CRITICAL)
test("Empty subject handled", '[SUSPICIOUS]' in result_empty['subject'])

# Test 10: Unicode subject
unicode_email = {'subject': 'Test email', 'body': 'Test', 'headers': {}, 'threat_score': 0.8}
result_unicode = injector.inject_warning(unicode_email, WarningLevel.CRITICAL)
test("Unicode preserved", 'Test email' in result_unicode['subject'])

# Test 11: Warning level determination
print("\n10. Warning level determination:")
test("0.85 = CRITICAL", injector.determine_warning_level(0.85) == WarningLevel.CRITICAL)
test("0.65 = HIGH", injector.determine_warning_level(0.65) == WarningLevel.HIGH)
test("0.45 = MEDIUM", injector.determine_warning_level(0.45) == WarningLevel.MEDIUM)
test("0.25 = LOW", injector.determine_warning_level(0.25) == WarningLevel.LOW)
test("0.15 = SAFE", injector.determine_warning_level(0.15) == WarningLevel.SAFE)

# Test 12: Enum order
print("\n11. Warning level enum order:")
test("SAFE < LOW", WarningLevel.SAFE < WarningLevel.LOW)
test("LOW < MEDIUM", WarningLevel.LOW < WarningLevel.MEDIUM)
test("MEDIUM < HIGH", WarningLevel.MEDIUM < WarningLevel.HIGH)
test("HIGH < CRITICAL", WarningLevel.HIGH < WarningLevel.CRITICAL)

# Test 13: Min warning level config
print("\n12. Minimum warning level configuration:")
config_injector = EmailWarningInjector(min_warning_level=WarningLevel.MEDIUM)
test("MEDIUM emails modified", config_injector.inject_warning(suspicious_email.copy(), WarningLevel.MEDIUM)['modified'])
test("LOW emails NOT modified", not config_injector.inject_warning(suspicious_email.copy(), WarningLevel.LOW)['modified'])

# Test 14: Multiple explanations
print("\n13. Multiple explanations handling:")
multi_exp_email = {
    'subject': 'Test',
    'body': 'Test',
    'headers': {},
    'threat_score': 0.9,
    'explanations': ['Reason 1', 'Reason 2', 'Reason 3', 'Reason 4', 'Reason 5', 'Reason 6']
}
result_multi = injector.inject_warning(multi_exp_email, WarningLevel.CRITICAL)
test("Multiple explanations in body", result_multi['body'].count('Reason') >= 5)

# Test 15: Relevant tips based on explanations
print("\n14. Just-in-Time Training - Relevant tips:")
gcash_email = {
    'subject': 'GCash Verify',
    'body': 'Verify now',
    'headers': {},
    'threat_score': 0.85,
    'explanations': ['GCash impersonation', 'Suspicious URL']
}
result_gcash = injector.inject_warning(gcash_email, WarningLevel.CRITICAL)
test("GCash-specific tip", 'GCash never sends' in result_gcash['body'])

# Summary
print('\n' + '=' * 60)
print(f'TEST SUMMARY: {tests_passed} passed, {tests_failed} failed')
print('=' * 60)

if tests_failed == 0:
    print('\nALL TESTS PASSED!')
else:
    print(f'\nSOME TESTS FAILED - Please review')
    sys.exit(1)
