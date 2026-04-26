# Email Security Gateway - Project Summary

## Overview
AI-powered phishing and spam detection gateway for Philippine government email workflows.

## Current Runtime Architecture
- API: FastAPI on port 8000
- Dashboard: Streamlit on port 8501
- Gateway: aiosmtpd SMTP interceptor on port 10025
- Detection engine: lightweight heuristic model with TinyBERT-compatible interface
- External intelligence: VirusTotal, Google Safe Browsing, WHOIS (graceful fallback to mock/heuristic behavior when keys are missing)

## Security Pipeline (Current Behavior)
1. Parse inbound SMTP message into structured fields
2. Run SPF/DKIM/DMARC verification (best-effort)
3. Compute threat score via heuristic detector + optional external intelligence
4. Decide action:
   - >= 0.8: quarantine
   - 0.4 to < 0.8: warn and deliver
   - < 0.4: deliver
5. Apply click-time URL rewriting for delivered messages
6. Mutate outbound RFC822 content (subject/body/X-Security headers) before SMTP relay

## Validation Status (April 26, 2026)
- Dependencies installed in `.venv`
- Full test suite passed:
  - 47 passed
  - 0 failed
  - 4 warnings (FastAPI `on_event` deprecation)
- Launcher self-test passed (`python run.py --test`)

## Notable Updates in This Pass
- Patched SMTP forwarding path so warning and rewritten-link mutations are applied to outgoing message bytes
- Normalized warning injection to parsed `body_plain`/`body_html` fields
- Added SMTP regression tests to verify subject/header/body mutation survives forwarding
- Updated model wrapper compatibility (`tokenize`, `tokenizer`, `train_quick`, metadata save/load) so existing tests and scripts run reliably

## Known Technical Debt
1. FastAPI startup/shutdown uses deprecated `@app.on_event` instead of lifespan handlers
2. Linux shell scripts in `scripts/` are not Windows-native orchestration scripts
3. Some docs and knowledge-vault pages required reconciliation and are now being aligned with code truth

## Quick Run Commands
```bash
# API + Dashboard
python run.py

# System self-test
python run.py --test

# Full tests
python -m pytest tests -v
```

## Version Note
Reconciled and validated state as of April 26, 2026.
