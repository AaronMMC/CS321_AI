---
title: System Overview
updated: 2026-04-26
status: active
---

# System Overview

The Email Security Gateway is an SMTP interception and analysis platform with API and dashboard visibility.

## Core Flow
1. Receive inbound SMTP message (`src/gateway/smtp_handler.py`)
2. Parse RFC822 into structured fields (`src/gateway/email_parser.py`)
3. Verify sender authentication (SPF/DKIM/DMARC)
4. Score message risk using:
	- heuristic detector (`src/models/tinybert_model.py`)
	- external intelligence hub (`src/features/external_intelligence.py`)
5. Decide action:
	- quarantine high risk
	- warn and deliver medium/high
	- deliver low/safe
6. Rewrite URLs for click-time protection on delivered messages
7. Forward modified RFC822 payload to downstream SMTP relay

## Operational Interfaces
- FastAPI: `src/api/main.py` (port 8000)
- Streamlit dashboard: `src/dashboard/app.py` (port 8501)
- SMTP gateway: `src/gateway/smtp_handler.py` (port 10025)

## Important Current Behavior
- Detector baseline is heuristic, not a large downloaded checkpoint.
- Outbound delivery now includes warning/rewritten content at byte level.
- Test baseline is green with dedicated SMTP mutation regression tests.

## Related Pages
- [[hot]]
- [[log]]
- [[concepts/improved-model]]

