---
title: Hot Cache
updated: 2026-04-26
status: active
---

# Hot Cache

## Current State
- Dependencies installed in `.venv` from `requirements.txt`.
- Full automated tests are passing (`47 passed, 0 failed`).
- System launcher smoke test passes via `python run.py --test`.

## Key Runtime Truths
- The active detector in `src/models/tinybert_model.py` is heuristic-based.
- The detector exposes a TinyBERT-compatible API for integration compatibility.
- External intelligence calls degrade gracefully to mock/heuristic paths when API keys are missing.

## Critical Fix Completed
- SMTP forwarding path now sends mutated outbound RFC822 content.
- Subject/body/X-Security header changes now survive relay delivery.
- Warning injection now correctly normalizes parsed body fields (`body_plain` / `body_html`).

## Regression Coverage Added
- New tests in `tests/test_gateway/test_smtp_handler.py` validate:
	- plain-text outbound mutation
	- multipart plain/html outbound mutation
	- warning injection body-field wiring

## Active Technical Debt
- FastAPI startup/shutdown events use deprecated `@app.on_event` hooks.
- Consider migration to lifespan handlers.

## Cross-links
- [[overview]]
- [[log]]
- [[concepts/improved-model]]

