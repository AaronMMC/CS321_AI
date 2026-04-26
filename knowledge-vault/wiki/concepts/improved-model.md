---
title: Detector Baseline (Improved Model Notes)
updated: 2026-04-26
status: active
---

# Detector Baseline (Improved Model Notes)

This page reconciles earlier "improved TinyBERT" notes with current implementation reality.

## Current Implementation
- `src/models/tinybert_model.py` is a lightweight heuristic detector.
- It exposes a TinyBERT-compatible interface to preserve integration compatibility.
- It supports compatibility methods (`tokenize`, `train_quick`, `save/load`) for existing scripts/tests.

## Why This Matters
- The project can run reliably without downloading large model checkpoints.
- API, gateway, and dashboard integrations remain stable.
- Test suites and training/demo scripts continue to function.

## Behavior Characteristics
- Fast and deterministic rule-based scoring
- Low operational overhead
- External-intelligence augmentation when URLs and API keys are available

## Limits vs. Full Transformer Models
- Not a semantic deep language model in current baseline
- Heuristics can underperform on nuanced social-engineering language
- Should be treated as deployable baseline with clear upgrade path

## Upgrade Path
- Keep `tinybert_model.py` API stable.
- Introduce pluggable backend that can load real transformer checkpoints.
- Compare both backends under the same integration and test contracts.

## Related Pages
- [[../overview]]
- [[../hot]]
- [[../log]]

