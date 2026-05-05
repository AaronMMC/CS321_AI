# Email Security Gateway
## CS321 — AI-Powered Email Phishing Detection for Philippine Government

A four-layer email security prototype built entirely from scratch — no pre-trained model weights, no third-party AI services. Every component, from the neural network to the SMTP proxy, is implemented in Python and trained on real public phishing/spam datasets.

---

## What This Project Does

The gateway sits between the internet and an internal mail server, intercepting every inbound email before it reaches a recipient's inbox. Each email is run through four sequential security layers in real time:

**Layer 1 — Email Authentication (SPF / DKIM / DMARC)**
DNS records for the sender's domain are queried to verify the email actually came from who it claims to be from. A mismatch adds a significant boost to the threat score.

**Layer 2 — AI Threat Detection**
The email subject and body are tokenised and fed through a Transformer-based classifier trained from scratch on labelled phishing and legitimate email datasets. The model produces a threat score between 0 and 1. This is combined with external intelligence signals (VirusTotal URL reputation, WHOIS domain age, Google Safe Browsing) using a 60/30/10 weighted formula.

**Layer 3 — Visual Warning Injection**
Emails scoring above the medium threshold (≥ 0.4) are modified before delivery. The subject line gets a visible `[WARNING]` or `[SUSPICIOUS]` prefix, and a plain-text warning banner is prepended to the body explaining why the email was flagged, along with contextual safety tips. This means recipients are warned regardless of which email client they use.

**Layer 4 — Click-Time URL Protection**
Every URL in the email body is rewritten to route through a local security proxy. If a recipient clicks a link after the email arrives, the proxy checks the URL in real time and blocks it if it has become malicious — catching threats that were clean at delivery time.

Emails scoring critically high (≥ 0.8) are quarantined entirely and never reach the inbox. When a threat is detected, an alert email is dispatched to the admin address via Gmail.

---

## The AI Model

The classifier is a `ScratchTransformerClassifier` — a standard Transformer encoder architecture implemented directly in PyTorch with no pre-trained weights of any kind. Every parameter is randomly initialised and trained from the ground up on your own data.

**Architecture:**
- Word-level tokeniser (`SimpleTokenizer`) built from the training corpus — no external vocabulary
- Sinusoidal positional encoding
- 4 Transformer encoder layers, 8 attention heads, embedding dimension 256, FFN dimension 512
- Mean-pooling over real tokens (padding masked out)
- Two-layer classification head with GELU activations and dropout
- Total: approximately 9.82 million parameters

**Why from scratch?** Using a pre-trained model like BERT or TinyBERT would rely on weights generated from data that may not reflect Philippine government email patterns, GCash phishing, DICT impersonation, or other locally-relevant threats. Training from scratch on the actual dataset means the model learns exactly the vocabulary and patterns present in the threat landscape being targeted.

**Training datasets** (downloaded automatically by `scripts/download_datasets.py`):
- Enron spam corpus (~33k emails)
- Nazario phishing corpus
- SpamAssassin corpus
- CEAS 2008 spam challenge dataset
- Nigerian fraud corpus
- Rokibulroni Enron variant

The datasets are normalised to a common `(text, label)` format and split 70/10/20 into train, validation, and test sets with stratification to preserve class balance. Data augmentation (synonym swapping, sentence shuffling, noise insertion) is applied to the training set to improve generalisation.

**Training procedure:**
- Optimiser: AdamW with weight decay 1e-2
- Scheduler: OneCycleLR with 10% warm-up and cosine annealing
- Gradient clipping at max norm 1.0
- Early stopping on validation F1 with patience 3
- Default run: 5-minute wall-clock cap (configurable)

---

## System Components

```
Internet / MTA
       │  SMTP :10025
       ▼
┌─────────────────────┐
│  SMTP Proxy Gateway │  ← intercepts every inbound email
│  smtp_handler.py    │
└────────┬────────────┘
         │ parsed email dict
         ▼
┌─────────────────────┐       ┌──────────────────────┐
│  Scratch Transformer│ ◄────►│  Threat Intel Hub    │
│  (text classifier)  │       │  VirusTotal / WHOIS  │
└────────┬────────────┘       │  Google Safe Browse  │
         │ threat_score       └──────────────────────┘
         ▼
┌─────────────────────┐
│  Decision Engine    │  quarantine / warn / deliver
└────────┬────────────┘
         │
    ┌────┴────┐
    ▼         ▼
FastAPI    Streamlit
REST API   Dashboard
:8000      :8501
```

**`src/gateway/smtp_handler.py`** — aiosmtpd-based SMTP proxy. Receives raw email bytes, coordinates all four security layers, rewrites the envelope if a warning is injected, and forwards to the downstream mail server.

**`src/models/scratch_transformer.py`** — Complete Transformer implementation: tokeniser, positional encoding, encoder layers, classification head, dataset wrapper, and the `ScratchModelForEmailSecurity` high-level wrapper with `train_quick()` and `predict()`.

**`src/features/external_intelligence.py`** — Queries VirusTotal (URL maliciousness scores), WHOIS (domain age), and Google Safe Browsing. Returns a 4-dimensional feature vector used alongside the model score.

**`src/features/warning_injection.py`** — Modifies email subject lines and bodies with visible warnings. Generates contextual Just-in-Time Training safety tips based on the specific threat detected (e.g. GCash-specific advice when a GCash impersonation is detected).

**`src/features/click_time_protection.py`** — Rewrites URLs to a local proxy endpoint. The proxy checks URL safety at click time and renders a block page if a threat is confirmed.

**`src/features/authentication_verification.py`** — SPF, DKIM, and DMARC verification via DNS. Runs in an async thread-pool executor so it never stalls the event loop.

**`src/api/main.py`** — FastAPI REST service exposing `/api/v1/check-email`, `/api/v1/check-batch`, `/api/v1/alerts`, and `/api/v1/stats`. Includes the same four-layer scoring logic so external tools can submit emails for analysis.

**`src/dashboard/app.py`** — Streamlit admin dashboard with real-time metrics, alert management, an email checker, model performance analytics (ROC/PR curves, confusion matrix, training curves parsed from logs), and dataset explorer.

---

## Quick Start

### Step 1 — Train the model

```bash
python scripts/train_model.py
```

This downloads the datasets if missing, trains the Scratch Transformer for up to 5 minutes (configurable), and saves the checkpoint to `models_saved/email_security_model/`.

```bash
# Longer run
python scripts/train_model.py --max-minutes 30 --epochs 20

# Force CPU (if no GPU)
python scripts/train_model.py --no-gpu
```

### Step 2 — Start the services

```bash
# API + Dashboard (recommended)
python run.py

# All services including SMTP gateway
python run.py --all

# Or start individually
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
python -m streamlit run src/dashboard/app.py --server.port 8501
```

### Step 3 — Run the live demo

```bash
python scripts/demo_scenarios.py
```

This runs four scenarios against the API and prints a colour-coded report showing the threat score, risk level, and action taken for each email.

### Step 4 (optional) — Docker

```bash
docker compose up --build
# Dashboard: http://localhost:8501
# API docs:  http://localhost:8000/docs
```

---

## Access Points

| Service | URL |
|---|---|
| Admin Dashboard | http://localhost:8501 (admin / admin123) |
| REST API | http://localhost:8000 |
| API Documentation | http://localhost:8000/docs |
| SMTP Gateway | localhost:10025 |

---

## Configuration

All settings are loaded from `.env`. The file is created automatically on first run.

| Variable | Default | Purpose |
|---|---|---|
| `TINYBERT_MODEL_PATH` | `models_saved/email_security_model` | Path to saved Scratch Transformer checkpoint |
| `GMAIL_ADDRESS` | *(empty)* | Gmail address used to send threat alerts |
| `GMAIL_APP_PASSWORD` | *(empty)* | Gmail App Password (generate at myaccount.google.com/apppasswords) |
| `ALERT_RECIPIENT` | same as GMAIL_ADDRESS | Who receives threat alert emails |
| `GMAIL_ALERT_THRESHOLD` | `0.6` | Minimum score before an alert email is sent |
| `VIRUSTOTAL_API_KEY` | *(empty)* | VirusTotal v3 key — uses mock scores if absent |
| `GOOGLE_SAFE_BROWSING_API_KEY` | *(empty)* | Google SB key — uses mock scores if absent |
| `DATABASE_URL` | `sqlite:///email_security.db` | Database connection string |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

API keys are optional. When absent, the system substitutes heuristic mock scores so the full pipeline remains functional for demonstration.

---

## API Reference

### Analyse a single email

```bash
curl -X POST http://localhost:8000/api/v1/check-email \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "URGENT: Your GCash Account Will Be Suspended",
    "body": "Click here to verify: http://bit.ly/gcash-verify",
    "from_email": "support@gcash-verify.net"
  }'
```

Response:

```json
{
  "threat_score": 0.87,
  "risk_level": "CRITICAL",
  "explanations": [
    "AI model flagged suspicious language",
    "URLs have poor reputation",
    "Contains urgency language",
    "Requests account verification"
  ],
  "auth": {
    "spf": "Fail — No SPF record found",
    "dkim": "Fail — No DKIM-Signature header found",
    "dmarc": "Policy: none — Fail"
  },
  "intel": {
    "virustotal_flags": "5 malicious / 8 suspicious out of 60 vendors",
    "domain_age_label": "Unknown",
    "google_safe_browsing": "Threat detected"
  },
  "timestamp": "2026-05-05T14:32:00",
  "alert_sent": true
}
```

### Other endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Service info, model and alert status |
| `POST` | `/api/v1/check-email` | Analyse a single email |
| `POST` | `/api/v1/check-batch` | Queue a batch for async processing |
| `GET` | `/api/v1/job-status/{job_id}` | Poll a queued job |
| `GET` | `/api/v1/alerts` | List recent alerts |
| `GET` | `/api/v1/stats` | Queue and model statistics |
| `POST` | `/api/v1/feedback` | Submit human-in-the-loop correction |
| `POST` | `/api/v1/whitelist` | Add a sender to the whitelist |
| `POST` | `/api/v1/blacklist` | Add a sender to the blacklist |

---

## Threat Scoring Logic

The final combined score is computed as:

```
combined_score = (model_score × 0.60) + (external_score × 0.30) + (heuristic_score × 0.10)
```

The heuristic score is derived from hand-crafted text features (urgency words, verification requests, prize language, sensitive information requests) and URL structural features (URL shorteners, suspicious TLDs, IP addresses used as hostnames, domain entropy).

| Score range | Risk level | Action |
|---|---|---|
| 0.80 – 1.00 | CRITICAL | Email quarantined — never reaches inbox |
| 0.60 – 0.79 | HIGH | Warning injected, URL rewriting applied, admin alerted |
| 0.40 – 0.59 | MEDIUM | Warning injected, URL rewriting applied |
| 0.20 – 0.39 | LOW | Delivered cleanly |
| 0.00 – 0.19 | SAFE | Delivered cleanly |

---

## Project Structure

```
email-security-gateway/
├── src/
│   ├── models/
│   │   ├── scratch_transformer.py      # Core AI model — Transformer from scratch
│   │   └── bert_classifier.py          # Larger variant (ScratchBERTClassifier)
│   ├── gateway/
│   │   ├── smtp_handler.py             # SMTP proxy — orchestrates all layers
│   │   ├── email_parser.py             # RFC 822 email parser
│   │   └── queue_manager.py            # Async email processing queue
│   ├── features/
│   │   ├── authentication_verification.py  # SPF / DKIM / DMARC
│   │   ├── external_intelligence.py        # VirusTotal, WHOIS, Google SB
│   │   ├── text_features.py                # Hand-crafted NLP features
│   │   ├── url_features.py                 # URL structural analysis
│   │   ├── metadata_features.py            # Header anomaly detection
│   │   ├── warning_injection.py            # Visual warning injection
│   │   ├── click_time_protection.py        # URL rewriting proxy
│   │   └── performance_metrics.py          # Runtime telemetry
│   ├── data/
│   │   ├── collector.py                # Dataset downloader
│   │   ├── preprocessor.py             # Text cleaning pipeline
│   │   ├── loader.py                   # PyTorch Dataset wrapper
│   │   └── augmenter.py                # Synthetic data generation
│   ├── training/
│   │   ├── trainer.py                  # Full training loop
│   │   ├── config.py                   # Hyperparameter dataclasses
│   │   ├── evaluate.py                 # Evaluation and threshold search
│   │   └── cross_validation.py         # Stratified k-fold CV
│   ├── inference/
│   │   ├── predictor.py                # Combined scoring (model + external + heuristic)
│   │   ├── batch_predictor.py          # Batch inference with progress
│   │   └── explainer.py                # Human-readable prediction explanations
│   ├── api/
│   │   └── main.py                     # FastAPI application
│   ├── dashboard/
│   │   ├── app.py                      # Streamlit entry point
│   │   ├── alerts.py                   # Alert visualisation components
│   │   ├── admin.py                    # Admin panel (users, logs, training)
│   │   └── analytics.py               # Performance charts and dataset explorer
│   ├── alerting/
│   │   └── email.py                    # Gmail alert sender
│   └── utils/
│       ├── config.py                   # Environment-based settings
│       ├── logger.py                   # Loguru configuration
│       ├── helpers.py                  # Cache, score calculator
│       └── validators.py              # Email, URL, domain validation
├── scripts/
│   ├── train_model.py                  # Model trainer CLI with time cap and tqdm
│   ├── download_datasets.py            # Dataset downloader and merger
│   ├── demo_scenarios.py               # Live demo runner
│   └── start_gateway.sh / .bat        # Service startup scripts
├── tests/
│   ├── test_features/                  # Warning injection, click-time tests
│   ├── test_models/                    # Model load and prediction tests
│   └── test_api/                       # FastAPI integration tests
├── run.py                              # One-file launcher
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env
```

---

## Running Tests

```bash
# Full test suite
pytest tests/ -v

# Specific modules
pytest tests/test_features/test_warning_injection.py -v
pytest tests/test_models/test_bert.py -v
pytest tests/test_api/test_api.py -v

# System self-test (checks model + all feature modules)
python run.py --test
```

---

## Performance

At typical CPU inference speeds (no GPU), end-to-end latency per email is roughly 150–300 ms. With CUDA the model inference portion drops to under 20 ms. Throughput on a single instance is approximately 200–400 emails per minute. The async queue in `queue_manager.py` buffers traffic spikes gracefully.

---

## License

MIT License — see `LICENSE` for details.

Copyright (c) 2026 Email Security Gateway Contributors