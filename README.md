# Email Security Gateway
**AI-Powered Phishing & Spam Detection for Philippine Government Email**

A production-ready email security prototype built for CS321. It intercepts inbound SMTP traffic, scores each message with a lightweight heuristic detector (TinyBERT-compatible interface), enriches predictions with external threat intelligence (VirusTotal, Google Safe Browsing, WHOIS), injects warning/URL protections, and surfaces alerts through a Streamlit admin dashboard and a FastAPI REST service.

---

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Quick Start (Docker)](#quick-start-docker)
3. [Quick Start (Local)](#quick-start-local)
4. [Project Structure](#project-structure)
5. [Configuration](#configuration)
6. [API Reference](#api-reference)
7. [Training a New Model](#training-a-new-model)
8. [Running Tests](#running-tests)
9. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

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
│  Threat Detector    │ ◄────►│  Threat Intel Hub    │
│  (heuristic + API)  │       │  VirusTotal / WHOIS  │
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

---

## Quick Start (Docker)

**Prerequisites:** Docker ≥ 24 and Docker Compose ≥ 2.

```bash
# 1. Clone & enter the repo
git clone <your-repo-url>
cd email-security-gateway

# 2. Copy and edit environment variables
cp .env .env.local          # keep .env as template
# Edit .env: add API keys if you have them (optional for demo)

# 3. Build and start all services
docker compose up --build

# 4. Open the dashboard
open http://localhost:8501   # admin / admin123
# API docs
open http://localhost:8000/docs
```

All three services (API, Dashboard, Redis) start automatically.

---

## Quick Start (Local)

**Prerequisites:** Python 3.10+, pip.

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Download training datasets
python scripts/download_datasets.py --all

# 4. Start all services
bash scripts/start_gateway.sh

# — or start each service individually —
uvicorn src.api.main:app --reload --port 8000
streamlit run src/dashboard/app.py --server.port 8501
```

---

## Project Structure

```
email-security-gateway/
├── src/
│   ├── api/                  # FastAPI application
│   │   ├── main.py           # App factory & core routes
│   │   ├── routes.py         # Additional routers
│   │   ├── dependencies.py   # Dependency injection (model, queue, threat hub)
│   │   └── schemas.py        # Pydantic request/response models
│   ├── models/               # ML and heuristic model interfaces
│   │   ├── tinybert_model.py # Primary lightweight detector (TinyBERT-compatible API)
│   │   ├── bert_classifier.py# Full BERT with external-feature head
│   │   ├── ensemble.py       # Weighted model ensemble
│   │   └── utils.py          # Metrics, save/load helpers
│   ├── features/             # Feature engineering
│   │   ├── external_intelligence.py  # VirusTotal, GSB, WHOIS
│   │   ├── text_features.py          # Keyword / structural features
│   │   ├── url_features.py           # URL structural analysis
│   │   └── metadata_features.py      # Header / attachment features
│   ├── inference/            # Prediction pipeline
│   │   ├── predictor.py      # Single-email predictor (combines all sources)
│   │   ├── batch_predictor.py# Chunked batch prediction
│   │   └── explainer.py      # Human-readable explanations
│   ├── gateway/              # SMTP proxy
│   │   ├── smtp_handler.py   # aiosmtpd-based SMTP interceptor
│   │   ├── email_parser.py   # RFC 822 parser → structured dict
│   │   ├── queue_manager.py  # Async email processing queue
│   │   └── proxy_server.py   # Proxy lifecycle manager
│   ├── training/             # Training pipeline
│   │   ├── trainer.py        # Full training loop
│   │   ├── config.py         # Hyperparameter dataclasses
│   │   ├── cross_validation.py
│   │   └── evaluate.py       # Evaluation & report generation
│   ├── data/                 # Data utilities
│   │   ├── collector.py      # Dataset downloader
│   │   ├── loader.py         # PyTorch Dataset / DataLoader
│   │   ├── preprocessor.py   # Text cleaning pipeline
│   │   └── augmenter.py      # Synthetic data generation
│   ├── dashboard/            # Streamlit UI
│   │   ├── app.py            # Main dashboard entry point
│   │   ├── alerts.py         # Alert visualisation components
│   │   └── admin.py          # Admin panel (users, logs, training)
│   ├── alerting/             # Notification channels
│   │   ├── sms.py            # Twilio SMS
│   │   ├── email.py          # SMTP email alerts
│   │   └── telegram.py       # Telegram bot
│   └── utils/
│       ├── config.py         # Settings (reads .env)
│       ├── logger.py         # Loguru setup
│       ├── helpers.py        # Cache, score calculator, misc
│       └── validators.py     # Email / URL / domain validators
├── tests/
│   ├── test_models/test_bert.py
│   └── test_api/test_api.py
├── scripts/
│   ├── start_gateway.sh      # Start all services (local)
│   ├── stop_gateway.sh       # Stop all services
│   ├── download_datasets.py  # Download training data
│   └── test_system.py        # End-to-end smoke test
├── notebooks/
│   ├── 01_eda.ipynb
│   ├── 02_data_preprocessing.ipynb
│   ├── 03_model_experiments.ipynb
│   └── 04_evaluation.ipynb
├── data/
│   ├── raw/                  # Downloaded datasets (git-ignored)
│   └── processed/            # Cleaned train/val/test splits
├── models_saved/             # Saved model weights (git-ignored)
├── logs/                     # Runtime logs (git-ignored)
├── quarantine/               # Quarantined emails (git-ignored)
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env                      # Environment variables (never commit secrets)
```

---

## Configuration

All settings are driven by environment variables loaded from `.env`.

| Variable | Default | Description |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | *(empty)* | VirusTotal v3 API key |
| `GOOGLE_SAFE_BROWSING_API_KEY` | *(empty)* | Google Safe Browsing API key |
| `TWILIO_ACCOUNT_SID` | *(empty)* | Twilio account SID for SMS alerts |
| `TWILIO_AUTH_TOKEN` | *(empty)* | Twilio auth token |
| `TELEGRAM_BOT_TOKEN` | *(empty)* | Telegram bot token |
| `DATABASE_URL` | `sqlite:///email_security.db` | SQLAlchemy database URL |
| `MODEL_PATH` | `models_saved/bert_phishing_detector_v1` | Optional path to full BERT artifacts |
| `TINYBERT_MODEL_PATH` | `models_saved/tinybert_enron_spam` | Optional path to saved detector metadata |
| `ADMIN_EMAIL` | `admin@prototype.local` | Recipient for email alerts |
| `ADMIN_PHONE` | *(empty)* | Phone number for SMS alerts |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

> **API keys are optional.** Without them, the system uses mock/heuristic scores so you can still run and demo the full pipeline locally.

---

## API Reference

Interactive docs are available at **http://localhost:8000/docs** once the API is running.

### Core endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Service info + model status |
| `POST` | `/api/v1/check-email` | Analyse a single email |
| `POST` | `/api/v1/check-batch` | Queue a batch of emails |
| `GET` | `/api/v1/job-status/{job_id}` | Poll a queued job |
| `GET` | `/api/v1/alerts` | List recent alerts |
| `GET` | `/api/v1/stats` | Queue and model statistics |
| `POST` | `/api/v1/feedback` | Submit human-in-the-loop label |
| `POST` | `/api/v1/whitelist` | Add sender to whitelist |
| `POST` | `/api/v1/blacklist` | Add sender to blacklist |

### Example — check a single email

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
    "High threat score detected",
    "Found 1 URL(s) in email",
    "Subject contains urgency/verification keywords"
  ],
  "timestamp": "2024-01-20T14:32:00",
  "job_id": "job_1705758720.123_-1234567890"
}
```

---

## Training a New Model

```bash
# 1. Download datasets (optional)
python scripts/download_datasets.py --all

# 2. (Optional) use only 20% of the data for a quick run
python scripts/download_datasets.py --train --sample 0.2

# 3. Run quick compatibility training/calibration
python - <<'EOF'
from src.models.tinybert_model import TinyBERTForEmailSecurity, create_mini_dataset_for_quick_training

texts, labels = create_mini_dataset_for_quick_training()
model = TinyBERTForEmailSecurity()
history = model.train_quick(texts, labels, epochs=3)
model.save_model("models_saved/tinybert_custom_v1")
print("Done!", history)
EOF

# 4. Train and export a real transformer artifact (optional)
python scripts/train_real_model.py --epochs 2 --batch-size 8 --output models_saved/real_tinybert
```

Set `TINYBERT_MODEL_PATH` in `.env` to a saved model directory.
If the directory contains transformer artifacts (for example `config.json` + tokenizer files), runtime will load transformer inference; otherwise it falls back to the heuristic backend.

---

## Running Tests

```bash
# All tests
pytest tests/ -v

# Model tests only
pytest tests/test_models/ -v

# API tests only
pytest tests/test_api/ -v

# End-to-end smoke test (requires running API)
python scripts/test_system.py
```

---

## Troubleshooting

**Model behaves as rule-based detector**
This happens when no transformer artifact path is available. Set `TINYBERT_MODEL_PATH` to a trained artifact directory (for example `models_saved/real_tinybert`) to enable transformer inference.

**Port already in use**
```bash
bash scripts/stop_gateway.sh
# then restart
bash scripts/start_gateway.sh
```

**API returns 503 "Model not loaded"**
Model initialisation failed. Check `logs/api.log` for the error. You can also test the detector directly:
```bash
python -c "from src.models.tinybert_model import TinyBERTForEmailSecurity; m = TinyBERTForEmailSecurity(); print(m.predict('test email'))"
```

**Dashboard shows mock data**
This is expected when the API is unreachable. Start the API first (`uvicorn src.api.main:app --reload`), then restart the dashboard.

**VirusTotal / Google SB returns zeros**
No API keys are configured. Add them to `.env`. The system degrades gracefully and still uses model + heuristic scores.

**SMTP warnings/rewritten links are not visible in delivered email**
Ensure the current `src/gateway/smtp_handler.py` is deployed. Newer code mutates outbound RFC822 bytes before relay so subject/body/header changes survive forwarding.

---

## License

MIT — see `LICENSE` for details.