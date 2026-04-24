#!/usr/bin/env python3
"""
run.py — One-file launcher for the Email Security Gateway
=========================================================
Run this from the project root:

    python run.py              # start API + Dashboard (default)
    python run.py --all        # start API + Dashboard + SMTP Gateway
    python run.py --api        # API only
    python run.py --dashboard  # Dashboard only
    python run.py --gateway    # SMTP gateway only
    python run.py --train      # quick-train the model on synthetic data
    python run.py --download   # download real datasets then train
    python run.py --test       # run the system self-test

Requirements
------------
    pip install -r requirements.txt
"""

import argparse
import asyncio
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# ── Ensure project root is on PYTHONPATH ──────────────────────────────────────
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
RESET  = "\033[0m"

def ok(msg):   print(f"{GREEN}✓  {msg}{RESET}")
def warn(msg): print(f"{YELLOW}⚠  {msg}{RESET}")
def err(msg):  print(f"{RED}✗  {msg}{RESET}")
def info(msg): print(f"{BLUE}→  {msg}{RESET}")
def banner(title):
    print(f"\n{BLUE}{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
#  PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def check_python():
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 8):
        err(f"Python 3.8+ required. You have {major}.{minor}")
        sys.exit(1)
    ok(f"Python {major}.{minor}")


def check_dependencies():
    """Check that the critical packages can be imported."""
    required = [
        ("fastapi",    "fastapi"),
        ("uvicorn",    "uvicorn"),
        ("streamlit",  "streamlit"),
        ("torch",      "torch"),
        ("loguru",     "loguru"),
        ("dotenv",     "python-dotenv"),
        ("pydantic",   "pydantic"),
        ("aiosmtpd",   "aiosmtpd"),
        ("sklearn",    "scikit-learn"),
        ("numpy",      "numpy"),
        ("pandas",     "pandas"),
    ]
    missing = []
    for mod, pkg in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)

    if missing:
        warn(f"Missing packages: {', '.join(missing)}")
        info("Installing missing packages …")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing, "-q"])
        ok("Packages installed")
    else:
        ok("All required packages present")


def ensure_directories():
    """Create runtime directories that must exist."""
    dirs = ["logs", "models_saved", "quarantine", "cache",
            "data/raw", "data/processed",
            "cache/virustotal", "cache/googlesb", "cache/whois", "cache/patterns"]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
    ok("Runtime directories ready")


def ensure_env_file():
    env = Path(".env")
    if not env.exists():
        env.write_text(
            "# Email Security Gateway – auto-generated .env\n"
            "VIRUSTOTAL_API_KEY=\n"
            "GOOGLE_SAFE_BROWSING_API_KEY=\n"
            "TWILIO_ACCOUNT_SID=\n"
            "TWILIO_AUTH_TOKEN=\n"
            "TELEGRAM_BOT_TOKEN=\n"
            "SMTP_SERVER=localhost\n"
            "SMTP_PORT=25\n"
            "IMAP_SERVER=localhost\n"
            "IMAP_PORT=143\n"
            "DATABASE_URL=sqlite:///email_security.db\n"
            "MODEL_PATH=models_saved/bert_phishing_detector_v1\n"
            "TINYBERT_MODEL_PATH=models_saved/tinybert_enron_spam\n"
            "ADMIN_EMAIL=admin@prototype.local\n"
            "LOG_LEVEL=INFO\n"
            "LOG_FILE=logs/email_security.log\n"
        )
        warn(".env not found – created a default one. Edit it to add API keys.")
    else:
        ok(".env file present")


# ─────────────────────────────────────────────────────────────────────────────
#  MODEL BOOTSTRAPPING
# ─────────────────────────────────────────────────────────────────────────────

def model_exists() -> bool:
    for p in [
        "models_saved/tinybert_enron_spam/model_weights.pt",
        "models_saved/bert_phishing_detector_v1/model_weights.pt",
    ]:
        if Path(p).exists():
            return True
    return False


def quick_train():
    """Train on the built-in synthetic dataset (no internet needed)."""
    banner("Quick-Training Model (synthetic data)")
    from src.models.scratch_transformer import ScratchModelForEmailSecurity, create_mini_dataset_for_quick_training

    texts, labels = create_mini_dataset_for_quick_training()
    info(f"Loaded {len(texts)} synthetic training samples")

    model = ScratchModelForEmailSecurity(embed_dim=128, num_heads=4, num_layers=2)
    model.build_tokenizer(texts)

    from sklearn.model_selection import train_test_split
    train_t, val_t, train_l, val_l = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    history = model.train_quick(
        train_t, train_l, val_t, val_l,
        epochs=5, batch_size=16, learning_rate=3e-4,
    )
    save_path = "models_saved/tinybert_enron_spam"
    model.save(save_path)
    ok(f"Model saved → {save_path}")
    final_loss = history["train_loss"][-1]
    ok(f"Training complete – final loss: {final_loss:.4f}")


def download_and_train(sample_frac: float = 0.2):
    """Download real datasets then train."""
    banner("Downloading Datasets")
    from scripts.download_datasets import DatasetDownloader
    dl = DatasetDownloader()
    dl.download_all()
    path = dl.create_training_data(sample_frac)
    ok(f"Training data at {path}")

    banner("Training on Real Data")
    import pandas as pd
    df = pd.read_csv(path).dropna(subset=["text", "label"])
    texts  = df["text"].tolist()
    labels = df["label"].astype(int).tolist()
    info(f"{len(texts)} samples loaded")

    from src.models.scratch_transformer import ScratchModelForEmailSecurity
    from sklearn.model_selection import train_test_split

    train_t, val_t, train_l, val_l = train_test_split(
        texts, labels, test_size=0.15, random_state=42, stratify=labels
    )

    model = ScratchModelForEmailSecurity()
    model.build_tokenizer(train_t)
    model.train_quick(train_t, train_l, val_t, val_l, epochs=5)
    model.save("models_saved/tinybert_enron_spam")
    ok("Training finished and model saved.")


# ─────────────────────────────────────────────────────────────────────────────
#  SERVICE LAUNCHERS
# ─────────────────────────────────────────────────────────────────────────────

_procs: list[subprocess.Popen] = []


def _spawn(cmd: list[str], label: str) -> subprocess.Popen:
    info(f"Starting {label} …")
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    _procs.append(proc)
    return proc


def start_api() -> subprocess.Popen:
    return _spawn(
        [sys.executable, "-m", "uvicorn", "src.api.main:app",
         "--host", "0.0.0.0", "--port", "8000", "--reload"],
        "API (port 8000)",
    )


def start_dashboard() -> subprocess.Popen:
    return _spawn(
        [sys.executable, "-m", "streamlit", "run", "src/dashboard/app.py",
         "--server.port", "8501", "--server.address", "0.0.0.0",
         "--server.headless", "true"],
        "Dashboard (port 8501)",
    )


async def _run_gateway():
    from src.gateway.proxy_server import run_proxy
    await run_proxy()


def start_gateway_subprocess() -> subprocess.Popen:
    return _spawn(
        [sys.executable, "-c",
         "import asyncio; from src.gateway.proxy_server import run_proxy; asyncio.run(run_proxy())"],
        "SMTP Gateway (port 10025)",
    )


def _shutdown(signum, frame):
    warn("Shutting down …")
    for p in _procs:
        try:
            p.terminate()
        except Exception:
            pass
    sys.exit(0)


def wait_for_api(timeout: int = 30):
    import urllib.request, urllib.error
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen("http://localhost:8000/", timeout=1)
            ok("API is up and responding")
            return True
        except Exception:
            time.sleep(1)
    warn("API did not respond within timeout – check logs/api.log")
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────

def run_self_test():
    banner("System Self-Test")
    passed = 0
    failed = 0

    def t(name, fn):
        nonlocal passed, failed
        try:
            fn()
            ok(name)
            passed += 1
        except Exception as exc:
            err(f"{name}: {exc}")
            failed += 1

    # Model
    def _model():
        from src.models.tinybert_model import TinyBERTForEmailSecurity
        m = TinyBERTForEmailSecurity(use_gpu=False)
        r = m.predict("Meeting at 10am tomorrow")
        assert isinstance(r, dict) and "threat_score" in r
        r2 = m.predict("URGENT click here to verify your GCash account now")
        assert isinstance(r2, dict)

    t("Model load + predict", _model)

    # Threat hub
    def _threat():
        from src.features.external_intelligence import ThreatIntelligenceHub
        hub = ThreatIntelligenceHub()
        feats = hub.get_features_for_model("test", ["http://bit.ly/verify"])
        assert len(feats) == 4

    t("Threat Intelligence Hub", _threat)

    # Email parser
    def _parser():
        from src.gateway.email_parser import EmailParser
        p = EmailParser()
        raw = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Hi\r\n\r\nHello"
        data = p.parse_raw_email(raw)
        assert "subject" in data

    t("Email Parser", _parser)

    # Warning injector
    def _warning():
        from src.features.warning_injection import EmailWarningInjector, WarningLevel
        inj = EmailWarningInjector()
        result = inj.inject_warning(
            {"subject": "URGENT", "body": "Click here", "headers": {},
             "threat_score": 0.9, "explanations": ["Test"]},
            WarningLevel.CRITICAL,
        )
        assert result["modified"]
        assert "[SUSPICIOUS]" in result["subject"]

    t("Warning Injection", _warning)

    # URL features
    def _url():
        from src.features.url_features import URLFeatureExtractor
        ext = URLFeatureExtractor()
        score = ext.score(["http://bit.ly/verify-now"])
        assert 0 <= score <= 1

    t("URL Feature Extractor", _url)

    # Performance metrics
    def _metrics():
        from src.features.performance_metrics import PerformanceMetrics
        m = PerformanceMetrics()
        m.record_email_processed(0.5)
        m.record_threat_detected(0.8, 0.1)
        stats = m.get_current_stats()
        assert stats["emails_processed"] == 1

    t("Performance Metrics", _metrics)

    print()
    info(f"Results: {passed} passed, {failed} failed")
    if failed == 0:
        ok("All tests passed — system is healthy ✔")
    else:
        warn("Some tests failed — review errors above")


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Email Security Gateway – one-file launcher",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--all",       action="store_true", help="API + Dashboard + SMTP gateway")
    parser.add_argument("--api",       action="store_true", help="API only (port 8000)")
    parser.add_argument("--dashboard", action="store_true", help="Dashboard only (port 8501)")
    parser.add_argument("--gateway",   action="store_true", help="SMTP gateway only (port 10025)")
    parser.add_argument("--train",     action="store_true", help="Quick-train model on synthetic data")
    parser.add_argument("--download",  action="store_true", help="Download real datasets then train")
    parser.add_argument("--test",      action="store_true", help="Run system self-test")
    parser.add_argument("--sample",    type=float, default=0.2,
                        help="Fraction of real data to use for training (default: 0.2)")
    args = parser.parse_args()

    banner("Email Security Gateway")

    # Pre-flight
    check_python()
    check_dependencies()
    ensure_directories()
    ensure_env_file()

    # ── Training mode ────────────────────────────────────────────────────────
    if args.train:
        quick_train()
        return

    if args.download:
        download_and_train(args.sample)
        return

    if args.test:
        # Auto-bootstrap model if needed before test
        if not model_exists():
            warn("No trained model found – running quick-train first …")
            quick_train()
        run_self_test()
        return

    # ── Service mode ─────────────────────────────────────────────────────────
    # Bootstrap model if needed
    if not model_exists():
        warn("No trained model found. Auto-training on synthetic data …")
        warn("(Run  python run.py --download  for better accuracy with real data)")
        quick_train()

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    start_api_flag       = args.api or args.all or not any([args.api, args.dashboard, args.gateway, args.all])
    start_dash_flag      = args.dashboard or args.all or not any([args.api, args.dashboard, args.gateway, args.all])
    start_gateway_flag   = args.gateway or args.all

    launched = []

    if start_api_flag:
        p = start_api()
        launched.append(("API",       p, "http://localhost:8000"))
    if start_dash_flag:
        if start_api_flag:
            info("Waiting for API before starting dashboard …")
            wait_for_api()
        p = start_dashboard()
        launched.append(("Dashboard", p, "http://localhost:8501"))
    if start_gateway_flag:
        p = start_gateway_subprocess()
        launched.append(("Gateway",   p, "localhost:10025 (SMTP)"))

    if not launched:
        err("Nothing to start. Use --help to see options.")
        sys.exit(1)

    banner("All services started")
    for name, _, url in launched:
        print(f"  {GREEN}{name:<12}{RESET}  {url}")

    print(f"\n  {YELLOW}Press Ctrl+C to stop all services{RESET}\n")

    # Keep alive – forward exit codes
    try:
        while True:
            for name, proc, _ in launched:
                rc = proc.poll()
                if rc is not None:
                    err(f"{name} exited unexpectedly (code {rc}). Check logs/")
            time.sleep(2)
    except KeyboardInterrupt:
        _shutdown(None, None)


if __name__ == "__main__":
    main()