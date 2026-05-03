#!/usr/bin/env python3
"""
run.py — One-file launcher for the Email Security Gateway
=========================================================
python run.py                     # auto-train (5 min cap) then start API + Dashboard
python run.py --all               # API + Dashboard + SMTP Gateway
python run.py --api               # API only
python run.py --dashboard         # Dashboard only
python run.py --retrain           # force retrain even if model exists
python run.py --max-train-minutes 10   # allow up to 10 minutes for training
python run.py --no-gpu            # force CPU training
python run.py --test              # system self-test
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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

MODEL_SAVE_PATH = "models_saved/email_security_model"


def check_python():
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 8):
        err(f"Python 3.8+ required. You have {major}.{minor}"); sys.exit(1)
    ok(f"Python {major}.{minor}")


def check_dependencies():
    required = [
        ("fastapi",   "fastapi"),
        ("uvicorn",   "uvicorn"),
        ("streamlit", "streamlit"),
        ("torch",     "torch"),
        ("loguru",    "loguru"),
        ("dotenv",    "python-dotenv"),
        ("pydantic",  "pydantic"),
        ("aiosmtpd",  "aiosmtpd"),
        ("sklearn",   "scikit-learn"),
        ("numpy",     "numpy"),
        ("pandas",    "pandas"),
        ("tqdm",      "tqdm"),
    ]
    missing = []
    for mod, pkg in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)

    if missing:
        warn(f"Missing packages: {', '.join(missing)}")
        info("Installing …")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing, "-q"])
        ok("Packages installed")
    else:
        ok("All required packages present")


def ensure_directories():
    for d in ["logs", "models_saved", "quarantine", "cache",
              "data/raw", "data/processed",
              "cache/virustotal", "cache/googlesb", "cache/whois", "cache/patterns"]:
        Path(d).mkdir(parents=True, exist_ok=True)
    ok("Runtime directories ready")


def ensure_env_file():
    env = Path(".env")
    if not env.exists():
        env.write_text(
            "# Email Security Gateway – auto-generated .env\n"
            "# See .env.example for all options including Gmail alerts\n"
            "VIRUSTOTAL_API_KEY=\n"
            "GOOGLE_SAFE_BROWSING_API_KEY=\n"
            "SMTP_SERVER=localhost\n"
            "SMTP_PORT=25\n"
            "DATABASE_URL=sqlite:///email_security.db\n"
            f"TINYBERT_MODEL_PATH={MODEL_SAVE_PATH}\n"
            "GMAIL_ADDRESS=\n"
            "GMAIL_APP_PASSWORD=\n"
            "ALERT_RECIPIENT=\n"
            "GMAIL_ALERT_THRESHOLD=0.6\n"
            "ADMIN_EMAIL=admin@prototype.local\n"
            "LOG_LEVEL=INFO\n"
            "LOG_FILE=logs/email_security.log\n"
        )
        warn(".env created — edit it to add your Gmail credentials for alerts")
    else:
        ok(".env file present")


def model_exists() -> bool:
    return Path(f"{MODEL_SAVE_PATH}/model_weights.pt").exists()


def training_data_exists() -> bool:
    return (Path("data/processed/training_data.csv").exists() or
            Path("data/processed/synthetic_training_data.csv").exists())


def download_data():
    banner("Step 1 — Downloading Training Data")
    try:
        from scripts.download_datasets import DatasetDownloader
        dl = DatasetDownloader()
        results = dl.download_all()
        failed = [k for k, v in results.items() if not v]
        if failed:
            warn(f"Some downloads failed (will use synthetic fallback): {failed}")
        dl.create_training_data(sample_frac=0.2)
        ok("Training data ready")
    except Exception as e:
        warn(f"Download failed ({e}) — synthetic data will be used")


def train_model(max_minutes: float, no_gpu: bool):
    banner("Step 2 — Training AI Model from Scratch")
    cmd = [
        sys.executable, "scripts/train_model.py",
        "--max-minutes", str(max_minutes),
        "--epochs", "20",
    ]
    if no_gpu:
        cmd.append("--no-gpu")
    subprocess.run(cmd, cwd=str(ROOT))


def ensure_model_ready(max_minutes: float, force_retrain: bool, no_gpu: bool):
    if force_retrain:
        info("--retrain flag: re-downloading data and retraining")

    if force_retrain or not training_data_exists():
        download_data()
    else:
        ok("Training data already present")

    if force_retrain or not model_exists():
        train_model(max_minutes, no_gpu)
    else:
        ok(f"Trained model already at {MODEL_SAVE_PATH}")


_procs: list = []

def _spawn(cmd, label):
    info(f"Starting {label} …")
    proc = subprocess.Popen(cmd, cwd=str(ROOT),
                            env={**os.environ, "PYTHONPATH": str(ROOT)})
    _procs.append(proc)
    return proc


def start_api():
    return _spawn([sys.executable, "-m", "uvicorn", "src.api.main:app",
                   "--host", "0.0.0.0", "--port", "8000", "--reload"],
                  "API (port 8000)")

def start_dashboard():
    return _spawn([sys.executable, "-m", "streamlit", "run", "src/dashboard/app.py",
                   "--server.port", "8501", "--server.address", "0.0.0.0",
                   "--server.headless", "true"],
                  "Dashboard (port 8501)")

def start_gateway():
    return _spawn([sys.executable, "-c",
                   "import asyncio; from src.gateway.smtp_handler import run_gateway; asyncio.run(run_gateway())"],
                  "SMTP Gateway (port 10025)")


def _shutdown(sig, frame):
    warn("Shutting down all services …")
    for p in _procs:
        try: p.terminate()
        except Exception: pass
    sys.exit(0)


def wait_for_api(timeout=30):
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen("http://localhost:8000/", timeout=1)
            ok("API is up"); return True
        except Exception:
            time.sleep(1)
    warn("API did not respond in time — check logs/api.log")
    return False


def run_self_test():
    banner("System Self-Test")
    if not model_exists():
        err("No trained model found — run without --test first")
        sys.exit(1)

    passed = failed = 0

    def t(name, fn):
        nonlocal passed, failed
        try:
            fn(); ok(name); passed += 1
        except Exception as exc:
            err(f"{name}: {exc}"); failed += 1

    def _model():
        from src.models.scratch_transformer import ScratchModelForEmailSecurity
        m = ScratchModelForEmailSecurity.load(MODEL_SAVE_PATH)
        r = m.predict("Meeting at 10am tomorrow")
        assert isinstance(r, dict) and 0 <= r["threat_score"] <= 1
        r2 = m.predict("URGENT click here to verify your account now")
        assert isinstance(r2, dict) and 0 <= r2["threat_score"] <= 1

    t("Model load + predict", _model)

    def _threat():
        from src.features.external_intelligence import ThreatIntelligenceHub
        hub = ThreatIntelligenceHub()
        feats = hub.get_features_for_model("test", ["http://bit.ly/verify"])
        assert len(feats) == 4

    t("Threat Intelligence Hub", _threat)

    def _parser():
        from src.gateway.email_parser import EmailParser
        p = EmailParser()
        data = p.parse_raw_email(b"From: a@b.com\r\nSubject: Hi\r\n\r\nHello")
        assert "subject" in data

    t("Email Parser", _parser)

    def _warning():
        from src.features.warning_injection import EmailWarningInjector, WarningLevel
        inj = EmailWarningInjector()
        r = inj.inject_warning(
            {"subject": "URGENT", "body": "Click here", "headers": {}, "threat_score": 0.9},
            WarningLevel.CRITICAL,
        )
        assert r["modified"] and "[SUSPICIOUS]" in r["subject"]

    t("Warning Injection", _warning)

    def _email_alert():
        from src.alerting.email import MockEmailAlertSender
        mock = MockEmailAlertSender()
        result = mock.send_alert("admin@test.local", {
            "threat_score": 0.9, "risk_level": "CRITICAL",
            "from": "x@y.com", "subject": "Test", "urls": [],
        })
        assert result is True

    t("Email Alert (mock)", _email_alert)

    print()
    info(f"Results: {passed} passed, {failed} failed")
    if failed == 0:
        ok("All tests passed ✔")
    else:
        warn("Some tests failed — see errors above")


def main():
    p = argparse.ArgumentParser(description="Email Security Gateway — launcher")
    p.add_argument("--all",               action="store_true")
    p.add_argument("--api",               action="store_true")
    p.add_argument("--dashboard",         action="store_true")
    p.add_argument("--gateway",           action="store_true")
    p.add_argument("--retrain",           action="store_true")
    p.add_argument("--test",              action="store_true")
    p.add_argument("--no-gpu",            action="store_true",
                   help="Force CPU training even if GPU is available")
    p.add_argument("--max-train-minutes", type=float, default=5.0,
                   help="Maximum training time in minutes (default: 5)")
    args = p.parse_args()

    banner("Email Security Gateway")
    check_python()
    check_dependencies()
    ensure_directories()
    ensure_env_file()

    if args.test:
        run_self_test(); return

    ensure_model_ready(
        max_minutes=args.max_train_minutes,
        force_retrain=args.retrain,
        no_gpu=args.no_gpu,
    )

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    start_api_flag  = args.api or args.all or not any([args.api, args.dashboard, args.gateway, args.all])
    start_dash_flag = args.dashboard or args.all or not any([args.api, args.dashboard, args.gateway, args.all])
    start_gw_flag   = args.gateway or args.all

    launched = []
    if start_api_flag:
        launched.append(("API",       start_api(),       "http://localhost:8000"))
    if start_dash_flag:
        if start_api_flag:
            info("Waiting for API …"); wait_for_api()
        launched.append(("Dashboard", start_dashboard(), "http://localhost:8501"))
    if start_gw_flag:
        launched.append(("Gateway",   start_gateway(),   "localhost:10025 (SMTP)"))

    if not launched:
        err("Nothing to start — use --help"); sys.exit(1)

    banner("All services running")
    for name, _, url in launched:
        print(f"  {GREEN}{name:<12}{RESET}  {url}")
    print(f"\n  {YELLOW}Press Ctrl-C to stop all services{RESET}\n")

    try:
        while True:
            for name, proc, _ in launched:
                if proc.poll() is not None:
                    err(f"{name} exited — check logs/")
            time.sleep(2)
    except KeyboardInterrupt:
        _shutdown(None, None)


if __name__ == "__main__":
    main()