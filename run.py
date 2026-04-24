#!/usr/bin/env python3
"""
run.py - One-file launcher for the Email Security Gateway
========================================================
Run this from the project root:

    python run.py              # start API + Dashboard (default)
    python run.py --api        # API only
    python run.py --dashboard  # Dashboard only
    python run.py --test       # run the system self-test

Requirements:
    pip install -r requirements.txt
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

# Ensure project root is on PYTHONPATH
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()


def ok(msg):
    print(f"[OK]  {msg}")

def warn(msg):
    print(f"[WARN]  {msg}")

def err(msg):
    print(f"[ERROR]  {msg}")

def info(msg):
    print(f"[INFO]  {msg}")

def banner(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def check_python():
    """Check Python version"""
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 8):
        err(f"Python 3.8+ required. You have {major}.{minor}")
        sys.exit(1)
    ok(f"Python {major}.{minor}")


def check_dependencies():
    """Check that the critical packages can be imported."""
    required = [
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
        ("streamlit", "streamlit"),
        ("torch", "torch"),
        ("loguru", "loguru"),
        ("dotenv", "python-dotenv"),
        ("pydantic", "pydantic"),
    ]
    missing = []
    for mod, pkg in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)

    if missing:
        warn(f"Missing packages: {', '.join(missing)}")
        info("Installing missing packages ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing, "-q"])
        ok("Packages installed")
    else:
        ok("All required packages present")


def ensure_directories():
    """Create runtime directories that must exist."""
    dirs = ["logs", "models_saved", "quarantine", "cache", "data/raw", "data/processed"]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
    ok("Runtime directories ready")


def test_model():
    """Test if the model works"""
    try:
        from src.models.tinybert_model import TinyBERTForEmailSecurity
        info("Loading threat detection model...")
        model = TinyBERTForEmailSecurity(use_gpu=False)
        
        # Test prediction
        test_result = model.predict("URGENT: Verify your account now")
        ok(f"Model loaded successfully")
        info(f"Test prediction: {test_result}")
        return True
    except Exception as e:
        err(f"Model test failed: {e}")
        return False


def start_api():
    """Start the API server"""
    info("Starting API server on http://localhost:8000")
    info("API docs available at http://localhost:8000/docs")
    subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "src.api.main:app",
         "--host", "0.0.0.0", "--port", "8000", "--reload"],
        cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )


def start_dashboard():
    """Start the Streamlit dashboard"""
    info("Starting Dashboard on http://localhost:8501")
    info("Login credentials: admin / admin123")
    subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "src/dashboard/app.py",
         "--server.port", "8501", "--server.address", "0.0.0.0",
         "--server.headless", "true"],
        cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )


def main():
    parser = argparse.ArgumentParser(
        description="Email Security Gateway - one-file launcher",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--all", action="store_true", help="API + Dashboard")
    parser.add_argument("--api", action="store_true", help="API only (port 8000)")
    parser.add_argument("--dashboard", action="store_true", help="Dashboard only (port 8501)")
    parser.add_argument("--test", action="store_true", help="Run system self-test")
    args = parser.parse_args()

    banner("Email Security Gateway")

    # Pre-flight checks
    check_python()
    check_dependencies()
    ensure_directories()

    if args.test:
        banner("System Self-Test")
        
        # Test model
        ok("Testing model...")
        model_ok = test_model()
        
        # Test imports
        ok("Testing API imports...")
        try:
            from src.api.main import app
            ok("API module loads successfully")
        except Exception as e:
            err(f"API import failed: {e}")
        
        ok("Testing dashboard imports...")
        try:
            from src.dashboard import app as dashboard_app
            ok("Dashboard module loads successfully")
        except Exception as e:
            err(f"Dashboard import failed: {e}")
        
        banner("Self-Test Complete")
        print("\nTo start the system:")
        print("  python run.py          # Start API + Dashboard")
        print("  python run.py --api    # API only")
        print("  python run.py --dashboard  # Dashboard only")
        return

    # Determine what to start
    start_api_flag = args.api or args.all
    start_dash_flag = args.dashboard or args.all
    
    # Default: start both if no flags provided
    if not start_api_flag and not start_dash_flag:
        start_api_flag = True
        start_dash_flag = True

    banner("Starting Services")
    
    if start_api_flag:
        start_api()
        time.sleep(2)  # Give API time to start
    
    if start_dash_flag:
        start_dashboard()

    banner("All services started")
    print(f"  API:       http://localhost:8000")
    print(f"  Dashboard: http://localhost:8501")
    print(f"\n  Login: admin / admin123")
    print(f"\n  Press Ctrl+C to stop\n")
    
    # Keep alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
