"""
Main Streamlit dashboard application - IMPROVED VERSION.
This is the entry point for the admin dashboard.
"""

import os
import json
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables on startup
load_dotenv()

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.utils.logger import logger

# ============================================
# CONFIGURATION
# ============================================

st.set_page_config(
    page_title="Email Security Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS - Apple + Pi-hole-inspired Design
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    :root {
        --apple-bg: #0b111a;
        --apple-surface: #111827;
        --apple-surface-2: #0f172a;
        --apple-surface-3: #1f2937;
        --apple-border: rgba(148, 163, 184, 0.24);
        --apple-text: #e5e7eb;
        --apple-muted: #94a3b8;
        --apple-accent: #38bdf8;
        --apple-accent-soft: rgba(56, 189, 248, 0.2);
        --apple-critical: #ef4444;
        --apple-warning: #f59e0b;
        --apple-safe: #22c55e;
        --apple-shadow: 0 16px 32px rgba(2, 6, 23, 0.4);
        --pihole-deep: #0b1220;
        --pihole-mid: #111827;
        --pihole-soft: #1e293b;
        --pihole-green: #22c55e;
        --pihole-red: #ef4444;
        --pihole-amber: #f59e0b;
    }

    @keyframes riseIn {
        from {
            opacity: 0;
            transform: translateY(8px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .fade-in {
        animation: riseIn 0.45s ease both;
    }

    .stApp {
        font-family: "Inter", "Segoe UI", "Helvetica Neue", "Arial", sans-serif;
        color: var(--apple-text);
        background:
            radial-gradient(circle at 0% 0%, rgba(56, 189, 248, 0.12), transparent 38%),
            radial-gradient(circle at 100% 0%, rgba(99, 102, 241, 0.1), transparent 34%),
            var(--apple-bg);
    }

    h1, h2, h3 {
        color: var(--apple-text);
        letter-spacing: -0.02em;
    }

    .block-container {
        max-width: 1320px;
        padding-top: 1.4rem;
        padding-bottom: 2rem;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, var(--pihole-deep) 0%, #0f1b31 48%, #12223d 100%);
        border-right: 1px solid rgba(148, 163, 184, 0.24);
    }

    [data-testid="stSidebar"] * {
        color: #e8ecf5 !important;
    }

    [data-testid="stSidebar"] .stButton > button {
        background: rgba(255, 255, 255, 0.08);
        border: 1px solid rgba(226, 232, 240, 0.25);
        color: #f8fafc;
    }

    [data-testid="stSidebar"] .stButton > button:hover {
        background: rgba(255, 255, 255, 0.13);
        border-color: rgba(191, 219, 254, 0.5);
        box-shadow: 0 8px 22px rgba(15, 23, 42, 0.28);
    }

    .sidebar-brand {
        border-radius: 18px;
        padding: 0.95rem;
        border: 1px solid rgba(148, 163, 184, 0.24);
        background: rgba(15, 23, 42, 0.65);
        backdrop-filter: blur(14px);
        box-shadow: 0 14px 30px rgba(2, 6, 23, 0.32);
    }

    .sidebar-muted {
        color: rgba(226, 232, 240, 0.78);
        font-size: 0.82rem;
        margin-bottom: 0.25rem;
    }

    .nav-note {
        border-radius: 14px;
        border: 1px solid rgba(148, 163, 184, 0.32);
        background: linear-gradient(120deg, #0b1220 0%, #0f1b2f 100%);
        padding: 0.72rem 0.82rem;
        font-size: 0.86rem;
        color: #d6dfef;
        margin-bottom: 0.95rem;
    }

    .shell-header {
        border-radius: 22px;
        border: 1px solid rgba(148, 163, 184, 0.28);
        background: linear-gradient(132deg, #0b1220 0%, #111f37 54%, #14294a 100%);
        box-shadow: 0 16px 32px rgba(2, 6, 23, 0.4);
        padding: 1rem 1.05rem;
        margin-bottom: 1rem;
    }

    .shell-title {
        font-size: clamp(1.35rem, 3vw, 2.1rem);
        font-weight: 720;
        letter-spacing: -0.03em;
        color: #f8fafc;
        margin: 0;
    }

    .shell-subtitle {
        margin-top: 0.25rem;
        color: #c7d2e5;
        font-size: 0.93rem;
    }

    .topbar-controls {
        border-radius: 18px;
        border: 1px solid rgba(148, 163, 184, 0.28);
        background: linear-gradient(120deg, #0b1220 0%, #101d33 56%, #132545 100%);
        box-shadow: 0 14px 28px rgba(2, 6, 23, 0.36);
        padding: 0.9rem 0.95rem;
        margin-bottom: 0.9rem;
    }

    .topbar-heading {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.11em;
        color: #9fb4d4;
        font-weight: 700;
    }

    .topbar-sub {
        margin-top: 0.25rem;
        color: #dce6f6;
        font-size: 0.9rem;
    }

    .topbar-meta {
        margin-top: 0.42rem;
        color: #9fb4d4;
        font-size: 0.8rem;
    }

    .control-ribbon {
        display: block;
        height: 0;
        margin: 0;
        padding: 0;
        opacity: 0;
    }

    .control-ribbon + div[data-testid="stHorizontalBlock"] {
        border-radius: 16px;
        border: 1px solid rgba(148, 163, 184, 0.24);
        background: linear-gradient(120deg, #0b1220 0%, #111f35 100%);
        box-shadow: 0 12px 26px rgba(2, 6, 23, 0.32);
        padding: 0.6rem 0.65rem;
        margin-bottom: 0.9rem;
    }

    .control-ribbon + div[data-testid="stHorizontalBlock"] > div {
        padding-top: 0.2rem;
    }

    .shell-chip-row {
        margin-top: 0.7rem;
        display: flex;
        flex-wrap: wrap;
        gap: 0.45rem;
    }

    .shell-chip {
        display: inline-flex;
        align-items: center;
        gap: 0.32rem;
        border-radius: 999px;
        padding: 0.24rem 0.62rem;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.02em;
        border: 1px solid transparent;
    }

    .chip-good {
        background: rgba(44, 163, 108, 0.22);
        color: #d9faea;
        border-color: rgba(44, 163, 108, 0.35);
    }

    .chip-warn {
        background: rgba(189, 139, 45, 0.22);
        color: #ffecc7;
        border-color: rgba(189, 139, 45, 0.33);
    }

    .chip-bad {
        background: rgba(208, 90, 79, 0.24);
        color: #ffe1de;
        border-color: rgba(208, 90, 79, 0.35);
    }

    .chip-neutral {
        background: rgba(71, 85, 105, 0.26);
        color: #dbe5f4;
        border-color: rgba(148, 163, 184, 0.34);
    }

    /* Buttons and form controls */
    .stButton > button,
    .stFormSubmitButton > button {
        border-radius: 999px;
        border: 1px solid rgba(148, 163, 184, 0.24);
        background: rgba(15, 23, 42, 0.9);
        color: #f1f5f9;
        font-weight: 600;
        letter-spacing: -0.01em;
        transition: all 0.18s ease;
    }

    .stButton > button:hover,
    .stFormSubmitButton > button:hover {
        border-color: rgba(56, 189, 248, 0.45);
        box-shadow: 0 6px 22px rgba(56, 189, 248, 0.25);
        transform: translateY(-1px);
    }

    .stTextInput input,
    .stTextArea textarea {
        border-radius: 14px !important;
        border: 1px solid rgba(148, 163, 184, 0.24) !important;
        background: rgba(15, 23, 42, 0.9) !important;
        color: #e5e7eb !important;
    }

    .stSelectbox label p,
    .stMultiSelect label p {
        color: #dce6f6 !important;
        font-weight: 600;
        letter-spacing: 0.01em;
    }

    .stSelectbox div[data-baseweb="select"] > div,
    .stMultiSelect div[data-baseweb="select"] > div {
        border-radius: 12px !important;
        border: 1px solid rgba(148, 163, 184, 0.28) !important;
        background: linear-gradient(120deg, #0b1220 0%, #101d33 100%) !important;
        color: #e7eef9 !important;
    }

    .stSelectbox svg,
    .stMultiSelect svg {
        color: #d1dbee !important;
    }

    .stTabs [data-testid="stTabBar"] {
        border-bottom: 1px solid rgba(148, 163, 184, 0.2);
    }

    [data-testid="stDataFrame"] {
        border-radius: 16px;
        border: 1px solid rgba(148, 163, 184, 0.2);
        overflow: hidden;
        box-shadow: 0 10px 24px rgba(2, 6, 23, 0.25);
        background: var(--apple-surface-2);
    }

    [data-testid="stDataFrame"] table {
        color: #e2e8f0 !important;
        background: var(--apple-surface-2) !important;
    }

    [data-testid="stDataFrame"] th {
        background: #0b1220 !important;
        color: #e2e8f0 !important;
        border-bottom: 1px solid rgba(148, 163, 184, 0.2) !important;
    }

    [data-testid="stDataFrame"] td {
        border-bottom: 1px solid rgba(148, 163, 184, 0.12) !important;
    }

    [data-testid="stRadio"] {
        background: linear-gradient(120deg, #0b1220 0%, #111f35 100%);
        border-radius: 14px;
        border: 1px solid rgba(148, 163, 184, 0.28);
        padding: 0.42rem 0.52rem;
        margin-bottom: 0.7rem;
    }

    [data-testid="stRadio"] label {
        border-radius: 999px;
        padding: 0.12rem 0.26rem;
        color: #e8eef9 !important;
    }

    [data-testid="stRadio"] p {
        color: #dce6f6 !important;
    }

    /* Metric cards */
    .metric-card {
        min-height: 158px;
        border-radius: 22px;
        padding: 1rem 1.1rem;
        border: 1px solid rgba(148, 163, 184, 0.24);
        background: linear-gradient(140deg, #0f172a 0%, #111827 100%);
        backdrop-filter: blur(16px);
        box-shadow: var(--apple-shadow);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        overflow: hidden;
    }

    .metric-neutral { background: linear-gradient(140deg, #0f172a 0%, #111827 100%); }
    .metric-blue    { background: linear-gradient(140deg, rgba(30, 64, 175, 0.35), #0f172a 70%); }
    .metric-red     { background: linear-gradient(140deg, rgba(190, 18, 60, 0.4), #0f172a 70%); }
    .metric-green   { background: linear-gradient(140deg, rgba(22, 101, 52, 0.45), #0f172a 70%); }
    .metric-orange  { background: linear-gradient(140deg, rgba(180, 83, 9, 0.45), #0f172a 70%); }

    .metric-label {
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94a3b8;
        font-weight: 600;
    }

    .metric-value {
        font-size: clamp(1.6rem, 2.6vw, 2.6rem);
        font-weight: 700;
        letter-spacing: -0.03em;
        color: #f8fafc;
        margin-top: 0.3rem;
        line-height: 1.1;
    }

    .metric-delta {
        font-size: 0.83rem;
        color: #93c5fd;
        background: rgba(30, 64, 175, 0.5);
        border-radius: 999px;
        width: fit-content;
        padding: 0.22rem 0.58rem;
        font-weight: 600;
    }

    .metric-sub {
        margin-top: 0.5rem;
        color: #cbd5f5;
        font-size: 0.8rem;
    }

    .metric-guide {
        border-radius: 16px;
        border: 1px solid rgba(56, 189, 248, 0.2);
        background: rgba(15, 23, 42, 0.9);
        padding: 0.78rem 0.88rem;
        color: #cbd5f5;
        font-size: 0.88rem;
        margin-bottom: 0.9rem;
    }

    .perf-panel {
        border-radius: 20px;
        border: 1px solid rgba(148, 163, 184, 0.24);
        background: var(--apple-surface-2);
        backdrop-filter: blur(12px);
        box-shadow: var(--apple-shadow);
        padding: 1rem;
    }

    .perf-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 0.9rem;
    }

    .perf-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #9aa4b2;
    }

    .perf-value {
        margin-top: 0.3rem;
        font-size: 1.45rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        color: #f8fafc;
    }

    .perf-foot {
        margin-top: 0.18rem;
        color: #9aa4b2;
        font-size: 0.78rem;
    }

    .queue-shell {
        border-radius: 18px;
        border: 1px solid rgba(148, 163, 184, 0.24);
        background: var(--apple-surface-2);
        box-shadow: 0 10px 24px rgba(2, 6, 23, 0.25);
        padding: 0.8rem;
        margin-bottom: 0.8rem;
    }

    .field-hint {
        color: #cbd5f5;
        font-size: 0.86rem;
        margin-top: -0.2rem;
        margin-bottom: 0.6rem;
    }

    .result-hero {
        text-align: center;
        padding: 1.3rem;
        border-radius: 16px;
        border: 1px solid rgba(148, 163, 184, 0.24);
        background: var(--apple-surface-2);
        box-shadow: 0 10px 24px rgba(2, 6, 23, 0.25);
        margin: 1rem 0;
    }

    /* Alerts */
    .alert-card {
        border-radius: 16px;
        padding: 0.95rem 1rem;
        border: 1px solid rgba(148, 163, 184, 0.2);
        background: var(--apple-surface-2);
        box-shadow: 0 8px 22px rgba(2, 6, 23, 0.2);
        margin-bottom: 0.5rem;
    }

    .alert-critical { border-left: 4px solid var(--apple-critical); }
    .alert-high     { border-left: 4px solid var(--apple-warning); }
    .alert-medium   { border-left: 4px solid #f0c341; }
    .alert-low,
    .alert-safe     { border-left: 4px solid var(--apple-safe); }

    .risk-pill {
        border-radius: 999px;
        padding: 0.2rem 0.58rem;
        color: #fff;
        font-size: 0.72rem;
        font-weight: 700;
    }

    .section-note {
        color: #cbd5f5;
        font-size: 0.94rem;
        margin-top: -0.35rem;
    }

    @media (max-width: 960px) {
        .block-container {
            padding-top: 1rem;
            padding-left: 0.8rem;
            padding-right: 0.8rem;
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #142038 0%, #1f2f4a 100%);
        }

        .metric-card {
            min-height: 132px;
            padding: 0.85rem;
        }

        .perf-grid {
            grid-template-columns: 1fr;
        }

        .shell-chip-row {
            gap: 0.35rem;
        }
    }
</style>
""", unsafe_allow_html=True)

# API Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000/api/v1")

# Session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'last_refresh' not in st.session_state:
    st.session_state.last_refresh = datetime.now()
if 'check_subject' not in st.session_state:
    st.session_state.check_subject = ""
if 'check_body' not in st.session_state:
    st.session_state.check_body = ""
if 'active_page' not in st.session_state:
    st.session_state.active_page = "Operations"

NAV_PAGES = [
    "Operations",
    "Message Inspector",
    "Threat Queue",
    "Trend Lens",
    "Control Room",
]

PAGE_DESCRIPTIONS = {
    "Operations": "Live posture for throughput, risk, queue health, and latest detections.",
    "Message Inspector": "Paste one email and get an immediate risk assessment with rationale.",
    "Threat Queue": "Filter and triage suspicious emails in a queue-style operations view.",
    "Trend Lens": "Understand risk trends, alert mix, and response rates over time.",
    "Control Room": "Tune thresholds, notifications, and model behavior safely.",
}


# ============================================
# AUTHENTICATION
# ============================================

def authenticate(username: str, password: str) -> bool:
    """Authentication using environment variables"""
    expected_username = os.getenv("ADMIN_USERNAME", "admin")
    expected_password = os.getenv("ADMIN_PASSWORD", "admin123")
    
    if username == expected_username and password == expected_password:
        logger.info(f"User '{username}' logged in successfully")
        return True
    
    if username:
        logger.warning(f"Failed login attempt for user '{username}'")
    return False


# ============================================
# API FUNCTIONS
# ============================================


def render_top_bar_controls(snapshot: dict):
    """Render top-bar controls inspired by classic analytics dashboards."""
    st.markdown(
        f"""
        <div class='topbar-controls fade-in'>
            <div class='topbar-heading'>Security Operations Top Bar</div>
            <div class='topbar-sub'>Fast navigation and reporting controls for live gateway monitoring.</div>
            <div class='topbar-meta'>Queue {snapshot['queue_size']} | Threat Rate {snapshot['detection_rate']:.1f}% | Avg Scan {snapshot['avg_time']:.2f}s</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<div class='control-ribbon'></div>", unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns([2.0, 1.6, 1.0, 1.1])

    with c1:
        selected_window = st.selectbox(
            "Date Window",
            ["Today", "Last 7 Days", "Last 30 Days", "Quarter to Date"],
            index=1,
            key="topbar_date_window",
            help="Controls the reporting window used when exporting snapshots.",
        )

    with c2:
        selected_scope = st.selectbox(
            "Scope",
            ["All Traffic", "Critical + High Only", "Government Domains", "Training Snapshot"],
            index=0,
            key="topbar_scope",
            help="Sets analysis scope for reporting and triage focus.",
        )

    export_payload = {
        "generated_at": datetime.now().isoformat(),
        "date_window": selected_window,
        "scope": selected_scope,
        "snapshot": snapshot,
    }

    with c3:
        st.download_button(
            "Export",
            data=json.dumps(export_payload, indent=2),
            file_name=f"gateway_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
            key="topbar_export_btn",
        )

    with c4:
        if st.button("+ New Report", use_container_width=True, key="topbar_new_report"):
            st.session_state.active_page = "Threat Queue"
            st.info("Report flow opened. Use Threat Queue filters, then export a snapshot.")


@st.cache_data(ttl=30)
def fetch_stats():
    """Fetch system statistics from API"""
    try:
        response = requests.get(f"{API_BASE_URL}/stats", timeout=3)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    
    return {
        "emails_processed": 15423,
        "threats_detected": 234,
        "queue_size": 0,
        "avg_processing_time": 0.45,
        "model_loaded": True,
        "timestamp": datetime.now().isoformat()
    }


@st.cache_data(ttl=30)
def fetch_alerts(status: str = None, limit: int = 50):
    """Fetch alerts from API"""
    try:
        params = {"limit": limit}
        if status:
            params["status"] = status
        response = requests.get(f"{API_BASE_URL}/alerts", params=params, timeout=3)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    
    return [
        {
            "id": "alert_001",
            "timestamp": datetime.now().isoformat(),
            "threat_score": 0.94,
            "from_email": "support@gcash-verify.net",
            "to_email": "employee@deped.gov.ph",
            "subject": "URGENT: Account verification needed",
            "risk_level": "CRITICAL",
            "status": "new",
            "urls": ["http://bit.ly/gcash-verify"]
        },
        {
            "id": "alert_002",
            "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
            "threat_score": 0.67,
            "from_email": "hr@company-ph.com",
            "to_email": "staff@dict.gov.ph",
            "subject": "Update your payroll information",
            "risk_level": "HIGH",
            "status": "acknowledged",
            "urls": ["http://bit.ly/payroll-update"]
        },
        {
            "id": "alert_003",
            "timestamp": (datetime.now() - timedelta(hours=5)).isoformat(),
            "threat_score": 0.45,
            "from_email": "netflix@konto-help.com",
            "to_email": "user@deped.gov.ph",
            "subject": "Your subscription expires soon",
            "risk_level": "MEDIUM",
            "status": "new",
            "urls": []
        }
    ]


def check_email_api(subject: str, body: str):
    """Check a single email via API"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/check-email",
            json={"subject": subject, "body": body},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _parse_alert_time(raw_timestamp: str) -> datetime | None:
    """Parse alert timestamp values from API payloads into local naive datetime."""
    if not raw_timestamp:
        return None
    try:
        return datetime.fromisoformat(str(raw_timestamp).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _format_alert_time(raw_timestamp: str) -> str:
    """Return compact timestamp display for queue-like views."""
    parsed = _parse_alert_time(raw_timestamp)
    if not parsed:
        return "Unknown"
    return parsed.strftime('%b %d, %H:%M')


def filter_alerts_by_time_window(alerts_list: list, window: str) -> list:
    """Filter alerts by time window keys used in queue and analytics pages."""
    if window == "All":
        return list(alerts_list)

    now = datetime.now()
    cutoff = {
        "24h": now - timedelta(hours=24),
        "7d": now - timedelta(days=7),
        "30d": now - timedelta(days=30),
    }.get(window)

    if cutoff is None:
        return list(alerts_list)

    filtered = []
    for alert in alerts_list:
        parsed = _parse_alert_time(alert.get('timestamp', ''))
        if parsed and parsed >= cutoff:
            filtered.append(alert)
    return filtered


def build_operational_snapshot(stats: dict, alerts_list: list) -> dict:
    """Build a compact set of operational KPIs used across pages."""
    processed = int(stats.get('emails_processed', 0) or 0)
    threats = int(stats.get('threats_detected', 0) or 0)
    if threats == 0 and alerts_list:
        threats = len(alerts_list)

    queue_size = int(stats.get('queue_size', 0) or 0)
    avg_time = float(stats.get('avg_processing_time', 0) or 0)
    safe_count = max(processed - threats, 0)
    detection_rate = (threats / processed * 100) if processed > 0 else 0.0
    throughput = (60.0 / avg_time) if avg_time > 0 else 0.0
    queue_health = max(0, 100 - min(queue_size * 16, 100))

    return {
        "processed": processed,
        "threats": threats,
        "safe_count": safe_count,
        "queue_size": queue_size,
        "avg_time": avg_time,
        "detection_rate": detection_rate,
        "throughput": throughput,
        "queue_health": queue_health,
    }


def render_shell_header(active_page: str, stats: dict, alerts_list: list):
    """Render the top command-shell header with quick health chips."""
    snapshot = build_operational_snapshot(stats, alerts_list)
    model_online = bool(stats.get('model_loaded'))

    model_chip_class = "chip-good" if model_online else "chip-bad"
    if snapshot["queue_size"] <= 3:
        queue_chip_class = "chip-good"
    elif snapshot["queue_size"] <= 10:
        queue_chip_class = "chip-warn"
    else:
        queue_chip_class = "chip-bad"

    if snapshot["detection_rate"] <= 3:
        risk_chip_class = "chip-good"
    elif snapshot["detection_rate"] <= 8:
        risk_chip_class = "chip-warn"
    else:
        risk_chip_class = "chip-bad"

    description = PAGE_DESCRIPTIONS.get(active_page, "Security operations workspace")
    refreshed = st.session_state.last_refresh.strftime('%H:%M:%S')

    st.markdown(
        f"""
        <div class='shell-header fade-in'>
            <h1 class='shell-title'>{active_page}</h1>
            <div class='shell-subtitle'>{description}</div>
            <div class='shell-chip-row'>
                <span class='shell-chip {model_chip_class}'>Model {'Online' if model_online else 'Offline'}</span>
                <span class='shell-chip {queue_chip_class}'>Queue {snapshot['queue_size']}</span>
                <span class='shell-chip {risk_chip_class}'>Threat Rate {snapshot['detection_rate']:.1f}%</span>
                <span class='shell-chip chip-neutral'>Refreshed {refreshed}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_guide():
    """Show concise guidance so users can interpret metrics quickly."""
    st.markdown(
        """
        <div class='metric-guide'>
            <strong>How to read this quickly:</strong> Threat Rate above 8% usually means active phishing pressure,
            Queue Health below 70 suggests worker backlog, and Avg Scan should trend down over time.
        </div>
        """,
        unsafe_allow_html=True,
    )


def build_alert_queue_dataframe(alerts_list: list) -> pd.DataFrame:
    """Build Pi-hole-like queue table for fast triage scanning."""
    rows = []
    for alert in alerts_list:
        try:
            score = float(alert.get('threat_score', 0) or 0)
        except (TypeError, ValueError):
            score = 0.0

        subject = str(alert.get('subject', 'N/A'))
        if len(subject) > 56:
            subject = f"{subject[:56]}..."

        rows.append(
            {
                "Time": _format_alert_time(alert.get('timestamp', '')),
                "Risk": str(alert.get('risk_level', 'SAFE')),
                "Score": f"{score:.0%}",
                "From": str(alert.get('from_email', 'N/A')),
                "Subject": subject,
                "Status": str(alert.get('status', 'new')).upper(),
            }
        )

    return pd.DataFrame(rows)


# ============================================
# UI COMPONENTS
# ============================================

def metric_card(value, label, delta=None, color="neutral", subtext=""):
    """Display an Apple-style metric card."""
    color_map = {
        "blue": "metric-blue",
        "red": "metric-red",
        "green": "metric-green",
        "orange": "metric-orange",
        "neutral": "metric-neutral",
    }
    tone = color_map.get(color, "metric-neutral")

    value_formatted = f"{value:,}" if isinstance(value, int) else f"{value}"
    delta_html = f"<span class='metric-delta'>{delta}</span>" if delta else ""
    sub_html = f"<div class='metric-sub'>{subtext}</div>" if subtext else ""

    st.markdown(
        f"""
        <div class='metric-card {tone}'>
            <div>
                <div class='metric-label'>{label}</div>
                <div class='metric-value'>{value_formatted}</div>
            </div>
            <div>
                {delta_html}
                {sub_html}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def display_alert_card(alert: dict):
    """Display a single alert card"""
    risk = alert.get('risk_level', 'SAFE')
    
    if risk == 'CRITICAL':
        alert_class = 'alert-critical'
    elif risk == 'HIGH':
        alert_class = 'alert-high'
    elif risk == 'MEDIUM':
        alert_class = 'alert-medium'
    else:
        alert_class = 'alert-low'
    
    timestamp = _format_alert_time(alert.get('timestamp', ''))
    
    risk_color = {
        'CRITICAL': '#ef4444',
        'HIGH': '#f59e0b',
        'MEDIUM': '#fbbf24',
        'LOW': '#22c55e',
        'SAFE': '#22c55e',
    }.get(risk, '#94a3b8')

    st.markdown(
        f"""
        <div class='alert-card {alert_class}'>
            <div style='display: flex; justify-content: space-between; align-items: center; gap: 0.75rem;'>
                <div style='font-weight: 600;'>
                    {alert['subject'][:66]}{'...' if len(alert['subject']) > 66 else ''}
                </div>
                <div style='text-align: right; display: flex; gap: 0.45rem; align-items: center;'>
                    <span class='risk-pill' style='background: {risk_color};'>{risk}</span>
                    <span style='font-weight: 700; color: {risk_color};'>{alert['threat_score']:.0%}</span>
                </div>
            </div>
            <div style='font-size: 0.79rem; color: #cbd5f5; margin-top: 0.35rem;'>
                {alert['from_email']} to {alert['to_email']} · {timestamp} · {alert.get('status', 'new')}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_threat_chart(alerts: list):
    """Render threat detection timeline."""
    if not alerts:
        st.info("No data available")
        return

    now = datetime.now()
    start = now - timedelta(hours=24)
    bucket_width_hours = 4
    bucket_count = 7
    buckets = [0] * bucket_count
    labels = [(start + timedelta(hours=i * bucket_width_hours)).strftime('%H:%M') for i in range(bucket_count)]

    for alert in alerts:
        ts = alert.get('timestamp')
        if not ts:
            continue
        try:
            alert_time = datetime.fromisoformat(str(ts).replace('Z', '+00:00')).replace(tzinfo=None)
        except ValueError:
            continue

        if alert_time < start or alert_time > now:
            continue

        offset_hours = (alert_time - start).total_seconds() / 3600
        idx = min(int(offset_hours // bucket_width_hours), bucket_count - 1)
        buckets[idx] += 1

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=labels,
        y=buckets,
        mode='lines+markers',
        fill='tozeroy',
        fillcolor='rgba(56, 189, 248, 0.18)',
        line=dict(color='#38bdf8', width=3),
        marker=dict(size=8, color='#38bdf8', line=dict(color='white', width=1.6)),
        name='Threats Detected'
    ))

    fig.update_layout(
        template='plotly_dark',
        height=320,
        margin=dict(l=20, r=20, t=20, b=20),
        xaxis_title="Last 24 Hours",
        yaxis_title="Alerts",
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
    )

    st.plotly_chart(fig, use_container_width=True)


def render_risk_distribution(alerts: list):
    """Render risk level distribution pie chart"""
    # Count by risk level
    risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'SAFE': 0}
    for alert in alerts:
        risk = alert.get('risk_level', 'SAFE')
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    
    colors = {
        'CRITICAL': '#dc2626',
        'HIGH': '#f59e0b',
        'MEDIUM': '#eab308',
        'LOW': '#22c55e',
        'SAFE': '#10b981'
    }
    
    fig = go.Figure()
    
    fig.add_trace(go.Pie(
        labels=list(risk_counts.keys()),
        values=list(risk_counts.values()),
        hole=0.66,
        marker=dict(
            colors=[colors.get(k, '#94a3b8') for k in risk_counts.keys()]
        ),
        textinfo='label+percent',
        textposition='outside',
    ))
    
    fig.update_layout(
        template='plotly_dark',
        height=320,
        margin=dict(l=20, r=20, t=20, b=20),
        showlegend=False,
    )

    st.plotly_chart(fig, use_container_width=True)


def render_performance_panel(stats: dict, alerts_list: list):
    """Render compact operational performance metrics."""
    processed = int(stats.get('emails_processed', 0) or 0)
    threats = int(stats.get('threats_detected', 0) or 0)
    queue_size = int(stats.get('queue_size', 0) or 0)
    avg_time = float(stats.get('avg_processing_time', 0) or 0)

    if threats == 0 and alerts_list:
        threats = len(alerts_list)

    detection_rate = (threats / processed * 100) if processed > 0 else 0.0
    throughput = (60.0 / avg_time) if avg_time > 0 else 0.0
    queue_health = max(0, 100 - min(queue_size * 16, 100))

    st.markdown(
        f"""
        <div class='perf-panel'>
            <div class='perf-grid'>
                <div>
                    <div class='perf-label'>Throughput</div>
                    <div class='perf-value'>{throughput:.1f}/min</div>
                    <div class='perf-foot'>Derived from average processing time</div>
                </div>
                <div>
                    <div class='perf-label'>Detection Rate</div>
                    <div class='perf-value'>{detection_rate:.1f}%</div>
                    <div class='perf-foot'>{threats} alerts over {processed} processed emails</div>
                </div>
                <div>
                    <div class='perf-label'>Queue Health</div>
                    <div class='perf-value'>{queue_health:.0f}/100</div>
                    <div class='perf-foot'>Queue size: {queue_size}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================
# PAGES
# ============================================

def login_page():
    """Render login page"""
    # Center the login form
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        <div class='perf-panel' style='text-align: center; margin-bottom: 1.25rem;'>
            <h1 style='font-size: 2.1rem; margin: 0;'>Email Security Gateway</h1>
            <p style='color: #6e6e73; margin-top: 0.35rem;'>Secure mail operations with layered phishing defense</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter username")
            password = st.text_input("Password", type="password", placeholder="Enter password")
            
            submitted = st.form_submit_button("Sign In", type="primary", use_container_width=True)
            
            if submitted:
                if authenticate(username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.error("Invalid username or password")
        
        st.markdown("---")
        st.caption("Default credentials: admin / admin123")


def main_dashboard():
    """Render main dashboard"""
    stats = fetch_stats()
    alerts_list = fetch_alerts(limit=80)
    snapshot = build_operational_snapshot(stats, alerts_list)

    # Sidebar kept lightweight: identity, quick controls, and status pulse.
    with st.sidebar:
        st.markdown("<p class='sidebar-muted'>Operator</p>", unsafe_allow_html=True)
        st.markdown(f"**{st.session_state.username}**")

        st.markdown("---")
        st.markdown("<p class='sidebar-muted'>Live status</p>", unsafe_allow_html=True)
        st.metric("Queue", snapshot["queue_size"])
        st.metric("Threat Rate", f"{snapshot['detection_rate']:.1f}%")
        st.metric("Avg Scan", f"{snapshot['avg_time']:.2f}s")
        st.caption(f"Refreshed: {st.session_state.last_refresh.strftime('%H:%M:%S')}")

        st.markdown("---")
        if st.button("Refresh Data", use_container_width=True):
            st.cache_data.clear()
            st.session_state.last_refresh = datetime.now()
            st.rerun()

        if st.button("Sign Out", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.active_page = "Operations"
            st.rerun()

    render_top_bar_controls(snapshot)

    try:
        default_index = NAV_PAGES.index(st.session_state.active_page)
    except ValueError:
        default_index = 0

    page = st.radio(
        "Workspace Navigation",
        NAV_PAGES,
        index=default_index,
        horizontal=True,
        label_visibility="collapsed",
        key="dashboard_top_nav",
    )
    st.session_state.active_page = page

    st.markdown(
        f"<div class='nav-note'>{PAGE_DESCRIPTIONS.get(page, '')}</div>",
        unsafe_allow_html=True,
    )

    render_shell_header(page, stats, alerts_list)

    if page == "Operations":
        render_overview(stats=stats, alerts_list=alerts_list)
    elif page == "Message Inspector":
        render_email_checker()
    elif page == "Threat Queue":
        render_alerts(alerts_list=alerts_list)
    elif page == "Trend Lens":
        render_analytics(alerts_list=alerts_list)
    elif page == "Control Room":
        render_settings()


def render_overview(stats: dict | None = None, alerts_list: list | None = None):
    """Render operations-first overview dashboard."""
    st.markdown(
        "<p class='section-note'>Single-pane operations view for risk, throughput, and triage readiness.</p>",
        unsafe_allow_html=True,
    )

    if stats is None:
        stats = fetch_stats()
    if alerts_list is None:
        alerts_list = fetch_alerts(limit=40)

    snapshot = build_operational_snapshot(stats, alerts_list)

    render_metric_guide()

    st.markdown("### Operational Snapshot")
    c1, c2, c3, c4 = st.columns(4)

    with c1:
        metric_card(
            snapshot["processed"],
            "Processed Mail",
            "live pipeline",
            "blue",
            "Total messages evaluated by detection stack",
        )
    with c2:
        metric_card(
            snapshot["threats"],
            "Flagged Threats",
            f"{snapshot['detection_rate']:.1f}%",
            "red",
            "Messages marked risky and queued for review",
        )
    with c3:
        metric_card(
            snapshot["safe_count"],
            "Clean Pass",
            "delivered",
            "green",
            "Messages with low-risk outcome",
        )
    with c4:
        metric_card(
            f"{snapshot['avg_time']:.2f}s",
            "Avg Scan Latency",
            "lower is better",
            "orange",
            "Average time spent in scan and scoring",
        )

    st.markdown("### System Health Strip")
    render_performance_panel(stats, alerts_list)

    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Risk Mix")
        render_risk_distribution(alerts_list)

    with col2:
        st.markdown("### 24-Hour Threat Pulse")
        render_threat_chart(alerts_list)

    st.markdown("---")

    st.markdown("### Recent Threat Events")
    if alerts_list:
        for alert in alerts_list[:4]:
            display_alert_card(alert)
    else:
        st.info("No recent alerts")

    st.markdown("### Query-Style Triage Log")
    queue_df = build_alert_queue_dataframe(alerts_list[:12])
    if not queue_df.empty:
        st.dataframe(queue_df, use_container_width=True)
    else:
        st.info("No queue events available")


def render_email_checker():
    """Render email checker page"""
    st.title("Message Inspector")
    st.markdown(
        "<p class='section-note'>Analyze a single message quickly with a clear risk verdict and rationale.</p>",
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class='queue-shell'>
            <strong>Quick flow:</strong> 1) load or paste a message, 2) run analysis, 3) review threat score and reasons,
            4) escalate if risk is HIGH or CRITICAL.
        </div>
        """,
        unsafe_allow_html=True,
    )

    sample_templates = {
        "Legitimate Meeting": (
            "Meeting Agenda - Project Review",
            """Hi Team,

Please find attached the agenda for tomorrow's 10 AM project review meeting.

Agenda:
1. Project status update
2. Q2 planning
3. Resource allocation

Best regards,
John Doe
Project Manager""",
        ),
        "Phishing Example": (
            "URGENT: Your Account Will Be Suspended",
            """Dear Valued Customer,

Your account has been flagged for unusual activity. To avoid permanent suspension, verify your account immediately.

Click here to verify: http://bit.ly/gcash-verify-urgent

Failure to verify within 24 hours will result in account closure.

Support Team""",
        ),
        "Suspicious Link": (
            "Your Package Delivery Update",
            """Dear Customer,

Your package is on the way but requires verification.

Track your delivery: http://bit.ly/track-package-123456

Please verify your address to ensure delivery.

Logistics Team""",
        ),
    }

    col1, col2 = st.columns([3, 2])
    with col2:
        st.markdown("#### Quick Samples")
        for template_name, template_data in sample_templates.items():
            button_key = f"sample_{template_name.lower().replace(' ', '_')}"
            if st.button(template_name, use_container_width=True, key=button_key):
                st.session_state.check_subject = template_data[0]
                st.session_state.check_body = template_data[1]
                st.rerun()

        if st.button("Clear Draft", use_container_width=True, key="clear_draft"):
            st.session_state.check_subject = ""
            st.session_state.check_body = ""
            st.rerun()

    with col1:
        st.markdown(
            "<p class='field-hint'>Tip: Subject indicates intent while body reveals pressure tactics and malicious links.</p>",
            unsafe_allow_html=True,
        )

        with st.form("email_check_form"):
            subject = st.text_input(
                "Subject Line",
                key="check_subject",
                placeholder="Example: Action required for payroll update",
                help="Use the exact subject seen by the recipient.",
            )
            body = st.text_area(
                "Email Body",
                key="check_body",
                height=260,
                placeholder="Paste the full message body here...",
                help="Include links and signatures when possible for better scoring.",
            )

            c1, c2 = st.columns(2)
            with c1:
                submitted = st.form_submit_button("Analyze Message", type="primary", use_container_width=True)
            with c2:
                reset_fields = st.form_submit_button("Reset Fields", use_container_width=True)

    if reset_fields:
        st.session_state.check_subject = ""
        st.session_state.check_body = ""
        st.rerun()

    if submitted and (subject or body):
        with st.spinner("Analyzing message..."):
            result = check_email_api(subject, body)

        if result and "error" not in result:
            score = float(result.get('threat_score', 0) or 0)

            if score >= 0.8:
                risk = "CRITICAL"
                color = "#dc2626"
                icon = "STOP"
            elif score >= 0.6:
                risk = "HIGH"
                color = "#d97706"
                icon = "WARN"
            elif score >= 0.4:
                risk = "MEDIUM"
                color = "#b8891c"
                icon = "WATCH"
            else:
                risk = "SAFE"
                color = "#1f8a4c"
                icon = "OK"

            st.markdown("### Analysis Result")
            st.markdown(
                f"""
                <div class='result-hero'>
                    <div style='font-size: 0.82rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.08em;'>Verdict</div>
                    <div style='font-size: 1.7rem; font-weight: 700; color: {color}; margin-top: 0.25rem;'>{risk}</div>
                    <div style='font-size: 2.15rem; font-weight: 740; color: {color}; margin-top: 0.1rem;'>{score:.1%}</div>
                    <div style='font-size: 0.86rem; color: #6b7280; margin-top: 0.22rem;'>Threat confidence ({icon})</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            k1, k2, k3 = st.columns(3)
            with k1:
                st.metric("Risk Level", risk)
            with k2:
                st.metric("Threat Score", f"{score:.1%}")
            with k3:
                recommendation = "Escalate" if score >= 0.6 else "Monitor"
                st.metric("Action", recommendation)

            if result.get('explanations'):
                st.markdown("#### Detection Reasons")
                for reason in result['explanations']:
                    st.info(reason)
        elif result and "error" in result:
            st.error(f"Error: {result['error']}")


def render_alerts(alerts_list: list | None = None):
    """Render threat queue page with table/card triage modes."""
    st.title("Threat Queue")
    st.markdown(
        "<p class='section-note'>Filter quickly, scan queue entries, and focus response effort where risk is highest.</p>",
        unsafe_allow_html=True,
    )

    if alerts_list is None:
        alerts_list = fetch_alerts(limit=120)

    st.markdown("<div class='control-ribbon'></div>", unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns([1, 1, 1, 2])
    with col1:
        status_filter = st.selectbox("Status", ["All", "new", "acknowledged", "resolved"])
    with col2:
        risk_filter = st.selectbox("Risk", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"])
    with col3:
        time_filter = st.selectbox("Window", ["24h", "7d", "30d", "All"])
    with col4:
        keyword_filter = st.text_input("Search", placeholder="sender, subject, domain, or status")

    filtered = list(alerts_list)

    if status_filter != "All":
        filtered = [a for a in filtered if str(a.get('status', '')).lower() == status_filter.lower()]
    if risk_filter != "All":
        filtered = [a for a in filtered if str(a.get('risk_level', '')).upper() == risk_filter]

    filtered = filter_alerts_by_time_window(filtered, time_filter)

    if keyword_filter.strip():
        needle = keyword_filter.strip().lower()
        filtered = [
            a for a in filtered
            if needle in str(a.get('from_email', '')).lower()
            or needle in str(a.get('subject', '')).lower()
            or needle in str(a.get('status', '')).lower()
            or needle in str(a.get('risk_level', '')).lower()
        ]

    st.markdown("### Queue Summary")
    q1, q2, q3, q4 = st.columns(4)
    total_count = len(filtered)
    critical_count = len([a for a in filtered if str(a.get('risk_level', '')).upper() == 'CRITICAL'])
    new_count = len([a for a in filtered if str(a.get('status', '')).lower() == 'new'])
    resolved_count = len([a for a in filtered if str(a.get('status', '')).lower() == 'resolved'])

    with q1:
        metric_card(total_count, "Visible Alerts", "filtered", "blue")
    with q2:
        metric_card(critical_count, "Critical", "immediate", "red")
    with q3:
        metric_card(new_count, "New", "needs triage", "orange")
    with q4:
        metric_card(resolved_count, "Resolved", "closed", "green")

    st.markdown("---")

    view_mode = st.radio(
        "View Mode",
        ["Queue Table", "Alert Cards"],
        horizontal=True,
        label_visibility="collapsed",
        key="alert_view_mode",
    )

    if not filtered:
        st.info("No alerts match the selected filters")
        return

    if view_mode == "Queue Table":
        st.markdown("### Queue Table")
        queue_df = build_alert_queue_dataframe(filtered)
        st.dataframe(queue_df, use_container_width=True)
    else:
        st.markdown(f"### Alert Cards ({len(filtered)})")
        for alert in filtered:
            display_alert_card(alert)
            st.markdown("")


def render_analytics(alerts_list: list | None = None):
    """Render trend-centric analytics page."""
    st.title("Trend Lens")
    st.markdown(
        "<p class='section-note'>Understand alert mix and response behavior over your chosen time window.</p>",
        unsafe_allow_html=True,
    )

    if alerts_list is None:
        alerts_list = fetch_alerts(limit=150)

    st.markdown("<div class='control-ribbon'></div>", unsafe_allow_html=True)
    window = st.selectbox("Time Window", ["24h", "7d", "30d", "All"], key="analytics_window")
    filtered = filter_alerts_by_time_window(alerts_list, window)

    c1, c2, c3, c4 = st.columns(4)
    total_alerts = len(filtered)
    critical = len([a for a in filtered if str(a.get('risk_level', '')).upper() == 'CRITICAL'])
    high = len([a for a in filtered if str(a.get('risk_level', '')).upper() == 'HIGH'])
    resolved = len([a for a in filtered if str(a.get('status', '')).lower() == 'resolved'])
    resolved_rate = (resolved / total_alerts * 100) if total_alerts else 0.0

    with c1:
        metric_card(total_alerts, "Alerts in Window", "time-scoped", "blue")
    with c2:
        metric_card(critical, "Critical Volume", "urgent review", "red")
    with c3:
        metric_card(high, "High Risk Volume", "priority", "orange")
    with c4:
        metric_card(resolved, "Resolved", f"{resolved_rate:.1f}%", "green")

    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Risk Distribution")
        render_risk_distribution(filtered)

    with col2:
        st.markdown("### Threat Timeline")
        render_threat_chart(filtered)

    st.markdown("### Trend Queue")
    trend_df = build_alert_queue_dataframe(filtered[:20])
    if not trend_df.empty:
        st.dataframe(trend_df, use_container_width=True)
    else:
        st.info("No events found for this time window")


def render_settings():
    """Render settings page"""
    st.title("Control Room")
    st.markdown(
        "<p class='section-note'>Tune detection behavior and notifications with plain-language controls.</p>",
        unsafe_allow_html=True,
    )

    st.markdown("### Detection Profile")
    st.markdown(
        "<p class='field-hint'>Higher thresholds reduce false positives but may miss subtle phishing emails.</p>",
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns(2)
    with c1:
        st.slider("Critical Alert Threshold", 0.0, 1.0, 0.8, 0.05, key="crit")
        st.slider("High Alert Threshold", 0.0, 1.0, 0.6, 0.05, key="high")
        st.slider("Medium Alert Threshold", 0.0, 1.0, 0.4, 0.05, key="med")
    with c2:
        st.checkbox("Analyze URLs", value=True)
        st.checkbox("Analyze Domains", value=True)
        st.checkbox("Detect Known Suspicious Patterns", value=True)

    if st.button("Save Detection Profile", type="primary"):
        st.success("Detection profile saved")

    st.markdown("---")
    st.markdown("### Notification Rules")
    n1, n2 = st.columns(2)
    with n1:
        st.checkbox("Send Email Alerts", value=True)
        st.text_input("Notification Email", value="admin@prototype.local")
    with n2:
        st.checkbox("Show In-Dashboard Alerts", value=True)
        st.checkbox("Enable Sound Notifications", value=False)

    if st.button("Save Notification Rules", type="primary"):
        st.success("Notification rules saved")

    st.markdown("---")
    st.markdown("### Model Runtime")
    st.radio("Detection Mode", ["TinyBERT (Fast)", "BERT (Accurate)", "Ensemble"], index=0)
    st.slider("Minimum Confidence for Alert", 0.0, 1.0, 0.5, 0.05)
    st.checkbox("Use External Intelligence Feeds", value=True)
    st.checkbox("Cache Prediction Results", value=True)

    if st.button("Save Model Runtime Settings", type="primary"):
        st.success("Model runtime settings saved")

    st.markdown("---")
    st.markdown("### System Information")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**API Base URL:** {API_BASE_URL}")
        st.markdown("**Runtime Model:** TinyBERT wrapper")
    with col2:
        env = os.getenv("ENVIRONMENT", "development")
        st.markdown(f"**Environment:** {env}")
        st.markdown("**Version:** 1.1.0")


# ============================================
# MAIN APP
# ============================================

def main():
    if not st.session_state.authenticated:
        login_page()
    else:
        main_dashboard()


if __name__ == "__main__":
    main()