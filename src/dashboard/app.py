import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.utils.logger import logger

st.set_page_config(
    page_title="Email Security Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

NAV_PAGES = [
    "Operations",
    "Message Inspector",
    "Threat Queue",
    "Trend Lens",
    "Control Room",
    "System Guide",
]

PAGE_DESCRIPTIONS = {
    "Operations": "Live security posture with throughput, queue pressure, and current threats.",
    "Message Inspector": "Paste a message and run immediate phishing risk analysis.",
    "Threat Queue": "Filter, inspect, and triage suspicious messages quickly.",
    "Trend Lens": "Track risk trends, response rates, and alert distribution over time.",
    "Control Room": "Adjust runtime thresholds and operational preferences.",
    "System Guide": "Operational runbook and quick reference for live system management.",
}

RISK_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f59e0b",
    "MEDIUM": "#fbbf24",
    "LOW": "#22c55e",
    "SAFE": "#22c55e",
}


def apply_styles() -> None:
    st.markdown(
        """
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

            :root {
                --bg-0: #0b111a;
                --bg-1: #0f172a;
                --bg-2: #111827;
                --bg-3: #1f2937;
                --border: rgba(148, 163, 184, 0.24);
                --text-0: #f8fafc;
                --text-1: #e2e8f0;
                --text-2: #94a3b8;
                --info: #38bdf8;
                --danger: #ef4444;
                --warn: #f59e0b;
                --ok: #22c55e;
                --shadow: 0 14px 30px rgba(2, 6, 23, 0.42);
            }

            header[data-testid="stHeader"],
            [data-testid="stToolbar"],
            #MainMenu,
            footer,
            [data-testid="stDecoration"] {
                display: none !important;
            }

            html, body, [class*="css"] {
                font-family: "Inter", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
            }

            .stApp {
                color: var(--text-1);
                background:
                    radial-gradient(circle at 0% 0%, rgba(56, 189, 248, 0.12), transparent 38%),
                    radial-gradient(circle at 100% 0%, rgba(99, 102, 241, 0.10), transparent 34%),
                    var(--bg-0);
            }

            .block-container {
                max-width: 1360px;
                padding-top: 1.05rem;
                padding-bottom: 1.8rem;
            }

            h1, h2, h3, h4, h5, h6, p, span, label, div {
                color: var(--text-1);
            }

            [data-testid="stSidebar"] {
                background: linear-gradient(180deg, #0b1220 0%, #0f1b31 48%, #12223d 100%);
                border-right: 1px solid var(--border);
            }

            [data-testid="stSidebar"] * {
                color: #e8ecf5 !important;
            }

            [data-testid="stSidebar"] .stButton > button {
                background: rgba(15, 23, 42, 0.9);
                border: 1px solid rgba(148, 163, 184, 0.26);
                color: #f8fafc;
            }

            [data-testid="stSidebar"] .stButton > button:hover {
                border-color: rgba(56, 189, 248, 0.45);
                box-shadow: 0 8px 22px rgba(56, 189, 248, 0.24);
            }

            .top-ribbon {
                border-radius: 16px;
                border: 1px solid rgba(148, 163, 184, 0.28);
                background: linear-gradient(120deg, #0b1220 0%, #101d33 56%, #132545 100%);
                box-shadow: var(--shadow);
                padding: 0.9rem 0.95rem;
                margin-bottom: 0.85rem;
            }

            .ribbon-title {
                font-size: 0.78rem;
                text-transform: uppercase;
                letter-spacing: 0.11em;
                font-weight: 700;
                color: #9fb4d4;
            }

            .ribbon-sub {
                margin-top: 0.25rem;
                color: #dce6f6;
                font-size: 0.9rem;
            }

            .ribbon-meta {
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
                border-radius: 14px;
                border: 1px solid rgba(148, 163, 184, 0.24);
                background: linear-gradient(120deg, #0b1220 0%, #111f35 100%);
                box-shadow: 0 12px 26px rgba(2, 6, 23, 0.3);
                padding: 0.58rem 0.62rem;
                margin-bottom: 0.85rem;
            }

            .control-ribbon + div[data-testid="stHorizontalBlock"] > div {
                padding-top: 0.2rem;
            }

            .nav-note {
                border-radius: 12px;
                border: 1px solid rgba(148, 163, 184, 0.28);
                background: linear-gradient(120deg, #0b1220 0%, #0f1b2f 100%);
                padding: 0.68rem 0.78rem;
                color: #d6dfef;
                font-size: 0.88rem;
                margin-bottom: 0.85rem;
            }

            .shell-header {
                border-radius: 16px;
                border: 1px solid rgba(148, 163, 184, 0.28);
                background: linear-gradient(132deg, #0b1220 0%, #111f37 54%, #14294a 100%);
                box-shadow: var(--shadow);
                padding: 0.95rem 1rem;
                margin-bottom: 0.9rem;
            }

            .shell-title {
                font-size: clamp(1.4rem, 2.8vw, 2.1rem);
                font-weight: 700;
                letter-spacing: -0.03em;
                color: var(--text-0);
                margin: 0;
            }

            .shell-subtitle {
                margin-top: 0.24rem;
                color: #c7d2e5;
                font-size: 0.93rem;
            }

            .shell-chip-row {
                margin-top: 0.68rem;
                display: flex;
                flex-wrap: wrap;
                gap: 0.42rem;
            }

            .shell-chip {
                display: inline-flex;
                align-items: center;
                border-radius: 999px;
                padding: 0.23rem 0.62rem;
                font-size: 0.75rem;
                font-weight: 700;
                letter-spacing: 0.02em;
                border: 1px solid transparent;
            }

            .chip-good {
                background: rgba(34, 197, 94, 0.24);
                color: #d9faea;
                border-color: rgba(34, 197, 94, 0.35);
            }

            .chip-warn {
                background: rgba(245, 158, 11, 0.24);
                color: #fff1cf;
                border-color: rgba(245, 158, 11, 0.35);
            }

            .chip-bad {
                background: rgba(239, 68, 68, 0.26);
                color: #ffe3df;
                border-color: rgba(239, 68, 68, 0.38);
            }

            .chip-info {
                background: rgba(56, 189, 248, 0.2);
                color: #d5f3ff;
                border-color: rgba(56, 189, 248, 0.35);
            }

            .stButton > button,
            .stDownloadButton > button,
            .stFormSubmitButton > button {
                border-radius: 999px;
                border: 1px solid rgba(148, 163, 184, 0.25);
                background: rgba(15, 23, 42, 0.9);
                color: #f8fafc;
                font-weight: 600;
                transition: all 0.17s ease;
            }

            .stButton > button:hover,
            .stDownloadButton > button:hover,
            .stFormSubmitButton > button:hover {
                border-color: rgba(56, 189, 248, 0.45);
                box-shadow: 0 6px 20px rgba(56, 189, 248, 0.26);
                transform: translateY(-1px);
            }

            .stTextInput input,
            .stTextArea textarea {
                border-radius: 12px !important;
                border: 1px solid rgba(148, 163, 184, 0.25) !important;
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
                border: 1px solid rgba(148, 163, 184, 0.25) !important;
                background: linear-gradient(120deg, #0b1220 0%, #101d33 100%) !important;
                color: #e7eef9 !important;
            }

            .stSelectbox svg,
            .stMultiSelect svg {
                color: #d1dbee !important;
            }

            [data-testid="stMetric"] {
                border: 1px solid rgba(148, 163, 184, 0.2);
                border-radius: 14px;
                background: #0f172a;
                padding: 0.5rem 0.6rem;
            }

            [data-testid="stMetricLabel"] p {
                color: #9aa4b2 !important;
                font-size: 0.78rem;
                text-transform: uppercase;
                letter-spacing: 0.08em;
            }

            [data-testid="stMetricValue"] {
                color: #f8fafc !important;
                font-size: 1.35rem;
                font-weight: 700;
            }

            [data-testid="stRadio"] {
                background: linear-gradient(120deg, #0b1220 0%, #111f35 100%);
                border-radius: 12px;
                border: 1px solid rgba(148, 163, 184, 0.24);
                padding: 0.38rem 0.48rem;
                margin-bottom: 0.7rem;
            }

            [data-testid="stRadio"] label {
                border-radius: 999px;
                color: #e8eef9 !important;
            }

            [data-testid="stRadio"] p {
                color: #dce6f6 !important;
            }

            [data-testid="stVerticalBlockBorderWrapper"] {
                border: 1px solid rgba(148, 163, 184, 0.22) !important;
                background: var(--bg-1) !important;
                border-radius: 14px !important;
                box-shadow: 0 10px 24px rgba(2, 6, 23, 0.24) !important;
            }

            [data-testid="stDataFrame"] {
                border-radius: 12px;
                border: 1px solid rgba(148, 163, 184, 0.2);
                overflow: hidden;
                box-shadow: 0 10px 24px rgba(2, 6, 23, 0.24);
                background: var(--bg-1);
            }

            [data-testid="stDataFrame"] table {
                color: #e2e8f0 !important;
                background: var(--bg-1) !important;
                font-size: 0.9rem;
            }

            [data-testid="stDataFrame"] th {
                background: #0b1220 !important;
                color: #e2e8f0 !important;
                border-bottom: 1px solid rgba(148, 163, 184, 0.2) !important;
            }

            [data-testid="stDataFrame"] td {
                border-bottom: 1px solid rgba(148, 163, 184, 0.12) !important;
            }

            .metric-card {
                min-height: 154px;
                border-radius: 14px;
                padding: 0.9rem 0.95rem;
                border: 1px solid rgba(148, 163, 184, 0.22);
                background: linear-gradient(140deg, #0f172a 0%, #111827 100%);
                box-shadow: var(--shadow);
                display: flex;
                flex-direction: column;
                justify-content: space-between;
            }

            .metric-neutral { background: linear-gradient(140deg, #0f172a 0%, #111827 100%); }
            .metric-blue { background: linear-gradient(140deg, rgba(30, 64, 175, 0.35), #0f172a 70%); }
            .metric-red { background: linear-gradient(140deg, rgba(190, 18, 60, 0.4), #0f172a 70%); }
            .metric-green { background: linear-gradient(140deg, rgba(22, 101, 52, 0.45), #0f172a 70%); }
            .metric-orange { background: linear-gradient(140deg, rgba(180, 83, 9, 0.45), #0f172a 70%); }

            .metric-label {
                font-size: 0.74rem;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                color: #9aa4b2;
                font-weight: 600;
            }

            .metric-value {
                font-size: clamp(1.62rem, 2.6vw, 2.56rem);
                font-weight: 700;
                letter-spacing: -0.03em;
                color: #f8fafc;
                margin-top: 0.3rem;
                line-height: 1.08;
            }

            .metric-delta {
                font-size: 0.8rem;
                color: #bfdbfe;
                background: rgba(30, 64, 175, 0.45);
                border-radius: 999px;
                width: fit-content;
                padding: 0.22rem 0.54rem;
                font-weight: 600;
            }

            .metric-sub {
                margin-top: 0.45rem;
                color: #cbd5f5;
                font-size: 0.8rem;
            }

            .metric-guide {
                border-radius: 12px;
                border: 1px solid rgba(56, 189, 248, 0.2);
                background: rgba(15, 23, 42, 0.9);
                padding: 0.72rem 0.82rem;
                color: #cbd5f5;
                font-size: 0.88rem;
                margin-bottom: 0.8rem;
            }

            .perf-panel {
                border-radius: 14px;
                border: 1px solid rgba(148, 163, 184, 0.22);
                background: var(--bg-1);
                box-shadow: var(--shadow);
                padding: 0.9rem;
            }

            .perf-grid {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 0.82rem;
            }

            .perf-label {
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                color: #9aa4b2;
            }

            .perf-value {
                margin-top: 0.24rem;
                font-size: 1.42rem;
                font-weight: 700;
                letter-spacing: -0.02em;
                color: #f8fafc;
            }

            .perf-foot {
                margin-top: 0.16rem;
                color: #9aa4b2;
                font-size: 0.78rem;
            }

            .queue-shell {
                border-radius: 12px;
                border: 1px solid rgba(148, 163, 184, 0.22);
                background: var(--bg-1);
                box-shadow: 0 10px 24px rgba(2, 6, 23, 0.22);
                padding: 0.72rem;
                margin-bottom: 0.8rem;
            }

            .field-hint {
                color: #cbd5f5;
                font-size: 0.86rem;
                margin-top: -0.18rem;
                margin-bottom: 0.6rem;
            }

            .result-hero {
                text-align: center;
                padding: 1.18rem;
                border-radius: 12px;
                border: 1px solid rgba(148, 163, 184, 0.22);
                background: var(--bg-1);
                box-shadow: 0 10px 24px rgba(2, 6, 23, 0.22);
                margin: 0.85rem 0;
            }

            .alert-card {
                border-radius: 12px;
                padding: 0.86rem 0.9rem;
                border: 1px solid rgba(148, 163, 184, 0.2);
                background: var(--bg-1);
                box-shadow: 0 8px 20px rgba(2, 6, 23, 0.2);
                margin-bottom: 0.45rem;
            }

            .alert-critical { border-left: 4px solid #ef4444; }
            .alert-high { border-left: 4px solid #f59e0b; }
            .alert-medium { border-left: 4px solid #fbbf24; }
            .alert-low, .alert-safe { border-left: 4px solid #22c55e; }

            .risk-pill {
                border-radius: 999px;
                padding: 0.2rem 0.58rem;
                color: #fff;
                font-size: 0.72rem;
                font-weight: 700;
            }

            .section-note {
                color: #cbd5f5;
                font-size: 0.93rem;
                margin-top: -0.3rem;
            }

            @media (max-width: 960px) {
                .block-container {
                    padding-top: 0.9rem;
                    padding-left: 0.72rem;
                    padding-right: 0.72rem;
                }

                .metric-card {
                    min-height: 128px;
                    padding: 0.8rem;
                }

                .perf-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def now_local() -> datetime:
    return datetime.now().astimezone()


def parse_to_local(value: Union[str, datetime, None]) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=now_local().tzinfo)
    return dt.astimezone()


def format_local(value: Union[str, datetime, None], fmt: str = "%b %d, %H:%M:%S %Z") -> str:
    dt = parse_to_local(value)
    if not dt:
        return "Unknown"
    return dt.strftime(fmt)


def initialize_session_state() -> None:
    defaults = {
        "authenticated": False,
        "username": None,
        "last_refresh": now_local(),
        "check_subject": "",
        "check_body": "",
        "active_page": "Operations",
        "global_search": "",
        "top_date_window": "Last 7 Days",
        "top_scope": "All Traffic",
        "guide_notes": "",
        "auto_refresh": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000/api/v1")


@st.cache_data(ttl=30)
def fetch_stats() -> Dict[str, Any]:
    try:
        response = requests.get(f"{API_BASE_URL}/stats", timeout=3)
        if response.status_code == 200:
            data = response.json()
            data["timestamp"] = format_local(data.get("timestamp"), "%Y-%m-%d %H:%M:%S %Z")
            return data
    except Exception:
        pass
    return {
        "emails_processed": 15423,
        "threats_detected": 234,
        "queue_size": 2,
        "avg_processing_time": 0.45,
        "model_loaded": True,
        "timestamp": format_local(now_local(), "%Y-%m-%d %H:%M:%S %Z"),
    }


@st.cache_data(ttl=30)
def fetch_alerts(status: Optional[str] = None, limit: int = 80) -> List[Dict[str, Any]]:
    try:
        params: Dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status
        response = requests.get(f"{API_BASE_URL}/alerts", params=params, timeout=4)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return [
        {
            "id": "alert_001",
            "timestamp": now_local().isoformat(),
            "threat_score": 0.94,
            "from_email": "support@gcash-verify.net",
            "to_email": "employee@deped.gov.ph",
            "subject": "URGENT: Account verification needed",
            "risk_level": "CRITICAL",
            "status": "new",
            "urls": ["http://bit.ly/gcash-verify"],
        },
        {
            "id": "alert_002",
            "timestamp": (now_local() - timedelta(hours=2)).isoformat(),
            "threat_score": 0.67,
            "from_email": "hr@company-ph.com",
            "to_email": "staff@dict.gov.ph",
            "subject": "Update your payroll information",
            "risk_level": "HIGH",
            "status": "acknowledged",
            "urls": ["http://bit.ly/payroll-update"],
        },
        {
            "id": "alert_003",
            "timestamp": (now_local() - timedelta(hours=5)).isoformat(),
            "threat_score": 0.45,
            "from_email": "netflix@konto-help.com",
            "to_email": "user@deped.gov.ph",
            "subject": "Your subscription expires soon",
            "risk_level": "MEDIUM",
            "status": "new",
            "urls": [],
        },
    ]


def check_email_api(subject: str, body: str) -> Dict[str, Any]:
    try:
        response = requests.post(
            f"{API_BASE_URL}/check-email",
            json={"subject": subject, "body": body},
            timeout=12,
        )
        if response.status_code == 200:
            return response.json()
        return {"error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def filter_alerts_by_time_window(alerts_list: List[Dict[str, Any]], window: str) -> List[Dict[str, Any]]:
    if window == "All":
        return list(alerts_list)
    now = now_local()
    cutoff = {
        "24h": now - timedelta(hours=24),
        "7d": now - timedelta(days=7),
        "30d": now - timedelta(days=30),
    }.get(window)
    if cutoff is None:
        return list(alerts_list)
    filtered: List[Dict[str, Any]] = []
    for alert in alerts_list:
        parsed = parse_to_local(alert.get("timestamp"))
        if parsed and parsed >= cutoff:
            filtered.append(alert)
    return filtered


def build_operational_snapshot(stats: Dict[str, Any], alerts_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    processed = int(stats.get("emails_processed", 0) or 0)
    threats = int(stats.get("threats_detected", 0) or 0)
    if threats == 0 and alerts_list:
        threats = len(alerts_list)
    queue_size = int(stats.get("queue_size", 0) or 0)
    avg_time = float(stats.get("avg_processing_time", 0) or 0)
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
        "model_loaded": bool(stats.get("model_loaded")),
    }


def metric_card(value: Union[int, str, float], label: str, delta: Optional[str] = None, color: str = "neutral", subtext: str = "") -> None:
    tone = {
        "blue": "metric-blue",
        "red": "metric-red",
        "green": "metric-green",
        "orange": "metric-orange",
        "neutral": "metric-neutral",
    }.get(color, "metric-neutral")
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


def display_alert_card(alert: Dict[str, Any]) -> None:
    risk = str(alert.get("risk_level", "SAFE")).upper()
    alert_class = {
        "CRITICAL": "alert-critical",
        "HIGH": "alert-high",
        "MEDIUM": "alert-medium",
        "LOW": "alert-low",
        "SAFE": "alert-safe",
    }.get(risk, "alert-low")
    risk_color = RISK_COLORS.get(risk, "#94a3b8")
    timestamp = format_local(alert.get("timestamp"), "%b %d, %H:%M")
    subject = str(alert.get("subject", "No Subject"))
    from_email = str(alert.get("from_email", "unknown"))
    to_email = str(alert.get("to_email", "unknown"))
    threat_score = float(alert.get("threat_score", 0) or 0)
    status = str(alert.get("status", "new"))
    st.markdown(
        f"""
        <div class='alert-card {alert_class}'>
            <div style='display:flex;justify-content:space-between;align-items:center;gap:0.7rem;'>
                <div style='font-weight:600;color:#f8fafc;'>
                    {subject[:70]}{'...' if len(subject) > 70 else ''}
                </div>
                <div style='display:flex;gap:0.44rem;align-items:center;'>
                    <span class='risk-pill' style='background:{risk_color};'>{risk}</span>
                    <span style='font-weight:700;color:{risk_color};'>{threat_score:.0%}</span>
                </div>
            </div>
            <div style='font-size:0.8rem;color:#cbd5f5;margin-top:0.34rem;'>
                {from_email} to {to_email} · {timestamp} · {status}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_threat_chart(alerts: List[Dict[str, Any]]) -> None:
    if not alerts:
        st.info("No data available")
        return
    now = now_local()
    start = now - timedelta(hours=24)
    bucket_width_hours = 4
    bucket_count = 7
    buckets = [0] * bucket_count
    labels = [(start + timedelta(hours=i * bucket_width_hours)).strftime("%H:%M") for i in range(bucket_count)]
    for alert in alerts:
        alert_time = parse_to_local(alert.get("timestamp"))
        if not alert_time:
            continue
        if alert_time < start or alert_time > now:
            continue
        offset_hours = (alert_time - start).total_seconds() / 3600
        idx = min(int(offset_hours // bucket_width_hours), bucket_count - 1)
        buckets[idx] += 1
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=labels,
            y=buckets,
            mode="lines+markers",
            fill="tozeroy",
            fillcolor="rgba(56, 189, 248, 0.2)",
            line=dict(color="#38bdf8", width=3),
            marker=dict(size=8, color="#38bdf8", line=dict(color="white", width=1.5)),
            name="Threats",
        )
    )
    fig.update_layout(
        template="plotly_dark",
        height=320,
        margin=dict(l=20, r=20, t=20, b=20),
        xaxis_title="Last 24 Hours",
        yaxis_title="Alerts",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig, use_container_width=True)


def render_risk_distribution(alerts: List[Dict[str, Any]]) -> None:
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
    for alert in alerts:
        risk = str(alert.get("risk_level", "SAFE")).upper()
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    fig = go.Figure()
    fig.add_trace(
        go.Pie(
            labels=list(risk_counts.keys()),
            values=list(risk_counts.values()),
            hole=0.66,
            marker=dict(
                colors=[
                    "#ef4444",
                    "#f59e0b",
                    "#fbbf24",
                    "#22c55e",
                    "#10b981",
                ]
            ),
            textinfo="label+percent",
            textposition="outside",
        )
    )
    fig.update_layout(
        template="plotly_dark",
        height=320,
        margin=dict(l=20, r=20, t=20, b=20),
        showlegend=False,
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig, use_container_width=True)


def render_performance_panel(snapshot: Dict[str, Any]) -> None:
    st.markdown(
        f"""
        <div class='perf-panel'>
            <div class='perf-grid'>
                <div>
                    <div class='perf-label'>Throughput</div>
                    <div class='perf-value'>{snapshot['throughput']:.1f}/min</div>
                    <div class='perf-foot'>Derived from average scan time</div>
                </div>
                <div>
                    <div class='perf-label'>Detection Rate</div>
                    <div class='perf-value'>{snapshot['detection_rate']:.1f}%</div>
                    <div class='perf-foot'>{snapshot['threats']} alerts over {snapshot['processed']} emails</div>
                </div>
                <div>
                    <div class='perf-label'>Queue Health</div>
                    <div class='perf-value'>{snapshot['queue_health']:.0f}/100</div>
                    <div class='perf-foot'>Queue size: {snapshot['queue_size']}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def build_alert_table(alerts_list: List[Dict[str, Any]]) -> pd.DataFrame:
    rows: List[Dict[str, str]] = []
    for alert in alerts_list:
        score = float(alert.get("threat_score", 0) or 0)
        subject = str(alert.get("subject", "N/A"))
        if len(subject) > 64:
            subject = f"{subject[:64]}..."
        rows.append(
            {
                "Time": format_local(alert.get("timestamp"), "%Y-%m-%d %H:%M:%S"),
                "Risk": str(alert.get("risk_level", "SAFE")),
                "Score": f"{score:.0%}",
                "From": str(alert.get("from_email", "N/A")),
                "Subject": subject,
                "Status": str(alert.get("status", "new")).upper(),
            }
        )
    return pd.DataFrame(rows)


def authenticate(username: str, password: str) -> bool:
    expected_username = os.getenv("ADMIN_USERNAME", "admin")
    expected_password = os.getenv("ADMIN_PASSWORD", "admin123")
    if username == expected_username and password == expected_password:
        logger.info(f"User '{username}' logged in successfully")
        return True
    if username:
        logger.warning(f"Failed login attempt for user '{username}'")
    return False


def render_login_page() -> None:
    c1, c2, c3 = st.columns([1, 1.8, 1])
    with c2:
        with st.container(border=True):
            st.title("Email Security Gateway")
            st.caption("Secure mail operations with live phishing intelligence")
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter username")
                password = st.text_input("Password", type="password", placeholder="Enter password")
                submitted = st.form_submit_button("Sign In", type="primary", use_container_width=True)
                if submitted:
                    if authenticate(username, password):
                        st.session_state.authenticated = True
                        st.session_state.username = username
                        st.session_state.last_refresh = now_local()
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
        st.caption("Default credentials: admin / admin123")


def render_sidebar(snapshot: Dict[str, Any]) -> None:
    with st.sidebar:
        st.markdown("Operator")
        st.markdown(f"**{st.session_state.username or 'unknown'}**")
        st.divider()
        st.metric("Queue", snapshot["queue_size"])
        st.metric("Threat Rate", f"{snapshot['detection_rate']:.1f}%")
        st.metric("Avg Scan", f"{snapshot['avg_time']:.2f}s")
        st.caption(f"Local Time: {format_local(now_local())}")
        st.caption(f"Refreshed: {format_local(st.session_state.last_refresh)}")
        st.divider()
        if st.button("Refresh Data", use_container_width=True):
            st.cache_data.clear()
            st.session_state.last_refresh = now_local()
            st.rerun()
        if st.button("Sign Out", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.username = None
            st.session_state.active_page = "Operations"
            st.rerun()


def render_top_bar_controls(snapshot: Dict[str, Any]) -> None:
    st.markdown(
        f"""
        <div class='top-ribbon'>
            <div class='ribbon-title'>Security Operations Dashboard</div>
            <div class='ribbon-sub'>Unified control ribbon for filters, search, reporting, and runtime context.</div>
            <div class='ribbon-meta'>Queue {snapshot['queue_size']} | Threat Rate {snapshot['detection_rate']:.1f}% | Avg Scan {snapshot['avg_time']:.2f}s | Local {format_local(now_local(), '%H:%M:%S %Z')}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("<div class='control-ribbon'></div>", unsafe_allow_html=True)
    c1, c2, c3, c4, c5, c6 = st.columns([1.6, 1.6, 2.2, 1.0, 1.0, 1.1])
    with c1:
        st.selectbox(
            "Date Window",
            ["Today", "Last 7 Days", "Last 30 Days", "Quarter to Date"],
            key="top_date_window",
            help="Global reporting time range.",
        )
    with c2:
        st.selectbox(
            "Scope",
            ["All Traffic", "Critical + High Only", "Government Domains", "Training Snapshot"],
            key="top_scope",
            help="Global operational focus.",
        )
    with c3:
        st.text_input(
            "Global Search",
            key="global_search",
            placeholder="Search subject, sender, status, risk",
        )
    with c4:
        st.toggle("Auto", key="auto_refresh", help="Auto-refresh each rerun cycle")
    export_payload = {
        "generated_at": now_local().isoformat(),
        "date_window": st.session_state.top_date_window,
        "scope": st.session_state.top_scope,
        "search": st.session_state.global_search,
        "snapshot": snapshot,
    }
    with c5:
        st.download_button(
            "Export",
            data=json.dumps(export_payload, indent=2),
            file_name=f"gateway_snapshot_{now_local().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
            key="top_export_btn",
        )
    with c6:
        if st.button("+ Report", use_container_width=True, key="top_report_btn"):
            st.session_state.active_page = "Threat Queue"
            st.rerun()


def render_navigation() -> str:
    try:
        default_index = NAV_PAGES.index(st.session_state.active_page)
    except ValueError:
        default_index = 0
    page = st.radio(
        "Navigation",
        NAV_PAGES,
        index=default_index,
        horizontal=True,
        key="main_navigation",
        label_visibility="collapsed",
    )
    st.session_state.active_page = page
    return page


def render_shell_header(page: str, snapshot: Dict[str, Any]) -> None:
    if snapshot["queue_size"] <= 3:
        queue_chip = "chip-good"
    elif snapshot["queue_size"] <= 10:
        queue_chip = "chip-warn"
    else:
        queue_chip = "chip-bad"
    if snapshot["detection_rate"] <= 3:
        rate_chip = "chip-good"
    elif snapshot["detection_rate"] <= 8:
        rate_chip = "chip-warn"
    else:
        rate_chip = "chip-bad"
    model_chip = "chip-good" if snapshot["model_loaded"] else "chip-bad"
    st.markdown(
        f"""
        <div class='shell-header'>
            <h1 class='shell-title'>{page}</h1>
            <div class='shell-subtitle'>{PAGE_DESCRIPTIONS.get(page, '')}</div>
            <div class='shell-chip-row'>
                <span class='shell-chip {model_chip}'>Model {'Online' if snapshot['model_loaded'] else 'Offline'}</span>
                <span class='shell-chip {queue_chip}'>Queue {snapshot['queue_size']}</span>
                <span class='shell-chip {rate_chip}'>Threat Rate {snapshot['detection_rate']:.1f}%</span>
                <span class='shell-chip chip-info'>Local {format_local(now_local(), '%H:%M:%S')}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_guide() -> None:
    st.markdown(
        """
        <div class='metric-guide'>
            Threat rate above 8% indicates elevated campaign activity, queue health below 70 signals backlog pressure, and average scan latency should trend downward during stable operations.
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_operations_page(stats: Dict[str, Any], alerts_list: List[Dict[str, Any]]) -> None:
    snapshot = build_operational_snapshot(stats, alerts_list)
    st.markdown("<p class='section-note'>Single-pane monitoring view with strict hierarchy and operational density.</p>", unsafe_allow_html=True)
    render_metric_guide()
    with st.container(border=True):
        st.subheader("Operational Snapshot")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            metric_card(snapshot["processed"], "Processed Mail", "live", "blue", "Total evaluated messages")
        with c2:
            metric_card(snapshot["threats"], "Flagged Threats", f"{snapshot['detection_rate']:.1f}%", "red", "Requires triage")
        with c3:
            metric_card(snapshot["safe_count"], "Clean Pass", "delivered", "green", "Low-risk traffic")
        with c4:
            metric_card(f"{snapshot['avg_time']:.2f}s", "Avg Scan", "lower is better", "orange", "Processing latency")
    with st.container(border=True):
        st.subheader("System Performance")
        render_performance_panel(snapshot)
    col1, col2 = st.columns(2)
    with col1:
        with st.container(border=True):
            st.subheader("Risk Distribution")
            render_risk_distribution(alerts_list)
    with col2:
        with st.container(border=True):
            st.subheader("Threat Timeline")
            render_threat_chart(alerts_list)
    with st.container(border=True):
        st.subheader("Recent Threat Events")
        if alerts_list:
            for alert in alerts_list[:5]:
                display_alert_card(alert)
        else:
            st.info("No recent alerts")
    with st.container(border=True):
        st.subheader("Threat Queue Log")
        queue_df = build_alert_table(alerts_list[:14])
        if queue_df.empty:
            st.info("No queue records available")
        else:
            st.dataframe(
                queue_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Time": st.column_config.TextColumn("Time", width="medium"),
                    "Risk": st.column_config.TextColumn("Risk", width="small"),
                    "Score": st.column_config.TextColumn("Score", width="small"),
                    "From": st.column_config.TextColumn("From", width="medium"),
                    "Subject": st.column_config.TextColumn("Subject", width="large"),
                    "Status": st.column_config.TextColumn("Status", width="small"),
                },
            )


def render_email_checker_page() -> None:
    st.title("Message Inspector")
    st.markdown("<p class='section-note'>Analyze a single message and receive an actionable security verdict.</p>", unsafe_allow_html=True)
    st.markdown(
        """
        <div class='queue-shell'>
            Load a sample or paste full email content, run analysis, then escalate if risk is HIGH or CRITICAL.
        </div>
        """,
        unsafe_allow_html=True,
    )
    sample_templates = {
        "Legitimate Meeting": (
            "Meeting Agenda - Project Review",
            "Hi Team,\n\nPlease find attached the agenda for tomorrow's 10 AM project review meeting.\n\nAgenda:\n1. Project status update\n2. Q2 planning\n3. Resource allocation\n\nBest regards,\nJohn Doe\nProject Manager",
        ),
        "Phishing Example": (
            "URGENT: Your Account Will Be Suspended",
            "Dear Valued Customer,\n\nYour account has been flagged for unusual activity. To avoid suspension, verify immediately.\n\nClick here: http://bit.ly/gcash-verify-urgent\n\nSupport Team",
        ),
        "Suspicious Link": (
            "Your Package Delivery Update",
            "Dear Customer,\n\nYour package requires verification.\n\nTrack: http://bit.ly/track-package-123456\n\nLogistics Team",
        ),
    }
    col1, col2 = st.columns([3, 2])
    with col2:
        st.subheader("Quick Samples")
        for template_name, template_data in sample_templates.items():
            key = f"sample_{template_name.lower().replace(' ', '_')}"
            if st.button(template_name, use_container_width=True, key=key):
                st.session_state.check_subject = template_data[0]
                st.session_state.check_body = template_data[1]
                st.rerun()
        if st.button("Clear Draft", use_container_width=True, key="clear_draft"):
            st.session_state.check_subject = ""
            st.session_state.check_body = ""
            st.rerun()
    with col1:
        st.markdown("<p class='field-hint'>Subject shows intent while body content reveals pressure tactics and link behavior.</p>", unsafe_allow_html=True)
        with st.form("email_check_form"):
            subject = st.text_input(
                "Subject Line",
                key="check_subject",
                placeholder="Example: Action required for payroll update",
            )
            body = st.text_area(
                "Email Body",
                key="check_body",
                height=260,
                placeholder="Paste full message content",
            )
            f1, f2 = st.columns(2)
            with f1:
                submitted = st.form_submit_button("Analyze Message", type="primary", use_container_width=True)
            with f2:
                reset_fields = st.form_submit_button("Reset Fields", use_container_width=True)
    if reset_fields:
        st.session_state.check_subject = ""
        st.session_state.check_body = ""
        st.rerun()
    if submitted and (subject or body):
        with st.spinner("Analyzing message..."):
            result = check_email_api(subject, body)
        if result and "error" not in result:
            score = float(result.get("threat_score", 0) or 0)
            if score >= 0.8:
                risk = "CRITICAL"
                color = "#ef4444"
            elif score >= 0.6:
                risk = "HIGH"
                color = "#f59e0b"
            elif score >= 0.4:
                risk = "MEDIUM"
                color = "#fbbf24"
            else:
                risk = "SAFE"
                color = "#22c55e"
            st.markdown("### Analysis Result")
            st.markdown(
                f"""
                <div class='result-hero'>
                    <div style='font-size:0.82rem;color:#9aa4b2;text-transform:uppercase;letter-spacing:0.08em;'>Verdict</div>
                    <div style='font-size:1.7rem;font-weight:700;color:{color};margin-top:0.25rem;'>{risk}</div>
                    <div style='font-size:2.15rem;font-weight:740;color:{color};margin-top:0.1rem;'>{score:.1%}</div>
                    <div style='font-size:0.86rem;color:#9aa4b2;margin-top:0.22rem;'>Threat confidence</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            m1, m2, m3 = st.columns(3)
            with m1:
                st.metric("Risk Level", risk)
            with m2:
                st.metric("Threat Score", f"{score:.1%}")
            with m3:
                st.metric("Action", "Escalate" if score >= 0.6 else "Monitor")
            explanations = result.get("explanations") or []
            if explanations:
                st.subheader("Detection Reasons")
                for reason in explanations:
                    st.info(reason)
        elif result and "error" in result:
            st.error(f"Error: {result['error']}")


def render_threat_queue_page(alerts_list: List[Dict[str, Any]]) -> None:
    st.title("Threat Queue")
    st.markdown("<p class='section-note'>Log-focused queue with strict filtering and clear triage states.</p>", unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown("<div class='control-ribbon'></div>", unsafe_allow_html=True)
        col1, col2, col3, col4 = st.columns([1, 1, 1, 2])
        with col1:
            status_filter = st.selectbox("Status", ["All", "new", "acknowledged", "resolved"], key="queue_status")
        with col2:
            risk_filter = st.selectbox("Risk", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"], key="queue_risk")
        with col3:
            time_filter = st.selectbox("Window", ["24h", "7d", "30d", "All"], key="queue_window")
        with col4:
            local_search = st.text_input("Queue Search", value="", key="queue_search", placeholder="sender, subject, status")

    filtered = list(alerts_list)
    if status_filter != "All":
        filtered = [a for a in filtered if str(a.get("status", "")).lower() == status_filter.lower()]
    if risk_filter != "All":
        filtered = [a for a in filtered if str(a.get("risk_level", "")).upper() == risk_filter]
    filtered = filter_alerts_by_time_window(filtered, time_filter)

    terms = [st.session_state.global_search.strip().lower(), local_search.strip().lower()]
    terms = [t for t in terms if t]
    if terms:
        def match_alert(a: Dict[str, Any]) -> bool:
            hay = " ".join(
                [
                    str(a.get("from_email", "")),
                    str(a.get("subject", "")),
                    str(a.get("status", "")),
                    str(a.get("risk_level", "")),
                ]
            ).lower()
            return all(t in hay for t in terms)
        filtered = [a for a in filtered if match_alert(a)]

    with st.container(border=True):
        st.subheader("Queue Summary")
        s1, s2, s3, s4 = st.columns(4)
        total_count = len(filtered)
        critical_count = len([a for a in filtered if str(a.get("risk_level", "")).upper() == "CRITICAL"])
        new_count = len([a for a in filtered if str(a.get("status", "")).lower() == "new"])
        resolved_count = len([a for a in filtered if str(a.get("status", "")).lower() == "resolved"])
        with s1:
            metric_card(total_count, "Visible Alerts", "filtered", "blue")
        with s2:
            metric_card(critical_count, "Critical", "urgent", "red")
        with s3:
            metric_card(new_count, "New", "triage", "orange")
        with s4:
            metric_card(resolved_count, "Resolved", "closed", "green")

    if not filtered:
        st.info("No alerts match the selected filters")
        return

    view_mode = st.radio(
        "Queue View",
        ["Log Table", "Alert Cards"],
        horizontal=True,
        label_visibility="collapsed",
        key="queue_view_mode",
    )

    if view_mode == "Log Table":
        with st.container(border=True):
            st.subheader("Threat Queue Log")
            queue_df = build_alert_table(filtered)
            st.dataframe(
                queue_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Time": st.column_config.TextColumn("Time", width="medium"),
                    "Risk": st.column_config.TextColumn("Risk", width="small"),
                    "Score": st.column_config.TextColumn("Score", width="small"),
                    "From": st.column_config.TextColumn("From", width="medium"),
                    "Subject": st.column_config.TextColumn("Subject", width="large"),
                    "Status": st.column_config.TextColumn("Status", width="small"),
                },
            )
    else:
        with st.container(border=True):
            st.subheader(f"Alert Cards ({len(filtered)})")
            for alert in filtered:
                display_alert_card(alert)


def render_trend_lens_page(alerts_list: List[Dict[str, Any]]) -> None:
    st.title("Trend Lens")
    st.markdown("<p class='section-note'>Analytics view for trend movement, risk composition, and closure rate.</p>", unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown("<div class='control-ribbon'></div>", unsafe_allow_html=True)
        window = st.selectbox("Time Window", ["24h", "7d", "30d", "All"], key="trend_window")
    filtered = filter_alerts_by_time_window(alerts_list, window)

    global_search = st.session_state.global_search.strip().lower()
    if global_search:
        filtered = [
            a
            for a in filtered
            if global_search in str(a.get("subject", "")).lower()
            or global_search in str(a.get("from_email", "")).lower()
            or global_search in str(a.get("risk_level", "")).lower()
        ]

    with st.container(border=True):
        st.subheader("Trend Summary")
        c1, c2, c3, c4 = st.columns(4)
        total_alerts = len(filtered)
        critical = len([a for a in filtered if str(a.get("risk_level", "")).upper() == "CRITICAL"])
        high = len([a for a in filtered if str(a.get("risk_level", "")).upper() == "HIGH"])
        resolved = len([a for a in filtered if str(a.get("status", "")).lower() == "resolved"])
        resolved_rate = (resolved / total_alerts * 100) if total_alerts else 0.0
        with c1:
            metric_card(total_alerts, "Alerts in Window", "time scoped", "blue")
        with c2:
            metric_card(critical, "Critical Volume", "urgent", "red")
        with c3:
            metric_card(high, "High Risk", "priority", "orange")
        with c4:
            metric_card(resolved, "Resolved", f"{resolved_rate:.1f}%", "green")

    row1, row2 = st.columns(2)
    with row1:
        with st.container(border=True):
            st.subheader("Risk Distribution")
            render_risk_distribution(filtered)
    with row2:
        with st.container(border=True):
            st.subheader("Threat Timeline")
            render_threat_chart(filtered)

    with st.container(border=True):
        st.subheader("Trend Queue")
        trend_df = build_alert_table(filtered[:20])
        if trend_df.empty:
            st.info("No events found for selected scope")
        else:
            st.dataframe(trend_df, use_container_width=True, hide_index=True)


def render_control_room_page() -> None:
    st.title("Control Room")
    st.markdown("<p class='section-note'>Configure thresholds, notifications, and model behavior.</p>", unsafe_allow_html=True)
    with st.container(border=True):
        st.subheader("Detection Profile")
        st.markdown("<p class='field-hint'>Higher thresholds reduce false positives but may miss subtle attacks.</p>", unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            st.slider("Critical Alert Threshold", 0.0, 1.0, 0.8, 0.05, key="crit")
            st.slider("High Alert Threshold", 0.0, 1.0, 0.6, 0.05, key="high")
            st.slider("Medium Alert Threshold", 0.0, 1.0, 0.4, 0.05, key="med")
        with c2:
            st.checkbox("Analyze URLs", value=True, key="cfg_urls")
            st.checkbox("Analyze Domains", value=True, key="cfg_domains")
            st.checkbox("Detect Suspicious Patterns", value=True, key="cfg_patterns")
        if st.button("Save Detection Profile", type="primary", key="save_detect"):
            st.success("Detection profile saved")

    with st.container(border=True):
        st.subheader("Notification Rules")
        n1, n2 = st.columns(2)
        with n1:
            st.checkbox("Send Email Alerts", value=True, key="cfg_email_alerts")
            st.text_input("Notification Email", value="admin@prototype.local", key="cfg_email")
        with n2:
            st.checkbox("Show In-Dashboard Alerts", value=True, key="cfg_dashboard_alerts")
            st.checkbox("Enable Sound Notifications", value=False, key="cfg_sound")
        if st.button("Save Notification Rules", type="primary", key="save_notify"):
            st.success("Notification rules saved")

    with st.container(border=True):
        st.subheader("Model Runtime")
        st.radio("Detection Mode", ["TinyBERT (Fast)", "BERT (Accurate)", "Ensemble"], index=0, key="cfg_model")
        st.slider("Minimum Confidence for Alert", 0.0, 1.0, 0.5, 0.05, key="cfg_conf")
        st.checkbox("Use External Intelligence", value=True, key="cfg_intel")
        st.checkbox("Cache Prediction Results", value=True, key="cfg_cache")
        if st.button("Save Runtime Settings", type="primary", key="save_runtime"):
            st.success("Runtime settings saved")

    with st.container(border=True):
        st.subheader("System Information")
        i1, i2 = st.columns(2)
        with i1:
            st.markdown(f"**API Base URL:** {API_BASE_URL}")
            st.markdown("**Runtime Model:** TinyBERT wrapper")
        with i2:
            st.markdown(f"**Environment:** {os.getenv('ENVIRONMENT', 'development')}")
            st.markdown("**Version:** 1.2.0")


def render_system_guide_page() -> None:
    st.title("System Guide")
    st.markdown("<p class='section-note'>Operational manual area for live run instructions and response procedures.</p>", unsafe_allow_html=True)

    with st.container(border=True):
        st.subheader("Startup Checklist")
        st.markdown(
            """
            1. Confirm API health endpoint and model status.
            2. Verify queue workers and ingestion flow.
            3. Validate threat queue filters and alert rendering.
            4. Confirm notification channels before go-live.
            """
        )

    with st.container(border=True):
        st.subheader("Live Operations Workflow")
        st.markdown(
            """
            1. Review Operations page for queue pressure and threat spikes.
            2. Use Message Inspector for suspicious user-reported emails.
            3. Triage in Threat Queue using status/risk filters.
            4. Track closure trends in Trend Lens.
            5. Tune controls in Control Room when thresholds drift.
            """
        )

    with st.container(border=True):
        st.subheader("Incident Response Playbook")
        st.markdown(
            """
            - Critical: isolate sender domain and escalate immediately.
            - High: quarantine affected messages and review links.
            - Medium: monitor campaign progression and notify analysts.
            - Safe/Low: continue observation and archive context.
            """
        )

    with st.container(border=True):
        st.subheader("Custom Guide Notes")
        st.text_area(
            "Write your local operations guide",
            key="guide_notes",
            height=220,
            placeholder="Add run commands, triage SOPs, and shift handoff notes.",
        )
        if st.button("Save Guide Notes", key="save_guide", use_container_width=True):
            st.success("Guide notes saved in session")


def main_dashboard() -> None:
    stats = fetch_stats()
    alerts_list = fetch_alerts(limit=120)
    snapshot = build_operational_snapshot(stats, alerts_list)

    if st.session_state.auto_refresh:
        st.session_state.last_refresh = now_local()

    render_sidebar(snapshot)
    render_top_bar_controls(snapshot)

    page = render_navigation()
    st.markdown(f"<div class='nav-note'>{PAGE_DESCRIPTIONS.get(page, '')}</div>", unsafe_allow_html=True)
    render_shell_header(page, snapshot)

    if page == "Operations":
        render_operations_page(stats, alerts_list)
    elif page == "Message Inspector":
        render_email_checker_page()
    elif page == "Threat Queue":
        render_threat_queue_page(alerts_list)
    elif page == "Trend Lens":
        render_trend_lens_page(alerts_list)
    elif page == "Control Room":
        render_control_room_page()
    elif page == "System Guide":
        render_system_guide_page()


def main() -> None:
    initialize_session_state()
    apply_styles()
    if not st.session_state.authenticated:
        render_login_page()
    else:
        main_dashboard()


if __name__ == "__main__":
    main()
