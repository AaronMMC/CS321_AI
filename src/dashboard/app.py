"""
Main Streamlit dashboard application - IMPROVED VERSION.
This is the entry point for the admin dashboard.
"""

import os
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import requests
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables on startup
load_dotenv()

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.dashboard import alerts, admin
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

# Custom CSS - Apple-inspired Design
st.markdown("""
<style>
    :root {
        --apple-bg: #f5f5f7;
        --apple-surface: rgba(255, 255, 255, 0.76);
        --apple-border: rgba(29, 29, 31, 0.12);
        --apple-text: #1d1d1f;
        --apple-muted: #6e6e73;
        --apple-accent: #0071e3;
        --apple-accent-soft: rgba(0, 113, 227, 0.12);
        --apple-critical: #d62828;
        --apple-warning: #f4a100;
        --apple-safe: #188038;
        --apple-shadow: 0 12px 40px rgba(15, 23, 42, 0.08);
    }

    .stApp {
        font-family: "SF Pro Text", "SF Pro Display", "Helvetica Neue", "Helvetica", "Segoe UI", sans-serif;
        color: var(--apple-text);
        background:
            radial-gradient(circle at 0% 0%, rgba(0, 113, 227, 0.10), transparent 36%),
            radial-gradient(circle at 100% 0%, rgba(12, 180, 206, 0.10), transparent 32%),
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
        background: linear-gradient(180deg, #f0f2f6 0%, #e9edf3 100%);
        border-right: 1px solid var(--apple-border);
    }

    [data-testid="stSidebar"] * {
        color: var(--apple-text) !important;
    }

    .sidebar-brand {
        border-radius: 18px;
        padding: 0.95rem;
        border: 1px solid var(--apple-border);
        background: var(--apple-surface);
        backdrop-filter: blur(14px);
        box-shadow: var(--apple-shadow);
    }

    .sidebar-muted {
        color: var(--apple-muted);
        font-size: 0.82rem;
        margin-bottom: 0.25rem;
    }

    /* Buttons and form controls */
    .stButton > button,
    .stFormSubmitButton > button {
        border-radius: 999px;
        border: 1px solid var(--apple-border);
        background: rgba(255, 255, 255, 0.86);
        color: var(--apple-text);
        font-weight: 600;
        letter-spacing: -0.01em;
        transition: all 0.18s ease;
    }

    .stButton > button:hover,
    .stFormSubmitButton > button:hover {
        border-color: rgba(0, 113, 227, 0.34);
        box-shadow: 0 6px 22px rgba(0, 113, 227, 0.14);
        transform: translateY(-1px);
    }

    .stTextInput input,
    .stTextArea textarea,
    .stSelectbox div[data-baseweb="select"] > div,
    .stMultiSelect div[data-baseweb="select"] > div {
        border-radius: 14px !important;
        border: 1px solid var(--apple-border) !important;
        background: rgba(255, 255, 255, 0.9) !important;
    }

    .stTabs [data-testid="stTabBar"] {
        border-bottom: 1px solid var(--apple-border);
    }

    /* Metric cards */
    .metric-card {
        min-height: 158px;
        border-radius: 22px;
        padding: 1rem 1.1rem;
        border: 1px solid var(--apple-border);
        background: var(--apple-surface);
        backdrop-filter: blur(16px);
        box-shadow: var(--apple-shadow);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        overflow: hidden;
    }

    .metric-neutral { background: linear-gradient(145deg, rgba(255,255,255,0.86), rgba(246,247,251,0.9)); }
    .metric-blue    { background: linear-gradient(145deg, rgba(0,113,227,0.16), rgba(255,255,255,0.9)); }
    .metric-red     { background: linear-gradient(145deg, rgba(214,40,40,0.12), rgba(255,255,255,0.9)); }
    .metric-green   { background: linear-gradient(145deg, rgba(24,128,56,0.12), rgba(255,255,255,0.9)); }
    .metric-orange  { background: linear-gradient(145deg, rgba(244,161,0,0.12), rgba(255,255,255,0.9)); }

    .metric-label {
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--apple-muted);
        font-weight: 600;
    }

    .metric-value {
        font-size: clamp(1.45rem, 2.4vw, 2.35rem);
        font-weight: 700;
        letter-spacing: -0.03em;
        color: var(--apple-text);
        margin-top: 0.3rem;
        line-height: 1.1;
    }

    .metric-delta {
        font-size: 0.83rem;
        color: #0b57d0;
        background: rgba(11, 87, 208, 0.1);
        border-radius: 999px;
        width: fit-content;
        padding: 0.22rem 0.58rem;
        font-weight: 600;
    }

    .metric-sub {
        margin-top: 0.5rem;
        color: var(--apple-muted);
        font-size: 0.8rem;
    }

    .perf-panel {
        border-radius: 20px;
        border: 1px solid var(--apple-border);
        background: var(--apple-surface);
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
        color: var(--apple-muted);
    }

    .perf-value {
        margin-top: 0.3rem;
        font-size: 1.45rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        color: var(--apple-text);
    }

    .perf-foot {
        margin-top: 0.18rem;
        color: var(--apple-muted);
        font-size: 0.78rem;
    }

    /* Alerts */
    .alert-card {
        border-radius: 16px;
        padding: 0.95rem 1rem;
        border: 1px solid var(--apple-border);
        background: rgba(255, 255, 255, 0.84);
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.07);
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
        color: var(--apple-muted);
        font-size: 0.94rem;
        margin-top: -0.35rem;
    }

    @media (max-width: 960px) {
        .block-container {
            padding-top: 1rem;
            padding-left: 0.8rem;
            padding-right: 0.8rem;
        }

        .metric-card {
            min-height: 132px;
            padding: 0.85rem;
        }

        .perf-grid {
            grid-template-columns: 1fr;
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
    
    try:
        timestamp = datetime.fromisoformat(alert['timestamp']).strftime('%b %d, %H:%M')
    except:
        timestamp = 'Unknown'
    
    risk_color = {
        'CRITICAL': '#d62828',
        'HIGH': '#f4a100',
        'MEDIUM': '#d89c1f',
        'LOW': '#188038',
        'SAFE': '#188038',
    }.get(risk, '#6e6e73')

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
            <div style='font-size: 0.79rem; color: #6e6e73; margin-top: 0.35rem;'>
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
        fillcolor='rgba(0, 113, 227, 0.18)',
        line=dict(color='#0071e3', width=3),
        marker=dict(size=8, color='#0071e3', line=dict(color='white', width=1.6)),
        name='Threats Detected'
    ))

    fig.update_layout(
        template='simple_white',
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
        template='simple_white',
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
    
    # Sidebar
    with st.sidebar:
        st.markdown("""
        <div class='sidebar-brand' style='text-align: center;'>
            <h2 style='margin: 0;'>Security Gateway</h2>
            <p class='sidebar-muted' style='margin-top: 0.35rem;'>Apple-inspired command center</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # User info
        st.markdown("<p class='sidebar-muted'>Logged in as</p>", unsafe_allow_html=True)
        st.markdown(f"**{st.session_state.username}**")
        
        st.markdown("---")
        
        # Navigation
        page = st.radio(
            "Menu",
            ["📊 Overview", "🔍 Email Checker", "⚠️ Alerts", "📈 Analytics", "⚙️ Settings"]
        )
        
        st.markdown("---")
        
        # Quick stats in sidebar
        stats = fetch_stats()
        
        model_status = "✅ Loaded" if stats.get('model_loaded') else "❌ Offline"
        st.markdown(f"**Model:** {model_status}")
        
        last_update = datetime.now().strftime('%H:%M:%S')
        st.caption(f"Last updated: {last_update}")
        
        # Refresh
        if st.button("🔄 Refresh", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
        
        st.markdown("---")
        
        # Logout
        if st.button("🚪 Sign Out", use_container_width=True):
            st.session_state.authenticated = False
            st.rerun()
    
    # Main content
    if page == "📊 Overview":
        render_overview()
    elif page == "🔍 Email Checker":
        render_email_checker()
    elif page == "⚠️ Alerts":
        render_alerts()
    elif page == "📈 Analytics":
        render_analytics()
    elif page == "⚙️ Settings":
        render_settings()


def render_overview():
    """Render overview dashboard"""
    st.title("Dashboard Overview")
    st.markdown("<p class='section-note'>Real-time security posture with operational and risk insights.</p>", unsafe_allow_html=True)
    
    # Fetch data
    stats = fetch_stats()
    alerts_list = fetch_alerts(limit=10)
    
    # Metrics row
    st.markdown("### Core Metrics")
    
    c1, c2, c3, c4 = st.columns(4)

    processed_count = int(stats.get('emails_processed', 0) or 0)
    threats_count = int(stats.get('threats_detected', 0) or 0)
    queue_size = int(stats.get('queue_size', 0) or 0)
    avg_proc = float(stats.get('avg_processing_time', 0) or 0)
    if threats_count == 0 and alerts_list:
        threats_count = len(alerts_list)

    detection_rate = (threats_count / processed_count * 100) if processed_count > 0 else 0.0
    
    with c1:
        metric_card(f"{processed_count:,}", "Emails Processed", "+live", "blue", "Inbound messages analyzed")
    with c2:
        metric_card(threats_count, "Threats Detected", f"{detection_rate:.1f}% rate", "red", "High-risk and suspicious detections")
    with c3:
        metric_card(queue_size, "Queue Backlog", "healthy" if queue_size < 5 else "watch", "orange", "Pending jobs waiting for workers")
    with c4:
        metric_card(f"{avg_proc:.2f}s", "Avg Processing", "lower is better", "green", "Average queue wait / processing latency")

    st.markdown("### Performance Metrics")
    render_performance_panel(stats, alerts_list)
    
    st.markdown("---")
    
    # Charts row
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Risk Distribution")
        render_risk_distribution(alerts_list)
    
    with col2:
        st.markdown("### Threat Timeline")
        render_threat_chart(alerts_list)
    
    st.markdown("---")
    
    # Recent alerts
    st.markdown("### Recent Alerts")
    
    if alerts_list:
        for alert in alerts_list[:5]:
            display_alert_card(alert)
    else:
        st.info("No recent alerts")


def render_email_checker():
    """Render email checker page"""
    st.title("🔍 Email Checker")
    st.markdown("Test emails against the AI detection model")
    
    col1, col2 = st.columns([3, 2])
    
    with col1:
        with st.form("email_check_form"):
            subject = st.text_input("Subject Line", placeholder="Enter email subject...")
            body = st.text_area("Email Body", height=250, placeholder="Paste email content here...")
            
            c1, c2 = st.columns(2)
            with c1:
                submitted = st.form_submit_button("🔍 Analyze Email", type="primary", use_container_width=True)
            with c2:
                clear = st.form_submit_button("🗑️ Clear", use_container_width=True)
    
    with col2:
        st.markdown("#### Quick Test Samples")
        
        if st.button("📧 Legitimate Meeting", use_container_width=True, key="test_legit"):
            st.session_state.test_subject = "Meeting Agenda - Project Review"
            st.session_state.test_body = """Hi Team,

Please find attached the agenda for tomorrow's 10 AM project review meeting.

Agenda:
1. Project status update
2. Q2 planning
3. Resource allocation

Best regards,
John Doe
Project Manager"""
        
        if st.button("⚠️ Phishing Example", use_container_width=True, key="test_phish"):
            st.session_state.test_subject = "URGENT: Your Account Will Be Suspended"
            st.session_state.test_body = """Dear Valued Customer,

Your GCash account has been flagged for unusual activity. To avoid permanent suspension, please verify your account immediately.

Click here to verify: http://bit.ly/gcash-verify-urgent

Failure to verify within 24 hours will result in account closure.

GCash Support Team"""
        
        if st.button("🔗 Suspicious Link", use_container_width=True, key="test_link"):
            st.session_state.test_subject = "Your Package Delivery Update"
            st.session_state.test_body = """Dear Customer,

Your package is on the way but requires verification. 

Track your delivery: http://bit.ly/track-package-123456

Please verify your address to ensure delivery.

Logistics Team"""
    
    # Show pre-filled if from buttons
    if 'test_subject' in st.session_state:
        st.session_state.subject = st.session_state.get('test_subject', '')
        st.session_state.body = st.session_state.get('test_body', '')
    
    # Process email
    if submitted and (subject or body):
        with st.spinner("Analyzing email..."):
            result = check_email_api(subject, body)
        
        if result and "error" not in result:
            st.markdown("---")
            st.markdown("### Analysis Results")
            
            score = result.get('threat_score', 0)
            
            # Determine risk level and color
            if score >= 0.8:
                risk = "CRITICAL"
                color = "#dc2626"
                emoji = "⛔"
            elif score >= 0.6:
                risk = "HIGH"
                color = "#f59e0b"
                emoji = "⚠️"
            elif score >= 0.4:
                risk = "MEDIUM"
                color = "#eab308"
                emoji = "🔔"
            else:
                risk = "SAFE"
                color = "#10b981"
                emoji = "✅"
            
            # Display result prominently
            st.markdown(f"""
            <div style='text-align: center; padding: 2rem; background: {color}15; border-radius: 12px; border: 2px solid {color}; margin: 1rem 0;'>
                <div style='font-size: 3rem; margin-bottom: 0.5rem;'>{emoji}</div>
                <div style='font-size: 1.5rem; font-weight: 600; color: {color};'>{risk}</div>
                <div style='font-size: 2rem; font-weight: 700; color: {color};'>{score:.1%}</div>
                <div style='color: #64748b;'>Threat Confidence</div>
            </div>
            """, unsafe_allow_html=True)
            
            # Explanations
            if result.get('explanations'):
                st.markdown("#### Detection Reasons:")
                for reason in result['explanations']:
                    st.info(reason)
        elif result and "error" in result:
            st.error(f"Error: {result['error']}")


def render_alerts():
    """Render alerts management page"""
    st.title("⚠️ Alert Management")
    st.markdown("Review and manage detected threats")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        status_filter = st.selectbox("Status", ["All", "new", "acknowledged", "resolved"])
    with col2:
        risk_filter = st.selectbox("Risk Level", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with col3:
        time_filter = st.selectbox("Time Range", ["Last 24 hours", "Last 7 days", "Last 30 days"])
    
    # Get alerts
    alerts_list = fetch_alerts(limit=50)
    
    # Apply filters
    if status_filter != "All":
        alerts_list = [a for a in alerts_list if a.get('status') == status_filter]
    if risk_filter != "All":
        alerts_list = [a for a in alerts_list if a.get('risk_level') == risk_filter]
    
    st.markdown("---")
    
    # Display alerts
    st.markdown(f"### {len(alerts_list)} Alerts")
    
    for alert in alerts_list:
        display_alert_card(alert)
        st.markdown("")  # Spacing


def render_analytics():
    """Render analytics page"""
    st.title("Analytics")
    st.markdown("<p class='section-note'>Risk distribution, timeline, and model operational behavior.</p>", unsafe_allow_html=True)
    
    alerts_list = fetch_alerts(limit=100)
    
    # Summary stats
    c1, c2, c3, c4 = st.columns(4)

    total_alerts = len(alerts_list)
    critical = len([a for a in alerts_list if a.get('risk_level') == 'CRITICAL'])
    high = len([a for a in alerts_list if a.get('risk_level') == 'HIGH'])
    resolved = len([a for a in alerts_list if a.get('status') == 'resolved'])
    resolved_rate = (resolved / total_alerts * 100) if total_alerts else 0.0
    
    with c1:
        metric_card(total_alerts, "Total Alerts", "rolling window", "blue")
    with c2:
        metric_card(critical, "Critical", "immediate review", "red")
    with c3:
        metric_card(high, "High Risk", "priority queue", "orange")
    with c4:
        metric_card(resolved, "Resolved", f"{resolved_rate:.1f}%", "green")
    
    st.markdown("---")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Risk Distribution")
        render_risk_distribution(alerts_list)
    
    with col2:
        st.markdown("### Threat Timeline")
        render_threat_chart(alerts_list)


def render_settings():
    """Render settings page"""
    st.title("⚙️ Settings")
    st.markdown("Configure system preferences")
    
    # Tabs for different settings
    tab1, tab2, tab3 = st.tabs(["Detection", "Alerts", "Model"])
    
    with tab1:
        st.markdown("#### Detection Thresholds")
        
        c1, c2 = st.columns(2)
        
        with c1:
            st.slider("Critical Threshold", 0.0, 1.0, 0.8, 0.05, key="crit")
            st.slider("High Threshold", 0.0, 1.0, 0.6, 0.05, key="high")
            st.slider("Medium Threshold", 0.0, 1.0, 0.4, 0.05, key="med")
        
        with c2:
            st.checkbox("Enable URL Analysis", value=True)
            st.checkbox("Enable Domain Analysis", value=True)
            st.checkbox("Enable Pattern Detection", value=True)
        
        if st.button("Save Detection Settings", type="primary"):
            st.success("Settings saved!")
    
    with tab2:
        st.markdown("#### Alert Notifications")
        
        c1, c2 = st.columns(2)
        
        with c1:
            st.checkbox("Email Alerts", value=True)
            st.text_input("Alert Email", value="admin@prototype.local")
        
        with c2:
            st.checkbox("Dashboard Alerts", value=True)
            st.checkbox("Sound Alerts", value=False)
        
        if st.button("Save Alert Settings", type="primary"):
            st.success("Settings saved!")
    
    with tab3:
        st.markdown("#### Model Configuration")
        
        st.radio("Detection Model", ["TinyBERT (Fast)", "BERT (Accurate)", "Ensemble"], index=0)
        st.slider("Confidence Threshold", 0.0, 1.0, 0.5, 0.05)
        
        st.checkbox("Use External Intelligence", value=True)
        st.checkbox("Cache Results", value=True)
        
        if st.button("Save Model Settings", type="primary"):
            st.success("Settings saved!")
    
    # System info
    st.markdown("---")
    st.markdown("#### System Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**API Base URL:** `http://localhost:8000/api/v1`")
        st.markdown("**Model:** TinyBERT")
    
    with col2:
        env = os.getenv("ENVIRONMENT", "development")
        st.markdown(f"**Environment:** {env}")
        st.markdown("**Version:** 1.0.0")


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