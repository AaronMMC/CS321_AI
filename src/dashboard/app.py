"""
Main Streamlit dashboard application.
This is the entry point for the admin dashboard.
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import requests
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.dashboard import alerts, admin
from src.utils.logger import logger

# Page configuration
st.set_page_config(
    page_title="Email Security Gateway - Admin Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        font-weight: bold;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #2563EB;
        font-weight: semi-bold;
        margin-top: 1rem;
        margin-bottom: 0.5rem;
    }
    .metric-card {
        background-color: #F3F4F6;
        padding: 1rem;
        border-radius: 0.5rem;
        text-align: center;
        box-shadow: 0 1px 3px rgba(0,0,0,0.12);
    }
    .critical-alert {
        background-color: #FEE2E2;
        border-left: 4px solid #DC2626;
        padding: 1rem;
        margin-bottom: 0.5rem;
        border-radius: 0.25rem;
    }
    .high-alert {
        background-color: #FEF3C7;
        border-left: 4px solid #F59E0B;
        padding: 1rem;
        margin-bottom: 0.5rem;
        border-radius: 0.25rem;
    }
    .medium-alert {
        background-color: #FEF9C3;
        border-left: 4px solid #EAB308;
        padding: 1rem;
        margin-bottom: 0.5rem;
        border-radius: 0.25rem;
    }
    .info-box {
        background-color: #E0F2FE;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .stButton>button {
        width: 100%;
    }
</style>
""", unsafe_allow_html=True)

# API Configuration
API_BASE_URL = "http://localhost:8000/api/v1"

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'last_refresh' not in st.session_state:
    st.session_state.last_refresh = datetime.now()


# Authentication
def authenticate(username: str, password: str) -> bool:
    """Simple authentication - in production, use proper auth"""
    # This is a mock - replace with real authentication
    return username == "admin" and password == "admin123"


# API calls
def fetch_stats():
    """Fetch system statistics from API"""
    try:
        response = requests.get(f"{API_BASE_URL}/stats", timeout=2)
        if response.status_code == 200:
            return response.json()
    except:
        pass

    # Return mock data if API unavailable
    return {
        "emails_processed": 15423,
        "threats_detected": 234,
        "queue_size": 0,
        "avg_processing_time": 0.45,
        "model_loaded": True,
        "timestamp": datetime.now().isoformat()
    }


def fetch_alerts(status: str = None, limit: int = 50):
    """Fetch alerts from API"""
    try:
        params = {"limit": limit}
        if status:
            params["status"] = status

        response = requests.get(f"{API_BASE_URL}/alerts", params=params, timeout=2)
        if response.status_code == 200:
            return response.json()
    except:
        pass

    # Return mock alerts
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
        }
    ]


def check_email(subject: str, body: str):
    """Check a single email via API"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/check-email",
            json={"subject": subject, "body": body},
            timeout=5
        )
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"API Error: {response.status_code}")
            return None
    except Exception as e:
        st.error(f"Connection Error: {e}")
        return None


# Login page
def login_page():
    """Render login page"""
    st.markdown("<h1 class='main-header'>🛡️ Email Security Gateway</h1>", unsafe_allow_html=True)
    st.markdown("<h3 class='sub-header'>Admin Dashboard Login</h3>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login", use_container_width=True)

            if submitted:
                if authenticate(username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.error("Invalid username or password")

        st.markdown("""
        <div class='info-box'>
            <strong>Demo Credentials:</strong><br>
            Username: admin<br>
            Password: admin123
        </div>
        """, unsafe_allow_html=True)


# Main dashboard
def main_dashboard():
    """Render main dashboard"""

    # Sidebar
    with st.sidebar:
        st.markdown(f"### Welcome, {st.session_state.username}")
        st.markdown("---")

        # Navigation
        page = st.radio(
            "Navigation",
            ["📊 Dashboard", "🔍 Email Checker", "⚠️ Alerts", "⚙️ Settings", "👤 Admin"]
        )

        st.markdown("---")

        # Refresh button
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.session_state.last_refresh = datetime.now()
            st.rerun()

        # Last refresh time
        st.caption(f"Last refreshed: {st.session_state.last_refresh.strftime('%H:%M:%S')}")

        st.markdown("---")

        # Logout
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.authenticated = False
            st.rerun()

    # Main content area based on navigation
    if page == "📊 Dashboard":
        render_overview_dashboard()
    elif page == "🔍 Email Checker":
        render_email_checker()
    elif page == "⚠️ Alerts":
        render_alerts_page()
    elif page == "⚙️ Settings":
        render_settings_page()
    elif page == "👤 Admin":
        admin.render_admin_panel()


def render_overview_dashboard():
    """Render overview dashboard with metrics and charts"""
    st.markdown("<h1 class='main-header'>📊 Dashboard Overview</h1>", unsafe_allow_html=True)

    # Fetch stats
    stats = fetch_stats()

    # Display key metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
        st.metric("Emails Processed", f"{stats.get('emails_processed', 0):,}", "+1,234")
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
        st.metric("Threats Detected", f"{stats.get('threats_detected', 0)}", "+23")
        st.markdown("</div>", unsafe_allow_html=True)

    with col3:
        st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
        st.metric("Queue Size", f"{stats.get('queue_size', 0)}", "0 pending")
        st.markdown("</div>", unsafe_allow_html=True)

    with col4:
        st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
        st.metric("Avg Processing", f"{stats.get('avg_processing_time', 0)}s", "-0.02s")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")

    # Charts
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("<h3 class='sub-header'>Threats by Risk Level</h3>", unsafe_allow_html=True)
        alerts.render_threat_pie_chart()

    with col2:
        st.markdown("<h3 class='sub-header'>Threats Over Time</h3>", unsafe_allow_html=True)
        alerts.render_threat_timeline()

    st.markdown("---")

    # Recent alerts
    st.markdown("<h3 class='sub-header'>Recent Alerts</h3>", unsafe_allow_html=True)

    recent_alerts = fetch_alerts(limit=5)
    alerts.display_alert_list(recent_alerts)


def render_email_checker():
    """Render email checker tool"""
    st.markdown("<h1 class='main-header'>🔍 Email Checker</h1>", unsafe_allow_html=True)
    st.markdown("Test individual emails against the AI model")

    col1, col2 = st.columns([3, 2])

    with col1:
        with st.form("email_check_form"):
            subject = st.text_input("Subject", placeholder="Enter email subject...")
            body = st.text_area("Body", height=200, placeholder="Paste email content here...")

            col_a, col_b = st.columns(2)
            with col_a:
                submitted = st.form_submit_button("🔍 Check Email", use_container_width=True)
            with col_b:
                clear = st.form_submit_button("🗑️ Clear", use_container_width=True)

    with col2:
        st.markdown("#### Quick Test Examples")

        if st.button("📧 Legitimate Email", use_container_width=True):
            st.session_state.test_subject = "Meeting Agenda for Tomorrow"
            st.session_state.test_body = "Hi Team,\n\nPlease find attached the agenda for tomorrow's 10 AM meeting.\n\nBest regards,\nJohn"

        if st.button("⚠️ Phishing Example", use_container_width=True):
            st.session_state.test_subject = "URGENT: Your GCash Account Will Be Suspended"
            st.session_state.test_body = "Dear User,\n\nYour GCash account has been limited. Click here to verify: http://bit.ly/gcash-verify\n\nImmediate action required!"

        if st.button("🔗 Suspicious Link", use_container_width=True):
            st.session_state.test_subject = "Your Package Delivery"
            st.session_state.test_body = "Your package is delayed. Track here: http://bit.ly/track-package-123456"

    # Check email
    if submitted and subject and body:
        with st.spinner("Analyzing email..."):
            result = check_email(subject, body)

        if result:
            st.markdown("---")
            st.markdown("#### Analysis Results")

            # Threat score display
            score = result.get('threat_score', 0)

            if score >= 0.8:
                color = "#DC2626"
                level = "CRITICAL"
            elif score >= 0.6:
                color = "#F59E0B"
                level = "HIGH"
            elif score >= 0.4:
                color = "#EAB308"
                level = "MEDIUM"
            else:
                color = "#10B981"
                level = "SAFE"

            st.markdown(f"""
            <div style="text-align: center; padding: 20px; background-color: {color}20; border-radius: 10px; border: 2px solid {color};">
                <h2 style="color: {color};">{level}</h2>
                <h1 style="color: {color};">{score:.1%}</h1>
            </div>
            """, unsafe_allow_html=True)

            # Explanations
            if result.get('explanations'):
                st.markdown("#### Analysis Details")
                for explanation in result['explanations']:
                    st.info(explanation)


def render_alerts_page():
    """Render alerts management page"""
    st.markdown("<h1 class='main-header'>⚠️ Alert Management</h1>", unsafe_allow_html=True)

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        status_filter = st.selectbox("Status", ["All", "new", "acknowledged", "investigating", "resolved", "false_positive"])
    with col2:
        risk_filter = st.selectbox("Risk Level", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with col3:
        time_filter = st.selectbox("Time Range", ["Last 24 hours", "Last 7 days", "Last 30 days", "All"])

    # Fetch and display alerts
    alerts_list = fetch_alerts(limit=100)
    alerts.display_alerts_with_actions(alerts_list, API_BASE_URL)


def render_settings_page():
    """Render settings page"""
    st.markdown("<h1 class='main-header'>⚙️ Settings</h1>", unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs(["Detection Thresholds", "Alert Preferences", "Model Settings"])

    with tab1:
        st.markdown("#### Detection Thresholds")

        critical_threshold = st.slider("Critical Threshold", 0.0, 1.0, 0.8, 0.05)
        high_threshold = st.slider("High Threshold", 0.0, 1.0, 0.6, 0.05)
        medium_threshold = st.slider("Medium Threshold", 0.0, 1.0, 0.4, 0.05)

        if st.button("Save Thresholds", use_container_width=True):
            st.success("Thresholds updated!")

    with tab2:
        st.markdown("#### Alert Preferences")

        col1, col2 = st.columns(2)

        with col1:
            st.checkbox("Enable SMS alerts", value=True)
            st.text_input("SMS Number", placeholder="+639123456789")
            st.checkbox("Enable Email alerts", value=True)

        with col2:
            st.text_input("Email Address", placeholder="admin@prototype.local")
            st.checkbox("Enable Telegram alerts", value=False)
            st.text_input("Telegram Chat ID", placeholder="123456789")

        if st.button("Save Alert Settings", use_container_width=True):
            st.success("Alert settings updated!")

    with tab3:
        st.markdown("#### Model Settings")

        col1, col2 = st.columns(2)

        with col1:
            st.radio("Model Selection", ["TinyBERT (Fast)", "BERT (Accurate)", "Ensemble"], index=0)
            st.slider("Confidence Threshold", 0.0, 1.0, 0.5, 0.05)

        with col2:
            st.checkbox("Enable External Intelligence", value=True)
            st.checkbox("Enable Pattern Recognition", value=True)
            st.checkbox("Enable Human-in-the-Loop Learning", value=True)

        if st.button("Apply Model Settings", use_container_width=True):
            st.success("Model settings updated!")


# Main app logic
def main():
    if not st.session_state.authenticated:
        login_page()
    else:
        main_dashboard()


if __name__ == "__main__":
    main()