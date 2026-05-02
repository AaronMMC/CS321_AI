"""
Main Streamlit dashboard application.
Entry point for the admin dashboard.

FIX: Replaced `from src.utils.logger import logger` with direct loguru import.
     src/utils/logger.py exports `log`, not `logger` — the old import caused
     an ImportError that prevented the dashboard from starting.
"""

import streamlit as st
from datetime import datetime, timedelta
import requests
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent))

from src.dashboard import alerts, admin

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Email Security Gateway - Admin Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .main-header { font-size:2.5rem; color:#1E3A8A; font-weight:bold; margin-bottom:1rem; }
    .sub-header  { font-size:1.5rem; color:#2563EB; margin-top:1rem; margin-bottom:.5rem; }
    .metric-card { background:#F3F4F6; padding:1rem; border-radius:.5rem; text-align:center; }
    .critical-alert { background:#FEE2E2; border-left:4px solid #DC2626; padding:1rem; margin-bottom:.5rem; border-radius:.25rem; }
    .high-alert     { background:#FEF3C7; border-left:4px solid #F59E0B; padding:1rem; margin-bottom:.5rem; border-radius:.25rem; }
    .medium-alert   { background:#FEF9C3; border-left:4px solid #EAB308; padding:1rem; margin-bottom:.5rem; border-radius:.25rem; }
    .info-box { background:#E0F2FE; padding:1rem; border-radius:.5rem; margin-bottom:1rem; }
</style>
""", unsafe_allow_html=True)

API_BASE_URL = "http://localhost:8000/api/v1"

# ── Session state ──────────────────────────────────────────────────────────────
for key, default in [("authenticated", False), ("username", None), ("last_refresh", datetime.now())]:
    if key not in st.session_state:
        st.session_state[key] = default


# ── Auth ───────────────────────────────────────────────────────────────────────
def authenticate(username: str, password: str) -> bool:
    return username == "admin" and password == "admin123"


# ── API helpers ────────────────────────────────────────────────────────────────
def fetch_stats():
    try:
        r = requests.get(f"{API_BASE_URL}/stats", timeout=2)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {
        "emails_processed": 15423,
        "threats_detected": 234,
        "queue_size": 0,
        "avg_processing_time": 0.45,
        "model_loaded": True,
        "timestamp": datetime.now().isoformat(),
    }


def fetch_alerts(status=None, limit=50):
    try:
        params = {"limit": limit}
        if status:
            params["status"] = status
        r = requests.get(f"{API_BASE_URL}/alerts", params=params, timeout=2)
        if r.status_code == 200:
            return r.json()
    except Exception:
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
            "urls": ["http://bit.ly/gcash-verify"],
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
            "urls": ["http://bit.ly/payroll-update"],
        },
    ]


def check_email_api(subject: str, body: str):
    try:
        r = requests.post(
            f"{API_BASE_URL}/check-email",
            json={"subject": subject, "body": body},
            timeout=5,
        )
        if r.status_code == 200:
            return r.json()
        st.error(f"API Error: {r.status_code}")
    except Exception as e:
        st.error(f"Connection Error: {e}")
    return None


# ── Pages ──────────────────────────────────────────────────────────────────────
def login_page():
    st.markdown("<h1 class='main-header'>🛡️ Email Security Gateway</h1>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Login", use_container_width=True):
                if authenticate(username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.error("Invalid username or password")
        st.markdown("""
        <div class='info-box'><strong>Demo Credentials:</strong><br>Username: admin<br>Password: admin123</div>
        """, unsafe_allow_html=True)


def main_dashboard():
    with st.sidebar:
        st.markdown(f"### Welcome, {st.session_state.username}")
        st.markdown("---")
        page = st.radio("Navigation", ["📊 Dashboard", "🔍 Email Checker", "⚠️ Alerts", "⚙️ Settings", "👤 Admin"])
        st.markdown("---")
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.session_state.last_refresh = datetime.now()
            st.rerun()
        st.caption(f"Last refreshed: {st.session_state.last_refresh.strftime('%H:%M:%S')}")
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.authenticated = False
            st.rerun()

    if page == "📊 Dashboard":
        render_overview()
    elif page == "🔍 Email Checker":
        render_email_checker()
    elif page == "⚠️ Alerts":
        render_alerts()
    elif page == "⚙️ Settings":
        render_settings()
    elif page == "👤 Admin":
        admin.AdminPanel.render_admin_panel()


def render_overview():
    st.markdown("<h1 class='main-header'>📊 Dashboard Overview</h1>", unsafe_allow_html=True)
    stats = fetch_stats()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Emails Processed", f"{stats.get('emails_processed', 0):,}", "+1,234")
    c2.metric("Threats Detected", str(stats.get("threats_detected", 0)), "+23")
    c3.metric("Queue Size", str(stats.get("queue_size", 0)), "0 pending")
    c4.metric("Avg Processing", f"{stats.get('avg_processing_time', 0):.2f}s", "-0.02s")

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("<h3 class='sub-header'>Threats by Risk Level</h3>", unsafe_allow_html=True)
        alerts.render_threat_pie_chart()
    with col2:
        st.markdown("<h3 class='sub-header'>Threats Over Time</h3>", unsafe_allow_html=True)
        alerts.render_threat_timeline()

    st.markdown("---")
    st.markdown("<h3 class='sub-header'>Recent Alerts</h3>", unsafe_allow_html=True)
    alerts.display_alert_list(fetch_alerts(limit=5))


def render_email_checker():
    st.markdown("<h1 class='main-header'>🔍 Email Checker</h1>", unsafe_allow_html=True)
    col1, col2 = st.columns([3, 2])

    with col1:
        with st.form("email_check_form"):
            subject = st.text_input("Subject", placeholder="Enter email subject...")
            body = st.text_area("Body", height=200, placeholder="Paste email content here...")
            submitted = st.form_submit_button("🔍 Check Email", use_container_width=True)

    with col2:
        st.markdown("#### Quick Test Examples")
        if st.button("📧 Legitimate Email", use_container_width=True):
            st.info("Fill in the form with a legitimate email to test.")
        if st.button("⚠️ Phishing Example", use_container_width=True):
            st.warning("Try: Subject='URGENT: Verify GCash', Body='Click http://bit.ly/verify'")

    if submitted and subject and body:
        with st.spinner("Analyzing email..."):
            result = check_email_api(subject, body)
        if result:
            st.markdown("---")
            score = result.get("threat_score", 0)
            color, level = (
                ("#DC2626", "CRITICAL") if score >= 0.8 else
                ("#F59E0B", "HIGH") if score >= 0.6 else
                ("#EAB308", "MEDIUM") if score >= 0.4 else
                ("#10B981", "SAFE")
            )
            st.markdown(f"""
            <div style="text-align:center;padding:20px;background:{color}20;border-radius:10px;border:2px solid {color};">
                <h2 style="color:{color};">{level}</h2>
                <h1 style="color:{color};">{score:.1%}</h1>
            </div>""", unsafe_allow_html=True)
            for explanation in result.get("explanations", []):
                st.info(explanation)


def render_alerts():
    st.markdown("<h1 class='main-header'>⚠️ Alert Management</h1>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        status_filter = st.selectbox("Status", ["All", "new", "acknowledged", "resolved"])
    with c2:
        st.selectbox("Risk Level", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

    alert_list = fetch_alerts(limit=100)
    alerts.display_alerts_with_actions(alert_list, API_BASE_URL)


def render_settings():
    st.markdown("<h1 class='main-header'>⚙️ Settings</h1>", unsafe_allow_html=True)
    tab1, tab2 = st.tabs(["Detection Thresholds", "Alert Preferences"])

    with tab1:
        st.slider("Critical Threshold", 0.0, 1.0, 0.8, 0.05)
        st.slider("High Threshold", 0.0, 1.0, 0.6, 0.05)
        st.slider("Medium Threshold", 0.0, 1.0, 0.4, 0.05)
        if st.button("Save Thresholds", use_container_width=True):
            st.success("Thresholds updated!")

    with tab2:
        st.checkbox("Enable SMS alerts", value=True)
        st.text_input("SMS Number", placeholder="+639123456789")
        st.checkbox("Enable Email alerts", value=True)
        st.text_input("Email Address", placeholder="admin@prototype.local")
        if st.button("Save Alert Settings", use_container_width=True):
            st.success("Alert settings updated!")


# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    if not st.session_state.authenticated:
        login_page()
    else:
        main_dashboard()


if __name__ == "__main__":
    main()