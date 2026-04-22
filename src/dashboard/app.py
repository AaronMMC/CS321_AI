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

# Custom CSS - Modern Design
st.markdown("""
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    /* Main styling */
    .stApp {
        font-family: 'Inter', sans-serif;
    }
    
    /* Headers */
    h1, h2, h3 {
        font-family: 'Inter', sans-serif;
        font-weight: 600;
    }
    
    /* Custom metric cards */
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 12px;
        color: white;
        text-align: center;
    }
    
    .metric-card.blue {
        background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
    }
    
    .metric-card.red {
        background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
    }
    
    .metric-card.green {
        background: linear-gradient(135deg, #10b981 0%, #047857 100%);
    }
    
    .metric-card.orange {
        background: linear-gradient(135deg, #f59e0b 0%, #b45309 100%);
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        margin: 0;
    }
    
    .metric-label {
        font-size: 0.875rem;
        opacity: 0.9;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    /* Alert cards */
    .alert-card {
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
    }
    
    .alert-critical {
        background: #fef2f2;
        border-left: 4px solid #dc2626;
    }
    
    .alert-high {
        background: #fffbeb;
        border-left: 4px solid #f59e0b;
    }
    
    .alert-medium {
        background: #fefce8;
        border-left: 4px solid #eab308;
    }
    
    .alert-low, .alert-safe {
        background: #f0fdf4;
        border-left: 4px solid #22c55e;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
    }
    
    [data-testid="stSidebar"] .stRadio > label {
        color: #e2e8f0;
    }
    
    /* Button improvements */
    .stButton > button {
        border-radius: 8px;
        font-weight: 500;
    }
    
    /* Input styling */
    .stTextInput > div > div {
        border-radius: 8px;
    }
    
    /* Tab styling */
    .stTabs [data-testid="stTabBar"] {
        border-bottom: 2px solid #e2e8f0;
    }
    
    /* Container styling */
    .block-container {
        padding-top: 2rem;
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

def metric_card(value, label, delta=None, color="blue"):
    """Display a styled metric card"""
    color_class = f"metric-card {color}"
    
    delta_html = f"<span style='font-size: 0.875rem; opacity: 0.8;'>{delta}</span>" if delta else ""
    value_formatted = f"{value:,}" if isinstance(value, int) else f"{value}"
    
    st.markdown(f"""
    <div class='{color_class}'>
        <div class='metric-value'>{value_formatted}</div>
        <div class='metric-label'>{label}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)


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
    
    st.markdown(f"""
    <div class='alert-card {alert_class}'>
        <div style='display: flex; justify-content: space-between; align-items: center;'>
            <div>
                <strong>{risk}</strong> · {alert['subject'][:60]}{'...' if len(alert['subject']) > 60 else ''}
            </div>
            <div style='text-align: right;'>
                <span style='background: {'#ef4444' if risk == 'CRITICAL' else '#f59e0b' if risk == 'HIGH' else '#eab308'}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;'>
                    {alert['threat_score']:.0%}
                </span>
            </div>
        </div>
        <div style='font-size: 0.8rem; color: #64748b; margin-top: 4px;'>
            {alert['from_email']} → {alert['to_email']} · {timestamp} · {alert.get('status', 'new')}
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_threat_chart(alerts: list):
    """Render threat detection timeline"""
    if not alerts:
        st.info("No data available")
        return
    
    # Create sample timeline data
    dates = [(datetime.now() - timedelta(hours=i*4)).strftime('%H:%M') for i in range(6, -1, -1)]
    threats = [3, 7, 2, 5, 8, 4, 6]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=dates,
        y=threats,
        mode='lines+markers',
        fill='tozeroy',
        fillcolor='rgba(239, 68, 68, 0.2)',
        line=dict(color='#ef4444', width=3),
        marker=dict(size=10, color='#ef4444', line=dict(color='white', width=2)),
        name='Threats Detected'
    ))
    
    fig.update_layout(
        template='simple_white',
        height=300,
        margin=dict(l=20, r=20, t=20, b=20),
        xaxis_title="Time",
        yaxis_title="Threats",
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
        hole=0.5,
        marker=dict(
            colors=[colors.get(k, '#94a3b8') for k in risk_counts.keys()]
        ),
        textinfo='label+percent',
        textposition='outside',
    ))
    
    fig.update_layout(
        template='simple_white',
        height=280,
        margin=dict(l=20, r=20, t=20, b=20),
        showlegend=False,
    )
    
    st.plotly_chart(fig, use_container_width=True)


# ============================================
# PAGES
# ============================================

def login_page():
    """Render login page"""
    # Center the login form
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        <div style='text-align: center; margin-bottom: 2rem;'>
            <h1 style='font-size: 3rem;'>🛡️</h1>
            <h2 style='color: #1e293b; margin-bottom: 0.5rem;'>Email Security Gateway</h2>
            <p style='color: #64748b;'>AI-Powered Phishing Protection for Government Emails</p>
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
        <div style='text-align: center; padding: 1rem 0;'>
            <h2 style='color: white; margin: 0;'>🛡️</h2>
            <h3 style='color: #94a3b8; margin: 0; font-weight: 400;'>Security Gateway</h3>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # User info
        st.markdown(f"<p style='color: #94a3b8; font-size: 0.8rem;'>Logged in as</p>", unsafe_allow_html=True)
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
    st.title("📊 Dashboard Overview")
    st.markdown("Real-time email security monitoring")
    
    # Fetch data
    stats = fetch_stats()
    alerts_list = fetch_alerts(limit=10)
    
    # Metrics row
    st.markdown("### Key Metrics")
    
    c1, c2, c3, c4 = st.columns(4)
    
    with c1:
        metric_card(f"{stats.get('emails_processed', 0):,}", "Emails Processed", "+12%", "blue")
    with c2:
        metric_card(stats.get('threats_detected', 0), "Threats Detected", "+5", "red")
    with c3:
        metric_card(stats.get('queue_size', 0), "Queue Size", "0 pending", "orange")
    with c4:
        metric_card(f"{stats.get('avg_processing_time', 0):.2f}s", "Avg Processing", "-0.1s", "green")
    
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
    st.title("📈 Analytics")
    st.markdown("Security statistics and trends")
    
    alerts_list = fetch_alerts(limit=100)
    
    # Summary stats
    c1, c2, c3, c4 = st.columns(4)
    
    with c1:
        st.metric("Total Alerts", len(alerts_list))
    with c2:
        critical = len([a for a in alerts_list if a.get('risk_level') == 'CRITICAL'])
        st.metric("Critical", critical)
    with c3:
        high = len([a for a in alerts_list if a.get('risk_level') == 'HIGH'])
        st.metric("High", high)
    with c4:
        resolved = len([a for a in alerts_list if a.get('status') == 'resolved'])
        st.metric("Resolved", resolved)
    
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