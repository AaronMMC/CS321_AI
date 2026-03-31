"""
Admin panel for user management and system configuration.
"""

import streamlit as st
import pandas as pd
from typing import Dict, List
from datetime import datetime
import time


def render_admin_panel():
    """Render the main admin panel (called from app.py)."""
    st.markdown("<h1 class='main-header'>👤 Admin Panel</h1>", unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs([
        "User Management",
        "System Logs",
        "Model Training",
        "Audit Trail",
    ])

    with tab1:
        _render_user_management()
    with tab2:
        _render_system_logs()
    with tab3:
        _render_model_training()
    with tab4:
        _render_audit_trail()


# ---------------------------------------------------------------------------
# Tab renderers (private)
# ---------------------------------------------------------------------------

def _render_user_management():
    st.markdown("### User Management")

    users = pd.DataFrame({
        "Username":   ["admin", "analyst1", "analyst2", "viewer1"],
        "Role":       ["Administrator", "Security Analyst", "Security Analyst", "Viewer"],
        "Email":      ["admin@prototype.local", "analyst1@prototype.local",
                       "analyst2@prototype.local", "viewer@prototype.local"],
        "Last Login": ["2024-01-20 09:30", "2024-01-20 10:15",
                       "2024-01-19 16:45", "2024-01-20 08:20"],
        "Status":     ["Active", "Active", "Active", "Inactive"],
    })

    st.dataframe(users, use_container_width=True)

    st.markdown("#### Add New User")
    col1, col2 = st.columns(2)
    with col1:
        new_username = st.text_input("Username")
        new_email = st.text_input("Email")
    with col2:
        new_role = st.selectbox("Role", ["Administrator", "Security Analyst", "Viewer"])
        new_password = st.text_input("Password", type="password")

    if st.button("Create User", use_container_width=True):
        if new_username and new_email and new_password:
            st.success(f"User {new_username} created successfully!")
        else:
            st.error("Please fill all fields")


def _render_system_logs():
    st.markdown("### System Logs")

    col1, col2, col3 = st.columns(3)
    with col1:
        log_level = st.selectbox("Log Level", ["ALL", "INFO", "WARNING", "ERROR", "DEBUG"])
    with col2:
        st.selectbox("Time Range", ["Last Hour", "Last 24 Hours", "Last 7 Days", "All"])
    with col3:
        log_source = st.selectbox("Source", ["ALL", "API", "Model", "Gateway", "Dashboard"])

    logs = [
        {"timestamp": "2024-01-20 14:32:15", "level": "INFO",    "source": "API",       "message": "Email check request processed - job_123"},
        {"timestamp": "2024-01-20 14:31:22", "level": "WARNING", "source": "Model",     "message": "High threat score detected: 0.94"},
        {"timestamp": "2024-01-20 14:30:05", "level": "INFO",    "source": "Gateway",   "message": "Email processed from support@gcash-verify.net"},
        {"timestamp": "2024-01-20 14:28:47", "level": "ERROR",   "source": "API",       "message": "Failed to connect to VirusTotal API"},
        {"timestamp": "2024-01-20 14:25:33", "level": "INFO",    "source": "Dashboard", "message": "User admin logged in"},
    ]

    log_df = pd.DataFrame(logs)
    if log_level != "ALL":
        log_df = log_df[log_df["level"] == log_level]
    if log_source != "ALL":
        log_df = log_df[log_df["source"] == log_source]

    st.dataframe(log_df, use_container_width=True)

    col_a1, col_a2 = st.columns(2)
    with col_a1:
        if st.button("📥 Download Logs", use_container_width=True):
            st.info("Logs downloaded")
    with col_a2:
        if st.button("🔄 Refresh Logs", use_container_width=True):
            st.rerun()


def _render_model_training():
    st.markdown("### Model Training")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Current Model", "TinyBERT v1.2", "BERT v2.0 available")
    with col2:
        st.metric("Accuracy", "94.2%", "+0.3%")
    with col3:
        st.metric("Last Trained", "2024-01-15", "5 days ago")

    st.markdown("#### Training Configuration")
    col_t1, col_t2 = st.columns(2)
    with col_t1:
        st.selectbox(
            "Training Dataset",
            ["Combined Fraud Dataset (194k samples)", "Enron Spam Dataset", "Custom Dataset"],
        )
        epochs = st.number_input("Epochs", min_value=1, max_value=50, value=5)
    with col_t2:
        st.selectbox("Model Type", ["TinyBERT (Fast)", "BERT (Accurate)", "Ensemble"])
        st.select_slider(
            "Learning Rate",
            options=[1e-5, 2e-5, 3e-5, 5e-5, 1e-4],
            value=2e-5,
        )

    if st.button("🚀 Start Training", use_container_width=True, type="primary"):
        with st.spinner(f"Training {epochs} epoch(s) … this may take a while."):
            progress_bar = st.progress(0)
            for i in range(100):
                time.sleep(0.04)
                progress_bar.progress(i + 1)
        st.success("Training complete! New model saved: tinybert_custom_v2.0")


def _render_audit_trail():
    st.markdown("### Audit Trail")

    col1, col2, col3 = st.columns(3)
    with col1:
        action_type = st.selectbox(
            "Action Type",
            ["ALL", "Login", "Alert Acknowledged", "Whitelist Added",
             "Blacklist Added", "Settings Changed"],
        )
    with col2:
        user_filter = st.selectbox("User", ["ALL", "admin", "analyst1", "analyst2"])
    with col3:
        st.date_input("Date Range", [datetime.now(), datetime.now()])

    audit_data = [
        {"timestamp": "2024-01-20 14:25:33", "user": "admin",    "action": "Login",              "details": "Logged in from 192.168.1.100",        "ip": "192.168.1.100"},
        {"timestamp": "2024-01-20 13:15:22", "user": "analyst1", "action": "Alert Acknowledged", "details": "Alert alert_001 acknowledged",         "ip": "192.168.1.101"},
        {"timestamp": "2024-01-20 11:42:08", "user": "admin",    "action": "Whitelist Added",    "details": "Added deped.gov.ph to whitelist",      "ip": "192.168.1.100"},
        {"timestamp": "2024-01-20 10:33:47", "user": "analyst2", "action": "Blacklist Added",    "details": "Added phishing-site.net to blacklist", "ip": "192.168.1.102"},
    ]

    audit_df = pd.DataFrame(audit_data)
    if action_type != "ALL":
        audit_df = audit_df[audit_df["action"] == action_type]
    if user_filter != "ALL":
        audit_df = audit_df[audit_df["user"] == user_filter]

    st.dataframe(audit_df, use_container_width=True)

    if st.button("📥 Export Audit Log", use_container_width=True):
        st.info("Audit log exported as CSV")


# ---------------------------------------------------------------------------
# Legacy class shim (keeps old `admin.render_admin_panel()` call working)
# ---------------------------------------------------------------------------

class AdminPanel:
    """Thin wrapper kept for backwards compatibility."""

    @staticmethod
    def render_admin_panel():
        render_admin_panel()


admin_panel = AdminPanel()