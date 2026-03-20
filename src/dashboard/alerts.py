"""
Alert visualization components for the dashboard.
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import requests


def display_alert_list(alerts: List[Dict]):
    """
    Display a list of alerts in a formatted way.

    Args:
        alerts: List of alert dictionaries
    """
    if not alerts:
        st.info("No alerts to display")
        return

    for alert in alerts:
        if alert['risk_level'] == 'CRITICAL':
            alert_class = 'critical-alert'
        elif alert['risk_level'] == 'HIGH':
            alert_class = 'high-alert'
        else:
            alert_class = 'medium-alert'

        # Format timestamp
        try:
            timestamp = datetime.fromisoformat(alert['timestamp']).strftime('%Y-%m-%d %H:%M')
        except:
            timestamp = alert['timestamp']

        st.markdown(f"""
        <div class='{alert_class}'>
            <strong>[{alert['risk_level']}]</strong> {alert['subject']}<br>
            From: {alert['from_email']} | To: {alert['to_email']}<br>
            Threat Score: {alert['threat_score']:.1%} | {timestamp} | Status: {alert['status']}
        </div>
        """, unsafe_allow_html=True)


def display_alerts_with_actions(alerts: List[Dict], api_base_url: str):
    """
    Display alerts with action buttons.

    Args:
        alerts: List of alert dictionaries
        api_base_url: Base URL for API calls
    """
    if not alerts:
        st.info("No alerts to display")
        return

    for i, alert in enumerate(alerts):
        # Format timestamp
        try:
            timestamp = datetime.fromisoformat(alert['timestamp']).strftime('%Y-%m-%d %H:%M')
        except:
            timestamp = alert['timestamp']

        with st.expander(f"[{alert['risk_level']}] {alert['subject']} - {timestamp}"):
            col1, col2 = st.columns([3, 1])

            with col1:
                st.markdown(f"**From:** {alert['from_email']}")
                st.markdown(f"**To:** {alert['to_email']}")
                st.markdown(f"**Threat Score:** {alert['threat_score']:.1%}")
                st.markdown(f"**Status:** {alert['status']}")

                if alert.get('urls'):
                    st.markdown("**Suspicious URLs:**")
                    for url in alert['urls']:
                        st.code(url)

            with col2:
                st.markdown("**Actions:**")

                if st.button("✅ Acknowledge", key=f"ack_{i}"):
                    st.success("Alert acknowledged")

                if st.button("🔍 Investigate", key=f"inv_{i}"):
                    st.info("Investigation started")

                if st.button("❌ False Positive", key=f"fp_{i}"):
                    st.success("Feedback submitted - model will learn from this")

                if st.button("🔄 Resolve", key=f"res_{i}"):
                    st.success("Alert resolved")


def render_threat_pie_chart():
    """Render pie chart of threats by risk level"""

    # Sample data
    threat_data = pd.DataFrame({
        'Risk Level': ['Critical', 'High', 'Medium', 'Low'],
        'Count': [45, 78, 92, 19]
    })

    fig = px.pie(
        threat_data,
        values='Count',
        names='Risk Level',
        color='Risk Level',
        color_discrete_map={
            'Critical': '#DC2626',
            'High': '#F59E0B',
            'Medium': '#EAB308',
            'Low': '#6B7280'
        }
    )

    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=30, b=20),
        showlegend=True
    )

    st.plotly_chart(fig, use_container_width=True)


def render_threat_timeline():
    """Render timeline chart of threats over time"""

    # Sample time series data
    dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
    threat_counts = [12, 15, 8, 22, 18, 14, 9, 11, 13, 16, 19, 14, 8, 10, 12, 15, 18, 22, 25, 19, 16, 14, 11, 9, 13, 15,
                     12, 10, 8, 14]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=dates,
        y=threat_counts,
        mode='lines+markers',
        name='Threats',
        line=dict(color='#2563EB', width=3),
        fill='tozeroy',
        fillcolor='rgba(37, 99, 235, 0.1)'
    ))

    fig.update_layout(
        height=300,
        xaxis_title="Date",
        yaxis_title="Number of Threats",
        hovermode='x',
        margin=dict(l=20, r=20, t=30, b=20),
        showlegend=False
    )

    st.plotly_chart(fig, use_container_width=True)