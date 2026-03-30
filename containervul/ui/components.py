"""Reusable Streamlit UI components."""

from __future__ import annotations

import streamlit as st
from containervul.ui.styles import SEVERITY_COLORS


def render_vulnerability_card(vuln: dict) -> None:
    """Render a styled vulnerability card."""
    severity = vuln.get("severity", "UNKNOWN")
    css_class = f"{severity.lower()}-vuln"
    st.markdown(f"""
    <div class="vulnerability-card {css_class}">
        <strong>{vuln.get('id', 'Unknown')}</strong> — {severity} Severity
        <br><em>{vuln.get('description', 'No description')[:150]}</em>
        <br><small>Line: {vuln.get('line_number', 'N/A')} | Category: {vuln.get('category', 'N/A')} | Status: {vuln.get('status', 'open')}</small>
    </div>
    """, unsafe_allow_html=True)


def render_section_header(title: str) -> None:
    st.markdown(f'<div class="section-header">{title}</div>', unsafe_allow_html=True)


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6c757d")
    return f'<span style="color:{color};font-weight:bold">{severity}</span>'


def render_risk_metrics(risk_data: dict) -> None:
    """Render risk assessment metrics in columns."""
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk Level", risk_data.get("risk_level", "LOW"))
    c2.metric("Risk Score", f"{risk_data.get('total_score', 0):.0f}")
    c3.metric("Vulnerabilities", risk_data.get("vulnerability_count", 0))
    c4.metric("Critical", risk_data.get("severity_breakdown", {}).get("CRITICAL", 0))


def render_cloud_service_card(service: dict, provider: str) -> None:
    accent = {"aws": "aws-accent", "azure": "azure-accent", "gcp": "gcp-accent"}.get(provider, "")
    st.markdown(f"""
    <div class="cloud-card {accent}">
        <strong>{service.get('name', 'Unknown')}</strong> — {service.get('status', 'UNKNOWN')}
        <br>Region: {service.get('region', 'N/A')} | Images: {service.get('image_count', 0)}
    </div>
    """, unsafe_allow_html=True)
