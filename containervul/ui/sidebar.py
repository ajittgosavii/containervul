"""Sidebar controls including account selector and configuration."""

from __future__ import annotations

from typing import Dict

import streamlit as st


def render_sidebar(account_names: list[str] = None) -> Dict:
    """Render sidebar and return configuration dict."""
    st.sidebar.markdown("## Enterprise Container Security")

    # Cloud Account Selector
    if account_names:
        st.sidebar.subheader("Cloud Accounts")
        selected_account = st.sidebar.selectbox("Active Account", ["All Accounts"] + account_names, key="active_account")
    else:
        selected_account = None

    # AI Configuration
    st.sidebar.subheader("AI Configuration")
    ai_status = "Enabled" if st.session_state.get("ai_available") else "Add CLAUDE_API_KEY to secrets"
    st.sidebar.info(ai_status)

    # Analysis Settings
    st.sidebar.subheader("Analysis Settings")
    scan_depth = st.sidebar.selectbox("Scan Depth", ["Basic", "Detailed", "Comprehensive"], index=1, key="scan_depth")
    include_low = st.sidebar.checkbox("Include Low Severity", value=False, key="include_low")
    auto_prioritize = st.sidebar.checkbox("Auto-prioritize", value=True, key="auto_prioritize")

    # CVE Settings
    st.sidebar.subheader("CVE Settings")
    max_cve = st.sidebar.slider("Max CVE Results", 10, 100, 50, key="max_cve_results")
    cache_hours = st.sidebar.slider("Cache (hours)", 1, 24, 6, key="cache_duration")

    # Report Settings
    st.sidebar.subheader("Reports")
    include_remediation = st.sidebar.checkbox("Include remediation", value=True, key="include_remediation")
    export_format = st.sidebar.selectbox("Export Format", ["Markdown", "JSON", "CSV"], key="export_format")

    return {
        "selected_account": selected_account,
        "scan_depth": scan_depth,
        "include_low_severity": include_low,
        "auto_prioritize": auto_prioritize,
        "max_cve_results": max_cve,
        "cache_duration": cache_hours,
        "include_remediation": include_remediation,
        "export_format": export_format,
    }
