"""Analytics and reporting page."""

from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from containervul.ui.components import render_section_header
from containervul.ui.styles import SEVERITY_COLORS


def render(config: dict) -> None:
    render_section_header("Security Analytics")

    vulns = st.session_state.get("vulnerabilities", [])
    if not vulns:
        st.info("No vulnerability data. Analyze Dockerfiles or scan cloud services first.")
        return

    severity_counts = {}
    status_counts = {}
    category_counts = {}
    provider_counts = {}

    for v in vulns:
        sev = v.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        status = v.get("status", "open")
        status_counts[status] = status_counts.get(status, 0) + 1
        cat = v.get("category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        provider = v.get("cloud_provider")
        if provider:
            provider_counts[provider] = provider_counts.get(provider, 0) + 1

    c1, c2 = st.columns(2)
    with c1:
        if severity_counts:
            fig = px.pie(values=list(severity_counts.values()), names=list(severity_counts.keys()),
                         title="By Severity", color_discrete_map=SEVERITY_COLORS)
            st.plotly_chart(fig, use_container_width=True)
    with c2:
        if status_counts:
            fig = px.pie(values=list(status_counts.values()), names=list(status_counts.keys()),
                         title="By Status", color_discrete_map={"open": "#dc3545", "in_progress": "#ffc107", "resolved": "#28a745", "false_positive": "#6c757d"})
            st.plotly_chart(fig, use_container_width=True)

    if category_counts:
        fig = px.bar(x=list(category_counts.keys()), y=list(category_counts.values()),
                     title="By Category", labels={"x": "Category", "y": "Count"})
        st.plotly_chart(fig, use_container_width=True)

    if provider_counts:
        fig = px.bar(x=list(provider_counts.keys()), y=list(provider_counts.values()),
                     title="By Cloud Provider", labels={"x": "Provider", "y": "Count"})
        st.plotly_chart(fig, use_container_width=True)

    # Data table
    st.subheader("Detailed Vulnerability Table")
    df_data = [{
        "ID": v.get("id", ""), "Severity": v.get("severity", ""), "Category": v.get("category", "").replace("_", " ").title(),
        "Status": v.get("status", ""), "Type": v.get("type", ""), "Priority": v.get("priority_score", 0),
        "Provider": v.get("cloud_provider", "N/A"), "Description": v.get("description", "")[:100],
    } for v in vulns]

    if df_data:
        df = pd.DataFrame(df_data)
        c1, c2, c3 = st.columns(3)
        sev_filter = c1.multiselect("Severity", df["Severity"].unique().tolist(), default=df["Severity"].unique().tolist())
        status_filter = c2.multiselect("Status", df["Status"].unique().tolist(), default=df["Status"].unique().tolist())
        cat_filter = c3.multiselect("Category", df["Category"].unique().tolist(), default=df["Category"].unique().tolist())

        filtered = df[(df["Severity"].isin(sev_filter)) & (df["Status"].isin(status_filter)) & (df["Category"].isin(cat_filter))]
        if not filtered.empty:
            st.dataframe(filtered, use_container_width=True)
            csv = filtered.to_csv(index=False)
            st.download_button("Export CSV", csv, f"vuln_analytics_{datetime.now():%Y%m%d}.csv", "text/csv")
