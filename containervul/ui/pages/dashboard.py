"""Dashboard page — security overview and quick actions."""

from __future__ import annotations

import streamlit as st
import plotly.express as px

from containervul.ui.components import render_section_header, render_vulnerability_card


def render(config: dict) -> None:
    render_section_header("Security Dashboard")

    vulns = st.session_state.get("vulnerabilities", [])

    if vulns:
        total = len(vulns)
        critical = len([v for v in vulns if v.get("severity") == "CRITICAL"])
        high = len([v for v in vulns if v.get("severity") == "HIGH"])
        medium = len([v for v in vulns if v.get("severity") == "MEDIUM"])
        low = len([v for v in vulns if v.get("severity") == "LOW"])
        open_count = len([v for v in vulns if v.get("status") == "open"])
        resolved = len([v for v in vulns if v.get("status") == "resolved"])

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Vulnerabilities", total)
        c2.metric("Critical", critical)
        c3.metric("High", high)
        c4.metric("Open", open_count)
        rate = (resolved / total * 100) if total else 0
        c5.metric("Resolution Rate", f"{rate:.1f}%")

        severity_data = {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low}
        if any(severity_data.values()):
            fig = px.pie(
                values=list(severity_data.values()),
                names=list(severity_data.keys()),
                title="Vulnerability Distribution by Severity",
                color_discrete_map={"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745"},
            )
            st.plotly_chart(fig, use_container_width=True)

        render_section_header("Recent High-Priority Vulnerabilities")
        sorted_vulns = sorted(vulns, key=lambda x: x.get("priority_score", 0), reverse=True)[:5]
        for v in sorted_vulns:
            render_vulnerability_card(v)

        # Cloud summary
        cloud_vulns = [v for v in vulns if v.get("cloud_account")]
        if cloud_vulns:
            render_section_header("Cloud Security Summary")
            providers = set(v.get("cloud_provider", "unknown") for v in cloud_vulns)
            cols = st.columns(len(providers))
            for i, provider in enumerate(sorted(providers)):
                pvulns = [v for v in cloud_vulns if v.get("cloud_provider") == provider]
                cols[i].metric(f"{provider.upper()} Vulnerabilities", len(pvulns))
    else:
        st.info("No vulnerabilities detected. Start by analyzing a Dockerfile, scanning cloud services, or searching the CVE database.")

    # Quick actions
    render_section_header("Quick Actions")
    c1, c2, c3, c4, c5 = st.columns(5)
    if c1.button("Dockerfile Scan", type="primary"):
        st.session_state.active_tab = "dockerfile"
        st.rerun()
    if c2.button("Search CVEs"):
        st.session_state.active_tab = "cve"
        st.rerun()
    if c3.button("Cloud Scan"):
        st.session_state.active_tab = "cloud_scanning"
        st.rerun()
    if c4.button("AI Agent"):
        st.session_state.active_tab = "agent_chat"
        st.rerun()
    if c5.button("Compliance"):
        st.session_state.active_tab = "compliance"
        st.rerun()
