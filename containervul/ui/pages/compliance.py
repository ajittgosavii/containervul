"""Compliance dashboard page."""

from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from containervul.enterprise.compliance.base import get_framework
from containervul.models import Vulnerability
from containervul.ui.components import render_section_header


def render(config: dict) -> None:
    render_section_header("Compliance Dashboard")

    vulns = st.session_state.get("vulnerabilities", [])
    if not vulns:
        st.info("No vulnerability data. Run scans first to check compliance.")
        return

    vuln_models = []
    for vd in vulns:
        try:
            vuln_models.append(Vulnerability(**vd))
        except Exception:
            pass

    framework_name = st.selectbox("Compliance Framework", [
        ("cis_docker", "CIS Docker Benchmark v1.6"),
        ("cis_kubernetes", "CIS Kubernetes Benchmark"),
        ("nist_800_190", "NIST SP 800-190"),
    ], format_func=lambda x: x[1], key="compliance_fw")

    if st.button("Run Compliance Check", type="primary"):
        with st.spinner(f"Evaluating {framework_name[1]}..."):
            fw = get_framework(framework_name[0])
            report = fw.evaluate(vuln_models)

            # Score gauge
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=report.compliance_score,
                title={"text": f"{framework_name[1]} Score"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#533483"},
                    "steps": [
                        {"range": [0, 50], "color": "#fed7d7"},
                        {"range": [50, 80], "color": "#fefcbf"},
                        {"range": [80, 100], "color": "#c6f6d5"},
                    ],
                },
            ))
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)

            c1, c2, c3 = st.columns(3)
            c1.metric("Total Controls", report.total_controls)
            c2.metric("Passed", report.passed_controls)
            c3.metric("Failed", report.total_controls - report.passed_controls)

            # Controls table
            st.subheader("Control Results")
            for ctrl in report.controls:
                status_icon = "PASS" if ctrl.passed else "FAIL"
                status_color = "compliance-pass" if ctrl.passed else "compliance-fail"

                with st.expander(f"[{status_icon}] {ctrl.control_id}: {ctrl.title}"):
                    st.markdown(f"""
<span class="{status_color}">{status_icon}</span> — **{ctrl.severity.value}** severity

**Description:** {ctrl.description}

**Remediation:** {ctrl.remediation}
""", unsafe_allow_html=True)

                    if ctrl.findings:
                        st.markdown("**Findings:**")
                        for f in ctrl.findings:
                            st.write(f"- {f}")
                    else:
                        st.success("No issues found for this control.")

    # Run all frameworks
    if st.button("Run All Frameworks"):
        with st.spinner("Evaluating all frameworks..."):
            results = {}
            for fw_key, fw_label in [("cis_docker", "CIS Docker"), ("cis_kubernetes", "CIS Kubernetes"), ("nist_800_190", "NIST 800-190")]:
                fw = get_framework(fw_key)
                report = fw.evaluate(vuln_models)
                results[fw_label] = report

            cols = st.columns(3)
            for i, (label, report) in enumerate(results.items()):
                with cols[i]:
                    score = report.compliance_score
                    color = "#28a745" if score >= 80 else "#ffc107" if score >= 50 else "#dc3545"
                    st.markdown(f"""
<div style="text-align:center;padding:1rem;border-radius:10px;background:#f8f9fa;">
<h3>{label}</h3>
<h1 style="color:{color}">{score:.0f}%</h1>
<p>{report.passed_controls}/{report.total_controls} controls passed</p>
</div>
""", unsafe_allow_html=True)
