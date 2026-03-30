"""Dockerfile security scanning page."""

from __future__ import annotations

import streamlit as st

from containervul.core.dockerfile_analyzer import DockerfileAnalyzer
from containervul.core.vulnerability_analyzer import VulnerabilityAnalyzer
from containervul.ui.components import render_section_header, render_risk_metrics

_analyzer = DockerfileAnalyzer()
_vuln_analyzer = VulnerabilityAnalyzer()

INSECURE_SAMPLE = """FROM ubuntu:16.04
USER root
RUN apt-get update && apt-get install -y nginx
COPY . /
ENV PASSWORD=mysecretpassword
ENV API_KEY=abc123secretkey
RUN chmod 777 /app
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]"""

SECURE_SAMPLE = """FROM ubuntu:24.04

RUN groupadd -r appuser && useradd -r -g appuser appuser

RUN apt-get update && \\
    apt-get install -y --no-install-recommends nginx && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --chown=appuser:appuser ./app /app
WORKDIR /app
USER appuser

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:80/health || exit 1

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]"""


def render(config: dict) -> None:
    render_section_header("Dockerfile Security Analyzer")

    c1, c2 = st.columns([3, 1])

    with c2:
        st.markdown("**Sample Dockerfiles**")
        if st.button("Insecure Example"):
            st.session_state.dockerfile_content = INSECURE_SAMPLE
        if st.button("Secure Example"):
            st.session_state.dockerfile_content = SECURE_SAMPLE
        if st.button("Clear"):
            st.session_state.dockerfile_content = ""

    with c1:
        content = st.text_area(
            "Paste Dockerfile Content",
            height=400,
            value=st.session_state.get("dockerfile_content", ""),
            placeholder="FROM ubuntu:24.04\nRUN apt-get update...",
            key="dockerfile_input",
        )
        st.session_state.dockerfile_content = content

    if st.button("Analyze Dockerfile", type="primary"):
        if not content:
            st.warning("Please paste Dockerfile content.")
            return

        with st.spinner("Analyzing..."):
            vulns = _analyzer.analyze_dockerfile(content)

            if not vulns:
                st.success("No security issues found! Great job.")
                return

            if config["auto_prioritize"]:
                vulns = _vuln_analyzer.prioritize(vulns)

            # Store as dicts in session
            vuln_dicts = [v.model_dump(mode="json") for v in vulns]
            for vd in vuln_dicts:
                vd["severity"] = vd["severity"].upper() if isinstance(vd["severity"], str) else vd["severity"]
            st.session_state.setdefault("vulnerabilities", []).extend(vuln_dicts)

            st.success(f"Found {len(vulns)} security issues.")
            render_section_header("Security Issues Found")

            # Group by severity
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                sev_vulns = [v for v in vulns if v.severity.value == sev]
                if not sev_vulns:
                    continue
                st.markdown(f"### {sev} ({len(sev_vulns)})")
                for v in sev_vulns:
                    with st.expander(f"Line {v.line_number}: {v.category.replace('_', ' ').title()}"):
                        c1, c2 = st.columns([2, 1])
                        with c1:
                            st.markdown(f"**Issue:** {v.description}")
                            st.code(v.line_content or "", language="dockerfile")
                            st.markdown(f"**Remediation:** {v.remediation}")
                        with c2:
                            st.markdown(f"**Severity:** {sev}\n**ID:** {v.id}")
                            new_status = st.selectbox("Status", ["open", "in_progress", "resolved", "false_positive"], key=f"s_{v.id}")
                            if st.button("Update", key=f"u_{v.id}"):
                                v.status = new_status
                                st.success("Updated!")

            # Risk assessment
            risk = _vuln_analyzer.calculate_risk_score(vulns)
            render_section_header("Risk Assessment")
            render_risk_metrics(risk.model_dump())
