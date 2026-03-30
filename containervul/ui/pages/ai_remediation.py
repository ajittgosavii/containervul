"""AI-powered remediation page."""

from __future__ import annotations

import streamlit as st

from containervul.ai.remediation_engine import AIRemediationEngine
from containervul.core.vulnerability_analyzer import VulnerabilityAnalyzer
from containervul.models import Vulnerability
from containervul.ui.components import render_section_header, render_risk_metrics

_vuln_analyzer = VulnerabilityAnalyzer()
_engine = AIRemediationEngine()


def render(config: dict) -> None:
    render_section_header("AI-Powered Remediation")

    vuln_dicts = st.session_state.get("vulnerabilities", [])
    if not vuln_dicts:
        st.info("No vulnerabilities found. Analyze a Dockerfile or scan cloud services first.")
        return

    open_vulns = [v for v in vuln_dicts if v.get("status") == "open"]
    if not open_vulns:
        st.success("All vulnerabilities have been addressed!")
        return

    st.subheader(f"Analyzing {len(open_vulns)} Open Vulnerabilities")

    if st.button("Generate AI Remediation Plan", type="primary"):
        with st.spinner("AI analyzing vulnerabilities..."):
            # Convert dicts to Vulnerability models
            vuln_models = []
            for vd in open_vulns:
                try:
                    vuln_models.append(Vulnerability(**vd))
                except Exception:
                    pass

            risk = _vuln_analyzer.calculate_risk_score(vuln_models)
            plan = _engine.generate_remediation_plan(vuln_models)
            st.session_state.remediation_plan = plan.model_dump()

            render_risk_metrics(risk.model_dump())
            st.metric("Estimated Effort", plan.estimated_effort)

            _render_plan(plan.model_dump())

    # Individual vulnerability remediation
    render_section_header("Individual Vulnerability Remediation")

    options = [f"{v.get('id', '?')} — {v.get('severity', '?')} — {v.get('description', '')[:50]}" for v in open_vulns[:20]]
    if options:
        idx = st.selectbox("Select Vulnerability", range(len(options)), format_func=lambda i: options[i])
        selected = open_vulns[idx]

        c1, c2 = st.columns([2, 1])
        with c1:
            st.markdown(f"""
**ID:** {selected.get('id')}
**Severity:** {selected.get('severity')}
**Category:** {selected.get('category', '').replace('_', ' ').title()}
**Description:** {selected.get('description')}
""")
            if selected.get("line_number"):
                st.code(selected.get("line_content", ""), language="dockerfile")
        with c2:
            if st.button("Generate Fix Script"):
                try:
                    vuln_model = Vulnerability(**selected)
                    script = _engine.generate_fix_script(vuln_model)
                    st.code(script, language="bash")
                    st.download_button("Download Script", script, file_name=f"fix_{selected.get('id', 'vuln')}.sh")
                except Exception as e:
                    st.error(f"Error: {e}")

            new_status = st.selectbox("Update Status", ["open", "in_progress", "resolved", "false_positive"], key="status_sel")
            if st.button("Update Status"):
                selected["status"] = new_status
                st.success(f"Updated to {new_status}")
                st.rerun()


def _render_plan(plan: dict) -> None:
    if plan.get("immediate_actions"):
        st.markdown('<div class="remediation-card"><h4>Immediate Actions Required</h4></div>', unsafe_allow_html=True)
        for a in plan["immediate_actions"]:
            st.write(f"- {a}")

    if plan.get("short_term_actions"):
        st.markdown('<div class="remediation-card"><h4>Short-term Actions (1-4 weeks)</h4></div>', unsafe_allow_html=True)
        for a in plan["short_term_actions"]:
            st.write(f"- {a}")

    if plan.get("long_term_actions"):
        st.markdown('<div class="remediation-card"><h4>Long-term Actions (1-3 months)</h4></div>', unsafe_allow_html=True)
        for a in plan["long_term_actions"]:
            st.write(f"- {a}")

    if plan.get("automated_fixes"):
        st.markdown('<div class="remediation-card"><h4>Automation Opportunities</h4></div>', unsafe_allow_html=True)
        for fix in plan["automated_fixes"]:
            if isinstance(fix, dict):
                st.write(f"- **{fix.get('type', '')}**: {fix.get('description', '')} (Feasibility: {fix.get('feasibility', '')})")
            else:
                st.write(f"- {fix}")

    if plan.get("ai_recommendations"):
        st.markdown('<div class="remediation-card"><h4>AI Insights</h4></div>', unsafe_allow_html=True)
        st.markdown(plan["ai_recommendations"])
