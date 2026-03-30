"""Report generation page."""

from __future__ import annotations

from datetime import datetime

import streamlit as st

from containervul.core.vulnerability_analyzer import VulnerabilityAnalyzer
from containervul.models import Vulnerability
from containervul.ui.components import render_section_header

_analyzer = VulnerabilityAnalyzer()


def render(config: dict) -> None:
    render_section_header("Security Reports")

    vulns = st.session_state.get("vulnerabilities", [])
    if not vulns:
        st.info("No vulnerability data available.")
        return

    report_type = st.selectbox("Report Type", ["Executive Summary", "Technical Report", "Remediation Plan", "Compliance Summary"])

    if st.button("Generate Report", type="primary"):
        with st.spinner("Generating..."):
            if report_type == "Executive Summary":
                report = _executive_summary(vulns)
            elif report_type == "Technical Report":
                report = _technical_report(vulns)
            elif report_type == "Remediation Plan":
                report = _remediation_report(vulns)
            else:
                report = _compliance_summary(vulns)

            st.markdown(report)
            st.download_button("Download Report", report,
                               f"{report_type.lower().replace(' ', '_')}_{datetime.now():%Y%m%d}.md",
                               "text/markdown")


def _executive_summary(vulns: list) -> str:
    models = _to_models(vulns)
    risk = _analyzer.calculate_risk_score(models)
    status_counts = {}
    for v in vulns:
        s = v.get("status", "open")
        status_counts[s] = status_counts.get(s, 0) + 1

    return f"""# Container Security Assessment — Executive Summary

## Overall Security Posture
- **Total Vulnerabilities:** {len(vulns)}
- **Risk Level:** {risk.risk_level}
- **Critical Issues:** {risk.severity_breakdown.get('CRITICAL', 0)}
- **High Priority:** {risk.severity_breakdown.get('HIGH', 0)}

## Remediation Status
- **Open:** {status_counts.get('open', 0)}
- **In Progress:** {status_counts.get('in_progress', 0)}
- **Resolved:** {status_counts.get('resolved', 0)}

## Cloud Coverage
- AWS (EKS/ECS), Azure (AKS/ACI), GCP (GKE/Cloud Run) supported
- Multi-account scanning enabled

## Recommendations
1. Immediate attention for {risk.severity_breakdown.get('CRITICAL', 0)} critical vulnerabilities
2. Prioritize remediation of high-severity issues
3. Implement automated scanning in CI/CD pipelines
4. Run compliance checks against CIS and NIST frameworks

**Risk Score:** {risk.total_score:.0f} | Generated: {datetime.now():%Y-%m-%d %H:%M}
"""


def _technical_report(vulns: list) -> str:
    report = "# Container Security Technical Report\n\n## Vulnerability Details\n\n"
    for v in vulns[:30]:
        report += f"""### {v.get('id', '?')} — {v.get('severity', '?')}
**Description:** {v.get('description', 'N/A')}
**Category:** {v.get('category', '').replace('_', ' ').title()}
**Status:** {v.get('status', 'open')} | **Provider:** {v.get('cloud_provider', 'N/A')}
**Remediation:** {v.get('remediation', 'Under investigation')}

---
"""
    return report


def _remediation_report(vulns: list) -> str:
    plan = st.session_state.get("remediation_plan", {})
    if not plan:
        from containervul.ai.remediation_engine import AIRemediationEngine
        engine = AIRemediationEngine()
        models = _to_models(vulns)
        plan = engine.generate_remediation_plan(models).model_dump()

    return f"""# Container Security Remediation Plan

## Immediate Actions
{chr(10).join('- ' + a for a in plan.get('immediate_actions', ['None identified']))}

## Short-term (1-4 weeks)
{chr(10).join('- ' + a for a in plan.get('short_term_actions', ['None identified']))}

## Long-term (1-3 months)
{chr(10).join('- ' + a for a in plan.get('long_term_actions', ['None identified']))}

**Estimated Effort:** {plan.get('estimated_effort', 'Unknown')}
**Risk Reduction:** {plan.get('risk_reduction', 0)}%

Generated: {datetime.now():%Y-%m-%d %H:%M}
"""


def _compliance_summary(vulns: list) -> str:
    from containervul.enterprise.compliance.base import get_framework
    models = _to_models(vulns)
    lines = ["# Compliance Summary Report\n"]
    for fw_name, label in [("cis_docker", "CIS Docker Benchmark"), ("cis_kubernetes", "CIS Kubernetes Benchmark"), ("nist_800_190", "NIST SP 800-190")]:
        fw = get_framework(fw_name)
        report = fw.evaluate(models)
        lines.append(f"## {label}\n- **Score:** {report.compliance_score}%\n- **Passed:** {report.passed_controls}/{report.total_controls}\n")
        for c in report.controls:
            status = "PASS" if c.passed else "FAIL"
            lines.append(f"- [{status}] {c.control_id}: {c.title}")
        lines.append("")
    lines.append(f"\nGenerated: {datetime.now():%Y-%m-%d %H:%M}")
    return "\n".join(lines)


def _to_models(vulns: list) -> list:
    models = []
    for vd in vulns:
        try:
            models.append(Vulnerability(**vd))
        except Exception:
            pass
    return models
