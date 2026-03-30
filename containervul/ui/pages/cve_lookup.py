"""CVE database lookup and product search page."""

from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from containervul.core.cve_integrator import CVEIntegrator
from containervul.ui.components import render_section_header
from containervul.ui.styles import SEVERITY_COLORS

_cve = CVEIntegrator()


def render(config: dict) -> None:
    render_section_header("CVE Database Integration")

    tab1, tab2 = st.tabs(["CVE Lookup", "Product Search"])

    with tab1:
        st.subheader("CVE Lookup")
        cve_id = st.text_input("Enter CVE ID", placeholder="CVE-2023-12345")
        if st.button("Lookup CVE", type="primary") and cve_id:
            with st.spinner(f"Fetching {cve_id}..."):
                details = _cve.get_cve_details(cve_id)
                if "error" not in details:
                    c1, c2 = st.columns([2, 1])
                    with c1:
                        st.markdown(f"""
**CVE ID:** {details['id']}
**Severity:** {details['severity']} | **CVSS:** {details['cvss_score']}
**Published:** {details['published_date']}

**Description:** {details['description']}
""")
                    with c2:
                        st.markdown("**Affected Products:**")
                        for p in details.get("affected_products", [])[:10]:
                            st.write(f"- {p}")
                        st.markdown("**CWE IDs:**")
                        for cwe in details.get("cwe_ids", []):
                            st.write(f"- {cwe}")
                        if st.button("Add to Tracking"):
                            _add_cve_to_tracking(details)
                else:
                    st.error(f"Error: {details['error']}")

    with tab2:
        st.subheader("Product Vulnerability Search")
        c1, c2 = st.columns([2, 1])
        with c1:
            product = st.text_input("Product Name", placeholder="nginx")
            max_results = st.slider("Max Results", 10, 100, config["max_cve_results"])
        with c2:
            st.markdown("**Popular:**")
            for p in ["nginx", "apache", "mysql", "postgresql", "redis", "mongodb", "nodejs", "python"]:
                if st.button(p, key=f"pop_{p}"):
                    product = p

        if st.button("Search CVEs", type="primary") and product:
            with st.spinner(f"Searching {product}..."):
                cves = _cve.search_cves_by_product(product, max_results)
                if cves:
                    st.success(f"Found {len(cves)} CVEs for {product}")
                    for i, cve in enumerate(cves):
                        color = SEVERITY_COLORS.get(cve["severity"], "#6c757d")
                        st.markdown(f"""
**{cve['id']}** — <span style="color:{color}">**{cve['severity']}**</span> (CVSS: {cve['cvss_score']})
{cve['description']}
*Published: {cve['published_date']}*
""", unsafe_allow_html=True)
                        if st.button(f"Track {cve['id']}", key=f"track_{i}"):
                            _add_cve_to_tracking(cve, product)

                    df = pd.DataFrame(cves)
                    if not df.empty:
                        fig = px.pie(
                            values=df["severity"].value_counts().values,
                            names=df["severity"].value_counts().index,
                            title=f"CVE Severity for {product}",
                            color_discrete_map=SEVERITY_COLORS,
                        )
                        st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info(f"No CVEs found for {product}")


def _add_cve_to_tracking(cve_data: dict, product: str = "") -> None:
    vuln = {
        "id": cve_data.get("id", ""),
        "severity": cve_data.get("severity", "UNKNOWN"),
        "description": cve_data.get("description", ""),
        "cvss_score": cve_data.get("cvss_score", 0),
        "type": "cve_lookup",
        "category": "external_cve",
        "status": "open",
        "discovered_date": datetime.now().isoformat(),
        "priority_score": cve_data.get("cvss_score", 0),
        "product": product,
    }
    st.session_state.setdefault("vulnerabilities", []).append(vuln)
    st.success(f"Added {cve_data.get('id', '')} to tracking!")
