"""
Enterprise Container Vulnerability Management Platform
Multi-cloud security scanning with Agentic AI and MCP integration.

Supports: EKS, ECS, AKS, ACI, GKE, Cloud Run
Features: Multi-account, Agentic AI (Claude tool-use), MCP server, Compliance (CIS, NIST)
"""

import streamlit as st

# Page configuration — must be the first Streamlit command
st.set_page_config(
    page_title="Enterprise Container Vulnerability Management",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from containervul.ui.app import ContainerVulnerabilityPlatform


def main():
    try:
        platform = ContainerVulnerabilityPlatform()
        platform.run()
    except Exception as e:
        st.error(f"An error occurred: {e}")
        st.info("Check configuration and logs. For cloud scanning, ensure SDKs are installed.")


if __name__ == "__main__":
    main()
