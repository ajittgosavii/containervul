"""Main application orchestrator — wires navigation, sidebar, and pages."""

from __future__ import annotations

import streamlit as st

from containervul.cloud.accounts import AccountManager
from containervul.enterprise.audit import AuditLogger
from containervul.ui.sidebar import render_sidebar
from containervul.ui.styles import apply_custom_css


# ── Page registry ────────────────────────────────────────────────────────────

PAGES = {
    "dashboard":      ("Dashboard",        "containervul.ui.pages.dashboard"),
    "cve":            ("CVE Lookup",        "containervul.ui.pages.cve_lookup"),
    "dockerfile":     ("Dockerfile Scan",   "containervul.ui.pages.dockerfile_scan"),
    "cloud_scanning": ("Cloud Scan",        "containervul.ui.pages.cloud_scanning"),
    "agent_chat":     ("AI Agent",          "containervul.ui.pages.agent_chat"),
    "ai_remediation": ("AI Remediation",    "containervul.ui.pages.ai_remediation"),
    "analytics":      ("Analytics",         "containervul.ui.pages.analytics"),
    "compliance":     ("Compliance",        "containervul.ui.pages.compliance"),
    "reports":        ("Reports",           "containervul.ui.pages.reports"),
    "audit_log":      ("Audit Log",         "containervul.ui.pages.audit_log"),
    "accounts":       ("Accounts",          "containervul.ui.pages.accounts"),
    "servicenow":     ("ServiceNow",        "containervul.ui.pages.servicenow"),
}

NAV_GROUPS = {
    "Scanning":      ["dockerfile", "cloud_scanning"],
    "Intelligence":  ["cve", "agent_chat"],
    "Analysis":      ["dashboard", "analytics", "compliance"],
    "Remediation":   ["ai_remediation"],
    "Integrations":  ["servicenow"],
    "Management":    ["reports", "audit_log", "accounts"],
}


class ContainerVulnerabilityPlatform:
    """Main Streamlit application."""

    def __init__(self) -> None:
        self._init_session_state()

    def _init_session_state(self) -> None:
        defaults = {
            "vulnerabilities": [],
            "scan_history": [],
            "active_tab": "dashboard",
            "remediation_plans": {},
            "dockerfile_content": "",
            "agent_messages": [],
            "ai_available": False,
        }
        for k, v in defaults.items():
            if k not in st.session_state:
                st.session_state[k] = v

        if "account_manager" not in st.session_state:
            st.session_state["account_manager"] = AccountManager()
        if "audit_logger" not in st.session_state:
            st.session_state["audit_logger"] = AuditLogger()

        # Check AI availability
        try:
            if hasattr(st, "secrets") and "CLAUDE_API_KEY" in st.secrets:
                st.session_state["ai_available"] = True
        except Exception:
            pass

    def run(self) -> None:
        # Page config must be first Streamlit command
        apply_custom_css()
        self._render_header()
        self._render_navigation()

        # Sidebar
        accounts: AccountManager = st.session_state["account_manager"]
        account_names = [a.name for a in accounts.list_all()]
        config = render_sidebar(account_names)

        # Audit logging for navigation
        audit: AuditLogger = st.session_state["audit_logger"]

        # Render active page
        active = st.session_state.active_tab
        if active in PAGES:
            _, module_path = PAGES[active]
            import importlib
            page_module = importlib.import_module(module_path)
            page_module.render(config)
        else:
            st.error(f"Unknown page: {active}")

    def _render_header(self) -> None:
        st.markdown("""
        <div class="main-header">
            <h1>Enterprise Container Vulnerability Management</h1>
            <p style="font-size:1.1rem;margin-top:0.5rem;">
                Multi-Cloud Security &bull; Agentic AI &bull; MCP Integration &bull; ServiceNow &bull; Compliance
            </p>
            <p style="font-size:0.9rem;opacity:0.9;">
                EKS &bull; ECS &bull; AKS &bull; ACI &bull; GKE &bull; Cloud Run &bull; Multi-Account Support
            </p>
        </div>
        """, unsafe_allow_html=True)

    def _render_navigation(self) -> None:
        # Create tabs from nav groups
        cols = st.columns(len(NAV_GROUPS))
        for i, (group, page_keys) in enumerate(NAV_GROUPS.items()):
            with cols[i]:
                st.markdown(f"**{group}**")
                for key in page_keys:
                    label = PAGES[key][0]
                    if st.button(label, key=f"nav_{key}", use_container_width=True):
                        st.session_state.active_tab = key
                        st.rerun()
