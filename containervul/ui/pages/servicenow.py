"""ServiceNow integration page — configuration, ticket dashboard, CMDB, bulk operations."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from containervul.integrations.servicenow.client import ServiceNowClient
from containervul.integrations.servicenow.tickets import VulnerabilityTicketManager, SEVERITY_TO_PRIORITY
from containervul.integrations.servicenow.cmdb import ContainerCMDBSync
from containervul.models import Vulnerability
from containervul.ui.components import render_section_header
from containervul.ui.styles import SEVERITY_COLORS


def _get_client() -> ServiceNowClient:
    """Get or create a ServiceNow client from session state or secrets."""
    cfg = st.session_state.get("snow_config", {})
    instance = cfg.get("instance", "")
    username = cfg.get("username", "")
    password = cfg.get("password", "")

    # Also check Streamlit secrets
    try:
        if hasattr(st, "secrets"):
            instance = instance or st.secrets.get("SERVICENOW_INSTANCE", "")
            username = username or st.secrets.get("SERVICENOW_USERNAME", "")
            password = password or st.secrets.get("SERVICENOW_PASSWORD", "")
    except Exception:
        pass

    return ServiceNowClient(instance=instance, username=username, password=password)


def render(config: dict) -> None:
    render_section_header("ServiceNow Integration")

    tab1, tab2, tab3, tab4 = st.tabs(["Configuration", "Ticket Dashboard", "CMDB", "Bulk Operations"])

    with tab1:
        _render_config_tab()
    with tab2:
        _render_ticket_dashboard()
    with tab3:
        _render_cmdb_tab()
    with tab4:
        _render_bulk_operations()


# ── Tab 1: Configuration ─────────────────────────────────────────────────────

def _render_config_tab() -> None:
    st.subheader("ServiceNow Connection")

    cfg = st.session_state.get("snow_config", {})

    instance = st.text_input("Instance URL", value=cfg.get("instance", ""), placeholder="https://devXXXXX.service-now.com", key="snow_instance")
    username = st.text_input("Username", value=cfg.get("username", ""), key="snow_username")
    password = st.text_input("Password", value=cfg.get("password", ""), type="password", key="snow_password")
    auth_method = st.radio("Auth Method", ["basic", "oauth"], index=0, key="snow_auth", horizontal=True)

    c1, c2 = st.columns(2)
    with c1:
        if st.button("Save Configuration", type="primary"):
            st.session_state["snow_config"] = {
                "instance": instance.rstrip("/"),
                "username": username,
                "password": password,
                "auth_method": auth_method,
            }
            st.success("ServiceNow configuration saved!")

    with c2:
        if st.button("Test Connection"):
            client = _get_client()
            if not client.is_configured:
                st.warning("Please configure instance URL, username, and password first.")
            else:
                with st.spinner("Testing connection..."):
                    result = client.test_connection()
                    if result["status"] == "connected":
                        st.success(f"Connected to {result['instance']}")
                    else:
                        st.error(f"Connection failed: {result['message']}")

    st.markdown("---")
    st.subheader("Ticket Settings")

    threshold = st.selectbox("Auto-create Severity Threshold", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], index=1, key="snow_threshold")
    assignment_group = st.text_input("Default Assignment Group", value="Container Security", key="snow_group")
    cmdb_sync = st.checkbox("Enable CMDB Sync", value=False, key="snow_cmdb_sync")
    bidir_sync = st.checkbox("Enable Bidirectional Status Sync", value=False, key="snow_bidir")

    st.session_state["snow_settings"] = {
        "threshold": threshold,
        "assignment_group": assignment_group,
        "cmdb_sync": cmdb_sync,
        "bidir_sync": bidir_sync,
    }


# ── Tab 2: Ticket Dashboard ─────────────────────────────────────────────────

def _render_ticket_dashboard() -> None:
    st.subheader("Vulnerability Tickets")

    client = _get_client()
    if not client.is_configured:
        st.info("Configure ServiceNow connection in the Configuration tab first.")
        return

    mgr = VulnerabilityTicketManager(client)

    # Quick metrics
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        if st.button("Load Open Tickets", type="primary"):
            with st.spinner("Fetching from ServiceNow..."):
                tickets = mgr.get_open_vulnerability_incidents(limit=100)
                st.session_state["snow_tickets"] = tickets
                st.success(f"Loaded {len(tickets)} open tickets")

    tickets = st.session_state.get("snow_tickets", [])

    if tickets:
        # Priority breakdown
        priorities = {"1": 0, "2": 0, "3": 0, "4": 0}
        for t in tickets:
            p = str(t.get("priority", "4"))
            priorities[p] = priorities.get(p, 0) + 1

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("P1 - Critical", priorities.get("1", 0))
        c2.metric("P2 - High", priorities.get("2", 0))
        c3.metric("P3 - Medium", priorities.get("3", 0))
        c4.metric("P4 - Low", priorities.get("4", 0))

        # Ticket table
        df_data = []
        for t in tickets:
            df_data.append({
                "Number": t.get("number", ""),
                "Description": t.get("short_description", "")[:80],
                "Priority": f"P{t.get('priority', '?')}",
                "State": _state_label(t.get("state", "")),
                "Vulnerability": t.get("u_vulnerability_id", ""),
                "Image": t.get("u_container_image", ""),
                "Opened": t.get("opened_at", ""),
            })

        if df_data:
            df = pd.DataFrame(df_data)
            st.dataframe(df, use_container_width=True)

            csv = df.to_csv(index=False)
            st.download_button("Export Tickets CSV", csv, "snow_tickets.csv", "text/csv")
    else:
        st.info("Click 'Load Open Tickets' to fetch from ServiceNow.")

    # Sync ticket statuses back
    if st.session_state.get("snow_settings", {}).get("bidir_sync"):
        st.markdown("---")
        if st.button("Sync Ticket Statuses"):
            with st.spinner("Pulling statuses from ServiceNow..."):
                vuln_dicts = st.session_state.get("vulnerabilities", [])
                vuln_models = []
                for vd in vuln_dicts:
                    try:
                        vuln_models.append(Vulnerability(**vd))
                    except Exception:
                        pass
                result = mgr.pull_ticket_statuses(vuln_models)
                st.success(f"Synced: {result['updated']} updated, {result['unchanged']} unchanged")
                if result.get("errors"):
                    st.warning(f"{len(result['errors'])} errors during sync")


# ── Tab 3: CMDB ─────────────────────────────────────────────────────────────

def _render_cmdb_tab() -> None:
    st.subheader("Configuration Management Database")

    client = _get_client()
    if not client.is_configured:
        st.info("Configure ServiceNow connection first.")
        return

    cmdb = ContainerCMDBSync(client)

    c1, c2 = st.columns(2)

    with c1:
        st.markdown("### Register Container Image")
        img_name = st.text_input("Image Name", placeholder="nginx", key="cmdb_img")
        img_tag = st.text_input("Tag", value="latest", key="cmdb_tag")
        img_provider = st.selectbox("Cloud Provider", ["aws", "azure", "gcp"], key="cmdb_provider")
        img_cluster = st.text_input("Cluster Name (optional)", key="cmdb_cluster")

        if st.button("Sync Image to CMDB", type="primary"):
            if img_name:
                with st.spinner("Syncing to CMDB..."):
                    result = cmdb.sync_container_image(img_name, img_tag, cloud_provider=img_provider, cluster_name=img_cluster)
                    st.success(f"{result['action'].title()} CI: {result['name']} (sys_id: {result['sys_id'][:8]}...)")

    with c2:
        st.markdown("### Register Cluster")
        cluster_name = st.text_input("Cluster Name", placeholder="prod-eks-cluster", key="cmdb_cl_name")
        cluster_provider = st.selectbox("Provider", ["aws", "azure", "gcp"], key="cmdb_cl_provider")
        cluster_region = st.text_input("Region", value="us-east-1", key="cmdb_cl_region")

        if st.button("Sync Cluster to CMDB"):
            if cluster_name:
                with st.spinner("Syncing cluster..."):
                    result = cmdb.sync_cluster(cluster_name, cluster_provider, cluster_region)
                    st.success(f"{result['action'].title()} CI: {result['name']}")

    st.markdown("---")
    st.subheader("CMDB Container CIs")
    if st.button("Load Container CIs"):
        with st.spinner("Querying CMDB..."):
            cis = cmdb.get_all_container_cis()
            if cis:
                df = pd.DataFrame([{
                    "Name": ci.get("name", ""),
                    "Version": ci.get("version", ""),
                    "Status": ci.get("operational_status", ""),
                    "Updated": ci.get("sys_updated_on", ""),
                } for ci in cis])
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No container CIs found in CMDB.")


# ── Tab 4: Bulk Operations ──────────────────────────────────────────────────

def _render_bulk_operations() -> None:
    st.subheader("Bulk Ticket Creation")

    client = _get_client()
    if not client.is_configured:
        st.info("Configure ServiceNow connection first.")
        return

    vulns = st.session_state.get("vulnerabilities", [])
    if not vulns:
        st.info("No vulnerabilities tracked. Run scans first.")
        return

    # Filter controls
    c1, c2, c3 = st.columns(3)
    severity_filter = c1.selectbox("Minimum Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], index=1, key="bulk_sev")
    provider_filter = c2.selectbox("Cloud Provider", ["All", "aws", "azure", "gcp"], key="bulk_provider")
    status_filter = c3.selectbox("Status", ["open", "in_progress", "All"], key="bulk_status")

    # Filter vulnerabilities
    filtered = vulns
    if provider_filter != "All":
        filtered = [v for v in filtered if v.get("cloud_provider") == provider_filter]
    if status_filter != "All":
        filtered = [v for v in filtered if v.get("status") == status_filter]

    # Show count by severity
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    threshold_idx = sev_order.index(severity_filter) + 1
    eligible = [v for v in filtered if v.get("severity", "UNKNOWN") in sev_order[:threshold_idx]]

    st.markdown(f"**{len(eligible)}** vulnerabilities eligible for ticket creation ({severity_filter}+ severity)")

    # Preview
    if eligible:
        preview_df = pd.DataFrame([{
            "ID": v.get("id", "")[:30],
            "Severity": v.get("severity", ""),
            "Category": v.get("category", ""),
            "Description": v.get("description", "")[:60],
        } for v in eligible[:50]])
        st.dataframe(preview_df, use_container_width=True)

    c1, c2 = st.columns(2)

    with c1:
        if st.button(f"Create Tickets for All {severity_filter}+", type="primary"):
            with st.spinner(f"Creating ServiceNow incidents for {len(eligible)} vulnerabilities..."):
                mgr = VulnerabilityTicketManager(client)
                vuln_models = []
                for vd in eligible:
                    try:
                        vuln_models.append(Vulnerability(**vd))
                    except Exception:
                        pass

                result = mgr.bulk_create_incidents(vuln_models, severity_filter)

                st.success(f"Created: {result['created']} | Skipped (existing): {result['skipped_existing']} | Below threshold: {result['skipped_below_threshold']}")
                if result.get("errors"):
                    st.warning(f"{len(result['errors'])} errors:")
                    for err in result["errors"][:5]:
                        st.write(f"- {err['vulnerability_id']}: {err['error']}")
                if result.get("tickets"):
                    st.markdown("**Created Tickets:**")
                    for t in result["tickets"]:
                        st.write(f"- {t['number']}: {t['vulnerability_id']}")

    with c2:
        if st.button("Create CRITICAL Tickets Only"):
            with st.spinner("Creating P1 incidents..."):
                mgr = VulnerabilityTicketManager(client)
                critical = [Vulnerability(**v) for v in vulns if v.get("severity") == "CRITICAL" and v.get("status") == "open"]
                if not critical:
                    st.info("No open CRITICAL vulnerabilities found.")
                else:
                    result = mgr.bulk_create_incidents(critical, "CRITICAL")
                    st.success(f"Created {result['created']} P1 incidents")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _state_label(state: str) -> str:
    return {"1": "New", "2": "In Progress", "3": "On Hold", "6": "Resolved", "7": "Closed"}.get(str(state), f"State {state}")
