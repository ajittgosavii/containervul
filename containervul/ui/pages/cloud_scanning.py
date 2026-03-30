"""Multi-cloud container scanning page."""

from __future__ import annotations

import json
from datetime import datetime

import streamlit as st

from containervul.cloud.accounts import AccountManager
from containervul.models import CloudAccount, CloudProviderType
from containervul.ui.components import render_section_header, render_cloud_service_card


def render(config: dict) -> None:
    render_section_header("Multi-Cloud Container Scanning")

    accounts: AccountManager = st.session_state.get("account_manager", AccountManager())

    provider = st.selectbox("Cloud Provider", ["AWS", "Azure", "GCP"], key="cloud_provider_select")
    provider_key = provider.lower()

    provider_accounts = accounts.list_accounts(CloudProviderType(provider_key))
    if not provider_accounts:
        st.warning(f"No {provider} accounts configured. Go to Account Management to add one.")
        _render_quick_add(accounts, provider_key)
        return

    account_names = {a.name: a for a in provider_accounts}
    selected_name = st.selectbox("Account", list(account_names.keys()), key="cloud_account_select")
    account = account_names[selected_name]

    service_types = {
        "aws": {"EKS (Kubernetes)": "eks", "ECS (Containers)": "ecs"},
        "azure": {"AKS (Kubernetes)": "aks", "Container Instances": "aci"},
        "gcp": {"GKE (Kubernetes)": "gke", "Cloud Run": "cloud_run"},
    }

    service_label = st.selectbox("Service Type", list(service_types[provider_key].keys()), key="svc_type_select")
    service_type = service_types[provider_key][service_label]

    region = st.text_input("Region (leave blank for all)", value=account.regions[0] if account.regions else "", key="scan_region")

    if st.button(f"Scan {provider} {service_label}", type="primary"):
        with st.spinner(f"Discovering {service_label} in {provider}..."):
            try:
                scanner = _get_scanner(provider_key, service_type)
                regions = [region] if region else (account.regions or [_default_region(provider_key)])

                total_images = 0
                for r in regions:
                    st.markdown(f"**Region: {r}**")
                    clusters = scanner.list_clusters(account, r)

                    if not clusters:
                        st.info(f"No {service_label} found in {r}")
                        continue

                    for cluster in clusters:
                        images = scanner.list_running_images(account, r, cluster["name"])
                        total_images += len(images)

                        cluster["image_count"] = len(images)
                        render_cloud_service_card(cluster, provider_key)

                        if images:
                            with st.expander(f"Images in {cluster['name']} ({len(images)})"):
                                for img in images:
                                    st.write(f"- `{img.image_uri}` (tag: {img.tag})")

                                    # Add to tracked vulnerabilities as discovered images
                                    vuln_entry = {
                                        "id": f"IMG-{img.image_uri[:50]}",
                                        "severity": "MEDIUM",
                                        "description": f"Container image discovered: {img.image_uri}",
                                        "category": "image_vulnerability",
                                        "type": "cloud_discovery",
                                        "status": "open",
                                        "discovered_date": datetime.now().isoformat(),
                                        "cloud_provider": provider_key,
                                        "cloud_account": account.account_id,
                                        "priority_score": 4.0,
                                    }
                                    st.session_state.setdefault("vulnerabilities", []).append(vuln_entry)

                st.success(f"Scan complete: found {total_images} container images across {len(clusters)} services")

            except Exception as exc:
                st.error(f"Scan error: {exc}")
                st.info("Ensure the required cloud SDK is installed and credentials are configured.")


def _render_quick_add(accounts: AccountManager, provider: str) -> None:
    """Quick-add account form."""
    st.markdown("### Quick Add Account")
    name = st.text_input("Account Name", key="qa_name")
    account_id = st.text_input(
        {"aws": "AWS Account ID", "azure": "Azure Subscription ID", "gcp": "GCP Project ID"}[provider],
        key="qa_id",
    )
    regions = st.text_input("Regions (comma-separated)", value=_default_region(provider), key="qa_regions")
    role_arn = ""
    if provider == "aws":
        role_arn = st.text_input("Cross-account Role ARN (optional)", key="qa_role")

    if st.button("Add Account", key="qa_add") and name and account_id:
        acct = CloudAccount(
            name=name,
            provider=CloudProviderType(provider),
            account_id=account_id,
            regions=[r.strip() for r in regions.split(",") if r.strip()],
            role_arn=role_arn or None,
        )
        accounts.add_account(acct)
        st.session_state["account_manager"] = accounts
        st.success(f"Added {provider.upper()} account: {name}")
        st.rerun()


def _get_scanner(provider: str, service_type: str):
    if provider == "aws":
        if service_type == "eks":
            from containervul.cloud.aws.eks import EKSScanner
            return EKSScanner()
        from containervul.cloud.aws.ecs import ECSScanner
        return ECSScanner()
    elif provider == "azure":
        if service_type == "aks":
            from containervul.cloud.azure.aks import AKSScanner
            return AKSScanner()
        from containervul.cloud.azure.aci import ACIScanner
        return ACIScanner()
    elif provider == "gcp":
        if service_type == "gke":
            from containervul.cloud.gcp.gke import GKEScanner
            return GKEScanner()
        from containervul.cloud.gcp.cloud_run import CloudRunScanner
        return CloudRunScanner()
    raise ValueError(f"Unknown: {provider}/{service_type}")


def _default_region(provider: str) -> str:
    return {"aws": "us-east-1", "azure": "eastus", "gcp": "us-central1"}.get(provider, "us-east-1")
