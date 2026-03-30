"""Cloud account management page."""

from __future__ import annotations

import streamlit as st

from containervul.cloud.accounts import AccountManager
from containervul.models import CloudAccount, CloudProviderType
from containervul.ui.components import render_section_header


def render(config: dict) -> None:
    render_section_header("Cloud Account Management")

    accounts: AccountManager = st.session_state.get("account_manager", AccountManager())

    # Current accounts
    all_accounts = accounts.list_all()
    if all_accounts:
        st.subheader(f"Configured Accounts ({len(all_accounts)})")
        for acct in all_accounts:
            provider_emoji = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}.get(acct.provider.value, acct.provider.value)
            status = "Active" if acct.is_active else "Inactive"
            with st.expander(f"{provider_emoji} — {acct.name} ({acct.account_id})"):
                c1, c2 = st.columns([2, 1])
                with c1:
                    st.markdown(f"""
- **Provider:** {acct.provider.value.upper()}
- **Account ID:** {acct.account_id}
- **Regions:** {', '.join(acct.regions) if acct.regions else 'Default'}
- **Status:** {status}
- **Added:** {acct.added_at:%Y-%m-%d}
""")
                    if acct.role_arn:
                        st.markdown(f"- **Role ARN:** {acct.role_arn}")
                with c2:
                    if st.button(f"Remove", key=f"rm_{acct.id}"):
                        accounts.remove_account(acct.id)
                        st.session_state["account_manager"] = accounts
                        st.rerun()
    else:
        st.info("No cloud accounts configured. Add an account below.")

    # Add account form
    st.markdown("---")
    st.subheader("Add Cloud Account")

    provider = st.selectbox("Provider", ["AWS", "Azure", "GCP"], key="add_provider")
    provider_key = provider.lower()

    name = st.text_input("Display Name", placeholder="Production Account", key="add_name")

    id_labels = {"aws": "AWS Account ID (12-digit)", "azure": "Azure Subscription ID (UUID)", "gcp": "GCP Project ID"}
    account_id = st.text_input(id_labels[provider_key], key="add_account_id")

    default_regions = {"aws": "us-east-1, us-west-2", "azure": "eastus, westus2", "gcp": "us-central1, us-east1"}
    regions_str = st.text_input("Regions (comma-separated)", value=default_regions[provider_key], key="add_regions")

    # Provider-specific fields
    role_arn = None
    tenant_id = None
    credential_profile = None

    if provider_key == "aws":
        role_arn = st.text_input("Cross-account Role ARN (optional)", key="add_role_arn")
        credential_profile = st.text_input("AWS CLI Profile Name (optional)", key="add_profile")
    elif provider_key == "azure":
        tenant_id = st.text_input("Tenant ID (optional)", key="add_tenant")
    elif provider_key == "gcp":
        credential_profile = st.text_input("Service Account JSON path (optional)", key="add_sa_path")

    if st.button("Add Account", type="primary"):
        if not name or not account_id:
            st.warning("Name and Account ID are required.")
            return

        acct = CloudAccount(
            name=name,
            provider=CloudProviderType(provider_key),
            account_id=account_id.strip(),
            regions=[r.strip() for r in regions_str.split(",") if r.strip()],
            role_arn=role_arn or None,
            tenant_id=tenant_id or None,
            credential_profile=credential_profile or None,
        )
        accounts.add_account(acct)
        st.session_state["account_manager"] = accounts
        st.success(f"Added {provider} account: {name}")
        st.rerun()

    # Test connection
    if all_accounts:
        st.markdown("---")
        st.subheader("Test Connection")
        test_acct_name = st.selectbox("Account to Test", [a.name for a in all_accounts], key="test_acct")
        if st.button("Test Connection"):
            target = next(a for a in all_accounts if a.name == test_acct_name)
            with st.spinner(f"Testing {target.provider.value.upper()} connection..."):
                try:
                    if target.provider == CloudProviderType.AWS:
                        from containervul.cloud.aws.client import AWSClientFactory
                        AWSClientFactory.verify(target)
                    elif target.provider == CloudProviderType.AZURE:
                        from containervul.cloud.azure.client import AzureClientFactory
                        AzureClientFactory.verify(target)
                    elif target.provider == CloudProviderType.GCP:
                        from containervul.cloud.gcp.client import GCPClientFactory
                        GCPClientFactory.verify(target)
                    st.success(f"Successfully connected to {target.provider.value.upper()} account {target.account_id}")
                except Exception as exc:
                    st.error(f"Connection failed: {exc}")
