"""Audit log viewer page."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from containervul.enterprise.audit import AuditLogger
from containervul.ui.components import render_section_header


def render(config: dict) -> None:
    render_section_header("Audit Log")

    audit: AuditLogger = st.session_state.get("audit_logger", AuditLogger())

    events = audit.get_all()

    if not events:
        st.info("No audit events recorded yet. Actions are logged as you use the platform.")
        return

    st.metric("Total Events", len(events))

    # Filters
    c1, c2 = st.columns(2)
    users = sorted(set(e.user for e in events))
    actions = sorted(set(e.action for e in events))
    user_filter = c1.multiselect("Filter by User", users, default=users)
    action_filter = c2.multiselect("Filter by Action", actions, default=actions)

    filtered = [e for e in events if e.user in user_filter and e.action in action_filter]

    df_data = [{
        "Timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "User": e.user,
        "Action": e.action,
        "Target": e.target,
        "Result": e.result,
    } for e in filtered]

    if df_data:
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True)

        csv = df.to_csv(index=False)
        st.download_button("Export Audit Log", csv, "audit_log.csv", "text/csv")
