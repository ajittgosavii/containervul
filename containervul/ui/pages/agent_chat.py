"""Agentic AI chat interface — conversational vulnerability analysis."""

from __future__ import annotations

import json

import streamlit as st

from containervul.ai.agent import VulnerabilityAgent
from containervul.ai.tools import ToolExecutor
from containervul.cloud.accounts import AccountManager
from containervul.core.cve_integrator import CVEIntegrator
from containervul.core.dockerfile_analyzer import DockerfileAnalyzer
from containervul.core.vulnerability_analyzer import VulnerabilityAnalyzer
from containervul.models import Vulnerability
from containervul.ui.components import render_section_header


def render(config: dict) -> None:
    render_section_header("AI Security Agent")

    st.markdown("""
    Chat with the AI agent to autonomously scan, analyze, and remediate container vulnerabilities.

    **Example prompts:**
    - "Scan this Dockerfile for vulnerabilities: FROM ubuntu:16.04..."
    - "Look up CVE-2024-3094 and tell me its impact"
    - "Search for nginx vulnerabilities and generate a remediation plan"
    - "Scan my AWS EKS clusters and report critical issues"
    - "Check compliance against CIS Docker Benchmark"
    - "What are the top risks across all my tracked vulnerabilities?"
    """)

    # Initialize chat history
    if "agent_messages" not in st.session_state:
        st.session_state.agent_messages = []

    # Display chat history
    for msg in st.session_state.agent_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    with st.expander(f"Tool: {tc['name']}"):
                        st.json(tc.get("input", {}))
                        st.code(tc.get("result", "")[:1000], language="json")

    # Chat input
    user_input = st.chat_input("Ask the AI agent about container security...")

    if user_input:
        # Add user message
        st.session_state.agent_messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        # Run agent
        with st.chat_message("assistant"):
            api_key = ""
            try:
                if hasattr(st, "secrets") and "CLAUDE_API_KEY" in st.secrets:
                    api_key = st.secrets["CLAUDE_API_KEY"]
            except Exception:
                pass

            if not api_key:
                st.warning("Add CLAUDE_API_KEY to Streamlit secrets for the AI agent.")
                st.session_state.agent_messages.append({"role": "assistant", "content": "API key not configured."})
                return

            # Set up tool executor with current state
            vuln_dicts = st.session_state.get("vulnerabilities", [])
            vuln_models = []
            for vd in vuln_dicts:
                try:
                    vuln_models.append(Vulnerability(**vd))
                except Exception:
                    pass

            accounts = st.session_state.get("account_manager", AccountManager())
            executor = ToolExecutor(
                cve_integrator=CVEIntegrator(),
                dockerfile_analyzer=DockerfileAnalyzer(),
                vuln_analyzer=VulnerabilityAnalyzer(),
                account_manager=accounts,
                vulnerability_store=vuln_models,
            )

            agent = VulnerabilityAgent(tool_executor=executor, api_key=api_key)

            response_text = []
            tool_calls = []
            status_container = st.empty()

            try:
                for event in agent.run(user_input):
                    if event.type == "response" and event.content:
                        response_text.append(event.content)
                        st.markdown(event.content)

                    elif event.type == "tool_call":
                        status_container.info(f"Running tool: {event.tool_name}...")
                        tool_calls.append({
                            "name": event.tool_name,
                            "input": event.tool_input,
                            "result": event.tool_result,
                        })
                        with st.expander(f"Tool: {event.tool_name}"):
                            st.json(event.tool_input or {})
                            try:
                                result_data = json.loads(event.tool_result) if isinstance(event.tool_result, str) else event.tool_result
                                st.json(result_data)
                            except (json.JSONDecodeError, TypeError):
                                st.code(str(event.tool_result)[:1000])

                    elif event.type == "error":
                        st.error(event.content or "Agent error")
                        response_text.append(f"Error: {event.content}")

                    elif event.type == "complete":
                        status_container.empty()

                # Sync discovered vulnerabilities back to session
                new_vulns = [v.model_dump(mode="json") for v in vuln_models if v.id not in {vd.get("id") for vd in vuln_dicts}]
                if new_vulns:
                    st.session_state.setdefault("vulnerabilities", []).extend(new_vulns)
                    st.info(f"Agent discovered {len(new_vulns)} new vulnerabilities — added to tracking.")

            except Exception as exc:
                st.error(f"Agent error: {exc}")
                response_text.append(f"Error: {exc}")

            st.session_state.agent_messages.append({
                "role": "assistant",
                "content": "\n".join(response_text) or "Agent completed with no text output.",
                "tool_calls": tool_calls,
            })
