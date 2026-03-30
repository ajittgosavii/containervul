"""CSS styling and theming for the Streamlit UI."""

import streamlit as st

CUSTOM_CSS = """
<style>
    .main-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 8px 32px rgba(0,0,0,0.2);
    }
    .vulnerability-card {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        box-shadow: 0 2px 12px rgba(0,0,0,0.1);
        border-left: 5px solid #dc3545;
    }
    .critical-vuln { border-left-color: #dc3545; background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%); }
    .high-vuln { border-left-color: #fd7e14; background: linear-gradient(135deg, #fffaf0 0%, #feebc8 100%); }
    .medium-vuln { border-left-color: #ffc107; background: linear-gradient(135deg, #fffff0 0%, #fefcbf 100%); }
    .low-vuln { border-left-color: #28a745; background: linear-gradient(135deg, #f0fff4 0%, #c6f6d5 100%); }
    .section-header {
        background: linear-gradient(135deg, #0f3460 0%, #533483 100%);
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        margin: 1.5rem 0 1rem 0;
        font-size: 1.2rem;
        font-weight: bold;
        box-shadow: 0 2px 8px rgba(15,52,96,0.3);
    }
    .metric-card {
        background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 5px solid #533483;
        margin: 0.75rem 0;
        box-shadow: 0 2px 12px rgba(0,0,0,0.08);
    }
    .remediation-card {
        background: linear-gradient(135deg, #e8f4fd 0%, #bee5eb 100%);
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 5px solid #17a2b8;
        margin: 1rem 0;
        box-shadow: 0 3px 15px rgba(23,162,184,0.1);
    }
    .cloud-card {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #007bff;
        margin: 1rem 0;
    }
    .aws-accent { border-left-color: #FF9900; }
    .azure-accent { border-left-color: #0078D4; }
    .gcp-accent { border-left-color: #4285F4; }
    .compliance-pass { color: #28a745; font-weight: bold; }
    .compliance-fail { color: #dc3545; font-weight: bold; }
    .agent-message {
        background: #f0f2f6;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
    }
    .tool-call-card {
        background: #e8eaf6;
        padding: 0.75rem;
        border-radius: 8px;
        border-left: 3px solid #3f51b5;
        margin: 0.5rem 0;
        font-size: 0.9rem;
    }
</style>
"""

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#28a745",
    "UNKNOWN": "#6c757d",
}

PROVIDER_COLORS = {
    "aws": "#FF9900",
    "azure": "#0078D4",
    "gcp": "#4285F4",
}


def apply_custom_css():
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
