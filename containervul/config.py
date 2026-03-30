"""Central configuration using pydantic-settings."""

from __future__ import annotations
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application-wide settings loaded from env vars / .env / Streamlit secrets."""

    # --- CVE / NVD ---
    nist_nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cache_ttl: int = 3600
    max_cve_results: int = 50
    request_timeout: int = 15

    # --- AI ---
    claude_api_key: str = ""
    claude_model: str = "claude-sonnet-4-20250514"
    claude_max_tokens: int = 4096
    claude_temperature: float = 0.3
    agent_max_turns: int = 15

    # --- AWS ---
    aws_default_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None

    # --- Azure ---
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None

    # --- GCP ---
    gcp_project_id: Optional[str] = None
    gcp_credentials_json: Optional[str] = None

    # --- Storage ---
    storage_backend: str = Field("session", description="session | sqlite")
    sqlite_path: str = "containervul.db"

    # --- MCP ---
    mcp_transport: str = Field("stdio", description="stdio | sse")
    mcp_port: int = 8100

    model_config = {"env_prefix": "CONTAINERVUL_", "env_file": ".env", "extra": "ignore"}


settings = Settings()
