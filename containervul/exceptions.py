"""Custom exception hierarchy for ContainerVul."""


class ContainerVulError(Exception):
    """Base exception for all ContainerVul errors."""


class CloudProviderError(ContainerVulError):
    """Error communicating with a cloud provider."""

    def __init__(self, provider: str, message: str):
        self.provider = provider
        super().__init__(f"[{provider}] {message}")


class AuthenticationError(CloudProviderError):
    """Failed to authenticate with a cloud provider."""


class ScanError(ContainerVulError):
    """Error during vulnerability scanning."""


class AgentError(ContainerVulError):
    """Error in the AI agent loop."""


class MCPServerError(ContainerVulError):
    """Error in the MCP server."""
