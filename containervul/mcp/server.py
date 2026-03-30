"""MCP server using FastMCP — exposes container vulnerability scanning as tools.

Run standalone:  python -m containervul.mcp.server
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

from containervul.core.cve_integrator import CVEIntegrator
from containervul.core.dockerfile_analyzer import DockerfileAnalyzer
from containervul.core.vulnerability_analyzer import VulnerabilityAnalyzer
from containervul.ai.remediation_engine import AIRemediationEngine
from containervul.cloud.accounts import AccountManager
from containervul.models import Vulnerability

logger = logging.getLogger(__name__)

# Singletons
_cve = CVEIntegrator()
_dockerfile = DockerfileAnalyzer()
_vuln_analyzer = VulnerabilityAnalyzer()
_remediation = AIRemediationEngine()
_accounts = AccountManager()
_tracked_vulns: list[Vulnerability] = []

mcp = FastMCP(
    "containervul",
    description="Enterprise Container Vulnerability Management — scan Dockerfiles, look up CVEs, assess risk, remediate vulnerabilities across EKS/ECS/AKS/ACI/GKE/Cloud Run.",
)


@mcp.tool()
def scan_dockerfile(dockerfile_content: str) -> str:
    """Scan a Dockerfile for security vulnerabilities (outdated images, secrets, misconfigurations)."""
    vulns = _dockerfile.analyze_dockerfile(dockerfile_content)
    _tracked_vulns.extend(vulns)
    risk = _vuln_analyzer.calculate_risk_score(vulns)
    return json.dumps({
        "vulnerabilities_found": len(vulns),
        "risk_level": risk.risk_level,
        "risk_score": risk.total_score,
        "severity_breakdown": risk.severity_breakdown,
        "details": [
            {
                "id": v.id,
                "severity": v.severity.value,
                "category": v.category,
                "line": v.line_number,
                "description": v.description,
                "remediation": v.remediation,
            }
            for v in vulns
        ],
    }, indent=2)


@mcp.tool()
def lookup_cve(cve_id: str) -> str:
    """Look up a specific CVE from the NIST NVD database."""
    result = _cve.get_cve_details(cve_id)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def search_product_vulnerabilities(product_name: str, max_results: int = 20) -> str:
    """Search for known CVEs affecting a software product (e.g., nginx, redis, postgresql)."""
    cves = _cve.search_cves_by_product(product_name, max_results)
    return json.dumps({"product": product_name, "count": len(cves), "cves": cves}, indent=2, default=str)


@mcp.tool()
def calculate_risk(vulnerability_ids: Optional[list[str]] = None) -> str:
    """Calculate risk score for tracked vulnerabilities. Pass empty list for all."""
    target = _tracked_vulns
    if vulnerability_ids:
        target = [v for v in _tracked_vulns if v.id in vulnerability_ids]
    risk = _vuln_analyzer.calculate_risk_score(target)
    return json.dumps(risk.model_dump(), indent=2, default=str)


@mcp.tool()
def generate_remediation(focus_severity: str = "ALL") -> str:
    """Generate a prioritized remediation plan for tracked vulnerabilities."""
    target = _tracked_vulns
    if focus_severity != "ALL":
        target = [v for v in _tracked_vulns if v.severity.value == focus_severity]
    plan = _remediation.generate_remediation_plan(target)
    return json.dumps(plan.model_dump(), indent=2, default=str)


@mcp.tool()
def scan_cloud_containers(provider: str, service_type: str, account_id: str = "", region: str = "") -> str:
    """Discover and scan containers in a cloud service (eks/ecs/aks/aci/gke/cloud_run)."""
    from containervul.ai.tools import ToolExecutor
    executor = ToolExecutor(
        cve_integrator=_cve,
        dockerfile_analyzer=_dockerfile,
        vuln_analyzer=_vuln_analyzer,
        account_manager=_accounts,
        vulnerability_store=_tracked_vulns,
    )
    result = executor.execute("scan_cloud_service", {
        "provider": provider,
        "service_type": service_type,
        "account_id": account_id,
        "region": region,
    })
    return result


@mcp.tool()
def check_compliance(framework: str) -> str:
    """Check vulnerabilities against a compliance framework (cis_docker, cis_kubernetes, nist_800_190)."""
    from containervul.enterprise.compliance.base import get_framework
    fw = get_framework(framework)
    report = fw.evaluate(_tracked_vulns)
    return json.dumps(report.model_dump(), indent=2, default=str)


@mcp.tool()
def list_tracked_vulnerabilities(severity_filter: str = "ALL") -> str:
    """List all tracked vulnerabilities, optionally filtered by severity."""
    target = _tracked_vulns
    if severity_filter != "ALL":
        target = [v for v in _tracked_vulns if v.severity.value == severity_filter]
    return json.dumps({
        "count": len(target),
        "vulnerabilities": [
            {"id": v.id, "severity": v.severity.value, "category": v.category, "status": v.status.value, "description": v.description[:100]}
            for v in target
        ],
    }, indent=2)


# ── ServiceNow MCP Tools ─────────────────────────────────────────────────────

@mcp.tool()
def servicenow_test_connection() -> str:
    """Test the ServiceNow connection and return instance info."""
    from containervul.integrations.servicenow.client import ServiceNowClient
    client = ServiceNowClient()
    return json.dumps(client.test_connection(), indent=2)


@mcp.tool()
def servicenow_create_incident(vulnerability_id: str, additional_notes: str = "") -> str:
    """Create a ServiceNow incident for a tracked container vulnerability."""
    vuln = next((v for v in _tracked_vulns if v.id == vulnerability_id), None)
    if not vuln:
        return json.dumps({"error": f"Vulnerability {vulnerability_id} not found"})
    from containervul.integrations.servicenow.tickets import VulnerabilityTicketManager
    mgr = VulnerabilityTicketManager()
    image = vuln.image.image_uri if vuln.image else ""
    cluster = vuln.image.cluster_name if vuln.image else ""
    provider = vuln.image.cloud_provider.value if vuln.image and vuln.image.cloud_provider else ""
    ticket = mgr.create_incident(vuln, image, cluster, provider, additional_notes)
    return json.dumps(ticket, indent=2, default=str)


@mcp.tool()
def servicenow_bulk_create_incidents(severity_threshold: str = "HIGH") -> str:
    """Create ServiceNow incidents for all tracked vulnerabilities above severity threshold."""
    from containervul.integrations.servicenow.tickets import VulnerabilityTicketManager
    mgr = VulnerabilityTicketManager()
    result = mgr.bulk_create_incidents(_tracked_vulns, severity_threshold)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def servicenow_search_tickets(cve_id: str = "", image_name: str = "", priority: str = "", limit: int = 20) -> str:
    """Search ServiceNow for existing vulnerability incidents."""
    from containervul.integrations.servicenow.tickets import VulnerabilityTicketManager
    mgr = VulnerabilityTicketManager()
    tickets = mgr.search_tickets(cve_id, image_name, priority, limit)
    return json.dumps({"count": len(tickets), "tickets": tickets}, indent=2, default=str)


@mcp.tool()
def servicenow_sync_cmdb(asset_type: str, name: str, tag: str = "latest", cloud_provider: str = "") -> str:
    """Sync a container image, cluster, or service to ServiceNow CMDB as a Configuration Item."""
    from containervul.integrations.servicenow.cmdb import ContainerCMDBSync
    cmdb = ContainerCMDBSync()
    if asset_type == "image":
        result = cmdb.sync_container_image(name, tag, cloud_provider=cloud_provider)
    elif asset_type == "cluster":
        result = cmdb.sync_cluster(name, cloud_provider)
    elif asset_type == "service":
        result = cmdb.sync_service(name, cloud_provider)
    else:
        result = {"error": f"Unknown asset_type: {asset_type}. Use image, cluster, or service."}
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def servicenow_create_change_request(vulnerability_id: str, remediation_action: str, container_image: str = "") -> str:
    """Create a ServiceNow change request for vulnerability remediation requiring a change window."""
    vuln = next((v for v in _tracked_vulns if v.id == vulnerability_id), None)
    if not vuln:
        return json.dumps({"error": f"Vulnerability {vulnerability_id} not found"})
    from containervul.integrations.servicenow.tickets import VulnerabilityTicketManager
    mgr = VulnerabilityTicketManager()
    result = mgr.create_change_request(vuln, remediation_action, container_image)
    return json.dumps(result, indent=2, default=str)


@mcp.resource("containervul://status")
def get_platform_status() -> str:
    """Get current platform status — tracked vulnerabilities and configured accounts."""
    return json.dumps({
        "tracked_vulnerabilities": len(_tracked_vulns),
        "configured_accounts": len(_accounts.list_all()),
        "severity_breakdown": {
            s: len([v for v in _tracked_vulns if v.severity.value == s])
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        },
    }, indent=2)


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
