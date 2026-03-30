"""Claude tool definitions and executor for the vulnerability agent."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional

from containervul.core.cve_integrator import CVEIntegrator
from containervul.core.dockerfile_analyzer import DockerfileAnalyzer
from containervul.core.vulnerability_analyzer import VulnerabilityAnalyzer
from containervul.cloud.accounts import AccountManager
from containervul.models import CloudProviderType, Vulnerability

logger = logging.getLogger(__name__)

# ── Tool Schemas (Claude tool_use format) ────────────────────────────────────

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "scan_dockerfile",
        "description": "Scan a Dockerfile for security vulnerabilities including outdated base images, exposed secrets, insecure configurations, and missing health checks.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dockerfile_content": {
                    "type": "string",
                    "description": "The full Dockerfile content to scan",
                }
            },
            "required": ["dockerfile_content"],
        },
    },
    {
        "name": "lookup_cve",
        "description": "Look up detailed information about a specific CVE from the NIST NVD database.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier, e.g. CVE-2024-1234",
                }
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "search_product_cves",
        "description": "Search for known CVEs affecting a specific software product (e.g., nginx, redis, postgresql).",
        "input_schema": {
            "type": "object",
            "properties": {
                "product_name": {
                    "type": "string",
                    "description": "Product name to search for",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of CVEs to return (default 20)",
                    "default": 20,
                },
            },
            "required": ["product_name"],
        },
    },
    {
        "name": "calculate_risk_score",
        "description": "Calculate a risk score and severity breakdown for a list of vulnerability IDs from the current session.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vulnerability_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of vulnerability IDs to assess. Use 'all' for all tracked vulnerabilities.",
                }
            },
            "required": ["vulnerability_ids"],
        },
    },
    {
        "name": "generate_remediation_plan",
        "description": "Generate a prioritized remediation plan for current vulnerabilities, including immediate, short-term, and long-term actions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "focus_severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "ALL"],
                    "description": "Focus remediation on this severity level or ALL",
                    "default": "ALL",
                }
            },
            "required": [],
        },
    },
    {
        "name": "scan_cloud_service",
        "description": "Discover and scan containers running in a cloud service (EKS, ECS, AKS, ACI, GKE, Cloud Run). Returns running images and their configurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": ["aws", "azure", "gcp"],
                    "description": "Cloud provider",
                },
                "service_type": {
                    "type": "string",
                    "enum": ["eks", "ecs", "aks", "aci", "gke", "cloud_run"],
                    "description": "Container service type",
                },
                "account_id": {
                    "type": "string",
                    "description": "Account/subscription/project ID (optional, uses first active if omitted)",
                },
                "region": {
                    "type": "string",
                    "description": "Cloud region (optional, scans all regions if omitted)",
                },
            },
            "required": ["provider", "service_type"],
        },
    },
    {
        "name": "check_compliance",
        "description": "Evaluate current vulnerabilities against a compliance framework (CIS Docker Benchmark, CIS Kubernetes, NIST 800-190).",
        "input_schema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "enum": ["cis_docker", "cis_kubernetes", "nist_800_190"],
                    "description": "Compliance framework to check against",
                }
            },
            "required": ["framework"],
        },
    },
    {
        "name": "list_cloud_accounts",
        "description": "List all configured cloud accounts/subscriptions/projects, optionally filtered by provider.",
        "input_schema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": ["aws", "azure", "gcp", "all"],
                    "description": "Filter by provider, or 'all' for everything",
                    "default": "all",
                }
            },
            "required": [],
        },
    },
    # ── ServiceNow Tools ─────────────────────────────────────────────────
    {
        "name": "servicenow_create_incident",
        "description": "Create a ServiceNow incident for a container vulnerability. Maps severity to priority and populates all fields automatically.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vulnerability_id": {"type": "string", "description": "ID of the vulnerability to create a ticket for"},
                "additional_notes": {"type": "string", "description": "Optional notes to add to the incident"},
            },
            "required": ["vulnerability_id"],
        },
    },
    {
        "name": "servicenow_bulk_create_incidents",
        "description": "Create ServiceNow incidents for multiple vulnerabilities at once. Filters by severity threshold and skips duplicates.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity_threshold": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"], "default": "HIGH"},
            },
            "required": [],
        },
    },
    {
        "name": "servicenow_search_tickets",
        "description": "Search ServiceNow for existing vulnerability incidents by CVE ID, container image, or priority.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE ID to search for"},
                "image_name": {"type": "string", "description": "Container image name to search for"},
                "priority": {"type": "string", "enum": ["1", "2", "3", "4"], "description": "ServiceNow priority (1=Critical, 4=Low)"},
                "limit": {"type": "integer", "default": 20},
            },
            "required": [],
        },
    },
    {
        "name": "servicenow_sync_cmdb",
        "description": "Register a container image or Kubernetes cluster as a Configuration Item in ServiceNow CMDB.",
        "input_schema": {
            "type": "object",
            "properties": {
                "asset_type": {"type": "string", "enum": ["image", "cluster", "service"], "description": "Type of asset to sync"},
                "name": {"type": "string", "description": "Image name, cluster name, or service name"},
                "tag": {"type": "string", "description": "Image tag (for images)", "default": "latest"},
                "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "cluster_name": {"type": "string", "description": "Cluster name (for services)"},
            },
            "required": ["asset_type", "name"],
        },
    },
    {
        "name": "servicenow_create_change_request",
        "description": "Create a ServiceNow change request for vulnerability remediation that requires a change window.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vulnerability_id": {"type": "string", "description": "Vulnerability ID"},
                "remediation_action": {"type": "string", "description": "Planned remediation action (e.g., 'Rebuild image with patched base')"},
                "container_image": {"type": "string", "description": "Container image being remediated"},
            },
            "required": ["vulnerability_id", "remediation_action"],
        },
    },
]


class ToolExecutor:
    """Dispatch Claude tool_use calls to the appropriate handler."""

    def __init__(
        self,
        cve_integrator: Optional[CVEIntegrator] = None,
        dockerfile_analyzer: Optional[DockerfileAnalyzer] = None,
        vuln_analyzer: Optional[VulnerabilityAnalyzer] = None,
        account_manager: Optional[AccountManager] = None,
        vulnerability_store: Optional[List[Vulnerability]] = None,
    ):
        self.cve = cve_integrator or CVEIntegrator()
        self.dockerfile = dockerfile_analyzer or DockerfileAnalyzer()
        self.vuln_analyzer = vuln_analyzer or VulnerabilityAnalyzer()
        self.accounts = account_manager or AccountManager()
        self._vulns: List[Vulnerability] = vulnerability_store or []

        self._handlers: Dict[str, Callable] = {
            "scan_dockerfile": self._scan_dockerfile,
            "lookup_cve": self._lookup_cve,
            "search_product_cves": self._search_product_cves,
            "calculate_risk_score": self._calculate_risk_score,
            "generate_remediation_plan": self._generate_remediation_plan,
            "scan_cloud_service": self._scan_cloud_service,
            "check_compliance": self._check_compliance,
            "list_cloud_accounts": self._list_cloud_accounts,
            "servicenow_create_incident": self._snow_create_incident,
            "servicenow_bulk_create_incidents": self._snow_bulk_create,
            "servicenow_search_tickets": self._snow_search_tickets,
            "servicenow_sync_cmdb": self._snow_sync_cmdb,
            "servicenow_create_change_request": self._snow_create_change,
        }

    def execute(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        handler = self._handlers.get(tool_name)
        if not handler:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})
        try:
            result = handler(**tool_input)
            return json.dumps(result, default=str)
        except Exception as exc:
            logger.error("Tool %s error: %s", tool_name, exc)
            return json.dumps({"error": str(exc)})

    # ── Tool Handlers ────────────────────────────────────────────────────

    def _scan_dockerfile(self, dockerfile_content: str) -> Dict:
        vulns = self.dockerfile.analyze_dockerfile(dockerfile_content)
        self._vulns.extend(vulns)
        risk = self.vuln_analyzer.calculate_risk_score(vulns)
        return {
            "vulnerabilities_found": len(vulns),
            "risk_level": risk.risk_level,
            "risk_score": risk.total_score,
            "severity_breakdown": risk.severity_breakdown,
            "details": [
                {
                    "id": v.id,
                    "severity": v.severity.value,
                    "category": v.category,
                    "line_number": v.line_number,
                    "description": v.description,
                    "remediation": v.remediation,
                }
                for v in vulns
            ],
        }

    def _lookup_cve(self, cve_id: str) -> Dict:
        return self.cve.get_cve_details(cve_id)

    def _search_product_cves(self, product_name: str, max_results: int = 20) -> Dict:
        cves = self.cve.search_cves_by_product(product_name, max_results)
        return {"product": product_name, "cve_count": len(cves), "cves": cves[:max_results]}

    def _calculate_risk_score(self, vulnerability_ids: List[str]) -> Dict:
        if vulnerability_ids == ["all"] or not vulnerability_ids:
            target_vulns = self._vulns
        else:
            target_vulns = [v for v in self._vulns if v.id in vulnerability_ids]
        risk = self.vuln_analyzer.calculate_risk_score(target_vulns)
        return risk.model_dump()

    def _generate_remediation_plan(self, focus_severity: str = "ALL") -> Dict:
        target = self._vulns
        if focus_severity != "ALL":
            target = [v for v in self._vulns if v.severity.value == focus_severity]

        from containervul.ai.remediation_engine import AIRemediationEngine
        engine = AIRemediationEngine()
        plan = engine.generate_remediation_plan(target)
        return plan.model_dump()

    def _scan_cloud_service(
        self,
        provider: str,
        service_type: str,
        account_id: str = "",
        region: str = "",
    ) -> Dict:
        provider_enum = CloudProviderType(provider)
        accounts = self.accounts.list_accounts(provider_enum)

        if account_id:
            accounts = [a for a in accounts if a.account_id == account_id]

        if not accounts:
            return {"error": f"No active {provider} accounts configured. Add an account first."}

        account = accounts[0]
        results: List[Dict] = []

        try:
            scanner = self._get_scanner(provider, service_type)
            regions = [region] if region else (account.regions or [self._default_region(provider)])

            for r in regions:
                clusters = scanner.list_clusters(account, r)
                for cluster in clusters:
                    images = scanner.list_running_images(account, r, cluster["name"])
                    results.append({
                        "cluster": cluster["name"],
                        "region": r,
                        "status": cluster.get("status", "UNKNOWN"),
                        "image_count": len(images),
                        "images": [
                            {"uri": img.image_uri, "tag": img.tag, "service": img.service_name or ""}
                            for img in images[:50]
                        ],
                    })

            return {
                "provider": provider,
                "service_type": service_type,
                "account": account.account_id,
                "clusters_found": len(results),
                "results": results,
            }
        except Exception as exc:
            return {"error": f"Cloud scan failed: {exc}"}

    def _check_compliance(self, framework: str) -> Dict:
        from containervul.enterprise.compliance.base import get_framework
        fw = get_framework(framework)
        report = fw.evaluate(self._vulns)
        return report.model_dump()

    def _list_cloud_accounts(self, provider: str = "all") -> Dict:
        if provider == "all":
            accounts = self.accounts.list_all()
        else:
            accounts = self.accounts.list_accounts(CloudProviderType(provider))
        return {
            "accounts": [
                {
                    "id": a.id,
                    "name": a.name,
                    "provider": a.provider.value,
                    "account_id": a.account_id,
                    "regions": a.regions,
                    "active": a.is_active,
                }
                for a in accounts
            ]
        }

    # ── ServiceNow Handlers ─────────────────────────────────────────────

    def _get_snow_ticket_mgr(self):
        from containervul.integrations.servicenow.tickets import VulnerabilityTicketManager
        return VulnerabilityTicketManager()

    def _get_snow_cmdb(self):
        from containervul.integrations.servicenow.cmdb import ContainerCMDBSync
        return ContainerCMDBSync()

    def _snow_create_incident(self, vulnerability_id: str, additional_notes: str = "") -> Dict:
        vuln = next((v for v in self._vulns if v.id == vulnerability_id), None)
        if not vuln:
            return {"error": f"Vulnerability {vulnerability_id} not found in tracked vulnerabilities"}
        mgr = self._get_snow_ticket_mgr()
        image = vuln.image.image_uri if vuln.image else ""
        cluster = vuln.image.cluster_name if vuln.image else ""
        provider = vuln.image.cloud_provider.value if vuln.image and vuln.image.cloud_provider else ""
        ticket = mgr.create_incident(vuln, image, cluster, provider, additional_notes)
        return ticket

    def _snow_bulk_create(self, severity_threshold: str = "HIGH") -> Dict:
        mgr = self._get_snow_ticket_mgr()
        return mgr.bulk_create_incidents(self._vulns, severity_threshold)

    def _snow_search_tickets(self, cve_id: str = "", image_name: str = "", priority: str = "", limit: int = 20) -> Dict:
        mgr = self._get_snow_ticket_mgr()
        tickets = mgr.search_tickets(cve_id, image_name, priority, limit)
        return {"count": len(tickets), "tickets": tickets}

    def _snow_sync_cmdb(self, asset_type: str, name: str, tag: str = "latest", cloud_provider: str = "", cluster_name: str = "") -> Dict:
        cmdb = self._get_snow_cmdb()
        if asset_type == "image":
            return cmdb.sync_container_image(name, tag, cloud_provider=cloud_provider, cluster_name=cluster_name)
        elif asset_type == "cluster":
            return cmdb.sync_cluster(name, cloud_provider)
        elif asset_type == "service":
            return cmdb.sync_service(name, cloud_provider, cluster_name)
        return {"error": f"Unknown asset type: {asset_type}"}

    def _snow_create_change(self, vulnerability_id: str, remediation_action: str, container_image: str = "") -> Dict:
        vuln = next((v for v in self._vulns if v.id == vulnerability_id), None)
        if not vuln:
            return {"error": f"Vulnerability {vulnerability_id} not found"}
        mgr = self._get_snow_ticket_mgr()
        return mgr.create_change_request(vuln, remediation_action, container_image)

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _get_scanner(provider: str, service_type: str):
        if provider == "aws":
            if service_type == "eks":
                from containervul.cloud.aws.eks import EKSScanner
                return EKSScanner()
            if service_type == "ecs":
                from containervul.cloud.aws.ecs import ECSScanner
                return ECSScanner()
        elif provider == "azure":
            if service_type == "aks":
                from containervul.cloud.azure.aks import AKSScanner
                return AKSScanner()
            if service_type == "aci":
                from containervul.cloud.azure.aci import ACIScanner
                return ACIScanner()
        elif provider == "gcp":
            if service_type == "gke":
                from containervul.cloud.gcp.gke import GKEScanner
                return GKEScanner()
            if service_type == "cloud_run":
                from containervul.cloud.gcp.cloud_run import CloudRunScanner
                return CloudRunScanner()
        raise ValueError(f"Unknown service type: {provider}/{service_type}")

    @staticmethod
    def _default_region(provider: str) -> str:
        return {"aws": "us-east-1", "azure": "eastus", "gcp": "us-central1"}.get(provider, "us-east-1")
