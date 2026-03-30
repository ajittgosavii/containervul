"""Vulnerability-to-ServiceNow ticket mapping — incidents, change requests, bidirectional sync."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from containervul.config import settings
from containervul.integrations.servicenow.client import ServiceNowClient
from containervul.models import Severity, Vulnerability, VulnStatus

logger = logging.getLogger(__name__)

# Severity → ServiceNow priority/impact mapping
SEVERITY_TO_PRIORITY = {
    Severity.CRITICAL: "1",  # P1 - Critical
    Severity.HIGH: "2",      # P2 - High
    Severity.MEDIUM: "3",    # P3 - Moderate
    Severity.LOW: "4",       # P4 - Low
    Severity.UNKNOWN: "4",
}

SEVERITY_TO_IMPACT = {
    Severity.CRITICAL: "1",  # High
    Severity.HIGH: "2",      # Medium
    Severity.MEDIUM: "2",    # Medium
    Severity.LOW: "3",       # Low
    Severity.UNKNOWN: "3",
}

# ServiceNow incident state → local status mapping
SNOW_STATE_TO_LOCAL = {
    "1": VulnStatus.OPEN,          # New
    "2": VulnStatus.IN_PROGRESS,   # In Progress
    "3": VulnStatus.IN_PROGRESS,   # On Hold
    "6": VulnStatus.RESOLVED,      # Resolved
    "7": VulnStatus.RESOLVED,      # Closed
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN]


class VulnerabilityTicketManager:
    """Create and manage ServiceNow incidents for container vulnerabilities."""

    def __init__(self, client: Optional[ServiceNowClient] = None):
        self.client = client or ServiceNowClient()
        self._ticket_cache: Dict[str, Dict] = {}  # vuln_id → ticket info

    # ── Incident Creation ────────────────────────────────────────────────

    def create_incident(
        self,
        vulnerability: Vulnerability,
        container_image: str = "",
        cluster_name: str = "",
        cloud_provider: str = "",
        additional_notes: str = "",
    ) -> Dict[str, Any]:
        """Create a ServiceNow incident from a vulnerability finding."""

        # Build short description
        vuln_id = vulnerability.id or "UNKNOWN"
        severity = vulnerability.severity.value
        short_desc = f"[Container Vuln] {vuln_id} - {severity}"
        if container_image:
            short_desc += f" in {container_image}"
        if cluster_name:
            short_desc += f" ({cluster_name})"

        # Build detailed description
        desc_parts = [
            f"Container Vulnerability: {vuln_id}",
            f"Severity: {severity}",
            f"CVSS Score: {vulnerability.cvss_score}",
            f"Category: {vulnerability.category}",
            f"Description: {vulnerability.description}",
        ]
        if container_image:
            desc_parts.append(f"Container Image: {container_image}")
        if cluster_name:
            desc_parts.append(f"Cluster: {cluster_name}")
        if cloud_provider:
            desc_parts.append(f"Cloud Provider: {cloud_provider.upper()}")
        if vulnerability.remediation:
            desc_parts.append(f"\nRemediation:\n{vulnerability.remediation}")
        if vulnerability.cwe_ids:
            desc_parts.append(f"CWE IDs: {', '.join(vulnerability.cwe_ids)}")
        if vulnerability.references:
            desc_parts.append(f"References:\n" + "\n".join(vulnerability.references[:5]))
        if additional_notes:
            desc_parts.append(f"\nAdditional Notes:\n{additional_notes}")

        desc_parts.append(f"\n--- Created by ContainerVul Platform at {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} ---")

        incident_data = {
            "short_description": short_desc[:160],
            "description": "\n".join(desc_parts),
            "category": "Security",
            "subcategory": "Vulnerability",
            "priority": SEVERITY_TO_PRIORITY.get(vulnerability.severity, "3"),
            "impact": SEVERITY_TO_IMPACT.get(vulnerability.severity, "2"),
            "urgency": SEVERITY_TO_PRIORITY.get(vulnerability.severity, "3"),
            "assignment_group": settings.servicenow_default_assignment_group,
            "caller_id": settings.servicenow_username,
            "contact_type": "Self-service",
            "u_vulnerability_id": vuln_id,
            "u_container_image": container_image,
            "u_cloud_provider": cloud_provider,
            "u_cvss_score": str(vulnerability.cvss_score),
        }

        result = self.client.create_record("incident", incident_data)

        ticket_info = {
            "sys_id": result.get("sys_id", ""),
            "number": result.get("number", ""),
            "state": result.get("state", "1"),
            "priority": result.get("priority", ""),
            "vulnerability_id": vuln_id,
            "container_image": container_image,
            "cloud_provider": cloud_provider,
            "cluster_name": cluster_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._ticket_cache[vuln_id] = ticket_info

        logger.info("Created incident %s for vulnerability %s", ticket_info["number"], vuln_id)
        return ticket_info

    def bulk_create_incidents(
        self,
        vulnerabilities: List[Vulnerability],
        severity_threshold: str = "HIGH",
    ) -> Dict[str, Any]:
        """Create incidents for multiple vulnerabilities, filtering by severity and deduplicating."""
        threshold_idx = next(
            (i for i, s in enumerate(SEVERITY_ORDER) if s.value == severity_threshold),
            1,
        )
        eligible_severities = {s for s in SEVERITY_ORDER[:threshold_idx + 1]}

        results = {"created": 0, "skipped_existing": 0, "skipped_below_threshold": 0, "errors": [], "tickets": []}

        for vuln in vulnerabilities:
            if vuln.severity not in eligible_severities:
                results["skipped_below_threshold"] += 1
                continue

            # Check for existing ticket
            if vuln.id in self._ticket_cache:
                results["skipped_existing"] += 1
                continue

            existing = self.find_ticket_by_vulnerability(vuln.id)
            if existing:
                self._ticket_cache[vuln.id] = existing
                results["skipped_existing"] += 1
                continue

            try:
                image = vuln.image.image_uri if vuln.image else ""
                cluster = vuln.image.cluster_name if vuln.image else ""
                provider = vuln.image.cloud_provider.value if vuln.image and vuln.image.cloud_provider else ""

                ticket = self.create_incident(vuln, image, cluster, provider)
                results["created"] += 1
                results["tickets"].append(ticket)
            except Exception as exc:
                results["errors"].append({"vulnerability_id": vuln.id, "error": str(exc)})

        return results

    def should_auto_create(self, vulnerability: Vulnerability) -> bool:
        """Check if a vulnerability meets the auto-create threshold."""
        threshold = settings.servicenow_auto_create_threshold
        threshold_idx = next(
            (i for i, s in enumerate(SEVERITY_ORDER) if s.value == threshold),
            1,
        )
        return vulnerability.severity in SEVERITY_ORDER[:threshold_idx + 1]

    # ── Change Requests ──────────────────────────────────────────────────

    def create_change_request(
        self,
        vulnerability: Vulnerability,
        remediation_action: str,
        container_image: str = "",
    ) -> Dict[str, Any]:
        """Create a change request for vulnerability remediation."""
        is_major = vulnerability.severity in (Severity.CRITICAL, Severity.HIGH)

        change_data = {
            "short_description": f"[Container Remediation] {vulnerability.id} - {remediation_action[:80]}",
            "description": (
                f"Remediation for container vulnerability {vulnerability.id}\n"
                f"Severity: {vulnerability.severity.value}\n"
                f"Image: {container_image}\n\n"
                f"Action: {remediation_action}\n\n"
                f"Vulnerability Details:\n{vulnerability.description}"
            ),
            "type": "normal" if is_major else "standard",
            "category": "Security",
            "priority": SEVERITY_TO_PRIORITY.get(vulnerability.severity, "3"),
            "risk": "high" if is_major else "moderate",
            "impact": SEVERITY_TO_IMPACT.get(vulnerability.severity, "2"),
            "assignment_group": settings.servicenow_default_assignment_group,
            "implementation_plan": remediation_action,
            "backout_plan": f"Revert container image to previous version. Rollback {container_image} to prior tag.",
            "test_plan": "Verify container starts successfully. Run health checks. Validate no new vulnerabilities introduced.",
        }

        result = self.client.create_record("change_request", change_data)
        return {
            "sys_id": result.get("sys_id", ""),
            "number": result.get("number", ""),
            "type": change_data["type"],
            "vulnerability_id": vulnerability.id,
        }

    # ── Ticket Updates ───────────────────────────────────────────────────

    def update_incident(self, sys_id: str, updates: Dict) -> Dict:
        return self.client.update_record("incident", sys_id, updates)

    def add_work_notes(self, sys_id: str, notes: str) -> Dict:
        return self.client.update_record("incident", sys_id, {
            "work_notes": f"[ContainerVul Platform] {notes}",
        })

    def resolve_incident(self, sys_id: str, resolution_notes: str) -> Dict:
        return self.client.update_record("incident", sys_id, {
            "state": "6",
            "close_code": "Solved (Permanently)",
            "close_notes": f"[ContainerVul] {resolution_notes}",
        })

    # ── Queries ──────────────────────────────────────────────────────────

    def get_open_vulnerability_incidents(self, priority: str = "", limit: int = 50) -> List[Dict]:
        """Query open vulnerability incidents from ServiceNow."""
        query = "category=Security^subcategory=Vulnerability^stateNOT IN6,7"
        if priority:
            query += f"^priority={priority}"
        query += "^ORDERBYDESCpriority"

        return self.client.query_table(
            "incident", query=query,
            fields=["sys_id", "number", "short_description", "priority", "state",
                     "assignment_group", "assigned_to", "opened_at", "u_vulnerability_id",
                     "u_container_image", "u_cloud_provider"],
            limit=limit,
        )

    def find_ticket_by_vulnerability(self, vulnerability_id: str) -> Optional[Dict]:
        """Find an existing ticket for a vulnerability."""
        results = self.client.query_table(
            "incident",
            query=f"u_vulnerability_id={vulnerability_id}^stateNOT IN7",
            fields=["sys_id", "number", "state", "priority"],
            limit=1,
        )
        return results[0] if results else None

    def search_tickets(
        self,
        cve_id: str = "",
        image_name: str = "",
        priority: str = "",
        limit: int = 20,
    ) -> List[Dict]:
        """Search vulnerability incidents by CVE, image, or priority."""
        query_parts = ["category=Security", "subcategory=Vulnerability"]
        if cve_id:
            query_parts.append(f"short_descriptionLIKE{cve_id}")
        if image_name:
            query_parts.append(f"u_container_imageLIKE{image_name}")
        if priority:
            query_parts.append(f"priority={priority}")

        return self.client.query_table(
            "incident", query="^".join(query_parts),
            fields=["sys_id", "number", "short_description", "priority", "state",
                     "opened_at", "u_vulnerability_id", "u_container_image"],
            limit=limit,
        )

    # ── Bidirectional Sync ───────────────────────────────────────────────

    def pull_ticket_statuses(self, tracked_vulns: List[Vulnerability]) -> Dict[str, Any]:
        """Pull ticket statuses from ServiceNow and update local vulnerability statuses."""
        results = {"updated": 0, "unchanged": 0, "errors": []}

        for vuln in tracked_vulns:
            ticket = self._ticket_cache.get(vuln.id)
            if not ticket:
                continue

            try:
                record = self.client.get_record("incident", ticket["sys_id"])
                snow_state = record.get("state", "1")
                new_local_status = SNOW_STATE_TO_LOCAL.get(snow_state, VulnStatus.OPEN)

                if vuln.status != new_local_status:
                    vuln.status = new_local_status
                    ticket["state"] = snow_state
                    results["updated"] += 1
                    logger.info("Synced %s: ServiceNow state=%s → local=%s", vuln.id, snow_state, new_local_status.value)
                else:
                    results["unchanged"] += 1
            except Exception as exc:
                results["errors"].append({"vulnerability_id": vuln.id, "error": str(exc)})

        return results

    def push_resolution(self, vulnerability: Vulnerability) -> Optional[Dict]:
        """When a vulnerability is resolved locally, resolve the ServiceNow ticket."""
        ticket = self._ticket_cache.get(vulnerability.id)
        if not ticket:
            return None

        if vulnerability.status == VulnStatus.RESOLVED:
            try:
                return self.resolve_incident(
                    ticket["sys_id"],
                    f"Vulnerability {vulnerability.id} resolved. Image patched/updated.",
                )
            except Exception as exc:
                logger.error("Failed to resolve SNOW ticket for %s: %s", vulnerability.id, exc)
        return None
