"""ServiceNow CMDB integration — register container images, clusters, and services as CIs."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from containervul.integrations.servicenow.client import ServiceNowClient
from containervul.models import ContainerImage, ContainerService

logger = logging.getLogger(__name__)

# CI class mapping — falls back to cmdb_ci_appl if specialized classes don't exist
CI_CLASSES = {
    "container_image": "cmdb_ci_docker_image",
    "container_image_fallback": "cmdb_ci_appl",
    "kubernetes_cluster": "cmdb_ci_kubernetes_cluster",
    "kubernetes_cluster_fallback": "cmdb_ci_cluster",
    "cloud_service": "cmdb_ci_cloud_service_account",
    "cloud_service_fallback": "cmdb_ci_service",
}


class ContainerCMDBSync:
    """Synchronize container assets to ServiceNow CMDB as Configuration Items."""

    def __init__(self, client: Optional[ServiceNowClient] = None):
        self.client = client or ServiceNowClient()
        self._class_cache: Dict[str, bool] = {}

    # ── CI Registration ──────────────────────────────────────────────────

    def sync_container_image(
        self,
        image_name: str,
        tag: str = "latest",
        registry: str = "",
        cloud_provider: str = "",
        cluster_name: str = "",
        vulnerability_count: int = 0,
        critical_count: int = 0,
    ) -> Dict[str, Any]:
        """Create or update a container image CI in CMDB."""
        ci_class = self._resolve_class("container_image")
        ci_name = f"{image_name}:{tag}"

        # Check if CI already exists
        existing = self._find_ci(ci_class, ci_name)

        ci_data = {
            "name": ci_name,
            "short_description": f"Container image from {registry or 'unknown registry'}",
            "version": tag,
            "vendor": registry or cloud_provider,
            "category": "Container",
            "subcategory": "Docker Image",
            "operational_status": "1" if critical_count == 0 else "5",  # 1=Operational, 5=Non-Functional
            "discovery_source": "ContainerVul Platform",
            "comments": (
                f"Cloud Provider: {cloud_provider}\n"
                f"Cluster: {cluster_name}\n"
                f"Vulnerabilities: {vulnerability_count} (Critical: {critical_count})\n"
                f"Last synced: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}"
            ),
        }

        if existing:
            result = self.client.update_record(ci_class, existing["sys_id"], ci_data)
            action = "updated"
        else:
            result = self.client.create_record(ci_class, ci_data)
            action = "created"

        return {
            "sys_id": result.get("sys_id", ""),
            "name": ci_name,
            "ci_class": ci_class,
            "action": action,
        }

    def sync_cluster(
        self,
        cluster_name: str,
        cloud_provider: str,
        region: str = "",
        node_count: int = 0,
        version: str = "",
    ) -> Dict[str, Any]:
        """Create or update a Kubernetes cluster CI."""
        ci_class = self._resolve_class("kubernetes_cluster")

        existing = self._find_ci(ci_class, cluster_name)

        ci_data = {
            "name": cluster_name,
            "short_description": f"{cloud_provider.upper()} Kubernetes cluster in {region}",
            "version": version,
            "category": "Container",
            "subcategory": "Kubernetes Cluster",
            "operational_status": "1",
            "discovery_source": "ContainerVul Platform",
            "comments": (
                f"Provider: {cloud_provider.upper()}\n"
                f"Region: {region}\n"
                f"Nodes: {node_count}\n"
                f"Last synced: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}"
            ),
        }

        if existing:
            result = self.client.update_record(ci_class, existing["sys_id"], ci_data)
            action = "updated"
        else:
            result = self.client.create_record(ci_class, ci_data)
            action = "created"

        return {
            "sys_id": result.get("sys_id", ""),
            "name": cluster_name,
            "ci_class": ci_class,
            "action": action,
        }

    def sync_service(
        self,
        service_name: str,
        cloud_provider: str,
        cluster_name: str = "",
        image_uri: str = "",
    ) -> Dict[str, Any]:
        """Create or update a container service CI and link it to its cluster."""
        ci_class = self._resolve_class("cloud_service")

        existing = self._find_ci(ci_class, service_name)

        ci_data = {
            "name": service_name,
            "short_description": f"Container service on {cloud_provider.upper()}",
            "category": "Container",
            "subcategory": "Container Service",
            "operational_status": "1",
            "discovery_source": "ContainerVul Platform",
            "comments": (
                f"Cluster: {cluster_name}\n"
                f"Image: {image_uri}\n"
                f"Last synced: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}"
            ),
        }

        if existing:
            result = self.client.update_record(ci_class, existing["sys_id"], ci_data)
            action = "updated"
        else:
            result = self.client.create_record(ci_class, ci_data)
            action = "created"

        svc_sys_id = result.get("sys_id", "")

        # Create relationship to cluster if both exist
        if cluster_name and svc_sys_id:
            cluster_ci = self._find_ci(self._resolve_class("kubernetes_cluster"), cluster_name)
            if cluster_ci:
                self._create_relationship(cluster_ci["sys_id"], svc_sys_id, "Runs on::Runs")

        return {"sys_id": svc_sys_id, "name": service_name, "ci_class": ci_class, "action": action}

    # ── Bulk Operations ──────────────────────────────────────────────────

    def bulk_sync_images(self, images: List[ContainerImage], vuln_counts: Optional[Dict[str, int]] = None) -> Dict:
        """Batch sync container images to CMDB."""
        vuln_counts = vuln_counts or {}
        results = {"created": 0, "updated": 0, "errors": []}

        for img in images:
            try:
                r = self.sync_container_image(
                    image_name=img.repository or img.image_uri,
                    tag=img.tag,
                    registry=img.registry or "",
                    cloud_provider=img.cloud_provider.value if img.cloud_provider else "",
                    cluster_name=img.cluster_name or "",
                    vulnerability_count=vuln_counts.get(img.image_uri, 0),
                )
                results[r["action"] + "d"] = results.get(r["action"] + "d", 0) + 1
            except Exception as exc:
                results["errors"].append({"image": img.image_uri, "error": str(exc)})

        return results

    def get_all_container_cis(self, limit: int = 100) -> List[Dict]:
        """List all container-related CIs from CMDB."""
        ci_class = self._resolve_class("container_image")
        return self.client.query_table(
            ci_class,
            query="discovery_source=ContainerVul Platform",
            fields=["sys_id", "name", "version", "operational_status", "comments", "sys_updated_on"],
            limit=limit,
        )

    # ── Private ──────────────────────────────────────────────────────────

    def _find_ci(self, ci_class: str, name: str) -> Optional[Dict]:
        results = self.client.query_table(ci_class, query=f"name={name}", fields=["sys_id", "name"], limit=1)
        return results[0] if results else None

    def _resolve_class(self, category: str) -> str:
        """Check if the preferred CI class exists, fall back if not."""
        preferred = CI_CLASSES.get(category, "cmdb_ci")
        if preferred in self._class_cache:
            return preferred if self._class_cache[preferred] else CI_CLASSES.get(f"{category}_fallback", "cmdb_ci")

        try:
            self.client.query_table(preferred, limit=1)
            self._class_cache[preferred] = True
            return preferred
        except Exception:
            self._class_cache[preferred] = False
            fallback = CI_CLASSES.get(f"{category}_fallback", "cmdb_ci")
            logger.info("CI class %s not available, falling back to %s", preferred, fallback)
            return fallback

    def _create_relationship(self, parent_sys_id: str, child_sys_id: str, rel_type: str) -> None:
        """Create a CMDB relationship between two CIs."""
        try:
            # Find the relationship type sys_id
            rel_types = self.client.query_table(
                "cmdb_rel_type",
                query=f"nameLIKE{rel_type.split('::')[0]}",
                fields=["sys_id"],
                limit=1,
            )
            if not rel_types:
                return

            self.client.create_record("cmdb_rel_ci", {
                "parent": parent_sys_id,
                "child": child_sys_id,
                "type": rel_types[0]["sys_id"],
            })
        except Exception as exc:
            logger.warning("Failed to create CMDB relationship: %s", exc)
