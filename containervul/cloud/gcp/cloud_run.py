"""GCP Cloud Run service scanning."""

from __future__ import annotations

import logging
from typing import Dict, List

from containervul.cloud.gcp.client import GCPClientFactory
from containervul.cloud.base import ContainerServiceScanner
from containervul.models import CloudAccount, CloudProviderType, ContainerImage, ServiceType

logger = logging.getLogger(__name__)


class CloudRunScanner(ContainerServiceScanner):
    """Discover Cloud Run services and extract container images."""

    def list_clusters(self, account: CloudAccount, region: str) -> List[Dict]:
        """For Cloud Run, 'clusters' are services."""
        client = GCPClientFactory.get_run_client(account)
        services: List[Dict] = []
        try:
            parent = f"projects/{account.account_id}/locations/{region or '-'}"
            for svc in client.list_services(parent=parent):
                services.append({
                    "name": svc.name.split("/")[-1],
                    "full_name": svc.name,
                    "status": "READY" if svc.terminal_condition and svc.terminal_condition.state else "UNKNOWN",
                    "uri": svc.uri,
                    "region": svc.name.split("/")[3] if len(svc.name.split("/")) > 3 else region,
                    "last_modifier": svc.last_modifier if hasattr(svc, "last_modifier") else "",
                })
        except Exception as exc:
            logger.error("Error listing Cloud Run services: %s", exc)
        return services

    def list_running_images(self, account: CloudAccount, region: str, cluster_name: str) -> List[ContainerImage]:
        client = GCPClientFactory.get_run_client(account)
        images: List[ContainerImage] = []
        try:
            # cluster_name is the service name for Cloud Run
            svc_name = f"projects/{account.account_id}/locations/{region}/services/{cluster_name}"
            svc = client.get_service(name=svc_name)

            for container in svc.template.containers:
                uri = container.image
                parts = uri.rsplit(":", 1)
                tag = parts[1] if len(parts) > 1 else "latest"
                images.append(ContainerImage(
                    image_uri=uri,
                    tag=tag,
                    registry=parts[0].split("/")[0] if "/" in parts[0] else None,
                    repository=parts[0],
                    cloud_provider=CloudProviderType.GCP,
                    service_type=ServiceType.CLOUD_RUN,
                    cluster_name=cluster_name,
                    service_name=cluster_name,
                    account_id=account.account_id,
                    region=region,
                ))
        except Exception as exc:
            logger.error("Error listing Cloud Run images for %s: %s", cluster_name, exc)
        return images
