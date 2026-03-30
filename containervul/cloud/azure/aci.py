"""Azure Container Instances scanning."""

from __future__ import annotations

import logging
from typing import Dict, List

from containervul.cloud.azure.client import AzureClientFactory
from containervul.cloud.base import ContainerServiceScanner
from containervul.models import CloudAccount, CloudProviderType, ContainerImage, ServiceType

logger = logging.getLogger(__name__)


class ACIScanner(ContainerServiceScanner):
    """Discover Azure Container Instances and extract images."""

    def list_clusters(self, account: CloudAccount, region: str) -> List[Dict]:
        """For ACI, 'clusters' are container groups."""
        client = AzureClientFactory.get_container_instance_client(account)
        groups: List[Dict] = []
        try:
            for group in client.container_groups.list():
                if region and group.location != region:
                    continue
                groups.append({
                    "name": group.name,
                    "status": group.provisioning_state,
                    "location": group.location,
                    "os_type": group.os_type,
                    "resource_group": group.id.split("/")[4] if group.id else "",
                    "container_count": len(group.containers) if group.containers else 0,
                    "ip_address": group.ip_address.ip if group.ip_address else None,
                    "region": group.location,
                })
        except Exception as exc:
            logger.error("Error listing ACI container groups: %s", exc)
        return groups

    def list_running_images(self, account: CloudAccount, region: str, cluster_name: str) -> List[ContainerImage]:
        """Extract images from an ACI container group."""
        client = AzureClientFactory.get_container_instance_client(account)
        images: List[ContainerImage] = []
        try:
            # Find the container group across resource groups
            for group in client.container_groups.list():
                if group.name != cluster_name:
                    continue
                for container in group.containers or []:
                    uri = container.image
                    images.append(ContainerImage(
                        image_uri=uri,
                        tag=uri.rsplit(":", 1)[1] if ":" in uri else "latest",
                        registry=uri.split("/")[0] if "/" in uri else None,
                        repository=uri.rsplit(":", 1)[0],
                        cloud_provider=CloudProviderType.AZURE,
                        service_type=ServiceType.ACI,
                        cluster_name=cluster_name,
                        service_name=container.name,
                        account_id=account.account_id,
                        region=region,
                    ))
                break
        except Exception as exc:
            logger.error("Error listing ACI images for %s: %s", cluster_name, exc)
        return images
