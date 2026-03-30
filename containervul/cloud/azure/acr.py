"""Azure Container Registry integration."""

from __future__ import annotations

import logging
from typing import List

from containervul.cloud.azure.client import AzureClientFactory
from containervul.cloud.base import RegistryClient
from containervul.core.image_scanner import ImageScanner
from containervul.models import (
    CloudAccount, CloudProviderType, ContainerImage, ServiceType, Vulnerability,
)

logger = logging.getLogger(__name__)


class ACRClient(RegistryClient):
    """Interact with Azure Container Registry."""

    def __init__(self, registry_url: str = ""):
        self._registry_url = registry_url

    def list_repositories(self, account: CloudAccount, region: str) -> List[str]:
        client = AzureClientFactory.get_acr_client(account, self._registry_url)
        repos: List[str] = []
        try:
            for repo in client.list_repository_names():
                repos.append(repo)
        except Exception as exc:
            logger.error("Error listing ACR repositories: %s", exc)
        return repos

    def list_images(self, account: CloudAccount, region: str, repository: str) -> List[ContainerImage]:
        client = AzureClientFactory.get_acr_client(account, self._registry_url)
        images: List[ContainerImage] = []
        try:
            for manifest in client.list_tag_properties(repository):
                tag = manifest.name
                uri = f"{self._registry_url}/{repository}:{tag}"
                images.append(ContainerImage(
                    image_uri=uri,
                    tag=tag,
                    digest=manifest.digest if hasattr(manifest, "digest") else "",
                    registry=self._registry_url,
                    repository=repository,
                    cloud_provider=CloudProviderType.AZURE,
                    service_type=ServiceType.ACR,
                    account_id=account.account_id,
                    region=region,
                ))
        except Exception as exc:
            logger.error("Error listing ACR images for %s: %s", repository, exc)
        return images

    def get_scan_findings(self, account: CloudAccount, region: str, image: ContainerImage) -> List[Vulnerability]:
        """ACR scan findings via Microsoft Defender for Containers / Qualys."""
        # Native ACR scanning is accessed via Azure Security Center / Defender APIs
        # For now, return empty and rely on Trivy or external scanning
        logger.info("ACR native scan findings retrieval — use Defender for Containers API or Trivy")
        return []
