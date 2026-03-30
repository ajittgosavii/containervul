"""GCP Artifact Registry / Container Analysis integration."""

from __future__ import annotations

import logging
from typing import List

from containervul.cloud.gcp.client import GCPClientFactory
from containervul.cloud.base import RegistryClient
from containervul.core.image_scanner import ImageScanner
from containervul.models import (
    CloudAccount, CloudProviderType, ContainerImage, ServiceType, Vulnerability,
)

logger = logging.getLogger(__name__)


class ArtifactRegistryClient(RegistryClient):
    """Interact with GCP Artifact Registry and Container Analysis."""

    def list_repositories(self, account: CloudAccount, region: str) -> List[str]:
        client = GCPClientFactory.get_artifact_registry_client(account)
        repos: List[str] = []
        try:
            parent = f"projects/{account.account_id}/locations/{region}"
            for repo in client.list_repositories(parent=parent):
                if repo.format_.name == "DOCKER":
                    repos.append(repo.name)
        except Exception as exc:
            logger.error("Error listing Artifact Registry repos: %s", exc)
        return repos

    def list_images(self, account: CloudAccount, region: str, repository: str) -> List[ContainerImage]:
        client = GCPClientFactory.get_artifact_registry_client(account)
        images: List[ContainerImage] = []
        try:
            for img in client.list_docker_images(parent=repository):
                uri = img.uri
                tags = img.tags or ["untagged"]
                for tag in tags:
                    images.append(ContainerImage(
                        image_uri=f"{uri}:{tag}",
                        tag=tag,
                        digest=uri.split("@")[-1] if "@" in uri else "",
                        registry=f"{region}-docker.pkg.dev",
                        repository=repository,
                        cloud_provider=CloudProviderType.GCP,
                        service_type=ServiceType.ARTIFACT_REGISTRY,
                        account_id=account.account_id,
                        region=region,
                    ))
        except Exception as exc:
            logger.error("Error listing Artifact Registry images: %s", exc)
        return images

    def get_scan_findings(self, account: CloudAccount, region: str, image: ContainerImage) -> List[Vulnerability]:
        """Query Container Analysis API for vulnerability occurrences."""
        try:
            from google.cloud import containeranalysis_v1

            cred = GCPClientFactory.get_credentials(account)
            ca_client = containeranalysis_v1.ContainerAnalysisClient(credentials=cred)
            grafeas_client = ca_client.get_grafeas_client()

            project_name = f"projects/{account.account_id}"
            filter_str = f'resourceUrl="{image.image_uri}" AND kind="VULNERABILITY"'

            occurrences = []
            for occ in grafeas_client.list_occurrences(parent=project_name, filter=filter_str):
                occurrences.append({
                    "name": occ.name,
                    "vulnerability": {
                        "effectiveSeverity": occ.vulnerability.effective_severity.name if occ.vulnerability else "UNKNOWN",
                        "shortDescription": occ.vulnerability.short_description if occ.vulnerability else "",
                        "longDescription": occ.vulnerability.long_description if occ.vulnerability else "",
                        "cvssScore": occ.vulnerability.cvss_score if occ.vulnerability else 0.0,
                    },
                })
            return ImageScanner.parse_gar_findings(occurrences, image)

        except ImportError:
            logger.info("google-cloud-containeranalysis SDK not installed")
            return []
        except Exception as exc:
            logger.error("Error fetching Container Analysis findings: %s", exc)
            return []
