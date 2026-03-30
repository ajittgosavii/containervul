"""AWS ECR registry integration — list images and retrieve scan findings."""

from __future__ import annotations

import logging
from typing import List

from containervul.cloud.aws.client import AWSClientFactory
from containervul.cloud.base import RegistryClient
from containervul.core.image_scanner import ImageScanner
from containervul.models import (
    CloudAccount, CloudProviderType, ContainerImage, ServiceType, Vulnerability,
)

logger = logging.getLogger(__name__)


class ECRClient(RegistryClient):
    """Interact with Amazon Elastic Container Registry."""

    def list_repositories(self, account: CloudAccount, region: str) -> List[str]:
        client = AWSClientFactory.get_client(account, "ecr", region)
        repos: List[str] = []
        paginator = client.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                repos.append(repo["repositoryName"])
        return repos

    def list_images(self, account: CloudAccount, region: str, repository: str) -> List[ContainerImage]:
        client = AWSClientFactory.get_client(account, "ecr", region)
        images: List[ContainerImage] = []
        paginator = client.get_paginator("list_images")
        for page in paginator.paginate(repositoryName=repository):
            for img_id in page.get("imageIds", []):
                tag = img_id.get("imageTag", "untagged")
                digest = img_id.get("imageDigest", "")
                registry_id = account.account_id
                uri = f"{registry_id}.dkr.ecr.{region}.amazonaws.com/{repository}:{tag}"
                images.append(ContainerImage(
                    image_uri=uri,
                    tag=tag,
                    digest=digest,
                    registry=f"{registry_id}.dkr.ecr.{region}.amazonaws.com",
                    repository=repository,
                    cloud_provider=CloudProviderType.AWS,
                    service_type=ServiceType.ECR,
                    account_id=account.account_id,
                    region=region,
                ))
        return images

    def get_scan_findings(self, account: CloudAccount, region: str, image: ContainerImage) -> List[Vulnerability]:
        client = AWSClientFactory.get_client(account, "ecr", region)
        findings: List[dict] = []

        try:
            image_id = {"imageTag": image.tag} if image.tag != "untagged" else {"imageDigest": image.digest}
            paginator = client.get_paginator("describe_image_scan_findings")
            for page in paginator.paginate(
                repositoryName=image.repository or "",
                imageId=image_id,
            ):
                findings.extend(page.get("imageScanFindings", {}).get("findings", []))
        except client.exceptions.ScanNotFoundException:
            logger.info("No ECR scan results for %s — triggering scan", image.image_uri)
            self._start_scan(client, image)
        except Exception as exc:
            logger.error("Error fetching ECR scan findings for %s: %s", image.image_uri, exc)

        return ImageScanner.parse_ecr_findings(findings, image)

    @staticmethod
    def _start_scan(client, image: ContainerImage) -> None:
        try:
            image_id = {"imageTag": image.tag} if image.tag != "untagged" else {"imageDigest": image.digest}
            client.start_image_scan(
                repositoryName=image.repository or "",
                imageId=image_id,
            )
            logger.info("Started ECR scan for %s", image.image_uri)
        except Exception as exc:
            logger.warning("Could not start ECR scan: %s", exc)
