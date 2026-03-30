"""AWS EKS cluster discovery and workload scanning."""

from __future__ import annotations

import base64
import logging
import tempfile
from typing import Dict, List, Optional

from containervul.cloud.aws.client import AWSClientFactory
from containervul.cloud.base import ContainerServiceScanner
from containervul.models import CloudAccount, CloudProviderType, ContainerImage, ServiceType

logger = logging.getLogger(__name__)


class EKSScanner(ContainerServiceScanner):
    """Discover EKS clusters and extract running container images."""

    def list_clusters(self, account: CloudAccount, region: str) -> List[Dict]:
        client = AWSClientFactory.get_client(account, "eks", region)
        clusters: List[Dict] = []
        paginator = client.get_paginator("list_clusters")
        for page in paginator.paginate():
            for name in page.get("clusters", []):
                try:
                    desc = client.describe_cluster(name=name)["cluster"]
                    clusters.append({
                        "name": name,
                        "status": desc.get("status", "UNKNOWN"),
                        "version": desc.get("version", ""),
                        "endpoint": desc.get("endpoint", ""),
                        "platform_version": desc.get("platformVersion", ""),
                        "region": region,
                    })
                except Exception as exc:
                    logger.warning("Failed to describe EKS cluster %s: %s", name, exc)
        return clusters

    def list_running_images(self, account: CloudAccount, region: str, cluster_name: str) -> List[ContainerImage]:
        """Extract images from EKS pods via the Kubernetes API."""
        images: List[ContainerImage] = []
        try:
            k8s_client = self._get_k8s_client(account, region, cluster_name)
            if not k8s_client:
                return images

            from kubernetes import client as k8s

            v1 = k8s.CoreV1Api(k8s_client)
            pods = v1.list_pod_for_all_namespaces(limit=500)

            seen: set[str] = set()
            for pod in pods.items:
                for container in pod.spec.containers:
                    uri = container.image
                    if uri in seen:
                        continue
                    seen.add(uri)
                    images.append(self._parse_image_uri(uri, account, region, cluster_name))

        except ImportError:
            logger.info("kubernetes SDK not installed — listing images via EKS Fargate/nodegroups instead")
            images = self._list_images_from_nodegroups(account, region, cluster_name)
        except Exception as exc:
            logger.error("Error listing EKS images for %s/%s: %s", region, cluster_name, exc)

        return images

    # ── K8s client setup ─────────────────────────────────────────────────

    def _get_k8s_client(self, account: CloudAccount, region: str, cluster_name: str):
        """Build a K8s API client using EKS auth token."""
        try:
            from kubernetes import client as k8s

            eks = AWSClientFactory.get_client(account, "eks", region)
            cluster_info = eks.describe_cluster(name=cluster_name)["cluster"]
            endpoint = cluster_info["endpoint"]
            ca_data = cluster_info["certificateAuthority"]["data"]

            # Write CA cert to temp file
            ca_path = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
            ca_path.write(base64.b64decode(ca_data))
            ca_path.close()

            # Get token via STS
            token = self._get_eks_token(account, region, cluster_name)

            config = k8s.Configuration()
            config.host = endpoint
            config.ssl_ca_cert = ca_path.name
            config.api_key = {"BearerToken": token}
            return k8s.ApiClient(config)

        except Exception as exc:
            logger.warning("Could not create K8s client for %s: %s", cluster_name, exc)
            return None

    def _get_eks_token(self, account: CloudAccount, region: str, cluster_name: str) -> str:
        """Generate a pre-signed URL token for EKS authentication."""
        session = AWSClientFactory.get_session(account, region)
        sts = session.client("sts", region_name=region)
        url = sts.generate_presigned_url(
            "get_caller_identity",
            Params={},
            ExpiresIn=60,
            HttpMethod="GET",
        )
        # EKS expects base64-encoded token prefixed with 'k8s-aws-v1.'
        token = "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return token

    def _list_images_from_nodegroups(self, account: CloudAccount, region: str, cluster_name: str) -> List[ContainerImage]:
        """Fallback: list launch template AMIs — limited info."""
        images: List[ContainerImage] = []
        try:
            eks = AWSClientFactory.get_client(account, "eks", region)
            resp = eks.list_nodegroups(clusterName=cluster_name)
            for ng_name in resp.get("nodegroups", []):
                ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)["nodegroup"]
                images.append(ContainerImage(
                    image_uri=f"eks-nodegroup:{ng_name}",
                    tag=ng.get("releaseVersion", "unknown"),
                    cloud_provider=CloudProviderType.AWS,
                    service_type=ServiceType.EKS,
                    cluster_name=cluster_name,
                    account_id=account.account_id,
                    region=region,
                ))
        except Exception as exc:
            logger.warning("Fallback image listing failed for %s: %s", cluster_name, exc)
        return images

    @staticmethod
    def _parse_image_uri(uri: str, account: CloudAccount, region: str, cluster_name: str) -> ContainerImage:
        parts = uri.rsplit(":", 1)
        repo = parts[0]
        tag = parts[1] if len(parts) > 1 else "latest"
        registry = repo.split("/")[0] if "/" in repo else None
        return ContainerImage(
            image_uri=uri,
            tag=tag,
            registry=registry,
            repository=repo,
            cloud_provider=CloudProviderType.AWS,
            service_type=ServiceType.EKS,
            cluster_name=cluster_name,
            account_id=account.account_id,
            region=region,
        )
