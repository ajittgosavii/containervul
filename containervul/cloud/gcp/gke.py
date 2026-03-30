"""GCP GKE cluster discovery and workload scanning."""

from __future__ import annotations

import logging
from typing import Dict, List

from containervul.cloud.gcp.client import GCPClientFactory
from containervul.cloud.base import ContainerServiceScanner
from containervul.models import CloudAccount, CloudProviderType, ContainerImage, ServiceType

logger = logging.getLogger(__name__)


class GKEScanner(ContainerServiceScanner):
    """Discover GKE clusters and extract running container images."""

    def list_clusters(self, account: CloudAccount, region: str) -> List[Dict]:
        client = GCPClientFactory.get_container_client(account)
        clusters: List[Dict] = []
        try:
            parent = f"projects/{account.account_id}/locations/{region or '-'}"
            response = client.list_clusters(parent=parent)
            for c in response.clusters:
                clusters.append({
                    "name": c.name,
                    "status": c.status.name if hasattr(c.status, "name") else str(c.status),
                    "location": c.location,
                    "current_master_version": c.current_master_version,
                    "current_node_version": c.current_node_version,
                    "node_count": sum(pool.initial_node_count for pool in c.node_pools),
                    "region": c.location,
                })
        except Exception as exc:
            logger.error("Error listing GKE clusters: %s", exc)
        return clusters

    def list_running_images(self, account: CloudAccount, region: str, cluster_name: str) -> List[ContainerImage]:
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
                    images.append(self._parse_image(uri, account, region, cluster_name))
        except ImportError:
            logger.info("kubernetes SDK not installed — cannot list GKE pod images")
        except Exception as exc:
            logger.error("Error listing GKE images for %s: %s", cluster_name, exc)
        return images

    def _get_k8s_client(self, account: CloudAccount, region: str, cluster_name: str):
        try:
            from kubernetes import client as k8s
            import google.auth
            import google.auth.transport.requests

            container_client = GCPClientFactory.get_container_client(account)
            name = f"projects/{account.account_id}/locations/{region}/clusters/{cluster_name}"
            cluster = container_client.get_cluster(name=name)

            cred = GCPClientFactory.get_credentials(account)
            auth_req = google.auth.transport.requests.Request()
            cred.refresh(auth_req)

            config = k8s.Configuration()
            config.host = f"https://{cluster.endpoint}"
            config.api_key = {"BearerToken": cred.token}
            # Note: In production, you'd also set up CA cert verification
            config.verify_ssl = False  # Simplified for discovery

            return k8s.ApiClient(config)
        except Exception as exc:
            logger.warning("Could not build K8s client for GKE %s: %s", cluster_name, exc)
            return None

    @staticmethod
    def _parse_image(uri: str, account: CloudAccount, region: str, cluster_name: str) -> ContainerImage:
        parts = uri.rsplit(":", 1)
        tag = parts[1] if len(parts) > 1 else "latest"
        registry = parts[0].split("/")[0] if "/" in parts[0] else None
        return ContainerImage(
            image_uri=uri,
            tag=tag,
            registry=registry,
            repository=parts[0],
            cloud_provider=CloudProviderType.GCP,
            service_type=ServiceType.GKE,
            cluster_name=cluster_name,
            account_id=account.account_id,
            region=region,
        )
