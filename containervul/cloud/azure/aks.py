"""Azure AKS cluster discovery and workload scanning."""

from __future__ import annotations

import logging
from typing import Dict, List

from containervul.cloud.azure.client import AzureClientFactory
from containervul.cloud.base import ContainerServiceScanner
from containervul.models import CloudAccount, CloudProviderType, ContainerImage, ServiceType

logger = logging.getLogger(__name__)


class AKSScanner(ContainerServiceScanner):
    """Discover AKS clusters and extract running container images."""

    def list_clusters(self, account: CloudAccount, region: str) -> List[Dict]:
        client = AzureClientFactory.get_container_client(account)
        clusters: List[Dict] = []
        try:
            for cluster in client.managed_clusters.list():
                if region and cluster.location != region:
                    continue
                clusters.append({
                    "name": cluster.name,
                    "status": cluster.provisioning_state,
                    "location": cluster.location,
                    "kubernetes_version": cluster.kubernetes_version,
                    "resource_group": cluster.id.split("/")[4] if cluster.id else "",
                    "node_count": sum(
                        pool.count or 0
                        for pool in (cluster.agent_pool_profiles or [])
                    ),
                    "region": cluster.location,
                })
        except Exception as exc:
            logger.error("Error listing AKS clusters: %s", exc)
        return clusters

    def list_running_images(self, account: CloudAccount, region: str, cluster_name: str) -> List[ContainerImage]:
        images: List[ContainerImage] = []
        try:
            k8s_client = self._get_k8s_client(account, cluster_name)
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
            logger.info("kubernetes SDK not installed — cannot list AKS pod images")
        except Exception as exc:
            logger.error("Error listing AKS images for %s: %s", cluster_name, exc)
        return images

    def _get_k8s_client(self, account: CloudAccount, cluster_name: str):
        """Build K8s client using AKS credentials."""
        try:
            from kubernetes import client as k8s, config as k8s_config
            import tempfile, yaml

            container_client = AzureClientFactory.get_container_client(account)
            # Find resource group for cluster
            for cluster in container_client.managed_clusters.list():
                if cluster.name == cluster_name:
                    rg = cluster.id.split("/")[4]
                    break
            else:
                return None

            cred_results = container_client.managed_clusters.list_cluster_user_credentials(rg, cluster_name)
            kubeconfig_data = cred_results.kubeconfigs[0].value.decode("utf-8")

            kubeconfig = yaml.safe_load(kubeconfig_data)
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".yaml", mode="w")
            yaml.dump(kubeconfig, tmp)
            tmp.close()

            k8s_config.load_kube_config(config_file=tmp.name)
            return k8s.ApiClient()
        except Exception as exc:
            logger.warning("Could not build K8s client for AKS %s: %s", cluster_name, exc)
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
            cloud_provider=CloudProviderType.AZURE,
            service_type=ServiceType.AKS,
            cluster_name=cluster_name,
            account_id=account.account_id,
            region=region,
        )
