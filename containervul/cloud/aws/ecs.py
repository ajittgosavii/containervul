"""AWS ECS service/task discovery and container image extraction."""

from __future__ import annotations

import logging
from typing import Dict, List

from containervul.cloud.aws.client import AWSClientFactory
from containervul.cloud.base import ContainerServiceScanner
from containervul.models import CloudAccount, CloudProviderType, ContainerImage, ServiceType

logger = logging.getLogger(__name__)


class ECSScanner(ContainerServiceScanner):
    """Discover ECS clusters, services, and running container images."""

    def list_clusters(self, account: CloudAccount, region: str) -> List[Dict]:
        client = AWSClientFactory.get_client(account, "ecs", region)
        cluster_arns = []
        paginator = client.get_paginator("list_clusters")
        for page in paginator.paginate():
            cluster_arns.extend(page.get("clusterArns", []))

        if not cluster_arns:
            return []

        clusters: List[Dict] = []
        described = client.describe_clusters(clusters=cluster_arns, include=["STATISTICS"])
        for c in described.get("clusters", []):
            clusters.append({
                "name": c["clusterName"],
                "arn": c["clusterArn"],
                "status": c.get("status", "UNKNOWN"),
                "running_tasks": c.get("runningTasksCount", 0),
                "active_services": c.get("activeServicesCount", 0),
                "region": region,
                "capacity_providers": c.get("capacityProviders", []),
            })
        return clusters

    def list_running_images(self, account: CloudAccount, region: str, cluster_name: str) -> List[ContainerImage]:
        client = AWSClientFactory.get_client(account, "ecs", region)
        images: List[ContainerImage] = []
        seen: set[str] = set()

        try:
            # List all running tasks in the cluster
            task_arns: List[str] = []
            paginator = client.get_paginator("list_tasks")
            for page in paginator.paginate(cluster=cluster_name, desiredStatus="RUNNING"):
                task_arns.extend(page.get("taskArns", []))

            if not task_arns:
                return images

            # Describe tasks in batches of 100
            for i in range(0, len(task_arns), 100):
                batch = task_arns[i : i + 100]
                described = client.describe_tasks(cluster=cluster_name, tasks=batch)

                for task in described.get("tasks", []):
                    task_def_arn = task.get("taskDefinitionArn", "")
                    if task_def_arn in seen:
                        continue
                    seen.add(task_def_arn)

                    # Get container definitions from the task definition
                    td = client.describe_task_definition(taskDefinition=task_def_arn)
                    td_data = td.get("taskDefinition", {})

                    for container_def in td_data.get("containerDefinitions", []):
                        uri = container_def.get("image", "")
                        if uri and uri not in seen:
                            seen.add(uri)
                            images.append(self._parse_ecs_image(
                                uri, account, region, cluster_name,
                                service_name=container_def.get("name", ""),
                                launch_type=task.get("launchType", "EC2"),
                            ))

        except Exception as exc:
            logger.error("Error listing ECS images for %s/%s: %s", region, cluster_name, exc)

        return images

    def list_services(self, account: CloudAccount, region: str, cluster_name: str) -> List[Dict]:
        """List ECS services within a cluster."""
        client = AWSClientFactory.get_client(account, "ecs", region)
        service_arns: List[str] = []
        paginator = client.get_paginator("list_services")
        for page in paginator.paginate(cluster=cluster_name):
            service_arns.extend(page.get("serviceArns", []))

        if not service_arns:
            return []

        services: List[Dict] = []
        for i in range(0, len(service_arns), 10):
            batch = service_arns[i : i + 10]
            described = client.describe_services(cluster=cluster_name, services=batch)
            for svc in described.get("services", []):
                services.append({
                    "name": svc["serviceName"],
                    "status": svc.get("status", ""),
                    "desired_count": svc.get("desiredCount", 0),
                    "running_count": svc.get("runningCount", 0),
                    "launch_type": svc.get("launchType", "EC2"),
                    "task_definition": svc.get("taskDefinition", ""),
                })
        return services

    @staticmethod
    def _parse_ecs_image(
        uri: str, account: CloudAccount, region: str,
        cluster_name: str, service_name: str = "", launch_type: str = "EC2",
    ) -> ContainerImage:
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
            service_type=ServiceType.ECS,
            cluster_name=cluster_name,
            service_name=service_name,
            account_id=account.account_id,
            region=region,
        )
