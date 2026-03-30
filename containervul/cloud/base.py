"""Abstract base classes for cloud provider integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from containervul.models import CloudAccount, ContainerImage, ContainerService, Vulnerability


class CloudProvider(ABC):
    """Abstract interface for a cloud provider."""

    @abstractmethod
    def authenticate(self, account: CloudAccount) -> bool:
        """Validate credentials and return True if authenticated."""

    @abstractmethod
    def list_regions(self, account: CloudAccount) -> List[str]:
        """Return available regions for this account."""

    @abstractmethod
    def list_container_services(self, account: CloudAccount, region: Optional[str] = None) -> List[ContainerService]:
        """Discover running container services."""


class ContainerServiceScanner(ABC):
    """Abstract interface for scanning a specific container service."""

    @abstractmethod
    def list_clusters(self, account: CloudAccount, region: str) -> List[Dict]:
        """List clusters / services in a region."""

    @abstractmethod
    def list_running_images(self, account: CloudAccount, region: str, cluster_name: str) -> List[ContainerImage]:
        """Extract container images running in a cluster / service."""


class RegistryClient(ABC):
    """Abstract interface for a container registry."""

    @abstractmethod
    def list_repositories(self, account: CloudAccount, region: str) -> List[str]:
        """List repositories in the registry."""

    @abstractmethod
    def list_images(self, account: CloudAccount, region: str, repository: str) -> List[ContainerImage]:
        """List images in a repository."""

    @abstractmethod
    def get_scan_findings(self, account: CloudAccount, region: str, image: ContainerImage) -> List[Vulnerability]:
        """Retrieve native scan findings for an image."""
