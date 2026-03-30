"""GCP credential factory."""

from __future__ import annotations

import json
import logging
import tempfile
from typing import Optional

from containervul.models import CloudAccount
from containervul.exceptions import AuthenticationError

logger = logging.getLogger(__name__)


class GCPClientFactory:
    """Create GCP credentials and service clients per project."""

    @staticmethod
    def get_credentials(account: CloudAccount):
        """Return google-auth credentials."""
        try:
            import google.auth
            from google.oauth2 import service_account
        except ImportError:
            raise AuthenticationError("GCP", "google-auth SDK not installed")

        if account.credential_profile:
            # credential_profile contains JSON key content or file path
            try:
                key_data = json.loads(account.credential_profile)
                return service_account.Credentials.from_service_account_info(key_data)
            except (json.JSONDecodeError, ValueError):
                return service_account.Credentials.from_service_account_file(account.credential_profile)

        # Application Default Credentials
        credentials, project = google.auth.default()
        return credentials

    @staticmethod
    def get_container_client(account: CloudAccount):
        try:
            from google.cloud import container_v1
        except ImportError:
            raise AuthenticationError("GCP", "google-cloud-container SDK not installed")

        cred = GCPClientFactory.get_credentials(account)
        return container_v1.ClusterManagerClient(credentials=cred)

    @staticmethod
    def get_run_client(account: CloudAccount):
        try:
            from google.cloud import run_v2
        except ImportError:
            raise AuthenticationError("GCP", "google-cloud-run SDK not installed")

        cred = GCPClientFactory.get_credentials(account)
        return run_v2.ServicesClient(credentials=cred)

    @staticmethod
    def get_artifact_registry_client(account: CloudAccount):
        try:
            from google.cloud import artifactregistry_v1
        except ImportError:
            raise AuthenticationError("GCP", "google-cloud-artifact-registry SDK not installed")

        cred = GCPClientFactory.get_credentials(account)
        return artifactregistry_v1.ArtifactRegistryClient(credentials=cred)

    @staticmethod
    def verify(account: CloudAccount) -> bool:
        try:
            from google.cloud import resourcemanager_v3

            cred = GCPClientFactory.get_credentials(account)
            client = resourcemanager_v3.ProjectsClient(credentials=cred)
            project = client.get_project(name=f"projects/{account.account_id}")
            logger.info("GCP authenticated: project %s (%s)", project.display_name, project.project_id)
            return True
        except Exception as exc:
            raise AuthenticationError("GCP", str(exc)) from exc
