"""Azure credential factory."""

from __future__ import annotations

import logging
from typing import Optional

from containervul.models import CloudAccount
from containervul.exceptions import AuthenticationError

logger = logging.getLogger(__name__)


class AzureClientFactory:
    """Create Azure SDK credentials and management clients per subscription."""

    @staticmethod
    def get_credential(account: CloudAccount):
        """Return an Azure credential object."""
        try:
            from azure.identity import DefaultAzureCredential, ClientSecretCredential
        except ImportError:
            raise AuthenticationError("Azure", "azure-identity SDK not installed")

        if account.tenant_id and account.credential_profile:
            # Service principal via credential_profile = client_secret
            return ClientSecretCredential(
                tenant_id=account.tenant_id,
                client_id=account.account_id,
                client_secret=account.credential_profile,
            )
        return DefaultAzureCredential()

    @staticmethod
    def get_container_client(account: CloudAccount):
        try:
            from azure.mgmt.containerservice import ContainerServiceClient
        except ImportError:
            raise AuthenticationError("Azure", "azure-mgmt-containerservice SDK not installed")

        cred = AzureClientFactory.get_credential(account)
        return ContainerServiceClient(cred, account.account_id)

    @staticmethod
    def get_container_instance_client(account: CloudAccount):
        try:
            from azure.mgmt.containerinstance import ContainerInstanceManagementClient
        except ImportError:
            raise AuthenticationError("Azure", "azure-mgmt-containerinstance SDK not installed")

        cred = AzureClientFactory.get_credential(account)
        return ContainerInstanceManagementClient(cred, account.account_id)

    @staticmethod
    def get_acr_client(account: CloudAccount, registry_url: str):
        try:
            from azure.containerregistry import ContainerRegistryClient
        except ImportError:
            raise AuthenticationError("Azure", "azure-containerregistry SDK not installed")

        cred = AzureClientFactory.get_credential(account)
        return ContainerRegistryClient(endpoint=registry_url, credential=cred)

    @staticmethod
    def verify(account: CloudAccount) -> bool:
        try:
            from azure.mgmt.resource import SubscriptionClient

            cred = AzureClientFactory.get_credential(account)
            sub_client = SubscriptionClient(cred)
            sub = sub_client.subscriptions.get(account.account_id)
            logger.info("Azure authenticated: subscription %s (%s)", sub.display_name, sub.subscription_id)
            return True
        except Exception as exc:
            raise AuthenticationError("Azure", str(exc)) from exc
