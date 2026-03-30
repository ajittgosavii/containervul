"""Multi-account credential management across AWS, Azure, GCP."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from containervul.models import CloudAccount, CloudProviderType

logger = logging.getLogger(__name__)


class AccountManager:
    """Manage cloud accounts / subscriptions / projects.

    Accounts are stored in-memory (or Streamlit session_state) and optionally
    persisted to a JSON file.
    """

    def __init__(self) -> None:
        self._accounts: Dict[str, CloudAccount] = {}

    def add_account(self, account: CloudAccount) -> None:
        self._accounts[account.id] = account
        logger.info("Added %s account: %s (%s)", account.provider.value, account.name, account.account_id)

    def remove_account(self, account_id: str) -> None:
        self._accounts.pop(account_id, None)

    def get_account(self, account_id: str) -> Optional[CloudAccount]:
        return self._accounts.get(account_id)

    def list_accounts(self, provider: Optional[CloudProviderType] = None) -> List[CloudAccount]:
        accts = list(self._accounts.values())
        if provider:
            accts = [a for a in accts if a.provider == provider]
        return [a for a in accts if a.is_active]

    def list_all(self) -> List[CloudAccount]:
        return list(self._accounts.values())

    def load_from_dicts(self, data: List[dict]) -> None:
        """Bulk-load accounts from a list of dicts (e.g. from JSON config)."""
        for d in data:
            try:
                acct = CloudAccount(**d)
                self.add_account(acct)
            except Exception as exc:
                logger.warning("Skipping invalid account config: %s", exc)

    def to_dicts(self) -> List[dict]:
        return [a.model_dump(mode="json") for a in self._accounts.values()]
