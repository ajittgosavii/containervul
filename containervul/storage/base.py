"""Abstract storage interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from containervul.models import Vulnerability, ScanResult, VulnStatus


class VulnerabilityStore(ABC):
    """Abstract interface for vulnerability persistence."""

    @abstractmethod
    def save_vulnerability(self, vuln: Vulnerability) -> None: ...

    @abstractmethod
    def save_many(self, vulns: List[Vulnerability]) -> None: ...

    @abstractmethod
    def get_all(self) -> List[Vulnerability]: ...

    @abstractmethod
    def get_by_status(self, status: VulnStatus) -> List[Vulnerability]: ...

    @abstractmethod
    def update_status(self, vuln_id: str, status: VulnStatus) -> None: ...

    @abstractmethod
    def clear(self) -> None: ...


class InMemoryStore(VulnerabilityStore):
    """Simple in-memory store (default backend)."""

    def __init__(self) -> None:
        self._vulns: dict[str, Vulnerability] = {}

    def save_vulnerability(self, vuln: Vulnerability) -> None:
        self._vulns[vuln.id] = vuln

    def save_many(self, vulns: List[Vulnerability]) -> None:
        for v in vulns:
            self._vulns[v.id] = v

    def get_all(self) -> List[Vulnerability]:
        return list(self._vulns.values())

    def get_by_status(self, status: VulnStatus) -> List[Vulnerability]:
        return [v for v in self._vulns.values() if v.status == status]

    def update_status(self, vuln_id: str, status: VulnStatus) -> None:
        if vuln_id in self._vulns:
            self._vulns[vuln_id].status = status

    def clear(self) -> None:
        self._vulns.clear()
