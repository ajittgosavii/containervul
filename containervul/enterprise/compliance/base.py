"""Abstract compliance framework and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from containervul.models import ComplianceReport, Vulnerability


class ComplianceFrameworkBase(ABC):
    """Evaluate vulnerabilities against a compliance framework."""

    @abstractmethod
    def evaluate(self, vulnerabilities: List[Vulnerability]) -> ComplianceReport:
        """Run all controls and return a report."""


def get_framework(name: str) -> ComplianceFrameworkBase:
    """Factory: return the framework instance by name."""
    from containervul.enterprise.compliance.cis_docker import CISDockerBenchmark
    from containervul.enterprise.compliance.cis_kubernetes import CISKubernetesBenchmark
    from containervul.enterprise.compliance.nist_800_190 import NIST800190

    registry = {
        "cis_docker": CISDockerBenchmark,
        "cis_kubernetes": CISKubernetesBenchmark,
        "nist_800_190": NIST800190,
    }
    cls = registry.get(name)
    if not cls:
        raise ValueError(f"Unknown compliance framework: {name}. Available: {list(registry)}")
    return cls()
