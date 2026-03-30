"""Shared test fixtures."""

import pytest

from containervul.core.dockerfile_analyzer import DockerfileAnalyzer
from containervul.core.vulnerability_analyzer import VulnerabilityAnalyzer
from containervul.models import Severity, Vulnerability


@pytest.fixture
def dockerfile_analyzer():
    return DockerfileAnalyzer()


@pytest.fixture
def vuln_analyzer():
    return VulnerabilityAnalyzer()


@pytest.fixture
def sample_vulnerabilities():
    return [
        Vulnerability(severity=Severity.CRITICAL, category="exposed_secrets", description="Hardcoded password"),
        Vulnerability(severity=Severity.HIGH, category="outdated_base_images", description="Ubuntu 16.04"),
        Vulnerability(severity=Severity.MEDIUM, category="insecure_configurations", description="Root user"),
        Vulnerability(severity=Severity.LOW, category="missing_healthcheck", description="No healthcheck"),
    ]
