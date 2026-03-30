"""Tests for compliance frameworks."""

from containervul.enterprise.compliance.base import get_framework
from containervul.models import Severity, Vulnerability


def _make_vulns():
    return [
        Vulnerability(severity=Severity.CRITICAL, category="exposed_secrets", description="Hardcoded password", line_content='ENV PASSWORD="secret"'),
        Vulnerability(severity=Severity.HIGH, category="outdated_base_images", description="Ubuntu 16.04", line_content="FROM ubuntu:16.04"),
        Vulnerability(severity=Severity.MEDIUM, category="insecure_configurations", description="Root user", line_content="USER root"),
        Vulnerability(severity=Severity.LOW, category="missing_healthcheck", description="No healthcheck", line_content="# HEALTHCHECK missing"),
    ]


def test_cis_docker():
    fw = get_framework("cis_docker")
    report = fw.evaluate(_make_vulns())
    assert report.total_controls > 0
    assert 0 <= report.compliance_score <= 100
    # Should fail some controls given our insecure vulns
    assert report.passed_controls < report.total_controls


def test_cis_kubernetes():
    fw = get_framework("cis_kubernetes")
    report = fw.evaluate(_make_vulns())
    assert report.total_controls > 0
    assert 0 <= report.compliance_score <= 100


def test_nist_800_190():
    fw = get_framework("nist_800_190")
    report = fw.evaluate(_make_vulns())
    assert report.total_controls > 0
    assert 0 <= report.compliance_score <= 100


def test_empty_vulns_full_compliance():
    for name in ("cis_docker", "cis_kubernetes", "nist_800_190"):
        fw = get_framework(name)
        report = fw.evaluate([])
        assert report.compliance_score == 100.0


def test_unknown_framework_raises():
    import pytest
    with pytest.raises(ValueError):
        get_framework("unknown_framework")
