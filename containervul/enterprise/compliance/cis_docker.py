"""CIS Docker Benchmark v1.6 compliance checks."""

from __future__ import annotations

from typing import List

from containervul.enterprise.compliance.base import ComplianceFrameworkBase
from containervul.models import (
    ComplianceControl, ComplianceFramework, ComplianceReport, Severity, Vulnerability,
)


class CISDockerBenchmark(ComplianceFrameworkBase):
    """Evaluate against CIS Docker Benchmark controls."""

    CONTROLS = [
        {
            "id": "CIS-DI-4.1",
            "title": "Ensure a user for the container has been created",
            "description": "Create a non-root user for the container",
            "severity": Severity.HIGH,
            "check_categories": ["insecure_configurations"],
            "check_keywords": ["USER root", "No USER directive"],
            "remediation": "Add 'USER <non-root>' directive to Dockerfile",
        },
        {
            "id": "CIS-DI-4.2",
            "title": "Ensure that containers use only trusted base images",
            "description": "Use signed, verified base images from trusted registries",
            "severity": Severity.HIGH,
            "check_categories": ["outdated_base_images"],
            "check_keywords": [],
            "remediation": "Use official, up-to-date base images from trusted registries. Enable Docker Content Trust.",
        },
        {
            "id": "CIS-DI-4.3",
            "title": "Ensure that unnecessary packages are not installed",
            "description": "Do not install unnecessary packages to reduce attack surface",
            "severity": Severity.MEDIUM,
            "check_categories": ["package_vulnerabilities"],
            "check_keywords": [],
            "remediation": "Use --no-install-recommends and multi-stage builds to minimize packages.",
        },
        {
            "id": "CIS-DI-4.6",
            "title": "Ensure HEALTHCHECK instructions have been added",
            "description": "Add HEALTHCHECK instruction for container health monitoring",
            "severity": Severity.LOW,
            "check_categories": ["missing_healthcheck"],
            "check_keywords": ["HEALTHCHECK missing"],
            "remediation": "Add HEALTHCHECK instruction to Dockerfile.",
        },
        {
            "id": "CIS-DI-4.7",
            "title": "Ensure update/patch instructions are not used alone in Dockerfile",
            "description": "Avoid apt-get upgrade or apk upgrade in Dockerfile",
            "severity": Severity.MEDIUM,
            "check_categories": ["insecure_configurations"],
            "check_keywords": ["apt-get upgrade", "apk upgrade"],
            "remediation": "Pin package versions instead of upgrading all packages.",
        },
        {
            "id": "CIS-DI-4.9",
            "title": "Ensure that COPY is used instead of ADD",
            "description": "Use COPY instead of ADD to avoid unexpected behavior",
            "severity": Severity.MEDIUM,
            "check_categories": ["insecure_configurations"],
            "check_keywords": ["ADD"],
            "remediation": "Replace ADD with COPY unless you specifically need ADD's URL/tar extraction features.",
        },
        {
            "id": "CIS-DI-4.10",
            "title": "Ensure secrets are not stored in Dockerfiles",
            "description": "Do not hardcode secrets in Dockerfiles or ENV instructions",
            "severity": Severity.CRITICAL,
            "check_categories": ["exposed_secrets"],
            "check_keywords": [],
            "remediation": "Use Docker secrets, build args at runtime, or external secret management.",
        },
        {
            "id": "CIS-DI-5.8",
            "title": "Ensure privileged mode is not used",
            "description": "Do not run containers in privileged mode",
            "severity": Severity.CRITICAL,
            "check_categories": ["insecure_configurations"],
            "check_keywords": ["--privileged", "SYS_ADMIN"],
            "remediation": "Remove --privileged flag. Use specific capabilities if needed.",
        },
        {
            "id": "CIS-DI-5.12",
            "title": "Ensure the container's root filesystem is mounted as read-only",
            "description": "Set container root filesystem to read-only",
            "severity": Severity.MEDIUM,
            "check_categories": ["insecure_configurations"],
            "check_keywords": ["chmod 777"],
            "remediation": "Use --read-only flag. Use volumes for writable paths.",
        },
    ]

    def evaluate(self, vulnerabilities: List[Vulnerability]) -> ComplianceReport:
        controls: List[ComplianceControl] = []

        for ctrl_def in self.CONTROLS:
            findings: List[str] = []

            for v in vulnerabilities:
                # Check by category
                if v.category in ctrl_def["check_categories"]:
                    if ctrl_def["check_keywords"]:
                        for kw in ctrl_def["check_keywords"]:
                            if kw.lower() in (v.line_content or "").lower() or kw.lower() in v.description.lower():
                                findings.append(f"{v.id}: {v.description[:80]}")
                                break
                    else:
                        findings.append(f"{v.id}: {v.description[:80]}")

            control = ComplianceControl(
                control_id=ctrl_def["id"],
                framework=ComplianceFramework.CIS_DOCKER,
                title=ctrl_def["title"],
                description=ctrl_def["description"],
                passed=len(findings) == 0,
                severity=ctrl_def["severity"],
                findings=findings,
                remediation=ctrl_def["remediation"],
            )
            controls.append(control)

        passed = sum(1 for c in controls if c.passed)
        score = (passed / len(controls) * 100) if controls else 100.0

        return ComplianceReport(
            framework=ComplianceFramework.CIS_DOCKER,
            controls=controls,
            total_controls=len(controls),
            passed_controls=passed,
            compliance_score=round(score, 1),
        )
