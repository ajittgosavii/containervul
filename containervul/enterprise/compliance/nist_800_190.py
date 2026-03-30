"""NIST SP 800-190 Application Container Security Guide compliance checks."""

from __future__ import annotations

from typing import List

from containervul.enterprise.compliance.base import ComplianceFrameworkBase
from containervul.models import (
    ComplianceControl, ComplianceFramework, ComplianceReport, Severity, Vulnerability,
)


class NIST800190(ComplianceFrameworkBase):
    """Evaluate against NIST SP 800-190 recommendations."""

    CONTROLS = [
        {
            "id": "NIST-800-190-3.1.1",
            "title": "Image vulnerabilities",
            "description": "Container images should be free of known vulnerabilities",
            "severity": Severity.CRITICAL,
            "categories": ["image_vulnerability", "outdated_base_images"],
            "remediation": "Scan all images with vulnerability scanners. Patch or rebuild images with known CVEs.",
        },
        {
            "id": "NIST-800-190-3.1.2",
            "title": "Image configuration defects",
            "description": "Images should follow secure configuration best practices",
            "severity": Severity.HIGH,
            "categories": ["insecure_configurations", "missing_healthcheck"],
            "remediation": "Follow CIS Docker Benchmark. Use non-root users, minimize packages, add health checks.",
        },
        {
            "id": "NIST-800-190-3.1.3",
            "title": "Embedded malware",
            "description": "Images should not contain malware or cryptominers",
            "severity": Severity.CRITICAL,
            "categories": ["package_vulnerabilities"],
            "remediation": "Use only trusted base images. Scan for malware. Verify package signatures.",
        },
        {
            "id": "NIST-800-190-3.1.4",
            "title": "Embedded secrets",
            "description": "Secrets should not be embedded in images",
            "severity": Severity.CRITICAL,
            "categories": ["exposed_secrets"],
            "remediation": "Use runtime secret injection (Vault, AWS Secrets Manager, K8s secrets). Never hardcode credentials.",
        },
        {
            "id": "NIST-800-190-3.2.1",
            "title": "Registry security — insecure connections",
            "description": "Registries should use TLS and authentication",
            "severity": Severity.HIGH,
            "categories": [],  # Requires infrastructure check
            "remediation": "Use private registries with TLS. Enforce authentication. Enable image signing.",
        },
        {
            "id": "NIST-800-190-3.3.1",
            "title": "Orchestrator configuration — unrestricted network access",
            "description": "Apply network policies to restrict container-to-container traffic",
            "severity": Severity.HIGH,
            "categories": ["insecure_configurations"],
            "keywords": ["--net=host", "host"],
            "remediation": "Implement network policies. Avoid host networking. Use service mesh for mTLS.",
        },
        {
            "id": "NIST-800-190-3.4.1",
            "title": "Container runtime vulnerabilities",
            "description": "Container runtime should be patched and configured securely",
            "severity": Severity.HIGH,
            "categories": ["insecure_configurations"],
            "keywords": ["--privileged", "seccomp:unconfined"],
            "remediation": "Keep container runtime updated. Enable seccomp/AppArmor profiles. Avoid privileged mode.",
        },
        {
            "id": "NIST-800-190-3.5.1",
            "title": "Host OS vulnerabilities",
            "description": "Host OS should be hardened and minimal",
            "severity": Severity.MEDIUM,
            "categories": ["outdated_base_images"],
            "remediation": "Use minimal host OS (Bottlerocket, Flatcar). Keep host OS patched.",
        },
    ]

    def evaluate(self, vulnerabilities: List[Vulnerability]) -> ComplianceReport:
        controls: List[ComplianceControl] = []

        for ctrl_def in self.CONTROLS:
            findings: List[str] = []
            categories = ctrl_def["categories"]
            keywords = ctrl_def.get("keywords", [])

            for v in vulnerabilities:
                if v.category in categories:
                    if keywords:
                        for kw in keywords:
                            if kw.lower() in (v.line_content or "").lower():
                                findings.append(f"{v.id}: {v.description[:80]}")
                                break
                    else:
                        findings.append(f"{v.id}: {v.description[:80]}")

            controls.append(ComplianceControl(
                control_id=ctrl_def["id"],
                framework=ComplianceFramework.NIST_800_190,
                title=ctrl_def["title"],
                description=ctrl_def["description"],
                passed=len(findings) == 0,
                severity=ctrl_def["severity"],
                findings=findings,
                remediation=ctrl_def["remediation"],
            ))

        passed = sum(1 for c in controls if c.passed)
        score = (passed / len(controls) * 100) if controls else 100.0

        return ComplianceReport(
            framework=ComplianceFramework.NIST_800_190,
            controls=controls,
            total_controls=len(controls),
            passed_controls=passed,
            compliance_score=round(score, 1),
        )
