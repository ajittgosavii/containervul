"""CIS Kubernetes Benchmark compliance checks."""

from __future__ import annotations

from typing import List

from containervul.enterprise.compliance.base import ComplianceFrameworkBase
from containervul.models import (
    ComplianceControl, ComplianceFramework, ComplianceReport, Severity, Vulnerability,
)


class CISKubernetesBenchmark(ComplianceFrameworkBase):
    """Evaluate against CIS Kubernetes Benchmark controls (container-focused subset)."""

    CONTROLS = [
        {
            "id": "CIS-K8S-5.1.1",
            "title": "Ensure that the cluster-admin role is only used where required",
            "description": "Restrict use of cluster-admin to reduce blast radius",
            "severity": Severity.HIGH,
            "check_fn": "_check_privileged_containers",
            "remediation": "Use RBAC to assign minimum required permissions. Avoid cluster-admin binding.",
        },
        {
            "id": "CIS-K8S-5.1.6",
            "title": "Ensure that Service Account Tokens are not mounted by default",
            "description": "Disable automounting of service account tokens in pods",
            "severity": Severity.MEDIUM,
            "check_fn": "_check_default",
            "remediation": "Set automountServiceAccountToken: false in pod/service account specs.",
        },
        {
            "id": "CIS-K8S-5.2.1",
            "title": "Minimize the admission of privileged containers",
            "description": "Do not allow privileged containers in the cluster",
            "severity": Severity.CRITICAL,
            "check_fn": "_check_privileged_containers",
            "remediation": "Use PodSecurityPolicy/PodSecurityAdmission to restrict privileged containers.",
        },
        {
            "id": "CIS-K8S-5.2.2",
            "title": "Minimize the admission of containers with root",
            "description": "Ensure containers do not run as root",
            "severity": Severity.HIGH,
            "check_fn": "_check_root_containers",
            "remediation": "Set runAsNonRoot: true and runAsUser to a non-zero UID in pod security context.",
        },
        {
            "id": "CIS-K8S-5.2.6",
            "title": "Minimize the admission of containers with added capabilities",
            "description": "Do not add unnecessary Linux capabilities",
            "severity": Severity.MEDIUM,
            "check_fn": "_check_capabilities",
            "remediation": "Drop ALL capabilities and only add specifically required ones.",
        },
        {
            "id": "CIS-K8S-5.4.1",
            "title": "Prefer using secrets as files over secrets as environment variables",
            "description": "Avoid passing secrets via environment variables",
            "severity": Severity.HIGH,
            "check_fn": "_check_env_secrets",
            "remediation": "Mount secrets as files instead of ENV. Use external secret operators.",
        },
        {
            "id": "CIS-K8S-5.7.1",
            "title": "Create administrative boundaries between resources using namespaces",
            "description": "Use namespaces to isolate workloads",
            "severity": Severity.MEDIUM,
            "check_fn": "_check_default",
            "remediation": "Deploy workloads in dedicated namespaces, not default.",
        },
        {
            "id": "CIS-K8S-5.7.3",
            "title": "Apply Security Context to pods and containers",
            "description": "Enforce security context on all pods",
            "severity": Severity.HIGH,
            "check_fn": "_check_root_containers",
            "remediation": "Define securityContext with runAsNonRoot, readOnlyRootFilesystem, and drop capabilities.",
        },
    ]

    def evaluate(self, vulnerabilities: List[Vulnerability]) -> ComplianceReport:
        controls: List[ComplianceControl] = []

        for ctrl_def in self.CONTROLS:
            check_fn = getattr(self, ctrl_def["check_fn"], self._check_default)
            findings = check_fn(vulnerabilities)

            controls.append(ComplianceControl(
                control_id=ctrl_def["id"],
                framework=ComplianceFramework.CIS_KUBERNETES,
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
            framework=ComplianceFramework.CIS_KUBERNETES,
            controls=controls,
            total_controls=len(controls),
            passed_controls=passed,
            compliance_score=round(score, 1),
        )

    # ── Check functions ──────────────────────────────────────────────────

    @staticmethod
    def _check_privileged_containers(vulns: List[Vulnerability]) -> List[str]:
        return [
            f"{v.id}: {v.description[:80]}"
            for v in vulns
            if v.category == "insecure_configurations"
            and any(kw in (v.line_content or "").lower() for kw in ["--privileged", "sys_admin"])
        ]

    @staticmethod
    def _check_root_containers(vulns: List[Vulnerability]) -> List[str]:
        return [
            f"{v.id}: {v.description[:80]}"
            for v in vulns
            if v.category == "insecure_configurations"
            and ("root" in (v.line_content or "").lower() or "no user directive" in v.description.lower())
        ]

    @staticmethod
    def _check_capabilities(vulns: List[Vulnerability]) -> List[str]:
        return [
            f"{v.id}: {v.description[:80]}"
            for v in vulns
            if v.category == "insecure_configurations"
            and "cap-add" in (v.line_content or "").lower()
        ]

    @staticmethod
    def _check_env_secrets(vulns: List[Vulnerability]) -> List[str]:
        return [
            f"{v.id}: {v.description[:80]}"
            for v in vulns
            if v.category == "exposed_secrets"
        ]

    @staticmethod
    def _check_default(vulns: List[Vulnerability]) -> List[str]:
        """Default check — no automated detection, passes by default."""
        return []
