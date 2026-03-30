"""Dockerfile security analysis via regex pattern matching."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Dict, List

from containervul.models import Vulnerability, Severity, VulnStatus


class DockerfileAnalyzer:
    """Analyze Dockerfile content for security issues."""

    VULNERABILITY_PATTERNS: Dict[str, Dict] = {
        "outdated_base_images": {
            "patterns": [
                r"FROM\s+ubuntu:(14\.04|16\.04|18\.04)",
                r"FROM\s+centos:[1-7](?:\s|$)",
                r"FROM\s+debian:[7-9](?:\s|$)",
                r"FROM\s+alpine:3\.[0-9](?:\.|$)",
                r"FROM\s+node:[0-9](?:\.|$)",
                r"FROM\s+python:[2-3]\.[0-6](?:\.|$)",
                r"FROM\s+nginx:1\.(1[0-9]|[0-9])(?:\.|$)",
                r"FROM\s+golang:1\.(1[0-7]|[0-9])(?:\.|$)",
            ],
            "severity": Severity.HIGH,
            "description": "Outdated base image that may contain known vulnerabilities",
        },
        "insecure_configurations": {
            "patterns": [
                r"USER\s+root\s*$",
                r"--privileged",
                r"COPY\s+\.\s+/",
                r"ADD\s+.*\s+/",
                r"chmod\s+777",
                r"sudo\s+",
                r"--disable-content-trust",
                r"--security-opt\s+seccomp[=:]unconfined",
                r"--cap-add\s+SYS_ADMIN",
                r"--net[=\s]+host",
            ],
            "severity": Severity.MEDIUM,
            "description": "Insecure configuration that may pose security risks",
        },
        "exposed_secrets": {
            "patterns": [
                r"password\s*=\s*[\"'].*[\"']",
                r"api[_-]?key\s*=\s*[\"'].*[\"']",
                r"secret\s*=\s*[\"'].*[\"']",
                r"token\s*=\s*[\"'].*[\"']",
                r"AWS_SECRET_ACCESS_KEY\s*=",
                r"DATABASE_PASSWORD\s*=",
                r"PRIVATE_KEY\s*=",
                r"CLIENT_SECRET\s*=",
            ],
            "severity": Severity.CRITICAL,
            "description": "Potential exposed secret or sensitive information",
        },
        "package_vulnerabilities": {
            "patterns": [
                r"apt-get\s+install.*--allow-unauthenticated",
                r"pip\s+install.*--trusted-host",
                r"npm\s+install.*--unsafe-perm",
                r"apk\s+add.*--allow-untrusted",
                r"curl\s+.*\|\s*sh",
                r"wget\s+.*\|\s*sh",
            ],
            "severity": Severity.HIGH,
            "description": "Insecure package installation that may introduce supply-chain risks",
        },
    }

    REMEDIATION_MAP: Dict[str, str] = {
        "outdated_base_images": "Update to the latest stable version of the base image",
        "insecure_configurations": "Review and secure the configuration according to CIS Docker Benchmark",
        "exposed_secrets": "Move secrets to environment variables or a secret management system (Vault, AWS Secrets Manager)",
        "missing_healthcheck": "Add HEALTHCHECK instruction to monitor container health",
        "package_vulnerabilities": "Use verified package sources and pin versions; avoid piping curl to shell",
    }

    def analyze_dockerfile(self, dockerfile_content: str) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        lines = dockerfile_content.split("\n")

        has_healthcheck = any("HEALTHCHECK" in line for line in lines)
        has_user = any(re.match(r"^\s*USER\s+(?!root)", line) for line in lines)

        for line_num, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            for category, cfg in self.VULNERABILITY_PATTERNS.items():
                for pattern in cfg["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append(
                            Vulnerability(
                                id=f"DOCKERFILE-{category.upper()}-{line_num}",
                                type="dockerfile_issue",
                                category=category,
                                severity=cfg["severity"],
                                line_number=line_num,
                                line_content=line,
                                description=cfg["description"],
                                remediation=self.REMEDIATION_MAP.get(category, "Review and fix the security issue"),
                                discovered_date=datetime.now(timezone.utc),
                                status=VulnStatus.OPEN,
                            )
                        )

        # Missing HEALTHCHECK
        if not has_healthcheck and len(lines) > 5:
            vulnerabilities.append(
                Vulnerability(
                    id=f"DOCKERFILE-HEALTHCHECK-{len(lines)}",
                    type="dockerfile_issue",
                    category="missing_healthcheck",
                    severity=Severity.LOW,
                    line_number=len(lines),
                    line_content="# HEALTHCHECK missing",
                    description="Dockerfile missing HEALTHCHECK instruction",
                    remediation=self.REMEDIATION_MAP["missing_healthcheck"],
                    discovered_date=datetime.now(timezone.utc),
                    status=VulnStatus.OPEN,
                )
            )

        # No non-root USER
        if not has_user and len(lines) > 5:
            vulnerabilities.append(
                Vulnerability(
                    id=f"DOCKERFILE-NO-USER-{len(lines)}",
                    type="dockerfile_issue",
                    category="insecure_configurations",
                    severity=Severity.MEDIUM,
                    line_number=len(lines),
                    line_content="# No USER directive (runs as root by default)",
                    description="Container runs as root by default — no non-root USER directive found",
                    remediation="Add a non-root USER directive (e.g., USER appuser)",
                    discovered_date=datetime.now(timezone.utc),
                    status=VulnStatus.OPEN,
                )
            )

        return vulnerabilities
