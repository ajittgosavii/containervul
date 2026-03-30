"""AI-powered remediation engine — knowledge base + Claude recommendations."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from containervul.ai.prompts import REMEDIATION_PROMPT_TEMPLATE
from containervul.config import settings
from containervul.models import RemediationPlan, Vulnerability

logger = logging.getLogger(__name__)


class AIRemediationEngine:
    """Generate remediation plans using a knowledge base and optional Claude AI."""

    REMEDIATION_KB: Dict[str, Dict] = {
        "outdated_base_images": {
            "strategy": "Update base images to latest stable versions",
            "steps": [
                "Identify current base image version",
                "Check for latest stable version",
                "Update Dockerfile with new base image",
                "Test updated image thoroughly",
                "Deploy updated image",
            ],
            "automation": "dockerfile_update",
        },
        "exposed_secrets": {
            "strategy": "Implement proper secret management",
            "steps": [
                "Identify exposed secrets",
                "Remove secrets from code/config",
                "Implement secret management system (Vault, AWS Secrets Manager, Azure Key Vault)",
                "Update application to use secret manager",
                "Rotate exposed secrets immediately",
            ],
            "automation": "secret_remediation",
        },
        "insecure_configurations": {
            "strategy": "Implement CIS Docker Benchmark security practices",
            "steps": [
                "Review current configuration against CIS benchmarks",
                "Apply security hardening (non-root user, read-only rootfs)",
                "Implement least privilege principle",
                "Add security scanning to CI/CD",
                "Regular security audits",
            ],
            "automation": "config_hardening",
        },
        "package_vulnerabilities": {
            "strategy": "Secure the software supply chain",
            "steps": [
                "Pin all package versions in Dockerfile",
                "Use verified/signed package repositories",
                "Implement Trivy/Grype in CI/CD pipeline",
                "Set up automated dependency updates (Dependabot, Renovate)",
                "Establish vulnerability SLA policies",
            ],
            "automation": "supply_chain_hardening",
        },
        "image_vulnerability": {
            "strategy": "Patch known image vulnerabilities",
            "steps": [
                "Identify vulnerable packages from scan results",
                "Update packages to patched versions",
                "Rebuild and rescan the image",
                "Validate application functionality after update",
                "Deploy patched image",
            ],
            "automation": "image_patching",
        },
    }

    def __init__(self, api_key: str = ""):
        self._api_key = api_key or settings.claude_api_key
        self._client = None

    @property
    def _ai_client(self):
        if self._client is None and self._api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self._api_key)
            except Exception:
                pass
        return self._client

    def generate_remediation_plan(self, vulnerabilities: List[Vulnerability]) -> RemediationPlan:
        plan = RemediationPlan()

        groups: Dict[str, List[Vulnerability]] = {}
        for v in vulnerabilities:
            groups.setdefault(v.category, []).append(v)

        total_effort = 0
        total_risk_reduction = 0

        for category, vuln_list in groups.items():
            remediation = self._get_remediation_for_category(category, vuln_list)

            if any(v.severity.value == "CRITICAL" for v in vuln_list):
                plan.immediate_actions.extend(remediation["immediate"])
            elif any(v.severity.value == "HIGH" for v in vuln_list):
                plan.short_term_actions.extend(remediation["short_term"])
            else:
                plan.long_term_actions.extend(remediation["long_term"])

            if remediation.get("automation"):
                plan.automated_fixes.append(remediation["automation"])
            plan.manual_steps.extend(remediation.get("manual_steps", []))
            total_effort += remediation.get("effort_hours", 2)
            total_risk_reduction += remediation.get("risk_reduction", 10)

        plan.estimated_effort = f"{total_effort} hours"
        plan.risk_reduction = min(100, total_risk_reduction)

        # AI-enhanced recommendations
        if self._ai_client:
            plan.ai_recommendations = self._get_ai_recommendations(vulnerabilities)

        return plan

    def generate_fix_script(self, vulnerability: Vulnerability) -> str:
        category = vulnerability.category
        scripts = {
            "outdated_base_images": self._dockerfile_update_script,
            "exposed_secrets": self._secret_remediation_script,
            "insecure_configurations": self._config_fix_script,
        }
        gen = scripts.get(category)
        if gen:
            return gen(vulnerability)
        return "# Manual remediation required\n# No automated script available for this vulnerability type"

    # ── Private ──────────────────────────────────────────────────────────

    def _get_remediation_for_category(self, category: str, vulns: List[Vulnerability]) -> Dict:
        kb = self.REMEDIATION_KB.get(category)
        if kb:
            return {
                "immediate": kb["steps"][:2],
                "short_term": kb["steps"][2:4],
                "long_term": kb["steps"][4:],
                "automation": {"type": kb.get("automation"), "description": kb["strategy"], "feasibility": "HIGH"},
                "manual_steps": kb["steps"],
                "effort_hours": len(vulns) * 2,
                "risk_reduction": len(vulns) * 15,
            }
        return {
            "immediate": ["Assess vulnerability impact", "Apply temporary mitigations"],
            "short_term": ["Research proper fix", "Test remediation"],
            "long_term": ["Implement permanent fix", "Update security policies"],
            "automation": None,
            "manual_steps": ["Manual assessment required"],
            "effort_hours": len(vulns) * 4,
            "risk_reduction": len(vulns) * 10,
        }

    def _get_ai_recommendations(self, vulnerabilities: List[Vulnerability]) -> str:
        if not self._ai_client:
            return "AI recommendations unavailable — API key not configured"
        try:
            summaries = []
            for v in vulnerabilities[:15]:
                summaries.append(
                    f"- {v.id}: {v.severity.value} — {v.description[:100]}"
                )
            prompt = REMEDIATION_PROMPT_TEMPLATE.format(
                vulnerability_summary="\n".join(summaries)
            )
            response = self._ai_client.messages.create(
                model=settings.claude_model,
                max_tokens=2000,
                temperature=settings.claude_temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text if response.content else "No AI recommendations available"
        except Exception as exc:
            logger.error("AI recommendation error: %s", exc)
            return f"AI recommendation error: {exc}"

    # ── Fix Scripts ──────────────────────────────────────────────────────

    @staticmethod
    def _dockerfile_update_script(vuln: Vulnerability) -> str:
        return """#!/bin/bash
# Automated Dockerfile base image update script
echo "Updating base image in Dockerfile..."

# Backup original
cp Dockerfile Dockerfile.backup.$(date +%Y%m%d_%H%M%S)

# Update common outdated base images
sed -i 's/ubuntu:16.04/ubuntu:24.04/g' Dockerfile
sed -i 's/ubuntu:18.04/ubuntu:24.04/g' Dockerfile
sed -i 's/centos:[1-7]/almalinux:9/g' Dockerfile
sed -i 's/debian:[7-9]/debian:12/g' Dockerfile
sed -i 's/alpine:3\\.[0-9]/alpine:3.19/g' Dockerfile
sed -i 's/node:[0-9]\\b/node:20/g' Dockerfile
sed -i 's/python:3\\.[0-6]/python:3.12/g' Dockerfile

echo "Update complete. Review changes and run: docker build --no-cache ."
"""

    @staticmethod
    def _secret_remediation_script(vuln: Vulnerability) -> str:
        return """#!/bin/bash
# Secret remediation script
echo "Scanning for exposed secrets..."

# Create environment variable template
cat > .env.template << 'EOF'
# Copy to .env and fill in actual values
# NEVER commit .env to version control!
PASSWORD=
API_KEY=
SECRET=
TOKEN=
DATABASE_PASSWORD=
EOF

# Add .env to .gitignore
grep -q '.env' .gitignore 2>/dev/null || echo '.env' >> .gitignore

echo "Created .env.template — migrate all secrets to environment variables."
echo "Consider using: AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault."
"""

    @staticmethod
    def _config_fix_script(vuln: Vulnerability) -> str:
        return """#!/bin/bash
# Configuration security hardening script
cat > Dockerfile.secure << 'DOCKERFILE'
# Use specific version tag, not :latest
FROM ubuntu:24.04

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser -s /sbin/nologin appuser

# Install packages, clean up
RUN apt-get update && \\
    apt-get install -y --no-install-recommends your-packages && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --chown=appuser:appuser ./app /app
WORKDIR /app
USER appuser

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080
CMD ["your-app-command"]
DOCKERFILE

echo "Created Dockerfile.secure — review and replace your current Dockerfile."
"""
