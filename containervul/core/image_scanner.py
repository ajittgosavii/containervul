"""Container image vulnerability scanning via registry APIs and Trivy."""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime, timezone
from typing import List, Optional

from containervul.models import ContainerImage, Severity, Vulnerability, VulnStatus

logger = logging.getLogger(__name__)


class ImageScanner:
    """Scan container images for vulnerabilities.

    Supports:
    - Trivy CLI (if installed locally)
    - Cloud-native scan results (ECR, ACR, Artifact Registry) via adapters
    """

    @staticmethod
    def scan_with_trivy(image_uri: str) -> List[Vulnerability]:
        """Run Trivy against an image and return structured vulnerabilities."""
        try:
            result = subprocess.run(
                ["trivy", "image", "--format", "json", "--quiet", image_uri],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                logger.warning("Trivy scan failed for %s: %s", image_uri, result.stderr[:500])
                return []

            data = json.loads(result.stdout)
            return ImageScanner._parse_trivy_json(data, image_uri)

        except FileNotFoundError:
            logger.info("Trivy not installed — skipping local scan for %s", image_uri)
            return []
        except Exception as exc:
            logger.error("Image scan error for %s: %s", image_uri, exc)
            return []

    @staticmethod
    def parse_ecr_findings(findings: List[dict], image: Optional[ContainerImage] = None) -> List[Vulnerability]:
        """Convert AWS ECR scan findings to Vulnerability objects."""
        vulns: List[Vulnerability] = []
        for f in findings:
            sev_str = f.get("severity", "UNKNOWN").upper()
            severity = Severity[sev_str] if sev_str in Severity.__members__ else Severity.UNKNOWN
            vulns.append(Vulnerability(
                id=f.get("name", ""),
                severity=severity,
                description=f.get("description", "")[:500],
                category="image_vulnerability",
                type="ecr_scan",
                cvss_score=_extract_ecr_cvss(f),
                remediation=f"Update package {f.get('name', '')} to a fixed version",
                discovered_date=datetime.now(timezone.utc),
                status=VulnStatus.OPEN,
                image=image,
                references=[f.get("uri", "")],
            ))
        return vulns

    @staticmethod
    def parse_acr_findings(findings: List[dict], image: Optional[ContainerImage] = None) -> List[Vulnerability]:
        """Convert Azure ACR / Defender findings."""
        vulns: List[Vulnerability] = []
        for f in findings:
            sev_str = f.get("severity", "UNKNOWN").upper()
            severity = Severity[sev_str] if sev_str in Severity.__members__ else Severity.UNKNOWN
            vulns.append(Vulnerability(
                id=f.get("patchable_cve", f.get("cve_id", "")),
                severity=severity,
                description=f.get("description", "")[:500],
                category="image_vulnerability",
                type="acr_scan",
                cvss_score=f.get("cvss_score", 0.0),
                remediation=f.get("remediation", "Update to patched version"),
                discovered_date=datetime.now(timezone.utc),
                status=VulnStatus.OPEN,
                image=image,
            ))
        return vulns

    @staticmethod
    def parse_gar_findings(occurrences: List[dict], image: Optional[ContainerImage] = None) -> List[Vulnerability]:
        """Convert GCP Artifact Registry / Container Analysis occurrences."""
        vulns: List[Vulnerability] = []
        for occ in occurrences:
            vuln_detail = occ.get("vulnerability", {})
            sev_str = vuln_detail.get("effectiveSeverity", "UNKNOWN").upper()
            severity = Severity[sev_str] if sev_str in Severity.__members__ else Severity.UNKNOWN
            vulns.append(Vulnerability(
                id=vuln_detail.get("shortDescription", occ.get("name", "")),
                severity=severity,
                description=vuln_detail.get("longDescription", "")[:500],
                category="image_vulnerability",
                type="gar_scan",
                cvss_score=vuln_detail.get("cvssScore", 0.0),
                remediation="Update to fixed version",
                discovered_date=datetime.now(timezone.utc),
                status=VulnStatus.OPEN,
                image=image,
            ))
        return vulns

    # ── Private ──────────────────────────────────────────────────────────

    @staticmethod
    def _parse_trivy_json(data: dict, image_uri: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                sev_str = v.get("Severity", "UNKNOWN").upper()
                severity = Severity[sev_str] if sev_str in Severity.__members__ else Severity.UNKNOWN
                vulns.append(Vulnerability(
                    id=v.get("VulnerabilityID", ""),
                    severity=severity,
                    description=v.get("Description", "")[:500],
                    category="image_vulnerability",
                    type="trivy_scan",
                    cvss_score=v.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
                    remediation=f"Update {v.get('PkgName', '')} from {v.get('InstalledVersion', '')} to {v.get('FixedVersion', 'latest')}",
                    discovered_date=datetime.now(timezone.utc),
                    status=VulnStatus.OPEN,
                    references=v.get("References", [])[:5],
                ))
        return vulns


def _extract_ecr_cvss(finding: dict) -> float:
    for attr in finding.get("attributes", []):
        if attr.get("key") == "CVSS2_SCORE":
            try:
                return float(attr["value"])
            except (ValueError, KeyError):
                pass
    return 0.0
