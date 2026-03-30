"""CVE database integration via NIST NVD API."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import requests
from cachetools import TTLCache

from containervul.config import settings

logger = logging.getLogger(__name__)


class CVEIntegrator:
    """Query the NIST NVD for CVE data. No Streamlit dependency."""

    def __init__(self) -> None:
        self._cache: TTLCache = TTLCache(maxsize=512, ttl=settings.cache_ttl)
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "ContainerVul-Enterprise/2.0"})

    # ── Public API ───────────────────────────────────────────────────────

    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        cache_key = f"cve:{cve_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            resp = self._session.get(
                settings.nist_nvd_url,
                params={"cveId": cve_id},
                timeout=settings.request_timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("vulnerabilities"):
                    vuln = data["vulnerabilities"][0]
                    cve_data = vuln["cve"]
                    result = {
                        "id": cve_id,
                        "description": self._extract_description(cve_data),
                        "severity": self._extract_severity(vuln),
                        "cvss_score": self._extract_cvss_score(vuln),
                        "published_date": cve_data.get("published", "Unknown"),
                        "modified_date": cve_data.get("lastModified", "Unknown"),
                        "affected_products": self._extract_affected_products(cve_data),
                        "references": self._extract_references(cve_data),
                        "cwe_ids": self._extract_cwe_ids(cve_data),
                    }
                    self._cache[cache_key] = result
                    return result
            return {"id": cve_id, "error": "CVE not found or API error"}
        except Exception as exc:
            logger.error("Error fetching CVE %s: %s", cve_id, exc)
            return {"id": cve_id, "error": str(exc)}

    def search_cves_by_product(self, product_name: str, limit: int = 50) -> List[Dict[str, Any]]:
        cache_key = f"product:{product_name}:{limit}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            resp = self._session.get(
                settings.nist_nvd_url,
                params={"keywordSearch": product_name, "resultsPerPage": min(limit, 100)},
                timeout=settings.request_timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                cves: List[Dict[str, Any]] = []
                for vuln in data.get("vulnerabilities", []):
                    cve_data = vuln["cve"]
                    cves.append({
                        "id": cve_data["id"],
                        "description": self._extract_description(cve_data)[:200] + "...",
                        "severity": self._extract_severity(vuln),
                        "cvss_score": self._extract_cvss_score(vuln),
                        "published_date": cve_data.get("published", "Unknown"),
                    })
                self._cache[cache_key] = cves
                return cves
            return []
        except Exception as exc:
            logger.error("Error searching CVEs for %s: %s", product_name, exc)
            return []

    # ── Internals ────────────────────────────────────────────────────────

    @staticmethod
    def _extract_description(cve_data: Dict) -> str:
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                return desc.get("value", "No description available")
        return "No description available"

    @staticmethod
    def _extract_severity(vuln: Dict) -> str:
        metrics = vuln.get("metrics", {})
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
        if "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
        if "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", 0)
            if score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            return "LOW"
        return "UNKNOWN"

    @staticmethod
    def _extract_cvss_score(vuln: Dict) -> float:
        metrics = vuln.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                return metrics[key][0]["cvssData"].get("baseScore", 0.0)
        return 0.0

    @staticmethod
    def _extract_affected_products(cve_data: Dict) -> List[str]:
        products: set[str] = set()
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    parts = cpe.get("criteria", "").split(":")
                    if len(parts) >= 5:
                        products.add(f"{parts[3]}:{parts[4]}")
        return list(products)

    @staticmethod
    def _extract_references(cve_data: Dict) -> List[str]:
        return [ref["url"] for ref in cve_data.get("references", []) if ref.get("url")]

    @staticmethod
    def _extract_cwe_ids(cve_data: Dict) -> List[str]:
        cwe_ids: List[str] = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_ids.append(desc.get("value", ""))
        return cwe_ids
