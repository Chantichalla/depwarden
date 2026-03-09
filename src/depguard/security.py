"""Security vulnerability scanner using the OSV.dev API."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

import httpx

from depguard.models import DependencyInfo, Severity, VulnerabilityInfo

# OSV.dev batch query endpoint — free, no API key needed
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://osv.dev/vulnerability/"

# Local cache to avoid hammering the API
_CACHE_DIR = Path.home() / ".cache" / "depguard"
_CACHE_FILE = _CACHE_DIR / "osv_cache.json"
_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours


def _load_cache() -> dict:
    """Load cached vulnerability results."""
    if not _CACHE_FILE.exists():
        return {}
    try:
        data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
        # Expire old cache
        if time.time() - data.get("_timestamp", 0) > _CACHE_TTL_SECONDS:
            return {}
        return data
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict) -> None:
    """Save vulnerability results to local cache."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache["_timestamp"] = time.time()
    _CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def _classify_severity(vuln_data: dict) -> tuple[Severity, Optional[float]]:
    """Extract severity and CVSS score from an OSV vulnerability entry."""
    severity_list = vuln_data.get("severity", [])
    for sev in severity_list:
        if sev.get("type") == "CVSS_V3":
            score_str = sev.get("score", "")
            try:
                score = float(score_str)
            except (ValueError, TypeError):
                # CVSS_V3 score might be a vector string, parse the score
                # from database_specific or just use severity mapping
                score = None

            if score is not None:
                if score >= 9.0:
                    return Severity.CRITICAL, score
                if score >= 7.0:
                    return Severity.HIGH, score
                if score >= 4.0:
                    return Severity.MEDIUM, score
                return Severity.LOW, score

    # Fallback: check database_specific severity
    db_severity = vuln_data.get("database_specific", {}).get("severity")
    if db_severity:
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        return severity_map.get(db_severity.upper(), Severity.UNKNOWN), None

    return Severity.UNKNOWN, None


def _extract_fix_version(vuln_data: dict) -> Optional[str]:
    """Extract the fix version from an OSV vulnerability entry."""
    for affected in vuln_data.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _build_batch_query(deps: list[DependencyInfo]) -> dict:
    """Build a batch query for the OSV API."""
    queries = []
    for dep in deps:
        query: dict = {
            "package": {
                "name": dep.name,
                "ecosystem": "PyPI",
            }
        }
        # Include version if available for more precise results
        version = dep.installed_version
        if version:
            query["version"] = version
        queries.append(query)

    return {"queries": queries}


def scan_vulnerabilities(
    deps: list[DependencyInfo],
    timeout: float = 30.0,
) -> list[VulnerabilityInfo]:
    """
    Scan dependencies for known vulnerabilities using the OSV.dev API.

    Args:
        deps: List of dependencies to scan.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of discovered vulnerabilities.
    """
    if not deps:
        return []

    cache = _load_cache()
    results: list[VulnerabilityInfo] = []
    deps_to_query: list[DependencyInfo] = []

    # Check cache first
    for dep in deps:
        cache_key = f"{dep.name}:{dep.installed_version or 'latest'}"
        cached = cache.get(cache_key)
        if cached is not None:
            for v in cached:
                results.append(VulnerabilityInfo(**v))
        else:
            deps_to_query.append(dep)

    # Query OSV for uncached deps
    if deps_to_query:
        try:
            batch_query = _build_batch_query(deps_to_query)

            with httpx.Client(timeout=timeout) as client:
                response = client.post(OSV_BATCH_URL, json=batch_query)
                response.raise_for_status()
                data = response.json()

            # Process batch results
            batch_results = data.get("results", [])
            for dep, result in zip(deps_to_query, batch_results):
                cache_key = f"{dep.name}:{dep.installed_version or 'latest'}"
                dep_vulns: list[VulnerabilityInfo] = []

                for vuln in result.get("vulns", []):
                    severity, cvss_score = _classify_severity(vuln)
                    fix_version = _extract_fix_version(vuln)
                    vuln_id = vuln.get("id", "UNKNOWN")

                    vuln_info = VulnerabilityInfo(
                        dep_name=dep.name,
                        vuln_id=vuln_id,
                        summary=vuln.get("summary", "No summary available"),
                        severity=severity,
                        cvss_score=cvss_score,
                        fix_version=fix_version,
                        url=f"{OSV_VULN_URL}{vuln_id}",
                    )
                    dep_vulns.append(vuln_info)

                results.extend(dep_vulns)
                # Cache as dicts
                cache[cache_key] = [v.model_dump() for v in dep_vulns]

            _save_cache(cache)

        except httpx.HTTPError as e:
            # Network error — return what we have from cache, don't crash
            # The tool should degrade gracefully
            import sys
            print(
                f"[depguard] Warning: Could not reach OSV API: {e}",
                file=sys.stderr,
            )
        except Exception as e:
            import sys
            print(
                f"[depguard] Warning: Security scan error: {e}",
                file=sys.stderr,
            )

    # Sort by severity (critical first)
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.UNKNOWN: 4,
    }
    results.sort(key=lambda v: severity_order.get(v.severity, 5))

    return results
