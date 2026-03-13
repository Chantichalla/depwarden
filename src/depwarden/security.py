"""Security vulnerability scanner using the OSV.dev API."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

import httpx

from depwarden.models import DependencyInfo, Severity, VulnerabilityInfo

try:
    from cvss import CVSS3
except ImportError:
    CVSS3 = None

# OSV.dev batch query endpoint — free, no API key needed
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://osv.dev/vulnerability/"

# Local cache to avoid hammering the API
_CACHE_DIR = Path.home() / ".cache" / "depwarden"
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
                score = None
                if CVSS3 is not None and isinstance(score_str, str) and score_str.startswith("CVSS:3"):
                    try:
                        c = CVSS3(score_str)
                        score = c.scores()[0]
                    except Exception:
                        pass

            if score is not None:
                if score >= 9.0:
                    return Severity.CRITICAL, score
                if score >= 7.0:
                    return Severity.HIGH, score
                if score >= 4.0:
                    return Severity.MEDIUM, score
                return Severity.LOW, score

    # Fallback to database_specific severity or cvss dict
    db_specific = vuln_data.get("database_specific", {})
    db_severity = db_specific.get("severity")

    if not db_severity and "cvss" in db_specific:
        db_severity = db_specific["cvss"].get("severity")

    if db_severity:
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        return severity_map.get(db_severity.upper(), Severity.UNKNOWN), None

    # Try specific ecosystem formats
    for affected in vuln_data.get("affected", []):
        db_specific = affected.get("database_specific", {})
        if "cwes" in db_specific and not db_severity:
            # If we only have CWEs but no severity string, we at least know it's a real vulnerability
            pass

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

    # Filter out deps with no known version — querying OSV without a
    # version returns EVERY historical CVE, flooding the report with
    # false positives.  Warn the user instead.
    import sys

    scannable_deps: list[DependencyInfo] = []
    for dep in deps:
        if not dep.installed_version:
            print(
                f"  ⚠️  Skipped CVE scan for {dep.name} (version unknown"
                " — install deps first)",
                file=sys.stderr,
            )
        else:
            scannable_deps.append(dep)

    if not scannable_deps:
        return []

    cache = _load_cache()
    results: list[VulnerabilityInfo] = []
    deps_to_query: list[DependencyInfo] = []

    # Check cache first
    for dep in scannable_deps:
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
                    
                    # Deduplicate vulnerabilities returned by OSV
                    seen_vulns = set()

                    for basic_vuln in result.get("vulns", []):
                        vuln_id = basic_vuln.get("id", "UNKNOWN")
                        
                        # Skip if we already processed this vulnerability for this package
                        if (dep.name, vuln_id) in seen_vulns:
                            continue
                        seen_vulns.add((dep.name, vuln_id))
                        
                        if vuln_id != "UNKNOWN":
                            try:
                                # Fetch full OSV JSON for this specific vulnerability
                                # because the Batch API strips summary and cvss details
                                vuln_resp = client.get(f"https://api.osv.dev/v1/vulns/{vuln_id}")
                                vuln_resp.raise_for_status()
                                vuln_full = vuln_resp.json()
                            except httpx.HTTPError:
                                vuln_full = basic_vuln
                        else:
                            vuln_full = basic_vuln

                        severity, cvss_score = _classify_severity(vuln_full)
                        fix_version = _extract_fix_version(vuln_full)

                        summary = vuln_full.get("summary")
                        if not summary:
                            details = vuln_full.get("details", "No details provided.")
                            # Truncate to first sentence or 80 chars
                            summary = details.split('\n')[0][:80]
                            if len(details) > 80:
                                summary += "..."

                        vuln_info = VulnerabilityInfo(
                            dep_name=dep.name,
                            vuln_id=vuln_id,
                            summary=summary,
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
                f"[depwarden] Warning: Could not reach OSV API: {e}",
                file=sys.stderr,
            )
        except Exception as e:
            import sys
            print(
                f"[depwarden] Warning: Security scan error: {e}",
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
