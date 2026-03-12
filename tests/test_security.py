"""Tests for security.py — OSV API vulnerability scanning."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from depguard.models import DependencyInfo, Severity
from depguard.security import (
    scan_vulnerabilities,
    _classify_severity,
    _extract_fix_version,
    _build_batch_query,
)


class TestClassifySeverity:
    """Tests for severity classification from OSV data."""

    def test_critical_cvss(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        severity, score = _classify_severity(vuln)
        assert severity == Severity.CRITICAL
        assert score == 9.8

    def test_high_cvss(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        severity, score = _classify_severity(vuln)
        assert severity == Severity.HIGH
        assert score == 7.5

    def test_medium_cvss(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "5.0"}]}
        severity, score = _classify_severity(vuln)
        assert severity == Severity.MEDIUM

    def test_low_cvss(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "2.0"}]}
        severity, score = _classify_severity(vuln)
        assert severity == Severity.LOW

    def test_database_specific_severity(self):
        vuln = {"database_specific": {"severity": "HIGH"}}
        severity, score = _classify_severity(vuln)
        assert severity == Severity.HIGH
        assert score is None

    def test_unknown_severity(self):
        vuln = {}
        severity, score = _classify_severity(vuln)
        assert severity == Severity.UNKNOWN


class TestExtractFixVersion:
    """Tests for fix version extraction."""

    def test_fix_version_found(self):
        vuln = {
            "affected": [{
                "ranges": [{
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.31.0"},
                    ]
                }]
            }]
        }
        assert _extract_fix_version(vuln) == "2.31.0"

    def test_no_fix_version(self):
        vuln = {"affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]}
        assert _extract_fix_version(vuln) is None

    def test_empty_vuln(self):
        assert _extract_fix_version({}) is None


class TestBuildBatchQuery:
    """Tests for batch query construction."""

    def test_query_structure(self):
        deps = [
            DependencyInfo(name="requests", installed_version="2.28.0"),
            DependencyInfo(name="flask", installed_version="3.0.0"),
        ]
        query = _build_batch_query(deps)
        assert "queries" in query
        assert len(query["queries"]) == 2
        assert query["queries"][0]["package"]["name"] == "requests"
        assert query["queries"][0]["package"]["ecosystem"] == "PyPI"
        assert query["queries"][0]["version"] == "2.28.0"

    def test_no_version(self):
        deps = [DependencyInfo(name="flask")]
        query = _build_batch_query(deps)
        assert "version" not in query["queries"][0]


class TestScanVulnerabilities:
    """Tests for the full scan function with mocked API."""

    @patch("depguard.security._load_cache", return_value={})
    @patch("depguard.security._save_cache")
    @patch("depguard.security.httpx.Client")
    def test_scan_with_vulns(self, mock_client_cls, mock_save, mock_load):
        """Test scanning with mocked OSV API returning vulnerabilities."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [{
                "vulns": [{
                    "id": "GHSA-test-1234",
                    "summary": "Test vulnerability",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                    "affected": [{
                        "ranges": [{"events": [{"fixed": "2.31.0"}]}]
                    }],
                }]
            }]
        }
        mock_response.raise_for_status = MagicMock()

        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {
            "id": "GHSA-test-1234",
            "summary": "Test vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "affected": [{
                "ranges": [{"events": [{"fixed": "2.31.0"}]}]
            }],
        }
        mock_get_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client.get.return_value = mock_get_response
        mock_client_cls.return_value = mock_client

        deps = [DependencyInfo(name="requests", installed_version="2.28.0")]
        vulns = scan_vulnerabilities(deps)

        assert len(vulns) == 1
        assert vulns[0].vuln_id == "GHSA-test-1234"
        assert vulns[0].severity == Severity.HIGH
        assert vulns[0].fix_version == "2.31.0"

    @patch("depguard.security._load_cache", return_value={})
    @patch("depguard.security._save_cache")
    @patch("depguard.security.httpx.Client")
    def test_scan_no_vulns(self, mock_client_cls, mock_save, mock_load):
        """Test scanning with no vulnerabilities found."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"results": [{"vulns": []}]}
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        deps = [DependencyInfo(name="flask", installed_version="3.0.0")]
        vulns = scan_vulnerabilities(deps)

        assert len(vulns) == 0

    def test_scan_empty_deps(self):
        """Scanning with no deps should return empty list immediately."""
        assert scan_vulnerabilities([]) == []
