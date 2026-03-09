"""Tests for cli.py — CLI commands and exit codes."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from depguard.cli import app

runner = CliRunner()


class TestScanCommand:
    """Tests for the `depguard scan` CLI command."""

    def test_scan_healthy_project(self, healthy_project):
        """Scanning a healthy fixture should succeed (exit 0)."""
        result = runner.invoke(app, ["scan", healthy_project, "--no-security"])
        assert result.exit_code == 0
        assert "depguard" in result.output

    def test_scan_nonexistent_path(self):
        """Scanning a nonexistent path should fail (exit 2)."""
        result = runner.invoke(app, ["scan", "/nonexistent/path"])
        assert result.exit_code == 2

    def test_scan_json_format(self, healthy_project):
        """JSON output should be parseable."""
        import json
        result = runner.invoke(
            app, ["scan", healthy_project, "--format", "json", "--no-security"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "project_path" in data
        assert "health" in data

    def test_scan_no_deps_file(self, tmp_path):
        """Scanning a dir with no dependency files should fail (exit 2)."""
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 2

    def test_scan_with_no_security(self, healthy_project):
        """--no-security should skip the security scan."""
        result = runner.invoke(app, ["scan", healthy_project, "--no-security"])
        assert result.exit_code == 0

    def test_scan_with_no_bloat(self, healthy_project):
        """--no-bloat should skip bloat analysis."""
        result = runner.invoke(
            app, ["scan", healthy_project, "--no-security", "--no-bloat"]
        )
        assert result.exit_code == 0


class TestVersionCommand:
    """Tests for the `depguard version` command."""

    def test_version_output(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "depguard v" in result.output
