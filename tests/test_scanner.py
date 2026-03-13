"""Tests for scanner.py — AST-based import scanning."""

from __future__ import annotations

from pathlib import Path

import pytest

from depwarden.scanner import scan_imports, _extract_imports_from_file


class TestExtractImports:
    """Tests for single-file import extraction."""

    def test_basic_import(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("import requests\nimport os\n")
        imports, _ = _extract_imports_from_file(str(f))
        assert "requests" in imports
        assert "os" in imports

    def test_from_import(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("from flask import Flask, jsonify\n")
        imports, _ = _extract_imports_from_file(str(f))
        assert "flask" in imports

    def test_dotted_import(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("import os.path\nfrom email.mime.text import MIMEText\n")
        imports, _ = _extract_imports_from_file(str(f))
        assert "os" in imports
        assert "email" in imports

    def test_relative_import_skipped(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("from . import utils\nfrom ..models import Foo\n")
        imports, _ = _extract_imports_from_file(str(f))
        assert "utils" not in imports
        assert "models" not in imports

    def test_syntax_error_handled(self, tmp_path):
        f = tmp_path / "bad.py"
        f.write_text("def broken(\n")
        imports, _ = _extract_imports_from_file(str(f))
        assert imports == set()

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.py"
        f.write_text("")
        imports, _ = _extract_imports_from_file(str(f))
        assert imports == set()


class TestScanImports:
    """Tests for project-wide import scanning."""

    def test_scan_project(self, tmp_path):
        (tmp_path / "app.py").write_text("import flask\nimport requests\n")
        (tmp_path / "utils.py").write_text("import json\nimport flask\n")

        import_map, _ = scan_imports(str(tmp_path))

        assert "flask" in import_map
        assert len(import_map["flask"]) == 2  # in both files
        assert "requests" in import_map
        assert "json" in import_map

    def test_skips_venv(self, tmp_path):
        """Should not scan inside .venv/venv directories."""
        (tmp_path / "app.py").write_text("import flask\n")
        venv_dir = tmp_path / ".venv" / "lib" / "site-packages"
        venv_dir.mkdir(parents=True)
        (venv_dir / "package.py").write_text("import secret_thing\n")

        import_map, _ = scan_imports(str(tmp_path))
        assert "flask" in import_map
        assert "secret_thing" not in import_map

    def test_skips_pycache(self, tmp_path):
        (tmp_path / "app.py").write_text("import flask\n")
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "cached.py").write_text("import old_stuff\n")

        import_map, _ = scan_imports(str(tmp_path))
        assert "old_stuff" not in import_map

    def test_healthy_fixture(self, healthy_project):
        """Test scanning the healthy fixture project."""
        import_map, _ = scan_imports(healthy_project)
        assert "flask" in import_map
        assert "requests" in import_map
