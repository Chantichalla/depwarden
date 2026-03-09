"""Shared fixtures for depguard tests."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def healthy_project():
    """Path to a fixture project with no issues."""
    return str(FIXTURES_DIR / "healthy_project")


@pytest.fixture
def vulnerable_project():
    """Path to a fixture project with known vulnerable deps."""
    return str(FIXTURES_DIR / "vulnerable_project")


@pytest.fixture
def bloated_project():
    """Path to a fixture project with bloated deps."""
    return str(FIXTURES_DIR / "bloated_project")


@pytest.fixture
def tmp_project(tmp_path):
    """Create a temporary project directory for dynamic test scenarios."""
    proj = tmp_path / "test_project"
    proj.mkdir()
    return proj


@pytest.fixture
def make_requirements(tmp_project):
    """Factory fixture: write a requirements.txt in the tmp project."""
    def _make(content: str):
        req_file = Path(tmp_project) / "requirements.txt"
        req_file.write_text(content, encoding="utf-8")
        return str(req_file)
    return _make


@pytest.fixture
def make_pyproject(tmp_project):
    """Factory fixture: write a pyproject.toml in the tmp project."""
    def _make(content: str):
        toml_file = Path(tmp_project) / "pyproject.toml"
        toml_file.write_text(content, encoding="utf-8")
        return str(toml_file)
    return _make


@pytest.fixture
def make_py_file(tmp_project):
    """Factory fixture: write a .py file in the tmp project."""
    def _make(filename: str, content: str):
        py_file = Path(tmp_project) / filename
        py_file.parent.mkdir(parents=True, exist_ok=True)
        py_file.write_text(content, encoding="utf-8")
        return str(py_file)
    return _make
