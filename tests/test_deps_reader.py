"""Tests for deps_reader — parsing requirements.txt, pyproject.toml, setup.cfg."""

from __future__ import annotations

import pytest

from depguard.deps_reader import (
    parse_requirements_txt,
    parse_pyproject_toml,
    read_dependencies,
)


class TestParseRequirementsTxt:
    """Tests for requirements.txt parsing."""

    def test_basic_requirements(self, make_requirements, tmp_project):
        make_requirements("flask==3.0.0\nrequests>=2.28.0\npandas\n")
        deps = read_dependencies(str(tmp_project))
        names = [d.name for d in deps]
        assert "flask" in names
        assert "requests" in names
        assert "pandas" in names
        assert len(deps) == 3

    def test_version_specifiers(self, make_requirements, tmp_project):
        make_requirements("flask==3.0.0\nrequests>=2.28.0\nnumpy~=1.24\n")
        deps = read_dependencies(str(tmp_project))
        flask_dep = next(d for d in deps if d.name == "flask")
        assert flask_dep.version_spec == "==3.0.0"

    def test_comments_and_blank_lines(self, make_requirements, tmp_project):
        content = "# This is a comment\n\nflask==3.0.0\n\n# Another comment\nrequests\n"
        make_requirements(content)
        deps = read_dependencies(str(tmp_project))
        assert len(deps) == 2

    def test_inline_comments(self, make_requirements, tmp_project):
        make_requirements("flask==3.0.0  # web framework\nrequests>=2.28 # http\n")
        deps = read_dependencies(str(tmp_project))
        names = [d.name for d in deps]
        assert "flask" in names
        assert "requests" in names

    def test_extras(self, make_requirements, tmp_project):
        make_requirements("requests[security]==2.31.0\n")
        deps = read_dependencies(str(tmp_project))
        assert deps[0].name == "requests"

    def test_editable_installs_skipped(self, make_requirements, tmp_project):
        make_requirements("-e git+https://github.com/foo/bar.git\nflask==3.0.0\n")
        deps = read_dependencies(str(tmp_project))
        assert len(deps) == 1
        assert deps[0].name == "flask"

    def test_deduplication(self, make_requirements, tmp_project):
        make_requirements("flask==3.0.0\nFlask==3.0.0\n")
        deps = read_dependencies(str(tmp_project))
        assert len(deps) == 1

    def test_no_deps_file_raises(self, tmp_project):
        with pytest.raises(FileNotFoundError):
            read_dependencies(str(tmp_project))


class TestParsePyprojectToml:
    """Tests for pyproject.toml parsing."""

    def test_pep621_format(self, make_pyproject, tmp_project):
        content = """
[project]
name = "myproject"
dependencies = [
    "flask>=3.0",
    "requests>=2.28",
]
"""
        make_pyproject(content)
        deps = read_dependencies(str(tmp_project))
        names = [d.name for d in deps]
        assert "flask" in names
        assert "requests" in names

    def test_poetry_format(self, make_pyproject, tmp_project):
        content = """
[tool.poetry.dependencies]
python = "^3.10"
flask = "^3.0"
requests = "^2.28"
"""
        make_pyproject(content)
        deps = read_dependencies(str(tmp_project))
        names = [d.name for d in deps]
        assert "flask" in names
        assert "requests" in names
        assert "python" not in names  # Python itself should be skipped


class TestAutoDetection:
    """Tests for auto-detecting dependency files."""

    def test_prefers_pyproject(self, tmp_project):
        """pyproject.toml should be preferred over requirements.txt."""
        from pathlib import Path

        (Path(tmp_project) / "pyproject.toml").write_text(
            '[project]\ndependencies = ["flask"]\n',
            encoding="utf-8",
        )
        (Path(tmp_project) / "requirements.txt").write_text(
            "requests\n",
            encoding="utf-8",
        )

        deps = read_dependencies(str(tmp_project))
        names = [d.name for d in deps]
        assert "flask" in names
        assert "requests" not in names  # requirements.txt should be ignored
