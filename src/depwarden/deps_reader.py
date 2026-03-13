"""Parse dependency files (requirements.txt, pyproject.toml)."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from depwarden.models import DependencyInfo

# Regex to split a requirement line into name and version spec
# Matches: flask==2.3.0, requests>=2.28, numpy~=1.24, pandas
_REQ_PATTERN = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"(.*)$"  # everything else (version spec, extras, etc.)
)

# Patterns to skip in requirements files
_SKIP_PREFIXES = ("-e", "--", "#", "git+", "http://", "https://")


def _parse_requirement_line(line: str, source_file: str) -> Optional[DependencyInfo]:
    """Parse a single requirement line into a DependencyInfo."""
    line = line.strip()

    # Skip empty, comments, options, editable installs, URLs
    if not line or any(line.startswith(p) for p in _SKIP_PREFIXES):
        return None

    # Strip inline comments
    if " #" in line:
        line = line[: line.index(" #")].strip()

    # Strip extras like requests[security]
    if "[" in line:
        bracket_start = line.index("[")
        bracket_end = line.index("]") + 1 if "]" in line else bracket_start
        line = line[:bracket_start] + line[bracket_end:]

    # Strip environment markers like ; python_version >= "3.8"
    if ";" in line:
        line = line[: line.index(";")].strip()

    match = _REQ_PATTERN.match(line)
    if not match:
        return None

    name = match.group(1).strip()
    version_spec = match.group(3).strip() or None

    return DependencyInfo(
        name=name,
        version_spec=version_spec,
        source_file=source_file,
    )


def parse_requirements_txt(filepath: str) -> list[DependencyInfo]:
    """Parse a requirements.txt file into a list of DependencyInfo."""
    deps: list[DependencyInfo] = []
    filepath = os.path.abspath(filepath)
    base_dir = os.path.dirname(filepath)

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            # Handle -r / -c includes (recursive)
            if line.startswith(("-r ", "-c ")):
                included = line.split(None, 1)[1].strip()
                included_path = os.path.join(base_dir, included)
                if os.path.exists(included_path):
                    deps.extend(parse_requirements_txt(included_path))
                continue

            dep = _parse_requirement_line(line, filepath)
            if dep:
                deps.append(dep)

    return deps


def parse_pyproject_toml(filepath: str) -> list[DependencyInfo]:
    """Parse pyproject.toml for dependencies."""
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]

    deps: list[DependencyInfo] = []

    with open(filepath, "rb") as f:
        data = tomllib.load(f)

    # PEP 621: [project.dependencies]
    project_deps = data.get("project", {}).get("dependencies", [])
    for dep_str in project_deps:
        dep = _parse_requirement_line(dep_str, filepath)
        if dep:
            deps.append(dep)

    # PEP 621: [project.optional-dependencies] (dev, test, docs, etc.)
    optional_deps = data.get("project", {}).get("optional-dependencies", {})
    for group_name, group_deps in optional_deps.items():
        for dep_str in group_deps:
            dep = _parse_requirement_line(dep_str, filepath)
            if dep:
                dep.is_dev = True
                deps.append(dep)

    # Poetry: [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, version in poetry_deps.items():
        if name.lower() == "python":
            continue
        version_spec = None
        if isinstance(version, str):
            version_spec = version if version != "*" else None
        elif isinstance(version, dict):
            version_spec = version.get("version")
        deps.append(
            DependencyInfo(name=name, version_spec=version_spec, source_file=filepath)
        )

    # Poetry: [tool.poetry.group.*.dependencies] (dev, test, etc.)
    poetry_groups = data.get("tool", {}).get("poetry", {}).get("group", {})
    for group_name, group_data in poetry_groups.items():
        for name, version in group_data.get("dependencies", {}).items():
            if name.lower() == "python":
                continue
            version_spec = None
            if isinstance(version, str):
                version_spec = version if version != "*" else None
            elif isinstance(version, dict):
                version_spec = version.get("version")
            deps.append(
                DependencyInfo(
                    name=name, version_spec=version_spec,
                    source_file=filepath, is_dev=True,
                )
            )

    return deps


def parse_setup_cfg(filepath: str) -> list[DependencyInfo]:
    """Parse setup.cfg [options] install_requires."""
    import configparser

    deps: list[DependencyInfo] = []
    config = configparser.ConfigParser()
    config.read(filepath, encoding="utf-8")

    install_requires = config.get("options", "install_requires", fallback="")
    for line in install_requires.strip().splitlines():
        dep = _parse_requirement_line(line, filepath)
        if dep:
            deps.append(dep)

    return deps


def _resolve_installed_version(dep: DependencyInfo) -> DependencyInfo:
    """Try to resolve the installed version of a dependency."""
    try:
        from importlib.metadata import version

        dep.installed_version = version(dep.name)
    except Exception:
        pass
    return dep


def read_dependencies(project_path: str) -> list[DependencyInfo]:
    """Auto-detect and parse dependency files from a project."""
    project = Path(project_path)
    deps: list[DependencyInfo] = []

    # Priority: pyproject.toml > requirements.txt > setup.cfg
    pyproject = project / "pyproject.toml"
    requirements = project / "requirements.txt"
    setup_cfg = project / "setup.cfg"

    if pyproject.exists():
        deps = parse_pyproject_toml(str(pyproject))
        
    if not deps and requirements.exists():
        deps = parse_requirements_txt(str(requirements))
        
    if not deps and setup_cfg.exists():
        deps = parse_setup_cfg(str(setup_cfg))
        
    if not deps:
        # Try to find any requirements*.txt
        for f in sorted(project.glob("requirements*.txt")):
            deps.extend(parse_requirements_txt(str(f)))

    if not deps:
        raise FileNotFoundError(
            f"No dependency files found in {project_path}. "
            "Expected: pyproject.toml, requirements.txt, or setup.cfg"
        )

    # Deduplicate by name (keep first occurrence)
    seen: set[str] = set()
    unique_deps: list[DependencyInfo] = []
    for dep in deps:
        normalized = dep.name.lower().replace("-", "_").replace(".", "_")
        if normalized not in seen:
            seen.add(normalized)
            unique_deps.append(dep)

    # Resolve installed versions
    unique_deps = [_resolve_installed_version(d) for d in unique_deps]

    return unique_deps
