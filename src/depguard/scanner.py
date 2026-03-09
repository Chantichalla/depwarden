"""AST-based import scanner — walks all .py files and extracts imports."""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Optional

# Directories always skipped (venvs, caches, build artifacts)
SKIP_DIRS = {
    ".venv", "venv", "env", ".env",
    "__pycache__", ".git", ".hg", ".svn",
    "node_modules", ".tox", ".nox",
    "build", "dist", ".eggs",
    "site-packages",
}


def _find_python_files(
    project_path: str,
    extra_skip_dirs: Optional[set[str]] = None,
) -> list[str]:
    """Find all .py files in the project, skipping virtual envs and caches."""
    py_files: list[str] = []
    skip = SKIP_DIRS | (extra_skip_dirs or set())

    for root, dirs, files in os.walk(project_path):
        # Remove skip dirs in-place so os.walk doesn't descend into them
        dirs[:] = [d for d in dirs if d not in skip]

        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))

    return py_files


def _extract_imports_from_file(filepath: str) -> set[str]:
    """Parse a single .py file and extract all top-level import module names."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    except (OSError, IOError):
        return set()

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        # Skip files with syntax errors (might be Python 2, templates, etc.)
        return set()

    imports: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # import requests, import os
            for alias in node.names:
                top_level = alias.name.split(".")[0]
                imports.add(top_level)

        elif isinstance(node, ast.ImportFrom):
            # from flask import Flask
            if node.module and node.level == 0:  # Skip relative imports (level > 0)
                top_level = node.module.split(".")[0]
                imports.add(top_level)

    return imports


def scan_imports(
    project_path: str,
    exclude_dirs: Optional[set[str]] = None,
) -> dict[str, set[str]]:
    """
    Scan all Python files in a project and extract imports.

    Args:
        project_path: Root directory of the project.
        exclude_dirs: Extra directory names to skip (e.g. {"tests", "docs"}).

    Returns:
        Dict mapping top-level module names to sets of files that import them.
        Example: {"flask": {"app.py", "routes.py"}, "requests": {"api.py"}}
    """
    import_map: dict[str, set[str]] = {}
    project = Path(project_path).resolve()

    for py_file in _find_python_files(str(project), extra_skip_dirs=exclude_dirs):
        file_imports = _extract_imports_from_file(py_file)
        relative = os.path.relpath(py_file, str(project))

        for module in file_imports:
            if module not in import_map:
                import_map[module] = set()
            import_map[module].add(relative)

    return import_map

