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


def _extract_imports_from_file(filepath: str) -> tuple[set[str], set[str]]:
    """Parse a single .py file and extract runtime and optional import module names.

    Skips entirely:
    - Imports inside ``if TYPE_CHECKING:`` blocks (static-only, never run).
    
    Tags as Optional:
    - Imports inside ``try: ... except ImportError`` blocks (try, except, and else bodies).
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    except (OSError, IOError):
        return set(), set()

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        # Skip files with syntax errors (might be Python 2, templates, etc.)
        return set(), set()

    # ── Phase 1: collect line ranges we should ignore or treat as optional ──────────────
    skip_lines: set[int] = set()
    optional_lines: set[int] = set()

    for node in ast.walk(tree):
        # Bug 3 fix: skip `if TYPE_CHECKING:` blocks
        if isinstance(node, ast.If) and _is_type_checking_guard(node.test):
            for child in ast.walk(node):
                if hasattr(child, "lineno"):
                    skip_lines.add(child.lineno)

        # Bug 4 fix: try: ... except ImportError blocks
        if isinstance(node, ast.Try):
            has_import_error = any(
                (isinstance(h.type, ast.Name) and h.type.id in ("ImportError", "ModuleNotFoundError"))
                for h in node.handlers
                if h.type is not None
            )
            if has_import_error:
                # Treat the entire try-except-else block as optional
                for child in ast.walk(node):
                    if hasattr(child, "lineno"):
                        optional_lines.add(child.lineno)

    # ── Phase 2: collect imports, respecting skip_lines ────────────
    imports: set[str] = set()
    optional_imports: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if node.lineno in skip_lines:
                continue
            for alias in node.names:
                top_level = alias.name.split(".")[0]
                if node.lineno in optional_lines:
                    optional_imports.add(top_level)
                else:
                    imports.add(top_level)

        elif isinstance(node, ast.ImportFrom):
            if node.lineno in skip_lines:
                continue
            if node.module and node.level == 0:  # Skip relative imports (level > 0)
                top_level = node.module.split(".")[0]
                if node.lineno in optional_lines:
                    optional_imports.add(top_level)
                else:
                    imports.add(top_level)

    # If a module is marked as optional anywhere in this file (e.g., inside a try-block), 
    # treat ALL imports of it in this file as optional (they are likely guarded by if-statements).
    imports -= optional_imports

    return imports, optional_imports


def _is_type_checking_guard(test_node: ast.expr) -> bool:
    """Check if an ``if`` test is ``TYPE_CHECKING`` or ``t.TYPE_CHECKING``."""
    # bare: if TYPE_CHECKING:
    if isinstance(test_node, ast.Name) and test_node.id == "TYPE_CHECKING":
        return True
    # aliased: if t.TYPE_CHECKING:  or  if typing.TYPE_CHECKING:
    if isinstance(test_node, ast.Attribute) and test_node.attr == "TYPE_CHECKING":
        return True
    return False


def scan_imports(
    project_path: str,
    exclude_dirs: Optional[set[str]] = None,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """
    Scan all Python files in a project and extract imports.

    Args:
        project_path: Root directory of the project.
        exclude_dirs: Extra directory names to skip (e.g. {"tests", "docs"}).

    Returns:
        Tuple of two dicts: (required_import_map, optional_import_map)
        Mapping top-level module names to sets of files that import them.
    """
    import_map: dict[str, set[str]] = {}
    optional_map: dict[str, set[str]] = {}
    project = Path(project_path).resolve()

    for py_file in _find_python_files(str(project), extra_skip_dirs=exclude_dirs):
        file_imports, opt_imports = _extract_imports_from_file(py_file)
        relative = os.path.relpath(py_file, str(project))

        for module in file_imports:
            if module not in import_map:
                import_map[module] = set()
            import_map[module].add(relative)

        for module in opt_imports:
            if module not in optional_map:
                optional_map[module] = set()
            optional_map[module].add(relative)

    # Cross-file deduplication: if required anywhere, it isn't optional
    for module in import_map:
        if module in optional_map:
            del optional_map[module]

    return import_map, optional_map

