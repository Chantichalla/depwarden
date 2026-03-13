"""Bloat analysis — transitive dependency counting and size estimation."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, requires, metadata
from typing import Optional

from depwarden.models import BloatEntry, DependencyInfo

# Thresholds for flagging bloat
TRANSITIVE_DEP_THRESHOLD = 20
INSTALL_SIZE_THRESHOLD_MB = 50


def _get_direct_requires(package_name: str) -> list[str]:
    """Get the direct dependencies of an installed package."""
    try:
        reqs = requires(package_name)
    except PackageNotFoundError:
        return []

    if reqs is None:
        return []

    direct: list[str] = []
    for req in reqs:
        # Skip extras/conditional deps like: foo ; extra == "dev"
        if ";" in req and "extra" in req.split(";")[1]:
            continue

        # Extract just the package name (before any version spec)
        name = req.split(";")[0].strip()
        for sep in (">=", "<=", "==", "!=", "~=", ">", "<", "["):
            name = name.split(sep)[0].strip()

        if name:
            direct.append(name)

    return direct


def _resolve_full_tree(
    package_name: str,
    visited: Optional[set[str]] = None,
) -> set[str]:
    """Recursively resolve the full transitive dependency tree."""
    if visited is None:
        visited = set()

    normalized = package_name.lower().replace("-", "_").replace(".", "_")
    if normalized in visited:
        return visited

    visited.add(normalized)

    for req in _get_direct_requires(package_name):
        _resolve_full_tree(req, visited)

    return visited


def _estimate_install_size(package_name: str) -> Optional[int]:
    """Estimate installed size from package metadata (if available)."""
    try:
        meta = metadata(package_name)
        # Some packages report their installed size — but many don't.
        # We'll try metadata first, then fall back to None.
        # Unfortunately there's no standard metadata field for install size.
        # We can check the RECORD file but that requires reading filesystem.
        return None
    except PackageNotFoundError:
        return None


def analyze_bloat(deps: list[DependencyInfo]) -> list[BloatEntry]:
    """
    Analyze dependency bloat: transitive dep counts and install sizes.

    Args:
        deps: List of declared dependencies to analyze.

    Returns:
        List of BloatEntry with analysis for each dependency.
    """
    entries: list[BloatEntry] = []

    for dep in deps:
        # Resolve full transitive tree
        full_tree = _resolve_full_tree(dep.name)
        # Remove the package itself from the tree count
        normalized_self = dep.name.lower().replace("-", "_").replace(".", "_")
        transitive = full_tree - {normalized_self}

        transitive_count = len(transitive)
        install_size = _estimate_install_size(dep.name)

        # Determine if bloated
        is_bloated = transitive_count > TRANSITIVE_DEP_THRESHOLD
        reasons: list[str] = []

        if transitive_count > TRANSITIVE_DEP_THRESHOLD:
            reasons.append(
                f"pulls {transitive_count} transitive dependencies "
                f"(threshold: {TRANSITIVE_DEP_THRESHOLD})"
            )

        if install_size and install_size > INSTALL_SIZE_THRESHOLD_MB * 1024 * 1024:
            is_bloated = True
            size_mb = install_size / (1024 * 1024)
            reasons.append(f"install size ~{size_mb:.0f}MB")

        entry = BloatEntry(
            dep_name=dep.name,
            installed_version=dep.installed_version,
            transitive_count=transitive_count,
            transitive_deps=sorted(transitive),
            install_size_bytes=install_size,
            is_bloated=is_bloated,
            reason="; ".join(reasons) if reasons else "OK",
        )
        entries.append(entry)

    # Sort by transitive count (heaviest first)
    entries.sort(key=lambda e: e.transitive_count, reverse=True)

    return entries


def get_dependency_tree(package_name: str, depth: int = 0, max_depth: int = 3) -> dict:
    """
    Get a nested dependency tree for visualization.

    Returns a dict like: {"name": "flask", "deps": [{"name": "werkzeug", "deps": [...]}]}
    """
    if depth >= max_depth:
        return {"name": package_name, "deps": [], "truncated": True}

    direct = _get_direct_requires(package_name)
    children = []
    for req in direct:
        children.append(get_dependency_tree(req, depth + 1, max_depth))

    return {"name": package_name, "deps": children, "truncated": False}
