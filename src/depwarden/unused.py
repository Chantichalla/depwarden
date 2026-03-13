"""Unused dependency detection — declared but never imported in the project."""

from __future__ import annotations

from depwarden.models import DependencyInfo, UnusedDep
from depwarden.utils import get_package_modules


def find_unused(
    declared_deps: list[DependencyInfo],
    third_party_imports: dict[str, set[str]],
    module_map: dict[str, list[str]],
) -> list[UnusedDep]:
    """
    Find dependencies that are declared but never imported in any .py file.

    Args:
        declared_deps: Dependencies from requirements.txt / pyproject.toml
        third_party_imports: Module → files map from AST scanner (filtered to 3rd-party)
        module_map: Module name → package name mapping

    Returns:
        List of unused dependencies.
    """
    imported_modules = {m.lower() for m in third_party_imports.keys()}
    unused: list[UnusedDep] = []

    for dep in declared_deps:
        # Dev-only dependencies (from [project.optional-dependencies]) are expected
        # to be unused in production code — skip them
        if dep.is_dev:
            continue

        # Get all possible module names for this package
        possible_modules = get_package_modules(dep.name)

        # Check if any of the possible module names are imported
        is_used = any(mod in imported_modules for mod in possible_modules)

        if not is_used:
            unused.append(
                UnusedDep(dep_name=dep.name, source_file=dep.source_file)
            )

    return unused
