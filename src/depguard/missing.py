"""Missing dependency detection — imported in code but not declared."""

from __future__ import annotations

from depguard.models import DependencyInfo, MissingDep
from depguard.utils import get_package_modules


def find_missing(
    declared_deps: list[DependencyInfo],
    third_party_imports: dict[str, set[str]],
    module_map: dict[str, list[str]],
) -> list[MissingDep]:
    """
    Find modules that are imported in code but not declared in dependency files.

    Args:
        declared_deps: Dependencies from requirements.txt / pyproject.toml
        third_party_imports: Module → files map from AST scanner (filtered to 3rd-party)
        module_map: Module name → package name mapping

    Returns:
        List of missing dependencies.
    """
    # Build a set of all module names that are covered by declared deps
    declared_modules: set[str] = set()
    for dep in declared_deps:
        for mod in get_package_modules(dep.name):
            declared_modules.add(mod)

    missing: list[MissingDep] = []

    for module, files in third_party_imports.items():
        module_lower = module.lower()

        # Skip if it's a first-party module (exists as a local directory/file)
        # This is handled by filtering before this function is called

        # Check if any declared dep covers this module
        if module_lower not in declared_modules:
            # Also check if the module name itself is a declared package
            dep_names_normalized = {
                d.name.lower().replace("-", "_").replace(".", "_")
                for d in declared_deps
            }
            if module_lower.replace("-", "_") not in dep_names_normalized:
                missing.append(
                    MissingDep(
                        module_name=module,
                        imported_in=sorted(files)[:10],  # Cap at 10 files
                    )
                )

    return missing
