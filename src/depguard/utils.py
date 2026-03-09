"""Utility functions — package↔module mapping and stdlib detection."""

from __future__ import annotations

import sys
from typing import Optional

# Hardcoded mappings for common PyPI packages where the import name
# differs from the package name. This handles cases where the package
# isn't installed but is declared in requirements.
KNOWN_PACKAGE_TO_MODULE: dict[str, str] = {
    "pillow": "PIL",
    "beautifulsoup4": "bs4",
    "opencv-python": "cv2",
    "opencv-python-headless": "cv2",
    "scikit-learn": "sklearn",
    "scikit-image": "skimage",
    "pyyaml": "yaml",
    "python-dateutil": "dateutil",
    "python-dotenv": "dotenv",
    "pygobject": "gi",
    "attrs": "attr",
    "pyserial": "serial",
    "pymysql": "MySQLdb",
    "python-jose": "jose",
    "python-multipart": "multipart",
    "pyjwt": "jwt",
    "pysocks": "socks",
    "python-magic": "magic",
    "pycryptodome": "Crypto",
    "google-cloud-storage": "google.cloud.storage",
    "google-auth": "google.auth",
    "msgpack-python": "msgpack",
    "ruamel-yaml": "ruamel",
    "setuptools": "pkg_resources",
}

# Reverse mapping: module → package
KNOWN_MODULE_TO_PACKAGE: dict[str, str] = {
    v.lower(): k for k, v in KNOWN_PACKAGE_TO_MODULE.items()
}


def get_module_to_package_map() -> dict[str, list[str]]:
    """
    Build a mapping of importable module names to distribution package names.

    Uses importlib.metadata.packages_distributions() (Python 3.11+)
    with fallback to our hardcoded mappings.
    """
    mapping: dict[str, list[str]] = {}

    try:
        from importlib.metadata import packages_distributions
        mapping = packages_distributions()
    except ImportError:
        # Python < 3.11 — fall back to hardcoded
        pass

    # Merge our known mappings (they override in case of conflicts)
    for package, module in KNOWN_PACKAGE_TO_MODULE.items():
        module_lower = module.split(".")[0].lower()
        if module_lower not in mapping:
            mapping[module_lower] = []
        if package not in mapping[module_lower]:
            mapping[module_lower].append(package)

    return mapping


def get_package_modules(package_name: str) -> set[str]:
    """Get the importable module name(s) for a given package name."""
    modules: set[str] = set()

    # Check hardcoded mappings first
    normalized = package_name.lower().replace("-", "_").replace(".", "_")
    known = KNOWN_PACKAGE_TO_MODULE.get(package_name.lower())
    if known:
        modules.add(known.split(".")[0].lower())

    # Try importlib.metadata
    try:
        from importlib.metadata import packages_distributions
        pkg_dist = packages_distributions()
        for module_name, dists in pkg_dist.items():
            norm_dists = [
                d.lower().replace("-", "_").replace(".", "_") for d in dists
            ]
            if normalized in norm_dists:
                modules.add(module_name.lower())
    except ImportError:
        pass

    # Fallback: package name often IS the module name
    if not modules:
        modules.add(normalized)

    return modules


def get_stdlib_modules() -> set[str]:
    """Get the set of Python standard library module names."""
    stdlib = set()
    if hasattr(sys, "stdlib_module_names"):
        # Python 3.10+
        stdlib = set(sys.stdlib_module_names)
    else:
        # Fallback for older Python — a reasonable approximation
        import pkgutil
        for module in pkgutil.iter_modules():
            stdlib.add(module.name)
            
    # Always include these, even on older Pythons where they might be polyfilled
    stdlib.update({"tomllib", "importlib"})
    return stdlib


def filter_third_party(import_map: dict[str, set[str]], project_path: str) -> dict[str, set[str]]:
    """Filter to only third-party modules (no stdlib, no local first-party files)."""
    import os
    stdlib = {s.lower() for s in get_stdlib_modules()}
    filtered = {}
    
    for module, files in import_map.items():
        mod_lower = module.lower()
        if mod_lower in stdlib:
            continue
            
        # Check if it's a local file/directory (first-party)
        # Check root level
        if os.path.exists(os.path.join(project_path, f"{module}.py")) or \
           os.path.isdir(os.path.join(project_path, module)):
            continue
            
        # Check src/ level
        if os.path.exists(os.path.join(project_path, "src", f"{module}.py")) or \
           os.path.isdir(os.path.join(project_path, "src", module)):
            continue
            
        filtered[module] = files
        
    return filtered
