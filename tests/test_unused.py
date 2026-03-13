"""Tests for unused.py — unused dependency detection."""

from __future__ import annotations

import pytest

from depwarden.models import DependencyInfo
from depwarden.unused import find_unused


class TestFindUnused:
    """Tests for unused dependency detection."""

    def test_all_used(self):
        """No unused deps when all are imported."""
        deps = [
            DependencyInfo(name="flask"),
            DependencyInfo(name="requests"),
        ]
        imports = {"flask": {"app.py"}, "requests": {"api.py"}}
        module_map = {}

        unused = find_unused(deps, imports, module_map)
        assert len(unused) == 0

    def test_one_unused(self):
        """Detect a dep that is declared but never imported."""
        deps = [
            DependencyInfo(name="flask"),
            DependencyInfo(name="pandas"),
        ]
        imports = {"flask": {"app.py"}}
        module_map = {}

        unused = find_unused(deps, imports, module_map)
        assert len(unused) == 1
        assert unused[0].dep_name == "pandas"

    def test_package_module_mismatch(self):
        """Pillow is imported as PIL — should NOT be flagged as unused."""
        deps = [DependencyInfo(name="Pillow")]
        imports = {"PIL": {"image.py"}}
        module_map = {}

        # This relies on get_package_modules resolving Pillow → PIL
        unused = find_unused(deps, imports, module_map)
        # Pillow should be recognized as used via the KNOWN_PACKAGE_TO_MODULE mapping
        assert len(unused) == 0

    def test_all_unused(self):
        """All deps unused when nothing is imported."""
        deps = [
            DependencyInfo(name="flask"),
            DependencyInfo(name="requests"),
        ]
        imports = {}  # Nothing imported
        module_map = {}

        unused = find_unused(deps, imports, module_map)
        assert len(unused) == 2

    def test_empty_deps(self):
        """No deps should return no unused."""
        unused = find_unused([], {"flask": {"app.py"}}, {})
        assert len(unused) == 0
