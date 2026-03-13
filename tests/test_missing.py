"""Tests for missing.py — missing dependency detection."""

from __future__ import annotations

import pytest

from depwarden.models import DependencyInfo
from depwarden.missing import find_missing


class TestFindMissing:
    """Tests for missing dependency detection."""

    def test_no_missing(self):
        """All imports covered by declared deps."""
        deps = [
            DependencyInfo(name="flask"),
            DependencyInfo(name="requests"),
        ]
        imports = {"flask": {"app.py"}, "requests": {"api.py"}}
        module_map = {}

        missing = find_missing(deps, imports, module_map)
        assert len(missing) == 0

    def test_one_missing(self):
        """Detect a module imported but not declared."""
        deps = [DependencyInfo(name="flask")]
        imports = {"flask": {"app.py"}, "pandas": {"data.py"}}
        module_map = {}

        missing = find_missing(deps, imports, module_map)
        assert len(missing) == 1
        assert missing[0].module_name == "pandas"
        assert "data.py" in missing[0].imported_in

    def test_package_module_mismatch_not_flagged(self):
        """PyYAML declared, yaml imported — should NOT be flagged as missing."""
        deps = [DependencyInfo(name="PyYAML")]
        imports = {"yaml": {"config.py"}}
        module_map = {}

        missing = find_missing(deps, imports, module_map)
        # yaml should be recognized as covered by PyYAML
        assert len(missing) == 0

    def test_nothing_imported(self):
        """No imports should return no missing."""
        deps = [DependencyInfo(name="flask")]
        missing = find_missing(deps, {}, {})
        assert len(missing) == 0

    def test_multiple_files(self):
        """Missing dep imported in multiple files should list them all."""
        deps = []
        imports = {"numpy": {"calc.py", "stats.py", "plot.py"}}
        module_map = {}

        missing = find_missing(deps, imports, module_map)
        assert len(missing) == 1
        assert len(missing[0].imported_in) == 3
