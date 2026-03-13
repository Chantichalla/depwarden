"""Tests for bloat.py — transitive dependency analysis."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from depwarden.bloat import analyze_bloat, _resolve_full_tree, get_dependency_tree
from depwarden.models import DependencyInfo


class TestResolveFullTree:
    """Tests for transitive dependency resolution."""

    @patch("depwarden.bloat._get_direct_requires")
    def test_simple_tree(self, mock_requires):
        """A → B → C should return {a, b, c}."""
        mock_requires.side_effect = lambda name: {
            "A": ["B"],
            "B": ["C"],
            "C": [],
        }.get(name, [])

        tree = _resolve_full_tree("A")
        assert "a" in tree
        assert "b" in tree
        assert "c" in tree

    @patch("depwarden.bloat._get_direct_requires")
    def test_circular_dependency(self, mock_requires):
        """A → B → A should not loop forever."""
        mock_requires.side_effect = lambda name: {
            "A": ["B"],
            "B": ["A"],
        }.get(name, [])

        tree = _resolve_full_tree("A")
        assert "a" in tree
        assert "b" in tree

    @patch("depwarden.bloat._get_direct_requires")
    def test_no_deps(self, mock_requires):
        """A with no dependencies should return just {a}."""
        mock_requires.return_value = []
        tree = _resolve_full_tree("standalone")
        assert "standalone" in tree
        assert len(tree) == 1


class TestAnalyzeBloat:
    """Tests for the full bloat analysis."""

    @patch("depwarden.bloat._resolve_full_tree")
    def test_flags_bloated_dep(self, mock_tree):
        """A dep with >20 transitive deps should be flagged as bloated."""
        # 25 transitive deps (+ self = 26 in tree)
        transitive = {f"dep_{i}" for i in range(25)}
        transitive.add("heavy_package")
        mock_tree.return_value = transitive

        deps = [DependencyInfo(name="heavy-package", installed_version="1.0.0")]
        entries = analyze_bloat(deps)

        assert len(entries) == 1
        assert entries[0].is_bloated is True
        assert entries[0].transitive_count == 25

    @patch("depwarden.bloat._resolve_full_tree")
    def test_not_flagged_when_small(self, mock_tree):
        """A dep with few transitive deps should NOT be flagged."""
        mock_tree.return_value = {"small_package", "dep_1", "dep_2"}

        deps = [DependencyInfo(name="small-package", installed_version="1.0.0")]
        entries = analyze_bloat(deps)

        assert len(entries) == 1
        assert entries[0].is_bloated is False

    def test_empty_deps(self):
        """No deps should return empty list."""
        assert analyze_bloat([]) == []


class TestDependencyTree:
    """Tests for tree visualization builder."""

    @patch("depwarden.bloat._get_direct_requires")
    def test_tree_depth_limit(self, mock_requires):
        """Tree should stop at max_depth."""
        mock_requires.return_value = ["child"]
        tree = get_dependency_tree("root", max_depth=2)
        assert tree["name"] == "root"
        assert len(tree["deps"]) == 1
        assert tree["deps"][0]["deps"][0]["truncated"] is True
