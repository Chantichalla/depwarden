"""Tests for health_score.py — scoring formula."""

from __future__ import annotations

import pytest

from depwarden.health_score import calculate_health_score
from depwarden.models import BloatEntry, HealthScore, Severity, UnusedDep, VulnerabilityInfo


class TestHealthScore:
    """Tests for the health score calculator."""

    def test_perfect_score(self):
        """No issues should yield 100/A."""
        score = calculate_health_score([], [], None)
        assert score.score == 100
        assert score.grade == "A"
        assert score.breakdown == {}

    def test_critical_vuln_penalty(self):
        """A critical vulnerability should deduct 25 points."""
        vulns = [
            VulnerabilityInfo(
                dep_name="requests",
                vuln_id="CVE-2024-0001",
                severity=Severity.CRITICAL,
            )
        ]
        score = calculate_health_score(vulns, [])
        assert score.score == 75
        assert score.grade == "B"
        assert score.breakdown["vulnerabilities"] == -25

    def test_high_vuln_penalty(self):
        """A high severity vulnerability should deduct 15 points."""
        vulns = [
            VulnerabilityInfo(
                dep_name="flask",
                vuln_id="CVE-2024-0002",
                severity=Severity.HIGH,
            )
        ]
        score = calculate_health_score(vulns, [])
        assert score.score == 85

    def test_bloated_dep_penalty(self):
        """A bloated dependency should deduct 5 points."""
        bloat = [BloatEntry(dep_name="pandas", is_bloated=True)]
        score = calculate_health_score([], bloat)
        assert score.score == 95
        assert score.breakdown["bloated_deps"] == -5

    def test_unused_dep_penalty(self):
        """An unused dependency should deduct 3 points."""
        unused = [UnusedDep(dep_name="scipy")]
        score = calculate_health_score([], [], unused)
        assert score.score == 97
        assert score.breakdown["unused_deps"] == -3

    def test_combined_penalties(self):
        """Multiple issue types should stack penalties."""
        vulns = [
            VulnerabilityInfo(dep_name="x", vuln_id="1", severity=Severity.CRITICAL),
        ]
        bloat = [BloatEntry(dep_name="y", is_bloated=True)]
        unused = [UnusedDep(dep_name="z")]

        score = calculate_health_score(vulns, bloat, unused)
        # 100 - 25 (critical) - 5 (bloat) - 3 (unused) = 67
        assert score.score == 67
        assert score.grade == "C"

    def test_floor_at_zero(self):
        """Score should never go below 0."""
        vulns = [
            VulnerabilityInfo(dep_name=f"pkg{i}", vuln_id=f"CVE-{i}", severity=Severity.CRITICAL)
            for i in range(10)  # 10 * 25 = 250 penalty
        ]
        score = calculate_health_score(vulns, [])
        assert score.score == 0
        assert score.grade == "F"

    def test_grade_boundaries(self):
        """Test grade calculation at boundaries."""
        assert HealthScore.calculate_grade(100) == "A"
        assert HealthScore.calculate_grade(90) == "A"
        assert HealthScore.calculate_grade(89) == "B"
        assert HealthScore.calculate_grade(75) == "B"
        assert HealthScore.calculate_grade(74) == "C"
        assert HealthScore.calculate_grade(60) == "C"
        assert HealthScore.calculate_grade(59) == "D"
        assert HealthScore.calculate_grade(40) == "D"
        assert HealthScore.calculate_grade(39) == "F"
        assert HealthScore.calculate_grade(0) == "F"
