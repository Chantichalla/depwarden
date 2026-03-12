"""Health score calculator — 0-100 project dependency health rating."""

from __future__ import annotations

from depguard.models import (
    BloatEntry,
    HealthScore,
    Severity,
    UnusedDep,
    VulnerabilityInfo,
)

# Scoring penalties
PENALTY_VULN_CRITICAL = 25
PENALTY_VULN_HIGH = 15
PENALTY_VULN_MEDIUM = 8
PENALTY_VULN_LOW = 3
PENALTY_BLOATED_DEP = 5
PENALTY_UNUSED_DEP = 3


def calculate_health_score(
    vulnerabilities: list[VulnerabilityInfo],
    bloat_entries: list[BloatEntry],
    unused_deps: list[UnusedDep] | None = None,
) -> HealthScore:
    """
    Calculate a 0-100 health score for the project.

    Scoring:
        - Start at 100
        - Subtract for each vulnerability by severity
        - Subtract for each bloated dependency
        - Subtract for each unused dependency (Phase 2)
        - Floor at 0
    """
    score = 100
    breakdown: dict[str, int] = {}

    # Vulnerability penalties
    vuln_penalty = 0
    severity_penalties = {
        Severity.CRITICAL: PENALTY_VULN_CRITICAL,
        Severity.HIGH: PENALTY_VULN_HIGH,
        Severity.MEDIUM: PENALTY_VULN_MEDIUM,
        Severity.LOW: PENALTY_VULN_LOW,
        Severity.UNKNOWN: PENALTY_VULN_LOW,
    }

    for vuln in vulnerabilities:
        vuln_penalty += severity_penalties.get(vuln.severity, PENALTY_VULN_LOW)

    if vuln_penalty:
        breakdown["vulnerabilities"] = -vuln_penalty
        score -= vuln_penalty

    # Bloat penalties (Capped at -20 so large frameworks don't auto-fail)
    bloat_penalty = 0
    for entry in bloat_entries:
        if entry.is_bloated:
            bloat_penalty += PENALTY_BLOATED_DEP
            
    bloat_penalty = min(bloat_penalty, 20)

    if bloat_penalty:
        breakdown["bloated_deps"] = -bloat_penalty
        score -= bloat_penalty

    # Unused dep penalties (Phase 2)
    if unused_deps:
        unused_penalty = len(unused_deps) * PENALTY_UNUSED_DEP
        if unused_penalty:
            breakdown["unused_deps"] = -unused_penalty
            score -= unused_penalty

    # Floor at 0
    score = max(0, score)

    return HealthScore(
        score=score,
        max_score=100,
        breakdown=breakdown,
        grade=HealthScore.calculate_grade(score),
    )
