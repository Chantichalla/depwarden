"""Pydantic models for depguard scan results."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class DependencyInfo(BaseModel):
    """A declared dependency from requirements.txt or pyproject.toml."""

    name: str
    version_spec: Optional[str] = None
    installed_version: Optional[str] = None
    source_file: Optional[str] = None
    is_dev: bool = False  # True if from [project.optional-dependencies] or poetry groups


class VulnerabilityInfo(BaseModel):
    """A known vulnerability (CVE) for a dependency."""

    dep_name: str
    vuln_id: str
    summary: str = ""
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = None
    fix_version: Optional[str] = None
    url: Optional[str] = None


class BloatEntry(BaseModel):
    """Bloat analysis for a single dependency."""

    dep_name: str
    installed_version: Optional[str] = None
    transitive_count: int = 0
    transitive_deps: list[str] = Field(default_factory=list)
    install_size_bytes: Optional[int] = None
    is_bloated: bool = False
    reason: str = ""


class UnusedDep(BaseModel):
    """A dependency declared but never imported in the project."""

    dep_name: str
    source_file: Optional[str] = None


class MissingDep(BaseModel):
    """A module imported in code but not declared in dependency files."""

    module_name: str
    imported_in: list[str] = Field(default_factory=list)


class SuggestionInfo(BaseModel):
    """A suggested replacement for a dependency."""

    current_dep: str
    suggested_dep: str
    reason: str


class HealthScore(BaseModel):
    """Overall project dependency health score."""

    score: int = 100  # 0-100
    max_score: int = 100
    breakdown: dict[str, int] = Field(default_factory=dict)
    grade: str = "A"  # A, B, C, D, F

    @staticmethod
    def calculate_grade(score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"


class ScanResult(BaseModel):
    """Aggregated results from all depguard scanners."""

    project_path: str
    total_declared_deps: int = 0
    dependencies: list[DependencyInfo] = Field(default_factory=list)

    # Phase 1: Security + Bloat
    vulnerabilities: list[VulnerabilityInfo] = Field(default_factory=list)
    bloat_entries: list[BloatEntry] = Field(default_factory=list)
    health: HealthScore = Field(default_factory=HealthScore)

    # Phase 2: Unused + Missing
    unused_deps: list[UnusedDep] = Field(default_factory=list)
    missing_deps: list[MissingDep] = Field(default_factory=list)
    optional_deps: dict[str, set[str]] = Field(default_factory=dict)

    # Phase 3: Suggestions
    suggestions: list[SuggestionInfo] = Field(default_factory=list)

    @property
    def has_critical_issues(self) -> bool:
        return any(
            v.severity in (Severity.CRITICAL, Severity.HIGH)
            for v in self.vulnerabilities
        )

    @property
    def has_issues(self) -> bool:
        return bool(
            self.vulnerabilities
            or self.unused_deps
            or self.missing_deps
            or any(b.is_bloated for b in self.bloat_entries)
        )
