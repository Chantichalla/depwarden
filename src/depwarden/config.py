"""Configuration reader for [tool.depwarden] in pyproject.toml."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Sensible defaults for directories to exclude from import scanning
DEFAULT_EXCLUDE_DIRS = [
    "tests",
    "test",
    "docs",
    "examples",
    "benchmarks",
    "scripts",
]


@dataclass
class DepwardenConfig:
    """Configuration for depwarden, loaded from [tool.depwarden] in pyproject.toml."""

    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_DIRS))
    fail_on: Optional[str] = None
    include_dev_deps: bool = True  # Whether to count dev deps as "declared"
    ignore_unused: list[str] = field(default_factory=list)
    ignore_vulns: list[str] = field(default_factory=list)

    @classmethod
    def from_pyproject(cls, project_path: str) -> "DepwardenConfig":
        """Load config from [tool.depwarden] in pyproject.toml, if it exists."""
        pyproject_path = Path(project_path) / "pyproject.toml"

        if not pyproject_path.exists():
            return cls()

        try:
            try:
                import tomllib
            except ModuleNotFoundError:
                import tomli as tomllib  # type: ignore[no-redef]

            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)

            tool_config = data.get("tool", {}).get("depwarden", {})
            if not tool_config:
                return cls()

            return cls(
                exclude=tool_config.get("exclude", list(DEFAULT_EXCLUDE_DIRS)),
                fail_on=tool_config.get("fail_on", tool_config.get("fail-on")),
                include_dev_deps=tool_config.get("include_dev_deps", True),
                ignore_unused=tool_config.get("ignore_unused", []),
                ignore_vulns=tool_config.get("ignore_vulns", []),
            )

        except Exception:
            # Config parsing should never crash the tool
            return cls()

    def get_all_excludes(self, extra_excludes: Optional[list[str]] = None) -> set[str]:
        """Merge config excludes with CLI --exclude overrides."""
        excludes = set(self.exclude)
        if extra_excludes:
            excludes.update(extra_excludes)
        return excludes
