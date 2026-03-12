"""CLI entry point for depguard using Typer."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.text import Text

from depguard import __version__
from depguard.bloat import analyze_bloat
from depguard.config import DepguardConfig
from depguard.deps_reader import read_dependencies
from depguard.health_score import calculate_health_score
from depguard.models import ScanResult
from depguard.reporter import report_json, report_rich
from depguard.security import scan_vulnerabilities

app = typer.Typer(
    name="depguard",
    help="🛡️  depguard — Escape Dependency Hell. Scan, audit, and fix your Python dependencies.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    path: str = typer.Argument(
        ".",
        help="Path to the Python project to scan.",
    ),
    format: str = typer.Option(
        "rich",
        "--format",
        "-f",
        help="Output format: 'rich' (terminal) or 'json' (CI/CD).",
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 if issues found. Values: critical, high, medium, low (security), unused, bloat, any.",
    ),
    no_security: bool = typer.Option(
        False,
        "--no-security",
        help="Skip vulnerability scanning (useful offline).",
    ),
    no_bloat: bool = typer.Option(
        False,
        "--no-bloat",
        help="Skip bloat analysis.",
    ),
    include_phase2: bool = typer.Option(
        False,
        "--full",
        help="Include unused/missing dependency detection (Phase 2).",
    ),
    exclude: Optional[list[str]] = typer.Option(
        None,
        "--exclude",
        "-e",
        help="Directories to exclude from import scanning (can be used multiple times).",
    ),
) -> None:
    """Scan a Python project for dependency health issues."""
    project_path = Path(path).resolve()

    if not project_path.exists():
        console.print(f"[red]Error: Path '{path}' does not exist.[/]")
        raise typer.Exit(code=2)

    if not project_path.is_dir():
        console.print(f"[red]Error: '{path}' is not a directory.[/]")
        raise typer.Exit(code=2)

    # --- Load config from [tool.depguard] in pyproject.toml ---
    config = DepguardConfig.from_pyproject(str(project_path))

    # Use config fail_on if CLI didn't specify one
    effective_fail_on = fail_on or config.fail_on

    # Merge exclude dirs: config defaults + CLI overrides
    exclude_dirs = config.get_all_excludes(exclude)

    if format == "rich":
        # Custom Mascot + Verbs Animation
        frames = ["[ •_• ]", "[ o_o ]", "[ O_O ]", "[ o_o ]", "[ -_- ]", "[ •_• ]"]
        frame_idx = 0
        
        def update_spinner(verb: str, verb_color: str = "yellow"):
            nonlocal frame_idx
            frame = frames[frame_idx % len(frames)]
            frame_idx += 1
            t = Text()
            t.append(f"{frame} ", style="bold cyan")
            t.append(verb, style=verb_color)
            return t

        with Live(update_spinner("Initializing depguard engine..."), refresh_per_second=10, transient=True) as live:
            # --- Step 1: Read dependencies ---
            live.update(update_spinner("Reading pyproject.toml / requirements..."))
            try:
                deps = read_dependencies(str(project_path))
            except FileNotFoundError as e:
                console.print(f"[red]Error: {e}[/]")
                raise typer.Exit(code=2)
        
            result = ScanResult(
                project_path=str(project_path),
                total_declared_deps=len(deps),
                dependencies=deps,
            )
        
            # --- Step 2: Security scan ---
            if not no_security:
                live.update(update_spinner("Contacting OSV.dev vulnerability database...", "red"))
                result.vulnerabilities = scan_vulnerabilities(deps)
                # Filter out ignored vulnerabilities
                if config.ignore_vulns:
                    ignored_ids = {vid.upper() for vid in config.ignore_vulns}
                    result.vulnerabilities = [
                        v for v in result.vulnerabilities if v.vuln_id.upper() not in ignored_ids
                    ]
        
            # --- Step 3: Bloat analysis ---
            if not no_bloat:
                live.update(update_spinner("Calculating transitive dependency bloat...", "blue"))
                result.bloat_entries = analyze_bloat(deps)
        
            # --- Step 4: Unused + Missing (Phase 2, opt-in) ---
            if include_phase2:
                try:
                    from depguard.scanner import scan_imports
                    from depguard.unused import find_unused
                    from depguard.missing import find_missing
                    from depguard.utils import filter_third_party, get_module_to_package_map
        
                    excluded_str = ", ".join(sorted(exclude_dirs)) if exclude_dirs else "none"
                    live.update(update_spinner(f"Parsing Abstract Syntax Trees (excluding: {excluded_str})...", "yellow"))
        
                    imports, optional_imports = scan_imports(str(project_path), exclude_dirs=exclude_dirs)
                    
                    live.update(update_spinner("Mapping imports to PyPI packages...", "magenta"))
                    third_party = filter_third_party(imports, str(project_path))
                    third_party_opt = filter_third_party(optional_imports, str(project_path))
                    module_map = get_module_to_package_map()
        
                    raw_unused = find_unused(deps, third_party, module_map)
                    if config.ignore_unused:
                        ignored_set = {name.lower() for name in config.ignore_unused}
                        result.unused_deps = [u for u in raw_unused if u.dep_name.lower() not in ignored_set]
                    else:
                        result.unused_deps = raw_unused
                    result.missing_deps = find_missing(deps, third_party, module_map, third_party_opt)
                    result.optional_deps = third_party_opt
                except ImportError:
                    pass  # Phase 2 modules not yet available
                    
            live.update(update_spinner("Finalizing health scores...", "green"))
    else:
        # JSON mode: No rich animations, fast execution
        try:
            deps = read_dependencies(str(project_path))
        except FileNotFoundError as e:
            console.print(f"[red]Error: {e}[/]")
            raise typer.Exit(code=2)
            
        result = ScanResult(
            project_path=str(project_path),
            total_declared_deps=len(deps),
            dependencies=deps,
        )
        if not no_security:
            result.vulnerabilities = scan_vulnerabilities(deps)
            # Filter out ignored vulnerabilities
            if config.ignore_vulns:
                ignored_ids = {vid.upper() for vid in config.ignore_vulns}
                result.vulnerabilities = [
                    v for v in result.vulnerabilities if v.vuln_id.upper() not in ignored_ids
                ]
        if not no_bloat:
            result.bloat_entries = analyze_bloat(deps)
            
        if include_phase2:
            try:
                from depguard.scanner import scan_imports
                from depguard.unused import find_unused
                from depguard.missing import find_missing
                from depguard.utils import filter_third_party, get_module_to_package_map
                imports, optional_imports = scan_imports(str(project_path), exclude_dirs=exclude_dirs)
                third_party = filter_third_party(imports, str(project_path))
                third_party_opt = filter_third_party(optional_imports, str(project_path))
                module_map = get_module_to_package_map()
                raw_unused = find_unused(deps, third_party, module_map)
                if config.ignore_unused:
                    ignored_set = {name.lower() for name in config.ignore_unused}
                    result.unused_deps = [u for u in raw_unused if u.dep_name.lower() not in ignored_set]
                else:
                    result.unused_deps = raw_unused
                result.missing_deps = find_missing(deps, third_party, module_map, third_party_opt)
                result.optional_deps = third_party_opt
            except ImportError:
                pass

    # --- Step 5: Calculate health score ---
    result.health = calculate_health_score(
        result.vulnerabilities,
        result.bloat_entries,
        result.unused_deps or None,
    )

    # --- Step 6: Output ---
    if format == "json":
        print(report_json(result))
    else:
        report_rich(result)

    # --- Step 7: Exit code ---
    if effective_fail_on:
        fail_val = effective_fail_on.lower()

        # Non-security fail-on values
        if fail_val == "any":
            if result.has_issues:
                raise typer.Exit(code=1)
        elif fail_val == "unused":
            if result.unused_deps:
                raise typer.Exit(code=1)
        elif fail_val == "bloat":
            if any(b.is_bloated for b in result.bloat_entries):
                raise typer.Exit(code=1)
        else:
            # Security severity levels
            severity_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
            }
            threshold = severity_order.get(fail_val)
            if threshold is None:
                console.print(
                    f"[red]Invalid --fail-on value: {effective_fail_on}. "
                    f"Valid: critical, high, medium, low, unused, bloat, any[/]"
                )
                raise typer.Exit(code=2)

            for vuln in result.vulnerabilities:
                vuln_level = severity_order.get(vuln.severity.value, 4)
                if vuln_level <= threshold:
                    raise typer.Exit(code=1)

    if result.has_critical_issues:
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)


@app.command()
def version() -> None:
    """Show depguard version."""
    console.print(f"depguard v{__version__}")


if __name__ == "__main__":
    app()

