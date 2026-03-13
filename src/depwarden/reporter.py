"""Rich terminal reporter and JSON output for depwarden."""

from __future__ import annotations

import json
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from depwarden.models import BloatEntry, ScanResult, Severity


console = Console()

# Severity → color mapping
_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.UNKNOWN: "dim",
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.UNKNOWN: "⚪",
}

_GRADE_COLORS = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bold red",
}


def _render_header(result: ScanResult) -> None:
    """Print the depwarden header banner."""
    console.print()
    console.print(
        Panel(
            "[bold white]🛡️  depwarden[/] — Escape Dependency Hell",
            style="blue",
            expand=False,
        )
    )
    console.print(f"  📂 Project: [bold]{result.project_path}[/]")
    console.print(f"  📦 Dependencies scanned: [bold]{result.total_declared_deps}[/]")
    console.print()


def _render_health_score(result: ScanResult) -> None:
    """Print the health score panel."""
    health = result.health
    grade_color = _GRADE_COLORS.get(health.grade, "white")

    score_text = Text()
    score_text.append(f"  {health.score}", style=f"bold {grade_color}")
    score_text.append(f" / {health.max_score}  ", style="dim")
    score_text.append(f"  Grade: ", style="white")
    score_text.append(f"{health.grade}", style=f"bold {grade_color}")

    console.print(Panel(score_text, title="📊 Health Score", border_style=grade_color))

    # Breakdown
    if health.breakdown:
        for category, penalty in health.breakdown.items():
            label = category.replace("_", " ").title()
            console.print(f"    {label}: [red]{penalty}[/] points")
        console.print()


def _render_vulnerabilities(result: ScanResult) -> None:
    """Print the vulnerability table."""
    vulns = result.vulnerabilities
    if not vulns:
        console.print(
            Panel(
                "  ✅ No known vulnerabilities found!",
                title="🔒 Security",
                border_style="green",
            )
        )
        console.print()
        return

    table = Table(
        title="🔒 Security Vulnerabilities (Affecting Installed Versions)",
        show_lines=True,
        border_style="red",
    )
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Package", style="bold")
    table.add_column("Vulnerability", style="dim")
    table.add_column("Summary", overflow="fold")
    table.add_column("Fix Version", style="green")

    for vuln in vulns:
        sev_color = _SEVERITY_COLORS.get(vuln.severity, "white")
        sev_icon = _SEVERITY_ICONS.get(vuln.severity, "")

        table.add_row(
            Text(f"{sev_icon} {vuln.severity.value.upper()}", style=sev_color),
            vuln.dep_name,
            f"[link={vuln.url}]{vuln.vuln_id}[/link]",
            vuln.summary,
            vuln.fix_version or "N/A",
        )

    console.print(table)
    console.print()


def _render_bloat(result: ScanResult) -> None:
    """Print the bloat analysis table."""
    entries = result.bloat_entries
    if not entries:
        return

    bloated = [e for e in entries if e.is_bloated]
    if not bloated:
        console.print(
            Panel(
                "  ✅ No excessive dependency bloat detected!",
                title="📦 Bloat Analysis",
                border_style="green",
            )
        )
        console.print()

        # Still show the summary table
        _render_bloat_summary(entries)
        return

    console.print(
        Panel(
            f"  ⚠️  {len(bloated)} bloated dependencies found",
            title="📦 Bloat Analysis",
            border_style="yellow",
        )
    )

    _render_bloat_summary(entries)


def _render_bloat_summary(entries: list[BloatEntry]) -> None:
    """Show a summary table of all dependencies and their transitive counts."""
    # Show top 10 heaviest
    table = Table(
        title="📦 Dependency Weight (Top 10)",
        show_lines=False,
        border_style="blue",
    )
    table.add_column("Package", style="bold")
    table.add_column("Version", style="dim")
    table.add_column("Pulls In", justify="right")
    table.add_column("Status")

    for entry in entries[:10]:
        dep_count_style = "red" if entry.is_bloated else "green"
        status = "⚠️  Bloated" if entry.is_bloated else "✅ OK"
        status_style = "yellow" if entry.is_bloated else "green"

        table.add_row(
            entry.dep_name,
            entry.installed_version or "?",
            Text(str(entry.transitive_count), style=dep_count_style),
            Text(status, style=status_style),
        )

    console.print(table)
    console.print()


def _render_unused(result: ScanResult) -> None:
    """Print unused dependencies."""
    if not result.unused_deps:
        return

    table = Table(
        title="🗑️  Unused Dependencies",
        show_lines=False,
        border_style="yellow",
    )
    table.add_column("Package", style="bold yellow")
    table.add_column("Declared In", style="dim")

    for dep in result.unused_deps:
        table.add_row(dep.dep_name, dep.source_file or "?")

    console.print(table)
    console.print()


def _render_missing(result: ScanResult) -> None:
    """Print missing dependencies."""
    if not result.missing_deps:
        return

    table = Table(
        title="❓ Missing Dependencies",
        show_lines=False,
        border_style="red",
    )
    table.add_column("Module", style="bold red")
    table.add_column("Imported In", style="dim")

    for dep in result.missing_deps:
        files = ", ".join(dep.imported_in[:3])
        if len(dep.imported_in) > 3:
            files += f" (+{len(dep.imported_in) - 3} more)"
        table.add_row(dep.module_name, files)

    console.print(table)
    console.print()


def _render_optional_deps(result: ScanResult) -> None:
    """Print optional dependencies (safe, purely informational)."""
    if not result.optional_deps:
        return

    table = Table(
        title="ℹ️  Optional Dependencies",
        show_lines=False,
        border_style="blue",
    )
    table.add_column("Module", style="bold blue")
    table.add_column("Imported In (try/except fallback)", style="dim")

    for module_name, file_set in sorted(result.optional_deps.items()):
        file_list = sorted(list(file_set))
        files_str = ", ".join(file_list[:3])
        if len(file_list) > 3:
            files_str += f" (+{len(file_list) - 3} more)"
        table.add_row(module_name, files_str)

    console.print(table)
    console.print()


def _render_suggestions(result: ScanResult) -> None:
    """Print smart replacement suggestions."""
    if not result.suggestions:
        return

    console.print("[bold blue]💡 Suggestions:[/]")
    for sug in result.suggestions:
        console.print(
            f"  • Replace [yellow]{sug.current_dep}[/] → "
            f"[green]{sug.suggested_dep}[/]: {sug.reason}"
        )
    console.print()


def _render_resolutions(result: ScanResult) -> None:
    """Print actionable next steps for the user."""
    issues = False
    actions = Text()
    
    # 1. Vulnerabilities
    if result.vulnerabilities:
        issues = True
        actions.append("> ", style="bold")
        actions.append("Security: ", style="bold red")
        packages = list(set([v.dep_name for v in result.vulnerabilities]))
        actions.append(f"Upgrade vulnerable packages ({', '.join(packages)}) to their fixed versions.\n")
    
    # 2. Unused
    if result.unused_deps:
        issues = True
        actions.append("> ", style="bold")
        actions.append("Unused:   ", style="bold yellow")
        packages = [u.dep_name for u in result.unused_deps]
        pkg_str = " ".join(packages[:3])
        if len(packages) > 3:
            pkg_str += f" (and {len(packages) - 3} others)"
        actions.append(f"Run 'pip uninstall {pkg_str}' or add them to 'ignore_unused' in pyproject.toml.\n")
        
    # 3. Missing
    if result.missing_deps:
        issues = True
        actions.append("> ", style="bold")
        actions.append("Missing:  ", style="bold magenta")
        packages = [m.module_name for m in result.missing_deps]
        pkg_str = " ".join(packages[:3])
        if len(packages) > 3:
            pkg_str += f" (and {len(packages) - 3} others)"
        actions.append(f"Run 'pip install {pkg_str}' and declare them in your dependency file.\n")
        
    if issues:
        # Strip trailing newline for cleaner panel padding
        actions.rstrip()
        console.print(Panel(actions, title="🛠️  Recommended Next Steps", border_style="blue", expand=False))
        console.print()



def _render_summary(result: ScanResult) -> None:
    """Print the final summary line."""
    issues: list[str] = []

    if result.vulnerabilities:
        critical = sum(
            1 for v in result.vulnerabilities if v.severity == Severity.CRITICAL
        )
        high = sum(1 for v in result.vulnerabilities if v.severity == Severity.HIGH)
        if critical:
            issues.append(f"[bold red]{critical} CRITICAL[/]")
        if high:
            issues.append(f"[red]{high} HIGH[/]")
        other = len(result.vulnerabilities) - critical - high
        if other:
            issues.append(f"[yellow]{other} other vulnerabilities[/]")

    bloated = sum(1 for b in result.bloat_entries if b.is_bloated)
    if bloated:
        issues.append(f"[yellow]{bloated} bloated deps[/]")

    if result.unused_deps:
        issues.append(f"[yellow]{len(result.unused_deps)} unused deps[/]")

    if result.missing_deps:
        issues.append(f"[red]{len(result.missing_deps)} missing deps[/]")

    if issues:
        console.print(f"  ⚡ Issues found: {', '.join(issues)}")
    else:
        console.print("  ✅ [bold green]No issues found — dependencies are healthy![/]")

    console.print()


def report_rich(result: ScanResult) -> None:
    """Render a full Rich console report."""
    _render_header(result)
    _render_health_score(result)
    _render_vulnerabilities(result)
    _render_bloat(result)
    _render_unused(result)
    _render_missing(result)
    _render_optional_deps(result)
    _render_suggestions(result)
    _render_resolutions(result)
    _render_summary(result)


def report_json(result: ScanResult) -> str:
    """Return JSON string of scan results (for CI/CD)."""
    return result.model_dump_json(indent=2)
