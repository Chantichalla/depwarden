# 🛡️ depwarden

> **Escape Dependency Hell** — Scan, audit, and fix your Python dependencies in one command.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## What is depwarden?

depwarden is a CLI tool that scans your Python project's dependencies for:

- 🔒 **Security vulnerabilities** — CVE scanning via the OSV.dev database with clickable advisory links
- 📦 **Dependency bloat** — how many sub-dependencies each package pulls in
- 📊 **Health scoring** — 0-100 project health rating with letter grades (A-F)
- 🗑️ **Unused dependencies** — packages declared but never imported (project-wide)
- ❓ **Missing dependencies** — modules imported but not declared
- 💡 **Smart suggestions** — modern alternatives for common packages
- 🛠️ **Actionable next steps** — copy-paste commands to fix every issue
- 🔗 **Clickable CVE links** — Ctrl+Click vulnerability IDs to open full advisories in your browser

## Quick Start

```bash
pip install depwarden

# Basic scan (security + bloat)
depwarden scan .

# Full scan (includes unused/missing detection)
depwarden scan . --full

# JSON output for CI/CD pipelines
depwarden scan . --format json

# Fail CI if HIGH+ vulnerabilities found
depwarden scan . --fail-on high

# Exclude specific directories from scanning
depwarden scan . --full --exclude migrations --exclude scripts
```

## Example Output

```
╭───────────────────────────────────────╮
│ 🛡️  depwarden — Escape Dependency Hell │
╰───────────────────────────────────────╯
  📂 Project: /home/user/myproject
  📦 Dependencies scanned: 7

╭────────── 📊 Health Score ──────────╮
│   100 / 100    Grade: A             │
╰─────────────────────────────────────╯

          📦 Dependency Weight (Top 10)
┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━┓
┃ Package  ┃ Version ┃ Pulls In ┃ Status ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━┩
│ typer    │ 0.24.1  │        7 │ ✅ OK  │
│ httpx    │ 0.28.1  │        7 │ ✅ OK  │
│ pydantic │ 2.12.5  │        4 │ ✅ OK  │
│ rich     │ 14.3.3  │        2 │ ✅ OK  │
└──────────┴─────────┴──────────┴────────┘

  ✅ No issues found — dependencies are healthy!
```

## Why depwarden?

AI IDEs catch import errors in your editor. **depwarden catches dependency health issues in your CI/CD pipeline** — where no IDE exists.

| Feature | pip-audit | deptry | safety | **depwarden** |
|---|---|---|---|---|
| CVE scanning | ✅ | ❌ | ✅ | ✅ |
| Clickable CVE links | ❌ | ❌ | ❌ | ✅ |
| Bloat analysis | ❌ | ❌ | ❌ | ✅ |
| Unused detection | ❌ | ✅ | ❌ | ✅ |
| Health score | ❌ | ❌ | ❌ | ✅ |
| Interactive loader | ❌ | ❌ | ❌ | ✅ |
| CVE ignore list | ✅ | ❌ | ❌ | ✅ |
| Free, no API key | ✅ | ✅ | ❌ | ✅ |

## Configuration

depwarden can be configured via `pyproject.toml` so you don't need to pass flags every time:

```toml
[tool.depwarden]
# Directories to exclude from import scanning
exclude = ["tests", "docs", "migrations", "scripts"]

# Automatically fail CI at this severity level
fail_on = "high"

# Whether to include dev dependencies in analysis
include_dev_deps = true

# Packages to ignore in unused dependency detection
# Useful for CLI tools (uvicorn), meta-packages (langchain), or runtime-only deps
ignore_unused = ["uvicorn", "gunicorn", "langchain"]

# Specific vulnerability IDs to ignore (accepted risk)
# Use the exact GHSA/PYSEC/CVE ID shown in the scan output
ignore_vulns = ["PYSEC-2022-43012", "GHSA-r9hx-vwmv-q579"]
```

### Default Excludes

When running `--full` scans, depwarden automatically skips these directories to avoid false positives from test fixtures and example code:

- `tests/`, `test/` — test directories
- `docs/` — documentation
- `examples/` — example/demo code
- `benchmarks/` — performance benchmarks
- `scripts/` — utility scripts

You can override these defaults in `[tool.depwarden]` or add more via `--exclude`.

## CLI Reference

```bash
depwarden scan [PATH] [OPTIONS]

Arguments:
  PATH                    Path to the project (default: current dir)

Options:
  --full                  Include unused/missing dependency detection
  --format, -f TEXT       Output format: 'rich' or 'json' (default: rich)
  --fail-on TEXT          Exit code 1 on issues. Values:
                            Security: critical, high, medium, low
                            Quality:  unused, bloat, any
  --no-security           Skip vulnerability scanning (useful offline)
  --no-bloat              Skip bloat analysis
  --exclude, -e TEXT      Directories to exclude (can be repeated)

depwarden version          Show version info
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Dependency Health Check
on: [push, pull_request]

jobs:
  depwarden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install depwarden
      - run: pip install -r requirements.txt
      - run: depwarden scan . --full --fail-on high
```

### GitLab CI

```yaml
depwarden:
  stage: test
  image: python:3.12-slim
  script:
    - pip install depwarden
    - pip install -r requirements.txt
    - depwarden scan . --full --fail-on high --format json
  allow_failure: false
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: depwarden
        name: depwarden
        entry: depwarden scan . --fail-on critical
        language: python
        additional_dependencies: [depwarden]
        always_run: true
        pass_filenames: false
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | All healthy, no issues |
| `1` | Issues found (vulnerabilities, unused deps, etc.) |
| `2` | Configuration error (bad path, missing deps file) |

## How It Works

depwarden works in two distinct phases to give you a complete picture of your project:

**Phase 1: Metadata Tracking (What you claim you use)**
1. **Reads** your `pyproject.toml`, `requirements.txt`, or `setup.cfg` to find your *declared* packages and their versions. (We support `requirements.txt` because many legacy or Docker-based projects still rely on it, but it is not mandatory if you use `pyproject.toml`).
2. **Queries** the [OSV.dev](https://osv.dev) database using those exact declared versions to find known CVEs.
3. **Analyzes** the transitive dependency tree to find hidden bloat.

**Phase 2: Actual Usage (What you actually use)**
4. **AST Code Scanning:** depwarden uses Python's `ast` (Abstract Syntax Tree) module to parse every single `.py` file in your project. It finds every actual `import` statement in your source code without executing the code.
5. **Cross-Referencing:** It compares the real imports (from AST) against your declared packages (from Phase 1) to identify **Unused dependencies** (declared but never imported) and **Missing dependencies** (imported but not declared).
6. **Scores** your project 0-100 and outputs a beautiful terminal report.

## Interactive Experience

depwarden features a custom loading animation during scans:

```
[ •_• ] Contacting OSV.dev vulnerability database...
[ o_o ] Calculating transitive dependency bloat...
[ O_O ] Parsing Abstract Syntax Trees...
[ -_- ] Finalizing health scores...
```

Vulnerability IDs in the output are **clickable hyperlinks** — Ctrl+Click (or Cmd+Click on Mac) any CVE/GHSA ID to open the full advisory in your browser.

## Supported Dependency Files

- `pyproject.toml` (PEP 621 + Poetry formats, including optional/dev dependencies)
- `requirements.txt` (including `-r` recursive includes)
- `setup.cfg`

## License

MIT
