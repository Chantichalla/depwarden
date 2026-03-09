# 🛡️ depguard

> **Escape Dependency Hell** — Scan, audit, and fix your Python dependencies in one command.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## What is depguard?

depguard is a CLI tool that scans your Python project's dependencies for:

- 🔒 **Security vulnerabilities** — CVE scanning via the OSV.dev database
- 📦 **Dependency bloat** — how many sub-dependencies each package pulls in
- 📊 **Health scoring** — 0-100 project health rating with letter grades (A-F)
- 🗑️ **Unused dependencies** — packages declared but never imported (project-wide)
- ❓ **Missing dependencies** — modules imported but not declared
- 💡 **Smart suggestions** — modern alternatives for common packages

## Quick Start

```bash
pip install depguard

# Basic scan (security + bloat)
depguard scan .

# Full scan (includes unused/missing detection)
depguard scan . --full

# JSON output for CI/CD pipelines
depguard scan . --format json

# Fail CI if HIGH+ vulnerabilities found
depguard scan . --fail-on high

# Exclude specific directories from scanning
depguard scan . --full --exclude migrations --exclude scripts
```

## Example Output

```
╭───────────────────────────────────────╮
│ 🛡️  depguard — Escape Dependency Hell │
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

## Why depguard?

AI IDEs catch import errors in your editor. **depguard catches dependency health issues in your CI/CD pipeline** — where no IDE exists.

| Feature | pip-audit | deptry | safety | **depguard** |
|---|---|---|---|---|
| CVE scanning | ✅ | ❌ | ✅ | ✅ |
| Bloat analysis | ❌ | ❌ | ❌ | ✅ |
| Unused detection | ❌ | ✅ | ❌ | ✅ |
| Health score | ❌ | ❌ | ❌ | ✅ |
| Free, no API key | ✅ | ✅ | ❌ | ✅ |

## Configuration

depguard can be configured via `pyproject.toml` so you don't need to pass flags every time:

```toml
[tool.depguard]
# Directories to exclude from import scanning
exclude = ["tests", "docs", "migrations", "scripts"]

# Automatically fail CI at this severity level
fail_on = "high"

# Whether to include dev dependencies in analysis
include_dev_deps = true
```

### Default Excludes

When running `--full` scans, depguard automatically skips these directories to avoid false positives from test fixtures and example code:

- `tests/`, `test/` — test directories
- `docs/` — documentation
- `examples/` — example/demo code
- `benchmarks/` — performance benchmarks
- `scripts/` — utility scripts

You can override these defaults in `[tool.depguard]` or add more via `--exclude`.

## CLI Reference

```bash
depguard scan [PATH] [OPTIONS]

Arguments:
  PATH                    Path to the project (default: current dir)

Options:
  --full                  Include unused/missing dependency detection
  --format, -f TEXT       Output format: 'rich' or 'json' (default: rich)
  --fail-on TEXT          Exit code 1 if severity >= threshold (critical/high/medium/low)
  --no-security           Skip vulnerability scanning (useful offline)
  --no-bloat              Skip bloat analysis
  --exclude, -e TEXT      Directories to exclude (can be repeated)

depguard version          Show version info
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Dependency Health Check
on: [push, pull_request]

jobs:
  depguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install depguard
      - run: depguard scan . --full --fail-on high
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | All healthy, no issues |
| `1` | Issues found (vulnerabilities, unused deps, etc.) |
| `2` | Configuration error (bad path, missing deps file) |

## How It Works

1. **Reads** your `pyproject.toml`, `requirements.txt`, or `setup.cfg`
2. **Queries** the [OSV.dev](https://osv.dev) database for known CVEs (free, no API key)
3. **Analyzes** each dependency's sub-dependency tree for bloat
4. **Scans** all `.py` files using Python's AST to find actual imports (with `--full`)
5. **Compares** declared vs. imported to find unused and missing dependencies
6. **Scores** your project 0-100 and outputs a beautiful terminal report or JSON

## Supported Dependency Files

- `pyproject.toml` (PEP 621 + Poetry formats, including optional/dev dependencies)
- `requirements.txt` (including `-r` recursive includes)
- `setup.cfg`

## License

MIT
