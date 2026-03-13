"""Smart replacement suggestions for dependencies."""

from __future__ import annotations

from depwarden.models import DependencyInfo, SuggestionInfo

# Suggestion database: current_package → (suggested_package, reason)
SUGGESTIONS: dict[str, tuple[str, str]] = {
    "requests": (
        "httpx",
        "Async support, HTTP/2, modern API, actively maintained",
    ),
    "pyyaml": (
        "ruamel.yaml",
        "Better YAML 1.2 support, preserves comments, actively maintained",
    ),
    "flask": (
        "fastapi",
        "Async support, auto-generated OpenAPI docs, better performance",
    ),
    "django-rest-framework": (
        "fastapi",
        "Lighter weight, async, auto-generated docs, better performance",
    ),
    "nose": (
        "pytest",
        "nose is deprecated; pytest is the standard with better plugin ecosystem",
    ),
    "mock": (
        "unittest.mock",
        "mock is now part of Python stdlib as unittest.mock",
    ),
    "six": (
        "(remove)",
        "Python 2 compatibility layer — unnecessary if targeting Python 3.10+",
    ),
    "future": (
        "(remove)",
        "Python 2 compatibility layer — unnecessary if targeting Python 3.10+",
    ),
    "typing-extensions": (
        "(check version)",
        "May be unnecessary if your minimum Python version is 3.10+",
    ),
    "importlib-metadata": (
        "(check version)",
        "Part of stdlib since Python 3.8, unnecessary unless supporting older versions",
    ),
}


def get_suggestions(deps: list[DependencyInfo]) -> list[SuggestionInfo]:
    """
    Generate smart replacement suggestions for declared dependencies.

    Args:
        deps: List of declared dependencies.

    Returns:
        List of suggestions.
    """
    suggestions: list[SuggestionInfo] = []

    for dep in deps:
        normalized = dep.name.lower().replace("-", "_").replace(".", "_")

        # Check exact match
        suggestion = SUGGESTIONS.get(dep.name.lower())
        if not suggestion:
            suggestion = SUGGESTIONS.get(normalized)

        if suggestion:
            suggested_dep, reason = suggestion
            suggestions.append(
                SuggestionInfo(
                    current_dep=dep.name,
                    suggested_dep=suggested_dep,
                    reason=reason,
                )
            )

    return suggestions
