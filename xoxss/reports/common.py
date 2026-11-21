"""Shared names and display helpers for report renderers."""

from typing import Any, Callable

from xoxss import __version__
from xoxss.utils.helpers import fmt_duration, now_iso, truncate

APP_NAME = "XOX$$"
VERSION = __version__


def field_getter(finding: Any) -> Callable[..., Any]:
    """Return a ``get(name, default)`` accessor for Finding objects or dicts."""
    if isinstance(finding, dict):
        return lambda name, default="": finding.get(name, default)
    return lambda name, default="": getattr(finding, name, default)


def iter_report_findings(scanner: Any) -> list:
    """Findings after the optional ``--min-confidence`` report floor.

    Falls back to ``scanner.findings`` for scanner-like objects that do not
    expose the filtered view.
    """
    filtered = getattr(scanner, "report_findings", None)
    if filtered is not None:
        return list(filtered)
    return list(getattr(scanner, "findings", []) or [])


__all__ = [
    "APP_NAME",
    "VERSION",
    "field_getter",
    "fmt_duration",
    "iter_report_findings",
    "now_iso",
    "truncate",
]
