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


__all__ = [
    "APP_NAME",
    "VERSION",
    "field_getter",
    "fmt_duration",
    "now_iso",
    "truncate",
]
