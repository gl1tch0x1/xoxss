"""Shared names and display helpers for report renderers."""

from xoxss import __version__
from xoxss.utils.helpers import fmt_duration, now_iso, truncate

APP_NAME = "XOX$$"
VERSION = __version__

__all__ = [
    "APP_NAME",
    "VERSION",
    "fmt_duration",
    "now_iso",
    "truncate",
]
