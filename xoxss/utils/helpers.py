"""
Helper utility functions.

These are the canonical implementations used across the scanner.  Console,
report and UI modules re-export them instead of keeping their own copies so
formatting stays consistent (and small edge cases only need fixing once).
"""

import re
from datetime import datetime, timezone


def truncate(text: str, limit: int = 400) -> str:
    """Truncate text to a maximum length, appending an ellipsis when cut."""
    value = str(text)
    if limit <= 0:
        return ""
    if len(value) <= limit:
        return value
    if limit <= 3:
        return value[:limit]
    return value[: limit - 3] + "..."


def fmt_duration(seconds: float) -> str:
    """Format duration in human-readable seconds/minutes/hours."""
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, sec = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {sec}s"
    return f"{minutes}m {sec}s"


def now_iso() -> str:
    """Get current time in ISO-8601 format (UTC, second precision)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def strip_ansi(text: str) -> str:
    """Strip ANSI SGR colour codes from text."""
    return re.sub(r"\033\[[0-9;]*m", "", text)
