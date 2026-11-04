"""Shared names and display helpers for report renderers."""

from datetime import datetime, timezone

from xoxss import __version__

APP_NAME = "XOX$$"
VERSION = __version__


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def truncate(text, limit: int = 400) -> str:
    value = str(text)
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def fmt_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, sec = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {sec}s"
    return f"{minutes}m {sec}s"
