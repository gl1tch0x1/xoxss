"""
Helper utility functions.
"""

from datetime import datetime, timezone


def truncate(text: str, max_length: int) -> str:
    """Truncate text to a maximum length."""
    if max_length <= 0:
        return ""
    if len(text) <= max_length:
        return text
    if max_length <= 3:
        return text[:max_length]
    return text[:max_length - 3] + "..."


def fmt_duration(seconds: float) -> str:
    """Format duration in human-readable format."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds / 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s"


def now_iso() -> str:
    """Get current time in ISO format."""
    return datetime.now(timezone.utc).isoformat()
