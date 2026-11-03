"""
Utility modules for XOXSS scanner.
"""

from xoxss.utils.console import Console
from xoxss.utils.marker import unique_token
from xoxss.utils.url import normalize_url, urljoin
from xoxss.utils.helpers import truncate, fmt_duration, now_iso

__all__ = [
    "Console",
    "unique_token",
    "normalize_url",
    "urljoin",
    "truncate",
    "fmt_duration",
    "now_iso",
]
