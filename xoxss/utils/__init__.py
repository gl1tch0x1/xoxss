"""
Utility modules for XOXSS scanner.
"""

from xoxss.utils.url import normalize_url, urljoin
from xoxss.utils.helpers import truncate, fmt_duration, now_iso

__all__ = [
    "fmt_duration",
    "normalize_url",
    "now_iso",
    "truncate",
    "urljoin",
]
