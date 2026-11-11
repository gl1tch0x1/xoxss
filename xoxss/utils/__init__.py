"""
Utility modules for XOXSS scanner.
"""

from xoxss.utils.url import normalize_url, urljoin
from xoxss.utils.helpers import truncate, fmt_duration, now_iso

__all__ = [
    "normalize_url",
    "urljoin",
    "truncate",
    "fmt_duration",
    "now_iso",
]
