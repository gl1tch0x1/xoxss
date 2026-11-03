"""
URL utility functions.
"""

import re
from urllib.parse import urljoin, urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """Normalize a URL."""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    return url


def safe_urljoin(base: str, relative: str) -> str:
    """Safely join URLs."""
    return urljoin(base, relative)
