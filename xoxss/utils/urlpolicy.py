"""URL classification helpers shared by the scanner and the crawler engine."""

from __future__ import annotations

import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tif", ".tiff",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".webm", ".ogg",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".exe", ".msi", ".dmg", ".apk", ".ipa", ".bin", ".iso",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
    ".js", ".mjs", ".map", ".json", ".xml", ".txt", ".rss", ".atom",
}

DANGEROUS_PATH_WORDS = (
    "logout", "log-out", "signout", "sign-out", "delete", "remove", "destroy",
    "unsubscribe", "cancel-account", "deactivate", "reset-password",
)

# Extensions worth scanning even though they are not HTML pages.
SCANNABLE_EXTENSIONS = {
    ".json",
    ".xml",
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".do",
    ".action",
    ".cgi",
    ".pl",
    ".py",
    ".rb",
}


def normalize_scan_url(url: str) -> str:
    """Canonical form used for crawl deduplication (scheme/host/path/query)."""
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "http").lower()
    netloc = parts.netloc.lower()
    path = parts.path or "/"
    query = urlencode(parse_qsl(parts.query, keep_blank_values=True))
    return urlunsplit((scheme, netloc, path, query, ""))


def url_cluster_key(url: str) -> str:
    """Cluster key representing endpoint signature: scheme://host/path?[sorted_param_names].

    Prevents pagination and ID traps like /item?id=1, /item?id=2, ... from exploding the queue.
    """
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "http").lower()
    netloc = parts.netloc.lower()
    path = (parts.path or "/").rstrip("/") or "/"
    param_names = sorted({k.lower() for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    query_sig = "&".join(param_names)
    return f"{scheme}://{netloc}{path}?{query_sig}" if query_sig else f"{scheme}://{netloc}{path}"


def looks_like_page(url: str) -> bool:
    path = urlsplit(url).path.lower()
    ext = os.path.splitext(path)[1]
    if ext and ext in SKIP_EXTENSIONS:
        return False
    if any(word in path for word in DANGEROUS_PATH_WORDS):
        return False
    return True


def looks_like_dangerous(url: str) -> bool:
    lowered = (urlsplit(url).path or "").lower()
    return any(word in lowered for word in DANGEROUS_PATH_WORDS)


def looks_like_scan_target(url: str, fuzz_params: bool = False) -> bool:
    """True when a discovered URL is worth scanning for XSS."""
    if looks_like_dangerous(url):
        return False
    parts = urlsplit(url)
    if parts.query:
        return True
    path = parts.path.lower()
    ext = os.path.splitext(path)[1]
    if ext in SKIP_EXTENSIONS and ext not in SCANNABLE_EXTENSIONS:
        return False
    if looks_like_page(url):
        return True
    return bool(fuzz_params)


__all__ = [
    "DANGEROUS_PATH_WORDS",
    "SCANNABLE_EXTENSIONS",
    "SKIP_EXTENSIONS",
    "looks_like_dangerous",
    "looks_like_page",
    "looks_like_scan_target",
    "normalize_scan_url",
]
