"""
Target scope enforcement, URL normalization, and boundary matching.
"""

from __future__ import annotations

import re
from typing import List, Optional, Sequence
from urllib.parse import urlsplit

from xoxss.utils.urlpolicy import (
    looks_like_dangerous,
    looks_like_page,
    normalize_scan_url,
)

# Canonical alias
normalize_url = normalize_scan_url


class Scope:
    """Enforces target boundary rules (hostname, ports, includes/excludes, subdomains)."""

    def __init__(
        self,
        base_url: str,
        allow_subdomains: bool = False,
        include: Optional[Sequence[str]] = None,
        exclude: Optional[Sequence[str]] = None,
        allow_scheme_downgrade: bool = False,
    ) -> None:
        parts = urlsplit(base_url)
        self.scheme = (parts.scheme or "https").lower()
        self.host = self._canonical_host(parts.hostname or "")
        try:
            self.base_port = parts.port
        except ValueError:
            self.base_port = -1
        self.allow_subdomains = allow_subdomains
        # Downgrading an https target to cleartext is never necessary for XSS
        # testing and leaks cookies/Authorization headers.  Keep it opt-in.
        self.allow_scheme_downgrade = allow_scheme_downgrade
        self.include: List[re.Pattern] = [re.compile(pattern, re.I) for pattern in (include or [])]
        self.exclude: List[re.Pattern] = [re.compile(pattern, re.I) for pattern in (exclude or [])]

    @staticmethod
    def _canonical_host(host: str) -> str:
        try:
            return host.rstrip(".").encode("idna").decode("ascii").lower()
        except (UnicodeError, AttributeError):
            return ""

    @property
    def origin(self) -> str:
        """Return the canonical ``scheme://host[:port]`` anchor for credentials."""
        default_port = 443 if self.scheme == "https" else 80
        if self.base_port and self.base_port != default_port:
            return f"{self.scheme}://{self.host}:{self.base_port}"
        return f"{self.scheme}://{self.host}"

    def in_scope(self, url: str) -> bool:
        """Return True if url falls within the configured target scope."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        if parts.scheme not in ("http", "https"):
            return False
        if (
            self.scheme == "https"
            and parts.scheme == "http"
            and not self.allow_scheme_downgrade
        ):
            return False
        if parts.username is not None or parts.password is not None or self.base_port == -1:
            return False
        host = self._canonical_host(parts.hostname or "")
        if not host:
            return False
        try:
            candidate_port = parts.port
        except ValueError:
            return False
        allowed_ports = {self.base_port} if self.base_port is not None else {80, 443}
        effective_port = candidate_port or (443 if parts.scheme == "https" else 80)
        if effective_port not in allowed_ports:
            return False
        if self.allow_subdomains:
            if host != self.host and not host.endswith("." + self.host):
                return False
        elif host != self.host:
            return False
        if self.include and not any(regex.search(url) for regex in self.include):
            return False
        if any(regex.search(url) for regex in self.exclude):
            return False
        return True


__all__ = [
    "Scope",
    "looks_like_dangerous",
    "looks_like_page",
    "normalize_scan_url",
    "normalize_url",
]

