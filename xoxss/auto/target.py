"""Target normalisation for the domain-first ``--auto`` workflow.

The operator should be able to type ``example.com`` and get a sane scan.  The
rules are intentionally conservative:

* only ``http``/``https`` are accepted;
* credentials in the URL are rejected (they would end up in reports);
* bare hosts get ``https://`` except loopback/private hosts, which get
  ``http://`` because local fixtures rarely have a trusted certificate;
* an explicit path is preserved, a trailing root slash is removed.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_BAD_HOST_RE = re.compile(r"[\s/\\@]")


class TargetError(ValueError):
    """Raised when a target cannot be normalised into a safe scan URL."""


def _is_local_host(host: str) -> bool:
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def normalize_target(raw: str, *, prefer_https: bool = True) -> str:
    """Return a canonical scan URL for ``raw``.

    >>> normalize_target("example.com")
    'https://example.com'
    >>> normalize_target("127.0.0.1:8080/app")
    'http://127.0.0.1:8080/app'
    """
    value = (raw or "").strip()
    if not value:
        raise TargetError("empty target")

    if not _SCHEME_RE.match(value):
        # ``example.com:8080`` is ambiguous; urlsplit would read the host as a
        # scheme.  Prefix the scheme before parsing.
        value = ("https://" if prefer_https else "http://") + value

    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise TargetError(f"cannot parse target {raw!r}: {exc}") from exc

    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise TargetError(
            f"unsupported scheme {scheme!r}; only http and https are allowed"
        )
    if parts.username is not None or parts.password is not None:
        raise TargetError("target URLs must not contain credentials")

    host = (parts.hostname or "").strip().rstrip(".")
    if not host:
        raise TargetError(f"target {raw!r} has no host")
    if _BAD_HOST_RE.search(host):
        raise TargetError(f"target host {host!r} contains invalid characters")
    if ".." in host:
        raise TargetError(f"target host {host!r} is malformed")

    try:
        port = parts.port
    except ValueError as exc:
        raise TargetError(f"target {raw!r} has an invalid port") from exc

    if _is_local_host(host):
        scheme = "http"
    elif scheme == "http" and prefer_https:
        # A bare host defaults to https; an explicit http:// is respected.
        scheme = "https" if not _SCHEME_RE.match((raw or "").strip()) else "http"

    netloc_host = f"[{host}]" if ":" in host else host
    netloc = netloc_host
    if port is not None:
        netloc = f"{netloc_host}:{port}"
    path = parts.path or ""
    if path == "/":
        path = ""

    return urlunsplit((scheme, netloc, path, parts.query, ""))


def target_host(url: str) -> str:
    """Return the canonical host of an already-normalised URL."""
    return (urlsplit(url).hostname or "").lower()


def sibling_targets(url: str, *, include_www: bool = True) -> list[str]:
    """Return likely alternate origins for the same site (https/www/http).

    Used by the auto planner to detect a redirect to a canonical host without
    silently leaving scope: the caller decides whether the sibling is in scope.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host:
        return [url]
    hosts = {host}
    if include_www:
        if host.startswith("www."):
            hosts.add(host[4:])
        else:
            hosts.add("www." + host)
    variants: list[str] = []
    for candidate_host in sorted(hosts):
        for scheme in ("https", "http"):
            netloc_host = f"[{candidate_host}]" if ":" in candidate_host else candidate_host
            netloc = netloc_host
            if parts.port:
                netloc = f"{netloc_host}:{parts.port}"
            variants.append(
                urlunsplit((scheme, netloc, parts.path, parts.query, ""))
            )
    return list(dict.fromkeys(variants))


__all__ = [
    "TargetError",
    "normalize_target",
    "sibling_targets",
    "target_host",
]
