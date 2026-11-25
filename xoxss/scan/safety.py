"""Payload safety filters.

The bundled corpus is a catalogue of *proofs*, not a weapon.  Several upstream
lists contain live exfiltration vectors that point at third-party domains
(``attacker.com``, ``webhook.site``, collaborator hosts) and read
``document.cookie``.  A scanner must never send a target's cookies to a domain
it does not control, so every payload is normalised before it can be fired:

* known callback hosts are rewritten to the reserved ``xoxss.invalid`` domain
  (RFC 6761: guaranteed not to resolve);
* cookie/DOM exfiltration expressions are replaced with an inert marker when
  the payload also performs a network request.

The transforms are deliberately conservative: they keep the executable shape
(``<img onerror=...>``, ``<script>...``) so the payload still proves execution,
but remove the data-leaving behaviour.
"""

from __future__ import annotations

import re

#: Domains used by public XSS proof-of-concept payloads.  None of these are
#: controlled by XOXSS, so a fired payload must not contact them.
CALLBACK_HOSTS = (
    "attacker.com",
    "attacker.tld",
    "evil.com",
    "evil.tld",
    "webhook.site",
    "requestbin.net",
    "requestbin.com",
    "pipedream.net",
    "burpcollaborator.net",
    "oastify.com",
    "oast.fun",
    "interact.sh",
    "dnslog.cn",
    "ceye.io",
)

#: Reserved, non-resolvable destination (RFC 6761).
SAFE_CALLBACK = "https://xoxss.invalid"

_CALLBACK_RE = re.compile(
    r"(?:https?:)?//(?:[A-Za-z0-9._-]+\.)?(?:"
    + "|".join(re.escape(host) for host in CALLBACK_HOSTS)
    + r")(?::\d+)?",
    re.IGNORECASE,
)

#: Network sinks that turn a cookie read into an exfiltration.
_NETWORK_SINK_RE = re.compile(
    r"(?:fetch\s*\(|XMLHttpRequest|sendBeacon|new\s+Image|\.src\s*=|"
    r"location(?:\.href)?\s*=|window\.open\s*\()",
    re.IGNORECASE,
)

_COOKIE_RE = re.compile(r"document\s*\.\s*cookie", re.IGNORECASE)
_STORAGE_RE = re.compile(
    r"(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|key)\s*\([^)]*\)",
    re.IGNORECASE,
)


def sanitize_payload(payload: str) -> str:
    """Return ``payload`` with third-party exfiltration made inert.

    The function is idempotent and safe to call on every corpus entry.
    """
    if not payload:
        return payload

    cleaned = _CALLBACK_RE.sub(SAFE_CALLBACK, payload)

    # Only neuter cookie/storage reads when the payload also performs a
    # network request.  ``alert(document.cookie)`` is a harmless proof and is
    # intentionally left alone.
    if _NETWORK_SINK_RE.search(cleaned):
        cleaned = _COOKIE_RE.sub("'xoxss-cookie'", cleaned)
        cleaned = _STORAGE_RE.sub("'xoxss-storage'", cleaned)

    return cleaned


def has_external_callback(payload: str) -> bool:
    """Return True when a payload still points at a known callback host."""
    return bool(_CALLBACK_RE.search(payload or ""))


__all__ = [
    "CALLBACK_HOSTS",
    "SAFE_CALLBACK",
    "has_external_callback",
    "sanitize_payload",
]
