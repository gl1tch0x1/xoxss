"""HTTP response splitting / CRLF header-injection probes.

A parameter that reaches a response header (``Location``, ``Set-Cookie``,
``Content-Type``, ``Link``) without CR/LF normalisation lets an attacker add
arbitrary headers and, with a second CRLF, a full response body.  When that
body is HTML the result is reflected XSS with no markup filtering to bypass.

Detection is intentionally conservative: a finding requires the injected
header to appear *parsed as a header* in the response, not merely for the
payload string to be echoed in a header value.
"""

from __future__ import annotations

import re
from typing import Dict, List, Mapping, Optional, Tuple

#: Query parameter names that commonly reach response headers (redirects,
#: cookies, content negotiation).  They are probed first so a scan spends its
#: budget where header injection actually happens.
HEADER_PARAM_HINTS: Tuple[str, ...] = (
    "url",
    "uri",
    "next",
    "redirect",
    "redirect_uri",
    "redirecturl",
    "redirect_url",
    "return",
    "returnurl",
    "return_url",
    "returnto",
    "continue",
    "dest",
    "destination",
    "goto",
    "target",
    "callback",
    "jsonp",
    "lang",
    "language",
    "locale",
    "country",
    "theme",
    "style",
    "page",
    "view",
    "format",
    "download",
    "file",
    "filename",
    "name",
)

_CRLF_HEADER = "X-XOXSS-{token}"


def rank_header_candidates(names: List[str]) -> List[str]:
    """Order parameter names by how likely they are to reach a header."""
    hints = {name.lower(): index for index, name in enumerate(HEADER_PARAM_HINTS)}
    ranked = sorted(
        enumerate(names),
        key=lambda item: (hints.get(item[1].lower(), len(hints)), item[0]),
    )
    return [name for _index, name in ranked]


def build_split_values(token: str) -> List[Tuple[str, str]]:
    """Return labelled CR/LF payload variants for one probe.

    ``\\r\\n`` is the canonical sequence; bare ``\\n`` catches parsers that
    normalise CR away, and the space-prefixed form exercises obsolete line
    folding.  The value is URL-encoded by the caller, so the server must decode
    it before echoing it into a header for an injection to occur.
    """
    header = _CRLF_HEADER.format(token=token)
    return [
        ("crlf", f"\r\n{header}: 1"),
        ("lf", f"\n{header}: 1"),
        ("obs-fold", f"\r\n {header}: 1"),
    ]


def find_injected_header(
    headers: Mapping[str, str], token: str
) -> Optional[str]:
    """Return the injected header name if the response contains it."""
    if not headers or not token:
        return None
    needle = _CRLF_HEADER.format(token=token).lower()
    for name in headers:
        if needle in str(name).lower():
            return str(name)
    return None


def header_value_risks(headers: Mapping[str, str]) -> List[Dict[str, str]]:
    """Flag response headers whose values are HTML-shaped.

    This is a lead, not a finding: a header value only executes when it is
    copied into the document body or used as an unsafe redirect target.
    """
    risky: List[Dict[str, str]] = []
    for name, value in (headers or {}).items():
        text = str(value or "")
        lowered = name.lower()
        if lowered not in {
            "location",
            "refresh",
            "content-security-policy",
            "link",
            "set-cookie",
        }:
            continue
        if re.search(r"<\s*(?:script|img|svg|iframe|body|html)\b", text, re.I):
            risky.append({"header": str(name), "value": text[:160]})
    return risky


__all__ = [
    "HEADER_PARAM_HINTS",
    "build_split_values",
    "find_injected_header",
    "header_value_risks",
    "rank_header_candidates",
]
