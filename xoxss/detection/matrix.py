"""Special-character reflection matrix.

A single probe encodes the same token around each delimiter an attacker needs
to break out of an HTML/JS/attribute context.  Analysing where those probes
land tells the payload engine (and the optional AI fallback) which delimiters
survive, which are entity/escape encoded, which are stripped, and which are
silently replaced.

The status model matches XSSRush:

* ``allowed``  - the raw character is reflected verbatim
* ``escaped``   - the character is present in an entity / escape form
* ``filtered``  - the character is removed entirely (token fragments remain)
* ``replaced``  - neither raw nor escaped nor removed; the position changed
* ``absent``    - the probe marker itself was not reflected

This module is deliberately request-free: callers send
:func:`build_matrix_probe` themselves and hand the response to
:func:`analyze_character_matrix`.
"""

from __future__ import annotations

from typing import Dict, List, Optional

PROBE_CHARS: List[str] = ["'", '"', "<", ">", "/", ";", "(", ")", "{", "}", "=", "`"]

# Encoded representations a server/WAF may emit instead of the raw delimiter.
ESCAPE_MAP: Dict[str, List[str]] = {
    "<": ["&lt;", "&#60;", "&#x3c;", r"\u003c", r"\x3c", "%3c"],
    ">": ["&gt;", "&#62;", "&#x3e;", r"\u003e", r"\x3e", "%3e"],
    '"': ["&quot;", "&#34;", "&#x22;", r"\"", r"\u0022", r"\x22", "%22"],
    "'": ["&#39;", "&apos;", "&#x27;", r"\'", r"\u0027", r"\x27", "%27"],
    "/": ["&#47;", "&#x2f;", r"\/", "%2f"],
    ";": ["&#59;", "&#x3b;", "%3b"],
    "(": ["&#40;", "&#x28;", "%28"],
    ")": ["&#41;", "&#x29;", "%29"],
    "{": ["&#123;", "&#x7b;", "%7b"],
    "}": ["&#125;", "&#x7d;", "%7d"],
    "=": ["&#61;", "&#x3d;", "%3d"],
    "`": ["&#96;", "&#x60;", r"\`", "%60"],
}

STATUSES = ("allowed", "escaped", "filtered", "replaced", "absent")


def build_matrix_probe(token: str, chars: Optional[List[str]] = None) -> str:
    """Build one probe carrying every delimiter bracketed by ``token``.

    ``token0'token token1"token ...`` lets the analyser attribute each
    delimiter independently even when the whole string is reflected together.
    """
    marker = str(token or "")
    selected = list(chars) if chars is not None else PROBE_CHARS
    return "".join(f"{marker}{idx}{ch}{marker}" for idx, ch in enumerate(selected))


def _probe_pair(token: str, index: int) -> str:
    return f"{token}{index}"


def analyze_character_matrix(
    html: str,
    token: str,
    chars: Optional[List[str]] = None,
) -> Dict[str, str]:
    """Classify each delimiter from a response to :func:`build_matrix_probe`."""
    results: Dict[str, str] = {}
    body = str(html or "")
    marker = str(token or "")
    if not body or not marker:
        return {ch: "absent" for ch in (chars or PROBE_CHARS)}

    lower_body = body.lower()
    selected = list(chars) if chars is not None else PROBE_CHARS
    for idx, ch in enumerate(selected):
        raw_pattern = f"{marker}{idx}{ch}{marker}"
        stripped_pattern = f"{marker}{idx}{marker}"
        start_pattern = _probe_pair(marker, idx)

        if raw_pattern in body:
            results[ch] = "allowed"
        elif any(
            f"{marker}{idx}{escaped}{marker}".lower() in lower_body
            for escaped in ESCAPE_MAP.get(ch, [])
        ):
            results[ch] = "escaped"
        elif stripped_pattern in body:
            results[ch] = "filtered"
        elif start_pattern in body:
            # The token and index survived but the delimiter did not appear in
            # any known encoding.  This covers replacement-by-another-char and
            # truncation/wrapping behaviour without claiming a raw delimiter.
            results[ch] = "replaced"
        else:
            results[ch] = "absent"
    return results


def format_matrix_summary(matrix: Dict[str, str]) -> Dict[str, List[str]]:
    """Group a matrix by status for reports and the AI prompt."""
    summary: Dict[str, List[str]] = {status: [] for status in STATUSES if status != "absent"}
    for ch, status in (matrix or {}).items():
        if status in summary:
            summary[status].append(ch)
    return summary


def matrix_delta(old: Dict[str, str], new: Dict[str, str]) -> str:
    """Short human-readable difference, used in logs and finding detail."""
    if not old:
        return ""
    changed = []
    for ch in PROBE_CHARS:
        before = old.get(ch)
        after = new.get(ch)
        if before and after and before != after:
            changed.append(f"{ch}:{before}->{after}")
    return ", ".join(changed)


__all__ = [
    "ESCAPE_MAP",
    "PROBE_CHARS",
    "STATUSES",
    "analyze_character_matrix",
    "build_matrix_probe",
    "format_matrix_summary",
    "matrix_delta",
]
