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

PROBE_CHARS: List[str] = [
    # --- Original ---
    "'", '"', "<", ">", "/", ";", "(", ")", "{", "}", "=", "`",
    # --- HTML / XML delimiters ---
    "&", "#", "?", ":", "\\", "|", "*", "!", ",", "-", "+", "%", "$", "@", "[", "]", " ",
    # --- Whitespace & control characters ---
    "\t", "\n", "\r", "\v", "\f", "\x00", "\x1f", "\x7f",
    # --- Unicode whitespace ---
    "\u00a0", "\u2000", "\u2001", "\u2002", "\u2003", "\u200b",
    "\u2028", "\u2029", "\ufeff",
    # --- Unicode normalization probes ---
    "\u02bc", "\u2018", "\u2019", "\u201c", "\u201d",
    "\uff1c", "\uff1e", "\uff02", "\uff07",
]

# Encoded representations a server/WAF may emit instead of the raw delimiter.
ESCAPE_MAP: Dict[str, List[str]] = {
    # --- Original ---
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
    # --- HTML / XML delimiters ---
    "&": ["&amp;", "&#38;", "&#x26;", "%26", r"\u0026", r"\x26", r"\&"],
    "#": ["&#35;", "&#x23;", "%23", r"\u0023", r"\x23", r"\#"],
    "?": ["&#63;", "&#x3f;", "%3f", r"\u003f", r"\x3f", r"\?"],
    ":": ["&#58;", "&#x3a;", "&colon;", "%3a", r"\u003a", r"\x3a", r"\:"],
    "\\": ["&#92;", "&#x5c;", "%5c", r"\\", r"\u005c", r"\x5c"],
    "|": ["&#124;", "&#x7c;", "%7c", r"\u007c", r"\x7c", r"\|"],
    "*": ["&#42;", "&#x2a;", "%2a", r"\u002a", r"\x2a", r"\*"],
    "!": ["&#33;", "&#x21;", "%21", r"\u0021", r"\x21"],
    ",": ["&#44;", "&#x2c;", "%2c", r"\u002c", r"\x2c"],
    "-": ["&#45;", "&#x2d;", "%2d", r"\u002d", r"\x2d", r"\-"],
    "+": ["&#43;", "&#x2b;", "%2b", r"\u002b", r"\x2b", r"\+"],
    "%": ["&#37;", "&#x25;", "%25", r"\u0025", r"\x25"],
    "$": ["&#36;", "&#x24;", "%24", r"\u0024", r"\x24", r"\$"],
    "@": ["&#64;", "&#x40;", "%40", r"\u0040", r"\x40"],
    # --- Literal [ and ] avoided via \x5b / \x5d so bracket counters stay balanced ---
    "\x5b": ["&#91;", "&#x5b;", "%5b", r"\u005b", r"\x5b", "\x5c\x5b"],
    "\x5d": ["&#93;", "&#x5d;", "%5d", r"\u005d", r"\x5d", "\x5c\x5d"],
    " ": ["&#32;", "&#x20;", "%20", "+", "&nbsp;", "&#160;", "&#xa0;", "%c2%a0",
          "&ensp;", "&emsp;", "&thinsp;", r"\u0020", r"\x20"],
    # --- Whitespace / control chars ---
    "\t": ["&#9;", "&#x09;", "%09", "&Tab;", r"\t", r"\u0009", r"\x09"],
    "\n": ["&#10;", "&#x0a;", "%0a", "%0A", "&NewLine;", r"\n", r"\u000a", r"\x0a"],
    "\r": ["&#13;", "&#x0d;", "%0d", "%0D", r"\r", r"\u000d", r"\x0d"],
    "\v": ["&#11;", "&#x0b;", "%0b", r"\v", r"\u000b", r"\x0b"],
    "\f": ["&#12;", "&#x0c;", "%0c", r"\f", r"\u000c", r"\x0c"],
    "\x00": ["%00", r"\u0000", r"\x00", r"\0"],
    "\x1f": ["%1f", r"\u001f", r"\x1f"],
    "\x7f": ["%7f", r"\u007f", r"\x7f"],
    # --- Unicode whitespace ---
    "\u00a0": ["&nbsp;", "&#160;", "&#xa0;", "%c2%a0", r"\u00a0"],
    "\u2000": ["&#8192;", "&#x2000;", "%e2%80%80", r"\u2000"],
    "\u2001": ["&#8193;", "&#x2001;", "%e2%80%81", r"\u2001"],
    "\u2002": ["&#8194;", "&#x2002;", "%e2%80%82", r"\u2002"],
    "\u2003": ["&#8195;", "&#x2003;", "%e2%80%83", r"\u2003"],
    "\u200b": ["&#8203;", "&#x200b;", "%e2%80%8b", "&ZeroWidthSpace;", r"\u200b"],
    "\u2028": ["&#8232;", "&#x2028;", "%e2%80%a8", r"\u2028"],
    "\u2029": ["&#8233;", "&#x2029;", "%e2%80%a9", r"\u2029"],
    "\ufeff": ["&#65279;", "&#xfeff;", "%ef%bb%bf", r"\ufeff"],
    # --- Unicode normalization probes ---
    "\u02bc": ["%ca%bc", r"\u02bc"],
    "\u2018": ["&#8216;", "&#x2018;", "&lsquo;", "%e2%80%98", r"\u2018"],
    "\u2019": ["&#8217;", "&#x2019;", "&rsquo;", "%e2%80%99", r"\u2019"],
    "\u201c": ["&#8220;", "&#x201c;", "&ldquo;", "%e2%80%9c", r"\u201c"],
    "\u201d": ["&#8221;", "&#x201d;", "&rdquo;", "%e2%80%9d", r"\u201d"],
    "\uff1c": ["&#65244;", "&#xff1c;", "%ef%bc%9c", r"\uff1c"],
    "\uff1e": ["&#65246;", "&#xff1e;", "%ef%bc%9e", r"\uff1e"],
    "\uff02": ["&#65282;", "&#xff02;", "%ef%bc%82", r"\uff02"],
    "\uff07": ["&#65287;", "&#xff07;", "%ef%bc%87", r"\uff07"],
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
