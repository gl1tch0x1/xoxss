"""Bounded probes for response-side delimiter normalization and decoding."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Sequence


@dataclass(frozen=True)
class MutationProbe:
    name: str
    sent: str
    expected: str
    kind: str
    pattern: str = "exact"
    marker: str = ""


@dataclass(frozen=True)
class MutationObservation:
    name: str
    kind: str
    sent: str
    transformed: str
    evidence: str


_UNICODE_DELIMITERS = (
    ("fullwidth-lt", "\uff1c", "<"),
    ("small-lt", "\ufe64", "<"),
    ("fullwidth-gt", "\uff1e", ">"),
    ("small-gt", "\ufe65", ">"),
    ("fullwidth-double-quote", "\uff02", '"'),
    ("fullwidth-single-quote", "\uff07", "'"),
    ("fullwidth-backtick", "\uff40", "`"),
)


def build_probes(marker: str, limit: int = 12) -> List[MutationProbe]:
    """Create compact, uniquely attributable probes; never emit raw binary bytes."""
    end = "xoxssend"
    probes = [
        MutationProbe(name, f"{marker}{source}{end}", f"{marker}{expected}{end}", "unicode-normalization", marker=marker)
        for name, source, expected in _UNICODE_DELIMITERS
    ]
    probes.extend(
        [
            MutationProbe("double-url-decode-lt", f"{marker}%253C{end}", f"{marker}<{end}", "multi-pass-decode", marker=marker),
            MutationProbe("double-url-decode-gt", f"{marker}%253E{end}", f"{marker}>{end}", "multi-pass-decode", marker=marker),
            MutationProbe("nested-html-entity-quote", f"{marker}&amp;quot;{end}", f'{marker}"{end}', "multi-pass-decode", marker=marker),
            MutationProbe("legacy-7bit-lt", f"{marker}%BC{end}", f"{marker}<{end}", "byte-mask", marker=marker),
            MutationProbe("legacy-7bit-gt", f"{marker}%BE{end}", f"{marker}>{end}", "byte-mask", marker=marker),
            MutationProbe("gbk-backslash-swallow", f"{marker}%DF%5C%22{end}", f'{marker}"{end}', "multibyte", "gbk-quote", marker),
            MutationProbe("shift-jis-backslash-swallow", f"{marker}%81%5C%27{end}", f"{marker}'{end}", "multibyte", "sjis-quote", marker),
        ]
    )
    return probes[: max(0, min(len(probes), int(limit)))]


def observe(body: str, probe: MutationProbe) -> Optional[MutationObservation]:
    """Require the unique marker and expected delimiter to co-occur in order."""
    if not body:
        return None
    if probe.pattern == "exact":
        if probe.expected not in body:
            return None
        transformed = probe.expected[len(probe.marker) : -len("xoxssend")]
    else:
        marker = probe.marker
        expected_delimiter = probe.expected[len(marker):len(marker) + 1]
        match = re.search(
            re.escape(marker) + r".{0,8}" + re.escape(expected_delimiter) + r"xoxssend",
            body,
        )
        if not match:
            return None
        transformed = match.group(0)
    return MutationObservation(
        name=probe.name,
        kind=probe.kind,
        sent=probe.sent,
        transformed=transformed,
        evidence=f"unique marker survived while encoded delimiter transformed ({probe.name})",
    )


def reverse_normalization(text: str, observations: Sequence[MutationObservation]) -> str:
    """Apply only observed Unicode-to-ASCII mappings to a payload candidate."""
    mappings = {
        source: ascii_char
        for name, source, ascii_char in _UNICODE_DELIMITERS
        for observation in observations
        if observation.name == name
    }
    if not mappings:
        return text
    return text.translate(str.maketrans(mappings))


def apply_observed_normalization(text: str, observations: Sequence[MutationObservation]) -> str:
    """Encode ASCII syntax delimiters using only empirically observed equivalents."""
    mappings = {
        ascii_char: source
        for name, source, ascii_char in _UNICODE_DELIMITERS
        for observation in observations
        if observation.name == name
    }
    if not mappings:
        return text
    return text.translate(str.maketrans(mappings))
