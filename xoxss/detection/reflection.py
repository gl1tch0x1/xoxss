"""
Reflection fidelity scoring.

This module used to host a second, context-classifying reflection analyzer.
That analyzer was never wired into the scanner (``scan/reflection.py`` owns the
live implementation), its fallback matched a literal ``x`` rather than the
injected marker, and keeping two importable analyzers with different semantics
was a maintenance trap.  Only the shared scoring primitive remains.
"""

from __future__ import annotations

import html
import re
from typing import Optional, Tuple


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def _decoded_start(response: str, position: int, count: int) -> int:
    """Walk backwards from ``position`` over ``count`` decoded characters.

    This keeps the alignment correct when the server entity- or
    percent-encodes the payload: e.g. ``&lt;`` counts as one character and
    ``%3C`` as one character, not four and three.
    """
    index = max(0, min(position, len(response)))
    seen = 0
    while index > 0 and seen < count:
        if index >= 3 and response[index - 1] == ";":
            window = response[max(0, index - 32):index]
            match = re.search(r"&(?:#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);$", window)
            if match:
                index -= len(match.group(0))
                seen += 1
                continue
        if index >= 3 and response[index - 3] == "%" and re.fullmatch(
            r"%[0-9a-fA-F]{2}", response[index - 3:index]
        ):
            index -= 3
            seen += 1
            continue
        index -= 1
        seen += 1
    return max(0, index)


def _best_window(
    payload: str,
    response: str,
    position: int,
    marker: str = "",
) -> Optional[Tuple[float, int, int]]:
    """Align the sent payload against the reflected response.

    The naive approach (``response[position:position + len(payload)]``) is only
    correct when the payload is echoed byte-for-byte, which makes the score
    useless for the cases we care about: truncation, entity encoding, and
    character stripping.  We locate the payload start by walking back over the
    encoded prefix, then vary only the window length to absorb encoding
    expansion (``&lt;`` is 3 chars longer, ``%3C`` is 2 chars longer).

    Returns ``(normalised_distance, distance, window_length)`` or ``None``.
    """
    if not payload or position < 0 or position >= len(response):
        return None

    # Fast path: byte-for-byte reflection (the common case) at C speed.
    if payload in response:
        return (0.0, 0, len(payload))

    offset = payload.find(marker) if marker else -1
    if offset < 0:
        offset = 0
    anchor = _decoded_start(response, position, offset)
    if len(response) - anchor <= 0:
        return None

    best: Optional[Tuple[float, int, int]] = None
    lengths = {len(payload), len(payload) + 6, len(payload) + 12, len(payload) * 2}
    available = len(response) - anchor
    for target_len in lengths:
        length = min(available, max(1, target_len))
        candidate = response[anchor:anchor + length]
        distance = levenshtein_distance(payload, candidate)
        denominator = max(len(payload), len(candidate))
        if denominator == 0:
            continue
        score = distance / denominator
        if best is None or (score, distance) < (best[0], best[1]):
            best = (score, distance, len(candidate))
    return best


def score_reflection(payload: str, response: str, marker: str = "") -> Tuple[float, float]:
    """Score how faithfully ``payload`` survived in ``response``.

    Returns ``(efficiency, distortion)`` as percentages (0-100).  This is the
    single shared implementation used by both the package analyzers and the
    scanner, so the console, JSON and SARIF reports agree on the metric.
    """
    if not payload or not response:
        return 0.0, 100.0

    position = -1
    anchors = [marker] if marker else []
    if marker and len(marker) >= 8:
        anchors.append(marker[:6])
    anchors.append(payload)

    haystacks = (response, html.unescape(response))
    for anchor in anchors:
        if not anchor:
            continue
        for haystack in haystacks:
            found = haystack.find(anchor)
            if found < 0:
                continue
            if haystack is response:
                position = found
            else:
                # The anchor only matched after entity decoding; map it back to
                # an offset in the raw response so the window stays aligned.
                raw = response.find(anchor[: min(6, len(anchor))])
                position = raw if raw >= 0 else min(found, len(response) - 1)
            break
        if position >= 0:
            break

    if position < 0:
        return 0.0, 100.0

    best = _best_window(payload, response, position, marker)
    if best is None:
        return 0.0, 100.0
    efficiency = round(max(0.0, (1.0 - best[0]) * 100.0), 2)
    return efficiency, round(100.0 - efficiency, 2)


__all__ = ["levenshtein_distance", "score_reflection"]
