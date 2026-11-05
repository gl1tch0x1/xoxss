"""Canonical response reflection and browser-escalation qualification."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

try:
    from xoxss.detection.reflection import score_reflection
except Exception:  # pragma: no cover - scanner remains usable in partial installs
    def score_reflection(payload: str, response: str, marker: str = ""):
        return 0.0, 100.0


@dataclass
class ReflectionInfo:
    reflected: bool = False
    context: str = "unknown"
    executable: bool = False
    raw_specials: List[str] = field(default_factory=list)
    snippet: str = ""
    detail: str = ""
    efficiency: float = 0.0
    distortion: float = 0.0
    marker: str = ""
    static_dead_zone: bool = False


SPECIAL_CHARS = "<>\"'`()=/\\ \t\r\n"


def analyze_reflection(
    body: str, token: str, sent_payload: str, content_type: str = ""
) -> ReflectionInfo:
    """Locate a marker and infer its response context and delimiter survival."""
    info = ReflectionInfo()
    if not body:
        return info
    index = body.find(token)
    if index < 0:
        index = body.lower().find(token.lower())
        if index < 0:
            return info

    after = body[index + len(token):]
    marker_offset = sent_payload.find(token) if token in sent_payload else -1
    context_index = index - marker_offset if marker_offset >= 0 else index
    context_index = max(0, min(context_index, len(body) - 1))
    context_before = body[:context_index]
    low_before = context_before.lower()
    context = "html"
    in_comment = low_before.rfind("<!--") > low_before.rfind("-->")
    in_script = low_before.rfind("<script") > low_before.rfind("</script")
    in_style = low_before.rfind("<style") > low_before.rfind("</style")
    last_lt, last_gt = context_before.rfind("<"), context_before.rfind(">")
    in_tag = last_lt > last_gt

    if in_comment:
        context = "comment"
    elif in_script:
        context = "script"
    elif in_style:
        context = "style"
    elif in_tag:
        segment = context_before[last_lt:]
        if segment.count('"') % 2:
            context = "attr_double"
        elif segment.count("'") % 2:
            context = "attr_single"
        elif re.search(r"=\s*[^\s\"'>]*$", segment):
            context = "attr_unquoted"
    elif "json" in content_type.lower() or body.lstrip()[:1] in ("{", "["):
        context = "json"

    tag_start = context_before.rfind("<")
    current_tag = context_before[tag_start:].lower() if tag_start >= 0 else ""
    in_template = low_before.rfind("<template") > low_before.rfind("</template")
    in_cdata = low_before.rfind("<![cdata[") > low_before.rfind("]]>")
    in_meta = in_tag and current_tag.startswith("<meta")

    if context == "html":
        try:
            from xoxss.detection.context import ContextDetector

            detailed = ContextDetector().detect_context(body, context_index)
            context = {
                "HTML_BODY": "html", "HTML_TAG": "html", "MATHML": "html", "SVG_DATA": "html",
                "ATTR_DOUBLE_QUOTED": "attr_double", "ATTR_SINGLE_QUOTED": "attr_single",
                "ATTR_UNQUOTED": "attr_unquoted", "JAVASCRIPT_STRING_DOUBLE": "script",
                "JAVASCRIPT_STRING_SINGLE": "script", "JAVASCRIPT_TEMPLATE": "script",
                "JAVASCRIPT_CODE": "script", "TEMPLATE_LITERAL": "script",
                "JAVASCRIPT_COMMENT": "comment", "HTML_COMMENT": "comment",
                "CSS_STRING": "style", "CSS_PROPERTY": "style", "JSON_STRING": "json",
                "JSON_VALUE": "json", "URL_PATH": "url", "URL_QUERY": "url",
                "URL_FRAGMENT": "url", "DATA_URI": "url",
            }.get(detailed.context_type.name, context)
        except Exception:
            pass

    tail_sent = sent_payload[sent_payload.find(token) + len(token):] if token in sent_payload else ""
    tail_recv = after[: max(1, len(tail_sent) + 8)]
    raw_specials = [
        char for offset, char in enumerate(tail_sent)
        if char in SPECIAL_CHARS and offset < len(tail_recv) and tail_recv[offset] == char
    ]
    verbatim = bool(sent_payload) and sent_payload in body
    raw = set(raw_specials)
    payload_chars = set(sent_payload)

    def survived(chars: str) -> bool:
        return any(char in raw for char in chars) or (
            verbatim and any(char in payload_chars for char in chars)
        )

    executable = {
        "html": survived("<"),
        "attr_double": survived('"'),
        "attr_single": survived("'"),
        "attr_unquoted": survived(" >\"'`"),
        "script": survived("'\"`<"),
        "style": survived("<"),
        "comment": survived(">-"),
        "json": survived('<"\\'),
        "url": True,
    }.get(context, False)

    info.reflected = True
    info.marker = token
    info.static_dead_zone = in_comment or in_template or in_cdata or in_meta
    info.context = context
    info.executable = executable
    info.raw_specials = raw_specials
    info.snippet = re.sub(r"\s+", " ", body[max(0, index - 90): index + len(token) + 90])
    info.efficiency, info.distortion = score_reflection(sent_payload, body, token)
    info.detail = (
        f"context={context}, raw={''.join(sorted(raw)) or 'none'}, "
        f"verbatim={'yes' if verbatim else 'no'}, executable={'yes' if executable else 'no'}, "
        f"efficiency={info.efficiency:.1f}%"
    )
    return info


def browser_prequalified(info: ReflectionInfo, content_type: str) -> bool:
    """Conservatively avoid browser work for non-executable reflection candidates."""
    if not info.reflected or not info.executable:
        return False
    mime = (content_type or "").split(";", 1)[0].strip().lower()
    if mime not in {"text/html", "application/xhtml+xml", "image/svg+xml"}:
        return False
    if info.context in {"comment", "json", "style"}:
        return False
    if info.static_dead_zone:
        return False
    snippet = info.snippet.lower()
    token_pos = snippet.find(info.marker.lower()) if info.marker else -1
    before = snippet[:token_pos] if token_pos >= 0 else snippet
    if before.rfind("<template") > before.rfind("</template"):
        return False
    if before.rfind("<![cdata[") > before.rfind("]]>"):
        return False
    if "<meta" in before[max(0, len(before) - 160):]:
        return False
    critical = set("<>\"'`\\")
    return bool(critical.intersection(info.raw_specials)) or info.context == "url"
