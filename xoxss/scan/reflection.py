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
    inert_reason: str = ""
    encoded_specials: List[str] = field(default_factory=list)


SPECIAL_CHARS = "<>\"'`()=/\\ \t\r\n"


def analyze_reflection(
    body: str, token: str, sent_payload: str, content_type: str = ""
) -> ReflectionInfo:
    """Locate a marker and infer its response context and delimiter survival.

    Survival is position-aware: only characters that land at the corresponding
    offset after the marker count.  Reflections inside ``<textarea>``/HTML
    comments are inert unless the payload itself closes the region, and
    entity-encoded output (``&lt;``) is never treated as executable.
    """
    info = ReflectionInfo()
    if not body:
        return info
    index = body.find(token)
    if index < 0:
        index = body.lower().find(token.lower())
        if index < 0:
            return info

    after = body[index + len(token):]
    # Classify the marker's *own* position.  Using the start of the reflected
    # payload would misclassify breakout payloads: ``--><script>TOKEN`` begins
    # inside a comment but the marker itself is already outside it.
    context_index = max(0, min(index, len(body) - 1))
    context_before = body[:context_index]
    low_before = context_before.lower()
    context = "html"
    in_comment = low_before.rfind("<!--") > low_before.rfind("-->")
    in_textarea = low_before.rfind("<textarea") > low_before.rfind("</textarea")
    in_script = low_before.rfind("<script") > low_before.rfind("</script")
    in_style = low_before.rfind("<style") > low_before.rfind("</style")
    last_lt, last_gt = context_before.rfind("<"), context_before.rfind(">")
    in_tag = last_lt > last_gt

    tail_sent = sent_payload[sent_payload.find(token) + len(token):] if token in sent_payload else ""
    tail_recv = after[: max(1, len(tail_sent) + 8)]
    comment_breakout = bool(in_comment and "-->" in tail_recv)
    textarea_breakout = bool(in_textarea and "</textarea" in tail_recv.lower())

    if in_comment and not comment_breakout:
        context = "comment"
    elif in_textarea and not textarea_breakout:
        context = "textarea"
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
                "TEXTAREA": "textarea", "CSS_STRING": "style", "CSS_PROPERTY": "style",
                "JSON_STRING": "json", "JSON_VALUE": "json", "URL_PATH": "url",
                "URL_QUERY": "url", "URL_FRAGMENT": "url", "DATA_URI": "url",
            }.get(detailed.context_type.name, context)
        except Exception:
            pass

    # Position-aware delimiter survival: compare the sent tail with the
    # received tail after decoding entities, remembering which characters were
    # emitted raw and which were entity-encoded.
    try:
        from xoxss.detection.context import analyze_char_survival

        raw_set, encoded_set = analyze_char_survival(body, index, token, sent_payload)
    except Exception:
        raw_set, encoded_set = set(), set()

    # Fallback for payloads whose marker offset cannot be derived: retain the
    # historical exact-offset comparison rather than dropping the evidence.
    if not raw_set and not encoded_set and tail_sent:
        for offset, char in enumerate(tail_sent):
            if char in SPECIAL_CHARS and offset < len(tail_recv) and tail_recv[offset] == char:
                raw_set.add(char)

    raw = sorted(raw_set)
    # Entity encoding is about delimiter characters, not incidental raw text:
    # ``&lt;/script&gt;`` leaves a raw ``/`` but is still not executable.
    critical = set("<>\"'`")
    entity_encoded = bool(encoded_set & critical) and not (raw_set & critical)
    verbatim = bool(sent_payload) and sent_payload in body and not entity_encoded
    payload_chars = set(sent_payload)

    def survived(chars: str) -> bool:
        return any(char in raw_set for char in chars) or (
            verbatim and any(char in payload_chars for char in chars)
        )

    # A URL context is only live when the reflected value really lands in a
    # URL-bearing attribute: it must survive verbatim (or keep a
    # ``javascript:``/``data:`` scheme that was not entity-encoded) and either
    # carry such a scheme or retain a delimiter that can break out of the
    # attribute.  Treating every URL-context reflection as executable let
    # escaped text nodes ending in ``javascript:alert(...)`` become
    # high-confidence findings without any usable injection point.
    url_scheme = bool(re.search(r"(?:javascript|data):", sent_payload or "", re.I))
    received = body[index: index + len(sent_payload) + 64]
    scheme_survived = bool(
        url_scheme
        and not entity_encoded
        and re.search(r"(?:javascript|data):", received, re.I)
    )
    url_executable = bool(
        (verbatim or scheme_survived) and (url_scheme or raw_set & set("\"'`<>"))
    )

    executable = {
        "html": survived("<"),
        "attr_double": survived('"'),
        "attr_single": survived("'"),
        "attr_unquoted": survived(" >\"'`"),
        "script": survived("'\"`<"),
        "style": survived("<"),
        "comment": comment_breakout and survived("<"),
        "textarea": textarea_breakout and survived("<"),
        "json": survived('<"\\'),
        "url": url_executable,
    }.get(context, False)

    inert_reason = ""
    if context == "comment":
        inert_reason = "reflection inside an HTML comment (no --> breakout)"
    elif context == "textarea":
        inert_reason = "reflection inside <textarea> (no </textarea> breakout)"
    elif entity_encoded:
        inert_reason = "entity-encoded output (&lt;/&gt;), not a live delimiter"
    elif in_template or in_cdata or in_meta:
        inert_reason = "static dead zone (<template>/<![CDATA[/<meta>)"

    info.reflected = True
    info.marker = token
    info.static_dead_zone = bool(inert_reason)
    info.context = context
    info.executable = executable and not inert_reason
    info.raw_specials = raw
    info.encoded_specials = sorted(encoded_set)
    info.inert_reason = inert_reason
    info.snippet = re.sub(r"\s+", " ", body[max(0, index - 90): index + len(token) + 90])
    info.efficiency, info.distortion = score_reflection(sent_payload, body, token)
    info.detail = (
        f"context={context}, raw={''.join(sorted(raw)) or 'none'}, "
        f"encoded={''.join(info.encoded_specials) or 'none'}, "
        f"verbatim={'yes' if verbatim else 'no'}, executable={'yes' if info.executable else 'no'}, "
        f"efficiency={info.efficiency:.1f}%"
        + (f", inert={inert_reason}" if inert_reason else "")
    )
    return info


#: MIME types a browser parses as an active document.  A missing/blank
#: ``Content-Type`` is included deliberately: browsers sniff the body and many
#: lightweight servers omit the header entirely.
DOCUMENT_EXECUTABLE_MIME = {
    "",
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
}

#: MIME types worth handing to the browser execution gate.  ``text/plain`` is
#: included here because a browser attempt is harmless and lets the gate
#: disprove odd sniffing deployments; it is *not* in
#: :data:`DOCUMENT_EXECUTABLE_MIME`, because a plain-text document cannot
#: execute markup on its own and must not be graded ``high`` without execution.
BROWSER_RENDERABLE_MIME = DOCUMENT_EXECUTABLE_MIME | {"text/plain"}


def http_executable(info: ReflectionInfo, content_type: str) -> bool:
    """True when HTTP-only evidence can justify a ``high``-confidence finding.

    The difference from :func:`browser_prequalified` is ``text/plain``: it is
    worth a browser attempt but is not executable markup, so an unconfirmed
    plain-text reflection is a candidate, not a high-severity finding.
    """
    if not browser_prequalified(info, content_type):
        return False
    mime = (content_type or "").split(";", 1)[0].strip().lower()
    return mime in DOCUMENT_EXECUTABLE_MIME


def browser_prequalified(info: ReflectionInfo, content_type: str) -> bool:
    """Conservatively avoid browser work for non-executable reflection candidates.

    The MIME check only rules out document types a browser can never execute
    (JSON, XML, binaries).  Everything else is decided by the browser itself,
    so the gate never becomes the reason a real XSS is dropped.
    """
    if not info.reflected or not info.executable:
        return False
    mime = (content_type or "").split(";", 1)[0].strip().lower()
    if mime not in BROWSER_RENDERABLE_MIME:
        return False
    if info.context in {"comment", "textarea", "json", "style"}:
        return False
    if info.static_dead_zone or info.inert_reason:
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
