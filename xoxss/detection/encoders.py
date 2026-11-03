"""
Encoder registry for XSS payload transforms.

The scanner historically had a fixed dictionary of "tampers".  This module turns
that idea into a small registry so new encoders can be added (or third-party
ones registered at runtime) without touching the CLI or the injection engine.

Every encoder is a pure ``str -> str`` callable.  ``apply_chain`` applies them in
order, which makes it easy to describe WAF-evasion chains such as
``urlencode -> mixed_case -> comment_break``.
"""

from __future__ import annotations

import base64
import html
import random
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Sequence, Tuple


@dataclass(frozen=True)
class Encoder:
    """A named payload transform."""

    name: str
    func: Callable[[str], str]
    description: str
    contexts: Tuple[str, ...] = ("any",)
    reversible: bool = False
    tags: Tuple[str, ...] = field(default_factory=tuple)

    def encode(self, value: str) -> str:
        return self.func(value or "")


def _random_case(value: str) -> str:
    """Randomise the case of tag/event/scheme tokens only (keeps JS intact)."""
    value = re.sub(
        r"<([a-zA-Z][a-zA-Z0-9]*)",
        lambda m: "<" + "".join(
            ch.upper() if random.random() < 0.5 else ch.lower() for ch in m.group(1)
        ),
        value,
    )
    value = re.sub(
        r"\b(on[a-zA-Z]+)(\s*=)",
        lambda m: "".join(
            ch.upper() if random.random() < 0.5 else ch.lower() for ch in m.group(1)
        )
        + m.group(2),
        value,
    )
    return re.sub(
        r"\b(javascript|data|vbscript)\s*:",
        lambda m: "".join(
            ch.upper() if random.random() < 0.5 else ch.lower() for ch in m.group(1)
        )
        + ":",
        value,
        flags=re.I,
    )


def _urlencode(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _double_urlencode(value: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(value, safe=""), safe="")


def _hex_entities(value: str) -> str:
    return "".join(f"&#x{ord(ch):x};" for ch in value)


def _dec_entities(value: str) -> str:
    return "".join(f"&#{ord(ch)};" for ch in value)


def _html_entities(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _js_unicode(value: str) -> str:
    out: List[str] = []
    for ch in value:
        if ch.isalnum() or ch in " \t\r\n":
            out.append(ch)
        else:
            out.append(f"\\u{ord(ch):04x}")
    return "".join(out)


def _js_hex(value: str) -> str:
    out: List[str] = []
    for ch in value:
        code = ord(ch)
        if ch.isalnum() or ch in " \t\r\n":
            out.append(ch)
        elif code <= 0xFF:
            out.append(f"\\x{code:02x}")
        elif code <= 0xFFFF:
            out.append(f"\\u{code:04x}")
        else:
            # \xXX / single \uXXXX cannot represent code points above 0xFFFF
            # ('\x1f600' would decode as \x1f followed by literal '600'); keep
            # the raw character, which is still valid inside a JS string.
            out.append(ch)
    return "".join(out)


def _js_fromcharcode(value: str) -> str:
    codes = ",".join(str(ord(ch)) for ch in value)
    return f"String.fromCharCode({codes})"


def _base64_eval(value: str) -> str:
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"eval(atob('{encoded}'))"


def _comment_break(value: str) -> str:
    """Inject empty HTML/JS comments inside dangerous keywords."""
    value = re.sub(r"(?i)<(script|svg|img|iframe|object|embed)", r"<\1/**/", value)
    value = re.sub(r"(?i)(javascript|data)\s*:", r"\1/**/:", value)
    return value.replace(" ", "/**/")


def _null_byte(value: str) -> str:
    return value.replace("<", "\x00<").replace(">", ">\x00")


def _tab_space(value: str) -> str:
    return value.replace(" ", "\t")


def _unicode_fullwidth(value: str) -> str:
    out: List[str] = []
    for ch in value:
        code = ord(ch)
        if 0x21 <= code <= 0x7E:
            out.append(chr(code + 0xFEE0))
        elif ch == " ":
            out.append("\u3000")
        else:
            out.append(ch)
    return "".join(out)


def _utf16le(value: str) -> str:
    return value.encode("utf-16-le", "ignore").hex()


def _backslash_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')


def _percent_unicode(value: str) -> str:
    out: List[str] = []
    for ch in value:
        if ch.isalnum():
            out.append(ch)
        elif ch == " ":
            out.append("%u0020")
        else:
            out.append(f"%u{ord(ch):04x}")
    return "".join(out)


def _newline_evasion(value: str) -> str:
    return value.replace(" ", "\n").replace("\t", "\r")


_ENCODERS: Dict[str, Encoder] = {}


def register_encoder(encoder: Encoder, *, replace: bool = False) -> Encoder:
    """Register an encoder.  Raises ``ValueError`` on a duplicate by default."""
    key = encoder.name.strip().lower()
    if not key:
        raise ValueError("encoder name must not be empty")
    if key in _ENCODERS and not replace:
        raise ValueError(f"encoder already registered: {key}")
    stored = Encoder(
        name=key,
        func=encoder.func,
        description=encoder.description,
        contexts=tuple(encoder.contexts),
        reversible=encoder.reversible,
        tags=tuple(encoder.tags),
    )
    _ENCODERS[key] = stored
    return stored


def _register(name: str, func: Callable[[str], str], description: str, contexts: Sequence[str] = ("any",), reversible: bool = False, tags: Sequence[str] = ()) -> None:
    register_encoder(
        Encoder(
            name=name,
            func=func,
            description=description,
            contexts=tuple(contexts),
            reversible=reversible,
            tags=tuple(tags),
        ),
        replace=True,
    )


_register("urlencode", _urlencode, "Percent-encode every byte", ("url", "query"), True, ("basic",))
_register("double_urlencode", _double_urlencode, "Percent-encode twice", ("url", "query"), True, ("basic",))
_register("hex_entities", _hex_entities, "HTML hexadecimal entities", ("html", "attr"), True)
_register("dec_entities", _dec_entities, "HTML decimal entities", ("html", "attr"), True)
_register("html_entities", _html_entities, "Named/HTML entities for specials", ("html", "attr"), True)
_register("js_unicode", _js_unicode, "JavaScript \\uXXXX escapes for specials", ("script", "json"), True)
_register("js_hex", _js_hex, "JavaScript \\xXX escapes for specials", ("script", "json"), True)
_register("js_fromcharcode", _js_fromcharcode, "Rebuild the string with String.fromCharCode", ("script",), False)
_register("base64_eval", _base64_eval, "Base64 payload wrapped in eval(atob())", ("script",), False)
_register("mixed_case", _random_case, "Randomise tag/event/scheme case", ("html", "attr"), False, ("waf",))
_register("comment_break", _comment_break, "Insert comments inside keywords", ("html", "script"), False, ("waf",))
_register("null_byte", _null_byte, "NUL bytes around angle brackets", ("html", "url"), False, ("waf",))
_register("tab_space", _tab_space, "Replace spaces with tabs", ("html", "attr"), False, ("waf",))
_register("newline_evasion", _newline_evasion, "Replace spaces with newlines", ("html", "attr"), False, ("waf",))
_register("unicode_fullwidth", _unicode_fullwidth, "Full-width Unicode characters", ("html",), True, ("waf",))
_register("percent_unicode", _percent_unicode, "IIS-style %uXXXX encoding", ("url", "query"), True, ("waf",))
_register("utf16le", _utf16le, "UTF-16LE hex encoding", ("script",), False)
_register("backslash_escape", _backslash_escape, "Escape quotes and backslashes", ("script", "json"), True)
_register("lowercase", str.lower, "Lowercase the payload", ("any",), False)
_register("uppercase", str.upper, "Uppercase the payload", ("any",), False)


def get_encoder(name: str) -> Encoder:
    key = (name or "").strip().lower()
    if key not in _ENCODERS:
        raise KeyError(f"unknown encoder: {name}")
    return _ENCODERS[key]


def apply_encoder(value: str, name: str) -> str:
    return get_encoder(name).encode(value)


def apply_chain(value: str, names: Iterable[str]) -> str:
    result = value or ""
    for name in names:
        result = apply_encoder(result, name)
    return result


def list_encoders(context: str = "") -> List[Encoder]:
    encoders = sorted(_ENCODERS.values(), key=lambda item: item.name)
    if not context:
        return encoders
    wanted = context.lower()
    return [item for item in encoders if wanted in item.contexts or "any" in item.contexts]


def encoder_names() -> List[str]:
    return sorted(_ENCODERS)


def describe_encoders() -> str:
    lines: List[str] = []
    for encoder in list_encoders():
        tags = f" [{', '.join(encoder.tags)}]" if encoder.tags else ""
        lines.append(f"  {encoder.name:<18} {encoder.description}{tags}")
    return "\n".join(lines)


__all__ = [
    "Encoder",
    "register_encoder",
    "get_encoder",
    "apply_encoder",
    "apply_chain",
    "list_encoders",
    "encoder_names",
    "describe_encoders",
]
