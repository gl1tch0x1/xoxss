"""
WAF evasion tamper transforms and mutation chains.
"""

from __future__ import annotations

import json
import random
import re
from typing import Callable, Dict, List, Optional
from urllib.parse import quote


def _random_case(value: str) -> str:
    """Randomly alternate character cases."""
    return "".join(ch.upper() if random.random() < 0.5 else ch.lower() for ch in value)


def tamper_uppercase(payload: str) -> str:
    """Randomise only case-insensitive parts (tag names, event names, scheme)."""
    payload = re.sub(r"<([a-zA-Z][a-zA-Z0-9]*)", lambda m: "<" + _random_case(m.group(1)), payload)
    payload = re.sub(r"\b(on[a-zA-Z]+)(\s*=)", lambda m: _random_case(m.group(1)) + m.group(2), payload)
    payload = re.sub(r"\b(javascript|data)\s*:", lambda m: _random_case(m.group(1)) + ":", payload, flags=re.I)
    return payload


def tamper_doubleencode(payload: str) -> str:
    """Double URL-encode special characters."""
    return quote(quote(payload, safe=""), safe="")


def tamper_hexencode(payload: str) -> str:
    """Convert characters to uppercase hex URL encoding."""
    return "".join(f"%{ord(ch):02X}" for ch in payload)


def tamper_urlencode(payload: str) -> str:
    """URL-encode the entire payload string."""
    return quote(payload, safe="")


def tamper_jsonfuzz(payload: str) -> str:
    """JSON unicode-escape payload delimiters."""
    encoded = json.dumps(payload)[1:-1]
    return encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def tamper_htmlentities(payload: str) -> str:
    """Convert quotes and angle brackets to HTML entities."""
    return (
        payload.replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def tamper_spacetab(payload: str) -> str:
    """Replace spaces with tabs."""
    return payload.replace(" ", "\t")


def tamper_jscomment(payload: str) -> str:
    """Insert inline C-style comments around semicolons and spaces."""
    return payload.replace(";", ";/**/").replace(" ", "/**/")


TAMPERS: Dict[str, Callable[[str], str]] = {
    "doubleencode": tamper_doubleencode,
    "uppercase": tamper_uppercase,
    "hexencode": tamper_hexencode,
    "urlencode": tamper_urlencode,
    "jsonfuzz": tamper_jsonfuzz,
    "htmlentities": tamper_htmlentities,
    "spacetab": tamper_spacetab,
    "jscomment": tamper_jscomment,
}

# "all" is deliberately limited to transforms that keep the payload semantically valid.
TAMPER_CHAINS: Dict[str, List[str]] = {
    "all": ["spacetab", "uppercase"],
}


def apply_tamper(payload: str, name: Optional[str]) -> str:
    """Apply a named tamper function or chain to payload."""
    if not name:
        return payload
    if name in TAMPER_CHAINS:
        result = payload
        for step in TAMPER_CHAINS[name]:
            result = TAMPERS[step](result)
        return result
    func = TAMPERS.get(name)
    return func(payload) if func else payload


__all__ = [
    "TAMPERS",
    "TAMPER_CHAINS",
    "apply_tamper",
    "tamper_uppercase",
    "tamper_doubleencode",
    "tamper_hexencode",
    "tamper_urlencode",
    "tamper_jsonfuzz",
    "tamper_htmlentities",
    "tamper_spacetab",
    "tamper_jscomment",
]

