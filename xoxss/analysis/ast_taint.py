"""
Lightweight JavaScript taint analysis for DOM-XSS.

This is deliberately dependency-free.  It is not a full ECMAScript parser: it
tokenises just enough structure to follow the two things that matter for DOM
XSS — attacker-controlled *sources* flowing into dangerous *sinks* — including
simple aliases, string concatenation and one level of function arguments.

The analyser is intentionally conservative.  A flow is reported only when a
source (or a variable that was assigned a source) appears in the sink
expression, which keeps false positives manageable on real-world bundles.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


SOURCE_PATTERNS: Dict[str, str] = {
    "location.hash": r"\b(?:window\.|document\.|self\.|top\.)?location\s*\.\s*hash\b",
    "location.search": r"\b(?:window\.|document\.|self\.|top\.)?location\s*\.\s*search\b",
    "location.href": r"\b(?:window\.|document\.|self\.|top\.)?location\s*\.\s*href\b",
    "location.pathname": r"\b(?:window\.|document\.|self\.|top\.)?location\s*\.\s*pathname\b",
    "document.URL": r"\bdocument\s*\.\s*URL\b",
    "document.documentURI": r"\bdocument\s*\.\s*documentURI\b",
    "document.referrer": r"\bdocument\s*\.\s*referrer\b",
    "document.cookie": r"\bdocument\s*\.\s*cookie\b",
    "window.name": r"\bwindow\s*\.\s*name\b",
    "localStorage": r"\b(?:window\s*\.\s*)?localStorage\b",
    "sessionStorage": r"\b(?:window\s*\.\s*)?sessionStorage\b",
    "history.state": r"\bhistory\s*\.\s*state\b",
    "postMessage.data": r"\b(?:event|e|evt|message)\s*\.\s*data\b",
    "URLSearchParams": r"\bURLSearchParams\b",
    "document.location": r"\bdocument\s*\.\s*location\b",
    "window.location": r"\bwindow\s*\.\s*location\b",
}

# Sinks are (name, regex, context, needs_string_argument).
SINK_PATTERNS: List[Tuple[str, str, str, bool]] = [
    ("innerHTML", r"\.\s*innerHTML\s*=\s*([^;\n]{0,600})", "html", False),
    ("outerHTML", r"\.\s*outerHTML\s*=\s*([^;\n]{0,600})", "html", False),
    ("insertAdjacentHTML", r"\.\s*insertAdjacentHTML\s*\(\s*[^,]{1,80},\s*([^)]{0,600})", "html", False),
    ("document.write", r"\bdocument\s*\.\s*write(?:ln)?\s*\(\s*([^)]{0,600})", "html", False),
    ("eval", r"(?<![\w$.])eval\s*\(\s*([^)]{0,600})", "js", False),
    ("Function", r"\b(?:new\s+)?Function\s*\(\s*([^)]{0,600})", "js", False),
    ("setTimeout", r"\bsetTimeout\s*\(\s*([^,)]{0,600})", "js", True),
    ("setInterval", r"\bsetInterval\s*\(\s*([^,)]{0,600})", "js", True),
    ("location.assign", r"\blocation\s*\.\s*assign\s*\(\s*([^)]{0,600})", "url", False),
    ("location.replace", r"\blocation\s*\.\s*replace\s*\(\s*([^)]{0,600})", "url", False),
    ("location.href", r"\blocation\s*\.\s*href\s*=\s*([^;\n]{0,600})", "url", False),
    ("location", r"(?<![\w$.])location\s*=\s*([^;\n]{0,600})", "url", False),
    ("setAttribute", r"\.\s*setAttribute\s*\(\s*['\"](?:href|src|srcdoc|action|formaction|style|on\w+)['\"]\s*,\s*([^)]{0,600})", "url", False),
    ("srcdoc", r"\.\s*srcdoc\s*=\s*([^;\n]{0,600})", "html", False),
    ("jquery.html", r"\.\s*html\s*\(\s*([^)]{0,600})", "html", False),
    ("jquery.append", r"\.\s*append\s*\(\s*([^)]{0,600})", "html", False),
    ("jquery.prepend", r"\.\s*prepend\s*\(\s*([^)]{0,600})", "html", False),
    ("jquery.before", r"\.\s*before\s*\(\s*([^)]{0,600})", "html", False),
    ("jquery.after", r"\.\s*after\s*\(\s*([^)]{0,600})", "html", False),
    ("jquery.replaceWith", r"\.\s*replaceWith\s*\(\s*([^)]{0,600})", "html", False),
    ("createContextualFragment", r"\bcreateContextualFragment\s*\(\s*([^)]{0,600})", "html", False),
    ("createElement.script", r"createElement\s*\(\s*['\"]script['\"]\s*\)", "js", False),
]

SANITIZER_PATTERNS: List[Tuple[str, str]] = [
    ("DOMPurify", r"\bDOMPurify\s*\.\s*sanitize\b"),
    ("sanitize-html", r"\bsanitizeHtml\b|\bsanitize\s*\("),
    ("escapeHtml", r"\bescape(?:Html|HTML)\b"),
    ("encodeURIComponent", r"\bencodeURIComponent\b"),
    ("encodeURI", r"\bencodeURI\b"),
    ("textContent", r"\.textContent\b"),
    ("innerText", r"\.innerText\b"),
    ("validator", r"\bvalidator\s*\.\s*escape\b"),
    ("xss", r"\bxss\s*\(|\bfilterXSS\b"),
    ("trustedTypes", r"\bTrustedTypes\b"),
]

_ASSIGN_RE = re.compile(
    r"(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)"
    r"\s*(\+=|=)\s*([^;\n]{0,800})"
)
_FUNCTION_RE = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|"
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>|"
    r"([A-Za-z_$][\w$]*)\s*[=:]\s*function\s*\(([^)]*)\))"
)
_CALL_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(([^()]{0,400})\)")


@dataclass
class TaintFlow:
    """A source -> sink data-flow edge."""

    source: str
    sink: str
    context: str
    line: int
    snippet: str
    url: str = ""
    sanitized: bool = False
    sanitizer: str = ""
    path: List[str] = field(default_factory=list)
    confidence: float = 0.7

    def key(self) -> str:
        return f"{self.url}|{self.source}|{self.sink}|{self.line}"

    def to_dict(self) -> Dict[str, object]:
        return {
            "source": self.source,
            "sink": self.sink,
            "context": self.context,
            "line": self.line,
            "snippet": self.snippet,
            "url": self.url,
            "sanitized": self.sanitized,
            "sanitizer": self.sanitizer,
            "path": list(self.path),
            "confidence": round(self.confidence, 3),
        }


def strip_comments(code: str) -> str:
    """Remove JS/HTML comments while preserving offsets and newlines."""
    code = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), code, flags=re.S)
    code = re.sub(r"(?m)(^|[^:])//[^\n]*", r"\1", code)
    code = re.sub(r"<!--.*?-->", lambda m: "\n" * m.group(0).count("\n"), code, flags=re.S)
    return code


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _snippet(text: str, offset: int, limit: int = 220) -> str:
    start = max(0, text.rfind("\n", 0, offset) + 1)
    end = text.find("\n", offset)
    if end < 0:
        end = min(len(text), offset + limit)
    line = text[start : min(end, start + limit)].strip()
    return line[:limit]


def _word_in(name: str, text: str) -> bool:
    if not name:
        return False
    return re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", text) is not None


def find_sources(code: str) -> List[Tuple[str, int, str]]:
    """Return ``(source, line, snippet)`` triples found in the code."""
    hits: List[Tuple[str, int, str]] = []
    for name, pattern in SOURCE_PATTERNS.items():
        for match in re.finditer(pattern, code, flags=re.I):
            hits.append((name, _line_of(code, match.start()), _snippet(code, match.start())))
    return hits


def _collect_assignments(code: str) -> Dict[str, List[Tuple[str, int, int, str]]]:
    assignments: Dict[str, List[Tuple[str, int, int, str]]] = {}
    for match in _ASSIGN_RE.finditer(code):
        name = re.sub(r"\s+", "", match.group(1)).split(".")[-1]
        if not name or name in ("if", "for", "while", "return", "typeof"):
            continue
        expr = match.group(3).strip()
        if not expr or expr.startswith("="):
            continue
        assignments.setdefault(name, []).append(
            (expr, _line_of(code, match.start()), match.start(), match.group(2))
        )
    return assignments


def _tainted_variables(code: str, assignments: Dict[str, List[Tuple[str, int, int, str]]]) -> Dict[str, Tuple[str, int]]:
    """Propagate taint through simple assignments/aliases.

    Returns ``{variable: (source, line)}`` for every tainted alias.
    """
    tainted: Dict[str, Tuple[str, int]] = {}
    source_patterns = list(SOURCE_PATTERNS.items())

    for name, entries in assignments.items():
        for expr, line, _pos, _op in entries:
            for source_name, pattern in source_patterns:
                if re.search(pattern, expr, flags=re.I):
                    tainted.setdefault(name, (source_name, line))
                    break

    # Fixed point over aliases (bounded to avoid pathological bundles).
    for _ in range(6):
        changed = False
        for name, entries in assignments.items():
            if name in tainted:
                continue
            for expr, line, _pos, _op in entries:
                for other, (source_name, src_line) in list(tainted.items()):
                    if _word_in(other, expr):
                        tainted[name] = (source_name, line or src_line)
                        changed = True
                        break
                if name in tainted:
                    break
        if not changed:
            break
    return tainted


def _sanitizer_in(expr: str) -> Tuple[bool, str]:
    for name, pattern in SANITIZER_PATTERNS:
        if re.search(pattern, expr, flags=re.I):
            return True, name
    return False, ""


def analyze_javascript(code: str, url: str = "") -> List[TaintFlow]:
    """Extract DOM-XSS source -> sink flows from a JavaScript blob."""
    if not code:
        return []
    # Cap pathological bundles; the caller normally already truncates.
    code = code[:3_000_000]
    cleaned = strip_comments(code)
    assignments = _collect_assignments(cleaned)
    tainted = _tainted_variables(cleaned, assignments)
    taint_names = set(tainted)

    flows: List[TaintFlow] = []
    seen: Set[str] = set()

    for sink_name, pattern, context, needs_string in SINK_PATTERNS:
        for match in re.finditer(pattern, cleaned, flags=re.I):
            expr = (match.group(1) if match.groups() else "").strip()
            if not expr:
                continue

            direct_source = ""
            for source_name, source_pattern in SOURCE_PATTERNS.items():
                if re.search(source_pattern, expr, flags=re.I):
                    direct_source = source_name
                    break

            alias = ""
            if not direct_source:
                for name in taint_names:
                    if _word_in(name, expr):
                        alias = name
                        break
            if not direct_source and not alias:
                continue

            # setTimeout('literal') is harmless; only flag dynamic arguments.
            if needs_string and re.fullmatch(r"['\"][^'\"]*['\"]", expr):
                continue

            sanitized, sanitizer = _sanitizer_in(expr)
            if alias and not sanitized:
                # Inspect the assignments that produced the alias.
                chain: List[str] = [alias]
                for entry_expr, _line, _pos, _op in assignments.get(alias, []):
                    if _sanitizer_in(entry_expr)[0]:
                        sanitized, sanitizer = _sanitizer_in(entry_expr)
                    for other in taint_names:
                        if other != alias and _word_in(other, entry_expr) and other not in chain:
                            chain.append(other)

            source_name = direct_source or (tainted.get(alias, ("unknown", 0))[0])
            if not source_name or source_name == "unknown":
                continue

            line = _line_of(cleaned, match.start())
            snippet = _snippet(cleaned, match.start())
            flow = TaintFlow(
                source=source_name,
                sink=sink_name,
                context=context,
                line=line,
                snippet=snippet,
                url=url,
                sanitized=sanitized,
                sanitizer=sanitizer,
                path=[alias] if alias else [],
                confidence=(
                    0.35
                    if sanitized
                    else (0.9 if direct_source else 0.72)
                ),
            )
            if flow.key() not in seen:
                seen.add(flow.key())
                flows.append(flow)

    flows.sort(key=lambda item: (not item.sanitized, -item.confidence, item.line))
    return flows


def summarize_flows(flows: Sequence[TaintFlow]) -> Dict[str, object]:
    """Small summary used by reports."""
    return {
        "total": len(flows),
        "executable": sum(1 for flow in flows if not flow.sanitized),
        "sanitized": sum(1 for flow in flows if flow.sanitized),
        "sources": sorted({flow.source for flow in flows}),
        "sinks": sorted({flow.sink for flow in flows}),
    }


__all__ = [
    "SOURCE_PATTERNS",
    "SINK_PATTERNS",
    "TaintFlow",
    "analyze_javascript",
    "find_sources",
    "strip_comments",
    "summarize_flows",
]
