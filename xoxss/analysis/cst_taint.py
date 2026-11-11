"""Scope-aware JavaScript taint analysis backed by tree-sitter.

The regex analyser in :mod:`xoxss.analysis.ast_taint` is fast but cannot tell
two same-named variables in different closures apart.  This module builds a
real concrete syntax tree and resolves every identifier through its lexical
scope, which keeps minified Webpack/esbuild bundles with aggressively reused
single-letter names analysable.

The backend is optional: ``tree_sitter`` and ``tree_sitter_javascript`` are
soft dependencies, and ``analyze_javascript`` falls back to the regex path
whenever they are unavailable or parsing fails.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from xoxss.analysis.ast_taint import TaintFlow
from xoxss.analysis.framework_sinks import (
    is_framework_internal_sink,
    is_sanitizer_barrier,
    is_static_or_feature_detection,
    is_third_party_analytics,
)

try:  # pragma: no cover - exercised only when the optional dependency exists
    from tree_sitter import Language, Parser  # type: ignore
    import tree_sitter_javascript  # type: ignore

    _LANGUAGE = Language(tree_sitter_javascript.language())
    _PARSER = Parser(_LANGUAGE)
    AVAILABLE = True
except Exception:  # pragma: no cover - dependency-free installations
    tree_sitter = None  # type: ignore
    tree_sitter_javascript = None  # type: ignore
    _PARSER = None
    AVAILABLE = False


_SOURCE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("location.hash", re.compile(r"^(?:(?:window|document|self|top)\.)?location\.hash$")),
    ("location.search", re.compile(r"^(?:(?:window|document|self|top)\.)?location\.search$")),
    ("location.href", re.compile(r"^(?:(?:window|document|self|top)\.)?location\.href$")),
    ("location.pathname", re.compile(r"^(?:(?:window|document|self|top)\.)?location\.pathname$")),
    ("document.URL", re.compile(r"^document\.URL$")),
    ("document.documentURI", re.compile(r"^document\.documentURI$")),
    ("document.referrer", re.compile(r"^document\.referrer$")),
    ("document.cookie", re.compile(r"^document\.cookie$")),
    ("window.name", re.compile(r"^window\.name$")),
    ("localStorage", re.compile(r"^(?:(?:window)\.)?localStorage(?:\.(?:getItem|key)|\[)")),
    ("sessionStorage", re.compile(r"^(?:(?:window)\.)?sessionStorage(?:\.(?:getItem|key)|\[)")),
    ("history.state", re.compile(r"^history\.state$")),
    ("postMessage.data", re.compile(r"^(?:event|e|evt|message)\.data$")),
    ("URLSearchParams", re.compile(r"^(?:new\s+)?URLSearchParams$")),
    ("document.location", re.compile(r"^document\.location$")),
    ("window.location", re.compile(r"^window\.location$")),
    ("indexedDB", re.compile(r"^(?:(?:window)\.)?indexedDB\.open$")),
]

_SANITIZERS: List[Tuple[str, re.Pattern]] = [
    ("DOMPurify", re.compile(r"DOMPurify\.sanitize$|^DOMPurify$")),
    ("sanitize-html", re.compile(r"^(?:sanitizeHtml|sanitize)$")),
    ("escapeHtml", re.compile(r"^escape(?:Html|HTML)$")),
    ("encodeURIComponent", re.compile(r"^encodeURIComponent$")),
    ("encodeURI", re.compile(r"^encodeURI$")),
    ("validator", re.compile(r"^validator\.escape$")),
    ("xss", re.compile(r"^(?:xss|filterXSS)$")),
    ("trustedTypes", re.compile(r"^TrustedTypes")),
]

_HTML_ASSIGN = {
    "innerHTML": "innerHTML",
    "outerHTML": "outerHTML",
    "srcdoc": "srcdoc",
    "dangerouslySetInnerHTML": "dangerouslySetInnerHTML",
    "v-html": "v-html",
}
_CALL_SINKS = {
    "document.write": ("document.write", "html", 0),
    "document.writeln": ("document.write", "html", 0),
    "eval": ("eval", "js", 0),
    "Function": ("Function", "js", 0),
    "setTimeout": ("setTimeout", "js", 0),
    "setInterval": ("setInterval", "js", 0),
    "location.assign": ("location.assign", "url", 0),
    "location.replace": ("location.replace", "url", 0),
    "insertAdjacentHTML": ("insertAdjacentHTML", "html", 1),
    "setAttribute": ("setAttribute", "url", 1),
    "createContextualFragment": ("createContextualFragment", "html", 0),
    "parseFromString": ("DOMParser.parseFromString", "html", 0),
    "html": ("jquery.html", "html", 0),
    "append": ("jquery.append", "html", 0),
    "prepend": ("jquery.prepend", "html", 0),
    "before": ("jquery.before", "html", 0),
    "after": ("jquery.after", "html", 0),
    "replaceWith": ("jquery.replaceWith", "html", 0),
    "setHTMLUnsafe": ("setHTMLUnsafe", "html", 0),
    "setHTML": ("setHTML", "html", 0),
    "bypassSecurityTrustHtml": ("bypassSecurityTrustHtml", "html", 0),
    "bypassSecurityTrustScript": ("bypassSecurityTrustScript", "js", 0),
    "bypassSecurityTrustResourceUrl": ("bypassSecurityTrustResourceUrl", "url", 0),
    "postMessage": ("postMessage", "js", 0),
    "importScripts": ("importScripts", "url", 0),
}
_DANGEROUS_ATTRS = re.compile(r"^(?:href|src|srcdoc|action|formaction|style|on\w+)$", re.I)
_FUNCTION_TYPES = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "generator_function_declaration",
    "generator_function",
    "method_definition",
}


@dataclass
class _Taint:
    source: str
    line: int
    sanitized: bool = False
    sanitizer: str = ""
    path: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.path is None:
            self.path = []


class _Binding:
    __slots__ = ("name", "kind", "taint", "function_node", "line")

    def __init__(self, name: str, kind: str, line: int) -> None:
        self.name = name
        self.kind = kind
        self.taint: Optional[_Taint] = None
        self.function_node = None
        self.line = line


class _Scope:
    __slots__ = ("parent", "kind", "bindings")

    def __init__(self, parent: Optional["_Scope"], kind: str) -> None:
        self.parent = parent
        self.kind = kind
        self.bindings: Dict[str, _Binding] = {}

    def resolve(self, name: str) -> Optional[_Binding]:
        scope: Optional[_Scope] = self
        while scope is not None:
            binding = scope.bindings.get(name)
            if binding is not None:
                return binding
            scope = scope.parent
        return None


def _text(node: Any) -> str:
    try:
        return re.sub(r"\s+", "", node.text.decode("utf-8", "replace"))
    except Exception:
        return ""


def _line(node: Any) -> int:
    return int(getattr(node, "start_point", (0, 0))[0]) + 1


def _snippet(code: str, node: Any, limit: int = 220) -> str:
    start = int(getattr(node, "start_byte", 0))
    line_start = code.rfind("\n", 0, start) + 1
    line_end = code.find("\n", start)
    if line_end < 0:
        line_end = min(len(code), start + limit)
    return code[line_start : min(line_end, line_start + limit)].strip()[:limit]


def _source_name(text: str) -> str:
    normalized = text.strip()
    for name, pattern in _SOURCE_PATTERNS:
        if pattern.match(normalized):
            return name
    return ""


def _sanitizer_name(text: str) -> str:
    normalized = text.strip()
    for name, pattern in _SANITIZERS:
        if pattern.search(normalized):
            return name
    return ""


def _pattern_names(node: Any) -> List[str]:
    """Extract declared names from identifier, object and array patterns."""
    names: List[str] = []
    if node is None:
        return names
    if node.type in ("identifier", "shorthand_property_identifier_pattern"):
        names.append(node.text.decode("utf-8", "replace"))
    elif node.type == "pair_pattern":
        value = node.child_by_field_name("value")
        names.extend(_pattern_names(value))
    elif node.type in ("object_pattern", "array_pattern", "rest_pattern", "assignment_pattern"):
        for child in node.named_children:
            names.extend(_pattern_names(child))
    return names


class _CstAnalyzer:
    def __init__(self, code: str, url: str = "") -> None:
        self.code = code
        self.url = url
        self.flows: List[TaintFlow] = []
        self.seen: Set[str] = set()
        self.node_scopes: Dict[Tuple[int, int, str], _Scope] = {}
        self.function_params: Dict[Tuple[int, int], List[_Binding]] = {}
        self.function_body: Dict[Tuple[int, int], Any] = {}
        self.function_scope: Dict[Tuple[int, int], _Scope] = {}
        self.root_scope: Optional[_Scope] = None
        self._active_calls: Set[Tuple[int, int]] = set()

    # -- scope construction ---------------------------------------------------------
    def build(self, root: Any) -> None:
        program = _Scope(None, "program")
        self.root_scope = program
        self._declare_children(root, program, program, program)

    def _declare_children(self, node: Any, scope: _Scope, func_scope: _Scope, program: _Scope) -> None:
        for child in node.named_children:
            self._declare(child, scope, func_scope, program)

    def _declare(self, node: Any, scope: _Scope, func_scope: _Scope, program: _Scope) -> None:
        node_type = node.type
        key = (node.start_byte, node.end_byte, node_type)
        self.node_scopes[key] = scope

        if node_type in _FUNCTION_TYPES:
            name_node = node.child_by_field_name("name")
            if name_node is not None and node_type in ("function_declaration", "generator_function_declaration"):
                binding = scope.bindings.get(_text(name_node))
                if binding is None:
                    binding = _Binding(_text(name_node), "function", _line(name_node))
                    scope.bindings[binding.name] = binding
                binding.function_node = node
            new_scope = _Scope(scope, "function")
            self.node_scopes[(node.start_byte, node.end_byte, node_type)] = new_scope
            params_node = node.child_by_field_name("parameters")
            params: List[_Binding] = []
            if params_node is not None:
                for child in params_node.named_children:
                    for name in _pattern_names(child):
                        binding = _Binding(name, "param", _line(child))
                        new_scope.bindings.setdefault(name, binding)
                        params.append(new_scope.bindings[name])
            self.function_params[(node.start_byte, node.end_byte)] = params
            body = node.child_by_field_name("body")
            if body is not None:
                self.function_body[(node.start_byte, node.end_byte)] = body
                self.function_scope[(node.start_byte, node.end_byte)] = new_scope
                self.node_scopes[(body.start_byte, body.end_byte, body.type)] = new_scope
                self._declare_children(body, new_scope, new_scope, program)
            return

        if node_type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            declaration = node.parent
            kind = "var" if declaration is not None and declaration.type == "variable_declaration" else "let"
            target_scope = func_scope if kind == "var" else scope
            for name in _pattern_names(name_node):
                target_scope.bindings.setdefault(name, _Binding(name, kind, _line(node)))
            if value is not None:
                self.node_scopes[(value.start_byte, value.end_byte, value.type)] = scope
                self._declare(value, scope, func_scope, program)
            return

        if node_type in ("class_declaration", "class_expression"):
            name_node = node.child_by_field_name("name")
            if name_node is not None and node_type == "class_declaration":
                scope.bindings.setdefault(_text(name_node), _Binding(_text(name_node), "class", _line(name_node)))
            body = node.child_by_field_name("body")
            if body is not None:
                self.node_scopes[(body.start_byte, body.end_byte, body.type)] = scope
                self._declare_children(body, scope, func_scope, program)
            return

        if node_type == "catch_clause":
            catch_scope = _Scope(scope, "block")
            self.node_scopes[key] = catch_scope
            param = node.child_by_field_name("parameter")
            for name in _pattern_names(param):
                catch_scope.bindings.setdefault(name, _Binding(name, "catch", _line(node)))
            body = node.child_by_field_name("body")
            if body is not None:
                self._declare_children(body, catch_scope, func_scope, program)
            return

        if node_type == "statement_block":
            block_scope = _Scope(scope, "block")
            self.node_scopes[key] = block_scope
            self._declare_children(node, block_scope, func_scope, program)
            return

        if node_type in ("for_statement", "for_in_statement"):
            loop_scope = _Scope(scope, "block")
            self.node_scopes[key] = loop_scope
            self._declare_children(node, loop_scope, func_scope, program)
            return

        if node_type == "import_statement":
            for child in node.named_children:
                for name in _pattern_names(child):
                    scope.bindings.setdefault(name, _Binding(name, "import", _line(node)))
            return

        self._declare_children(node, scope, func_scope, program)

    # -- taint evaluation -----------------------------------------------------------
    def _scope_of(self, node: Any, fallback: _Scope) -> _Scope:
        return self.node_scopes.get((node.start_byte, node.end_byte, node.type), fallback)

    def _binding_taint(self, binding: Optional[_Binding], overlay: Dict[_Binding, _Taint]) -> Optional[_Taint]:
        if binding is None:
            return None
        if binding in overlay:
            return overlay[binding]
        return binding.taint

    def _eval(self, node: Any, scope: _Scope, overlay: Dict[_Binding, _Taint], depth: int = 0) -> Optional[_Taint]:
        if node is None or depth > 24:
            return None
        node_type = node.type

        # Whole-expression sources such as ``location.hash``.
        if node_type in ("member_expression", "identifier", "new_expression", "subscript_expression"):
            source = _source_name(_text(node))
            if source:
                return _Taint(source, _line(node))

        if node_type == "identifier":
            binding = scope.resolve(node.text.decode("utf-8", "replace"))
            taint = self._binding_taint(binding, overlay)
            if taint is not None:
                return taint
            return None

        if node_type in ("string", "number", "true", "false", "null", "undefined", "regex"):
            return None

        if node_type == "template_string":
            for child in node.named_children:
                taint = self._eval(child, self._scope_of(child, scope), overlay, depth + 1)
                if taint:
                    return taint
            return None

        if node_type in ("binary_expression", "ternary_expression", "conditional_expression"):
            for field in ("left", "right", "consequent", "alternative"):
                child = node.child_by_field_name(field)
                taint = self._eval(child, self._scope_of(child, scope) if child else scope, overlay, depth + 1)
                if taint:
                    return taint
            return None

        if node_type in ("parenthesized_expression", "unary_expression", "await_expression", "spread_element"):
            for child in node.named_children:
                taint = self._eval(child, self._scope_of(child, scope), overlay, depth + 1)
                if taint:
                    return taint
            return None

        if node_type == "sequence_expression":
            last = node.named_children[-1] if node.named_children else None
            return self._eval(last, self._scope_of(last, scope) if last else scope, overlay, depth + 1)

        if node_type == "assignment_expression":
            right = node.child_by_field_name("right")
            return self._eval(right, self._scope_of(right, scope) if right else scope, overlay, depth + 1)

        if node_type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            callee = _text(function) if function is not None else ""
            sanitizer = _sanitizer_name(callee)
            if sanitizer:
                arg_taint = self._first_argument_taint(arguments, scope, overlay, depth)
                if arg_taint:
                    arg_taint.sanitized = True
                    arg_taint.sanitizer = sanitizer
                return arg_taint
            binding = scope.resolve(callee) if callee and re.fullmatch(r"[A-Za-z_$][\w$]*", callee) else None
            if binding is not None and binding.function_node is not None:
                return self._return_taint(binding, arguments, scope, overlay, depth + 1)
            return None

        if node_type == "new_expression":
            arguments = node.child_by_field_name("arguments")
            return self._first_argument_taint(arguments, scope, overlay, depth)

        if node_type in ("array", "object", "arguments"):
            for child in node.named_children:
                value = child
                if child.type == "pair":
                    value = child.child_by_field_name("value") or child
                taint = self._eval(value, self._scope_of(value, scope), overlay, depth + 1)
                if taint:
                    return taint
            return None

        # Generic fallback: inspect direct children.
        for child in node.named_children:
            taint = self._eval(child, self._scope_of(child, scope), overlay, depth + 1)
            if taint:
                return taint
        return None

    def _first_argument_taint(
        self, arguments: Any, scope: _Scope, overlay: Dict[_Binding, _Taint], depth: int
    ) -> Optional[_Taint]:
        if arguments is None:
            return None
        for child in arguments.named_children:
            taint = self._eval(child, self._scope_of(child, scope), overlay, depth + 1)
            if taint:
                return taint
        return None

    def _argument_taints(
        self, arguments: Any, scope: _Scope, overlay: Dict[_Binding, _Taint], depth: int
    ) -> List[Optional[_Taint]]:
        if arguments is None:
            return []
        return [
            self._eval(child, self._scope_of(child, scope), overlay, depth + 1)
            for child in arguments.named_children
        ]

    def _return_taint(
        self,
        binding: _Binding,
        arguments: Any,
        scope: _Scope,
        overlay: Dict[_Binding, _Taint],
        depth: int,
    ) -> Optional[_Taint]:
        node = binding.function_node
        if node is None or depth > 3:
            return None
        key = (node.start_byte, node.end_byte)
        if key in self._active_calls:
            return None
        params = self.function_params.get(key, [])
        arg_taints = self._argument_taints(arguments, scope, overlay, depth)
        call_overlay = dict(overlay)
        for param, taint in zip(params, arg_taints):
            if taint is not None:
                call_overlay[param] = taint
        body = self.function_body.get(key)
        if body is None:
            return None
        self._active_calls.add(key)
        try:
            return self._find_return_taint(body, self.function_scope.get(key, scope), call_overlay, depth)
        finally:
            self._active_calls.discard(key)

    def _find_return_taint(
        self, node: Any, scope: _Scope, overlay: Dict[_Binding, _Taint], depth: int
    ) -> Optional[_Taint]:
        for child in node.named_children:
            if child.type in _FUNCTION_TYPES:
                continue
            if child.type == "return_statement":
                value = child.named_children[0] if child.named_children else None
                taint = self._eval(value, self._scope_of(value, scope) if value else scope, overlay, depth + 1)
                if taint:
                    return taint
            taint = self._find_return_taint(child, scope, overlay, depth)
            if taint:
                return taint
        return None

    # -- sink discovery -------------------------------------------------------------
    def _assignment_sink(self, left: Any) -> Tuple[str, str]:
        if left is None:
            return "", ""
        if left.type == "member_expression":
            prop = left.child_by_field_name("property")
            prop_text = _text(prop) if prop is not None else ""
            if prop_text in _HTML_ASSIGN:
                return _HTML_ASSIGN[prop_text], "html"
            obj = left.child_by_field_name("object")
            if prop_text == "href" and obj is not None and _text(obj).endswith("location"):
                return "location.href", "url"
        elif left.type == "identifier":
            if _text(left) == "location":
                return "location", "url"
        return "", ""

    def _call_sink(self, node: Any) -> Optional[Tuple[str, str, Any]]:
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            return None
        callee = _text(function)
        if not callee:
            return None
        short = callee.split(".")[-1]
        if callee in ("new.Function",) or short == "Function" or callee == "Function":
            return "Function", "js", arguments
        entry = _CALL_SINKS.get(callee) or _CALL_SINKS.get(short)
        if entry is None:
            return None
        name, context, index = entry
        if short == "setAttribute":
            first = arguments.named_children[0] if arguments.named_children else None
            attr = _text(first).strip("'\"") if first is not None else ""
            if not _DANGEROUS_ATTRS.match(attr):
                return None
            context = "html" if attr.lower() == "srcdoc" else "url"
        if short in ("setTimeout", "setInterval"):
            first = arguments.named_children[0] if arguments.named_children else None
            if first is not None and first.type in ("string", "template_string") and first.type == "string":
                return None
        kids = arguments.named_children
        if index >= len(kids):
            return None
        return name, context, kids[index]

    def _record(self, sink: str, context: str, node: Any, taint: Optional[_Taint], alias: str = "") -> None:
        if taint is None:
            return
        line = _line(node)
        snippet = _snippet(self.code, node)

        # Guard 1: Static string literal or feature-detection probe
        if is_static_or_feature_detection(snippet):
            return

        # Guard 2: Framework runtime internal sink (Vue, Alpine, React, jQuery)
        if is_framework_internal_sink(self.code, snippet, node.start_byte):
            return

        is_third_party = is_third_party_analytics(self.url, self.code)
        path = list(taint.path or [])
        if alias and alias not in path:
            path.insert(0, alias)
        flow = TaintFlow(
            source=taint.source,
            sink=sink,
            context="third-party-analytics" if is_third_party else context,
            line=line,
            snippet=snippet,
            url=self.url,
            sanitized=taint.sanitized,
            sanitizer=taint.sanitizer,
            path=path,
            confidence=0.2 if (taint.sanitized or is_third_party) else (0.9 if not path else 0.75),
        )
        if flow.key() not in self.seen:
            self.seen.add(flow.key())
            self.flows.append(flow)

    # -- analysis pass --------------------------------------------------------------
    def analyze(self, node: Any, scope: _Scope, overlay: Optional[Dict[_Binding, _Taint]] = None) -> None:
        overlay = overlay or {}
        scope = self._scope_of(node, scope)
        node_type = node.type

        if node_type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if value is not None:
                taint = self._eval(value, self._scope_of(value, scope), overlay)
                if taint is not None:
                    taint.path = list(taint.path)
                    for name in _pattern_names(name_node):
                        binding = scope.resolve(name)
                        if binding is not None:
                            binding.taint = taint
                            if not taint.path:
                                taint.path = [name]
            self.analyze(value, scope, overlay) if value is not None else None
            return

        if node_type in ("assignment_expression", "augmented_assignment_expression"):
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            sink, context = self._assignment_sink(left)
            taint = self._eval(right, self._scope_of(right, scope) if right else scope, overlay)
            if sink and taint is not None:
                alias = _text(right) if right is not None and right.type == "identifier" else ""
                self._record(sink, context, node, taint, alias)
            elif left is not None and left.type == "identifier":
                binding = scope.resolve(_text(left))
                if binding is not None:
                    if taint is None and node_type == "augmented_assignment_expression":
                        taint = binding.taint
                    if taint is not None:
                        binding.taint = taint
            for child in node.named_children:
                if child is not left:
                    self.analyze(child, scope, overlay)
            return

        if node_type == "call_expression":
            sink_info = self._call_sink(node)
            if sink_info is not None:
                sink, context, target = sink_info
                taint = self._eval(target, self._scope_of(target, scope), overlay)
                alias = _text(target) if target is not None and target.type == "identifier" else ""
                self._record(sink, context, node, taint, alias)
            # Interprocedural: analyse a callee body with its parameters tainted
            # by tainted call arguments, so nested closures are followed.
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            callee = _text(function) if function is not None else ""
            if callee and re.fullmatch(r"[A-Za-z_$][\w$]*", callee):
                binding = scope.resolve(callee)
                if binding is not None and binding.function_node is not None:
                    key = (binding.function_node.start_byte, binding.function_node.end_byte)
                    body = self.function_body.get(key)
                    params = self.function_params.get(key, [])
                    arg_taints = self._argument_taints(arguments, scope, overlay, 0)
                    call_overlay = dict(overlay)
                    for param, taint in zip(params, arg_taints):
                        if taint is not None:
                            call_overlay[param] = taint
                    if body is not None and call_overlay and key not in self._active_calls:
                        self._active_calls.add(key)
                        try:
                            self.analyze(body, self.function_scope.get(key, scope), call_overlay)
                        finally:
                            self._active_calls.discard(key)
            for child in node.named_children:
                if child is not function:
                    self.analyze(child, scope, overlay)
            return

        if node_type in _FUNCTION_TYPES:
            body = node.child_by_field_name("body")
            if body is not None:
                self.analyze(body, self._scope_of(body, scope), overlay)
            return

        for child in node.named_children:
            self.analyze(child, scope, overlay)


def analyze_javascript_cst(code: str, url: str = "") -> List[TaintFlow]:
    """Parse ``code`` with tree-sitter and return scope-resolved taint flows."""
    if not AVAILABLE or _PARSER is None or not code:
        return []
    payload = code[:3_000_000].encode("utf-8", "replace")
    tree = _PARSER.parse(payload)
    if tree is None or tree.root_node is None:
        return []
    analyzer = _CstAnalyzer(code[:3_000_000], url)
    analyzer.build(tree.root_node)
    if analyzer.root_scope is None:
        return []
    analyzer.analyze(tree.root_node, analyzer.root_scope)
    analyzer.flows.sort(key=lambda item: (not item.sanitized, -item.confidence, item.line))
    return analyzer.flows


__all__ = ["AVAILABLE", "analyze_javascript_cst"]
