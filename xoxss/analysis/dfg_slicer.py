"""
AST, Control-Flow & Data-Flow Graph (DFG) Static Slicer.

Extracts data-flow graphs across function boundaries, asynchronous Promises,
fetch callbacks, and IndexedDB handlers. Suppresses framework runtime boilerplate
(Vue 3, Alpine, React, Angular, jQuery) and extracts minimal 50-150 line code slices.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from xoxss.analysis.ast_taint import SOURCE_PATTERNS, SINK_PATTERNS, strip_comments
from xoxss.analysis.cst_taint import AVAILABLE as HAS_TREE_SITTER, analyze_javascript_cst
from xoxss.analysis.framework_sinks import (
    is_framework_internal_sink,
    is_sanitizer_barrier,
    is_static_or_feature_detection,
    is_third_party_analytics,
)


@dataclass
class DfgNode:
    """A node in the Data-Flow Graph."""
    id: str
    variable: str
    expression: str
    line: int
    char_offset: int
    is_source: bool = False
    is_sink: bool = False
    source_name: str = ""
    sink_name: str = ""


@dataclass
class DfgFlow:
    """A verified source -> sink path through the Data-Flow Graph."""
    source: str
    sink: str
    source_line: int
    sink_line: int
    path: List[str]
    nodes: List[DfgNode]
    snippet: str
    code_slice: str = ""
    sanitized: bool = False
    sanitizer: str = ""
    confidence: float = 0.8
    is_async: bool = False


class DfgSlicer:
    """
    Constructs a scoped Data-Flow Graph from JavaScript source code
    and generates minimal code slices for verified source-to-sink flows.
    """

    def __init__(self, code: str = "", url: str = "") -> None:
        self.raw_code = code or ""
        self.url = url
        self.code = strip_comments(self.raw_code[:3_000_000]) if self.raw_code else ""
        self.lines = self.raw_code.splitlines() if self.raw_code else []

    @classmethod
    def analyze_script(cls, code: str, url: str = "") -> List[DfgFlow]:
        """Convenience method to construct and analyze a script in one call."""
        return cls(code, url).analyze()

    def analyze(self) -> List[DfgFlow]:
        """
        Analyze code and return verified DFG flows with minimal code slices.
        """
        if not self.code or len(self.code.strip()) < 10:
            return []

        # Suppress third-party analytics bundles from first-party DFG alerts
        if is_third_party_analytics(self.url, self.code):
            return []

        flows: List[DfgFlow] = []

        # 1. Primary: Use Tree-sitter CST analysis if available
        if HAS_TREE_SITTER:
            try:
                cst_flows = analyze_javascript_cst(self.code, self.url)
                for cf in cst_flows:
                    if cf.sanitized and cf.confidence < 0.4:
                        continue
                    if is_static_or_feature_detection(cf.snippet):
                        continue
                    if is_framework_internal_sink(self.code, cf.snippet, 0):
                        continue

                    code_slice = self.extract_slice_by_lines(
                        [cf.line],
                        cf.snippet,
                        cf.path,
                    )
                    flows.append(
                        DfgFlow(
                            source=cf.source,
                            sink=cf.sink,
                            source_line=cf.line,
                            sink_line=cf.line,
                            path=cf.path,
                            nodes=[],
                            snippet=cf.snippet,
                            code_slice=code_slice,
                            sanitized=cf.sanitized,
                            sanitizer=cf.sanitizer,
                            confidence=cf.confidence,
                        )
                    )
                if flows:
                    return flows
            except Exception:
                pass

        # 2. Enhanced Fallback: Async & Scoped Lexical DFG Analysis
        return self._analyze_lexical_dfg()

    def _analyze_lexical_dfg(self) -> List[DfgFlow]:
        """
        Build lexical DFG tracking assignments, promise handlers, and async sinks.
        """
        flows: List[DfgFlow] = []
        assign_re = re.compile(
            r"(?:^|[;{}\n,]|\b(?:var|let|const))\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*((?<![=!<>])=(?![=>])|\+=)\s*([^;\n]{1,800})"
        )

        nodes_by_var: Dict[str, List[DfgNode]] = {}
        all_nodes: List[DfgNode] = []

        # Index all assignments as DFG nodes
        for m in assign_re.finditer(self.code):
            raw_lhs = m.group(1).replace(" ", "")
            var_name = raw_lhs.split(".")[-1]
            expr = m.group(3).strip()
            line_no = self.code.count("\n", 0, m.start()) + 1

            if not var_name or var_name in ("if", "for", "while", "return", "typeof", "delete"):
                continue

            # Check if this assignment introduces a source
            source_name = ""
            for s_name, s_pat in SOURCE_PATTERNS.items():
                if re.search(s_pat, expr, re.IGNORECASE):
                    source_name = s_name
                    break

            node = DfgNode(
                id=f"node_{m.start()}",
                variable=var_name,
                expression=expr,
                line=line_no,
                char_offset=m.start(),
                is_source=bool(source_name),
                source_name=source_name,
            )
            all_nodes.append(node)
            nodes_by_var.setdefault(var_name, []).append(node)

        # Track asynchronous Promise & Fetch .then / await flows
        self._link_async_callbacks(nodes_by_var)

        # Match sinks and traverse DFG backwards to source
        for sink_name, pattern, context, needs_string in SINK_PATTERNS:
            for match in re.finditer(pattern, self.code, re.IGNORECASE):
                rhs = (match.group(1) if match.groups() else "").strip()
                if not rhs or is_static_or_feature_detection(rhs):
                    continue

                if sink_name == "Function" and not match.group(0).strip().startswith(("new Function", "Function", "window.Function")):
                    # Skip lowercase JS 'function' keyword definitions
                    continue

                snippet = self._get_snippet(match.start())
                if is_framework_internal_sink(self.code, snippet, match.start()):
                    continue

                sanitized, sanitizer = is_sanitizer_barrier(rhs)
                sink_line = self.code.count("\n", 0, match.start()) + 1

                # Check direct source in sink
                direct_src = ""
                for s_name, s_pat in SOURCE_PATTERNS.items():
                    if re.search(s_pat, rhs, re.IGNORECASE):
                        direct_src = s_name
                        break

                if direct_src:
                    code_slice = self.extract_slice_by_lines([sink_line], snippet, [])
                    flows.append(
                        DfgFlow(
                            source=direct_src,
                            sink=sink_name,
                            source_line=sink_line,
                            sink_line=sink_line,
                            path=[],
                            nodes=[],
                            snippet=snippet,
                            code_slice=code_slice,
                            sanitized=sanitized,
                            sanitizer=sanitizer,
                            confidence=0.35 if sanitized else 0.9,
                        )
                    )
                    continue

                # Check variable references in sink
                for var_name, nodes in nodes_by_var.items():
                    # Only match if var_name is an isolated identifier in the sink expression
                    if not re.search(r"\b" + re.escape(var_name) + r"\b", rhs):
                        continue

                    # Trace back through the most recent assignment to var_name before this sink
                    preceding = [n for n in nodes if n.char_offset < match.start()]
                    if not preceding:
                        continue
                    curr_node = preceding[-1]

                    # Traverse backwards to find source
                    path, source_node, is_async = self._trace_source(curr_node, nodes_by_var, set())
                    if source_node and source_node.source_name:
                        key_lines = [source_node.line, curr_node.line, sink_line]
                        code_slice = self.extract_slice_by_lines(key_lines, snippet, path)
                        flows.append(
                            DfgFlow(
                                source=source_node.source_name,
                                sink=sink_name,
                                source_line=source_node.line,
                                sink_line=sink_line,
                                path=path,
                                nodes=[source_node, curr_node],
                                snippet=snippet,
                                code_slice=code_slice,
                                sanitized=sanitized,
                                sanitizer=sanitizer,
                                confidence=0.35 if sanitized else (0.85 if not path else 0.75),
                                is_async=is_async,
                            )
                        )
                        break

        return flows

    @staticmethod
    def _is_minified_identifier(name: str) -> bool:
        """Check if an identifier name is a short minified variable (1-2 chars, not a source API)."""
        if not name:
            return False
        known_sources = {"db", "id", "store", "url", "hash", "loc"}
        if len(name) <= 2:
            return True
        return False

    def _link_async_callbacks(self, nodes_by_var: Dict[str, List[DfgNode]]) -> None:
        """Link async response parameters: fetch(...).then(res => res.json()).then(data => ...)"""
        # 1. Match fetch / promise calls followed by .then
        then_re = re.compile(
            r"(?:([A-Za-z0-9_$]+|\))\s*\.)?then\s*\(\s*(?:async\s*)?(?:function\s*)?\(?([A-Za-z0-9_$]+)\)?\s*(?:=>|\{)",
            re.IGNORECASE,
        )
        prev_param = ""
        for m in then_re.finditer(self.code):
            param = m.group(2)
            line_no = self.code.count("\n", 0, m.start()) + 1
            # Look backwards up to 300 chars for the call target (e.g. fetch(...) or previous then)
            preceding_chunk = self.code[max(0, m.start() - 300) : m.start()]
            fetch_match = re.search(r"fetch\s*\(([^)]+)(?:\)|$)", preceding_chunk, re.IGNORECASE)

            expr = "Promise.resolve()"
            if prev_param:
                expr = f"{prev_param}.then()"
            elif fetch_match:
                expr = f"fetch({fetch_match.group(1)})"

            node = DfgNode(
                id=f"async_{m.start()}",
                variable=param,
                expression=expr,
                line=line_no,
                char_offset=m.start(),
                is_source=False,
            )
            nodes_by_var.setdefault(param, []).append(node)
            prev_param = param

        # 2. Match IndexedDB onsuccess callbacks: e.g. req.onsuccess = function(ev) { ... }
        idb_onsuccess_re = re.compile(
            r"([A-Za-z0-9_$]+)\s*\.\s*onsuccess\s*=\s*(?:async\s*)?(?:function\s*)?\(?([A-Za-z0-9_$]+)\)?",
            re.IGNORECASE,
        )
        for m in idb_onsuccess_re.finditer(self.code):
            req_var = m.group(1)
            event_param = m.group(2)
            line_no = self.code.count("\n", 0, m.start()) + 1

            preceding_context = self.code[max(0, m.start() - 800) : m.start()]
            is_idb = "indexeddb" in preceding_context.lower() or "objectstore" in preceding_context.lower()

            node = DfgNode(
                id=f"idb_async_{m.start()}",
                variable=event_param,
                expression=f"{req_var}.result",
                line=line_no,
                char_offset=m.start(),
                is_source=is_idb,
                source_name="indexedDB" if is_idb else "",
            )
            nodes_by_var.setdefault(event_param, []).append(node)

    def _trace_source(
        self,
        start_node: DfgNode,
        nodes_by_var: Dict[str, List[DfgNode]],
        visited: Set[str],
        depth: int = 0,
    ) -> Tuple[List[str], Optional[DfgNode], bool]:
        """Traverse DFG nodes backwards from sink to source."""
        if depth > 10 or start_node.id in visited:
            return [], None, False
        visited.add(start_node.id)

        is_node_async = (
            "then" in start_node.expression
            or "await" in start_node.expression
            or "fetch" in start_node.expression
            or "idb" in start_node.id
            or start_node.source_name == "indexedDB"
        )
        if start_node.is_source:
            return [start_node.variable], start_node, is_node_async

        # Look for identifiers in start_node.expression
        tokens = set(re.findall(r"[A-Za-z_$][\w$]*", start_node.expression))
        for token in tokens:
            if token in nodes_by_var and token != start_node.variable:
                preceding = [n for n in nodes_by_var[token] if n.char_offset < start_node.char_offset]
                if preceding:
                    sub_path, src_node, sub_async = self._trace_source(
                        preceding[-1], nodes_by_var, visited, depth + 1
                    )
                    if src_node:
                        return [token] + sub_path, src_node, (is_node_async or sub_async)

        return [], None, is_node_async

    def _get_snippet(self, offset: int, limit: int = 220) -> str:
        start = max(0, self.code.rfind("\n", 0, offset) + 1)
        end = self.code.find("\n", offset)
        if end < 0:
            end = min(len(self.code), offset + limit)
        return self.code[start:min(end, start + limit)].strip()

    def extract_slice_by_lines(
        self,
        key_lines: List[int],
        sink_snippet: str,
        path: List[str],
        max_total_lines: int = 120,
    ) -> str:
        """
        Extract a clean, readable 50-150 line slice surrounding the source and sink.
        """
        if not self.lines:
            return sink_snippet

        selected_lines: Set[int] = set()
        padding = 15

        for line_idx in key_lines:
            # 1-indexed to 0-indexed
            target = max(0, line_idx - 1)
            start = max(0, target - padding)
            end = min(len(self.lines), target + padding + 1)
            for i in range(start, end):
                selected_lines.add(i)

        if not selected_lines:
            return sink_snippet

        sorted_indices = sorted(selected_lines)[:max_total_lines]
        formatted: List[str] = []
        last_idx = -1

        for idx in sorted_indices:
            if last_idx != -1 and idx > last_idx + 1:
                formatted.append("    // ... [intermediate context omitted] ...")
            line_str = self.lines[idx]
            formatted.append(f"{idx + 1:4d} | {line_str}")
            last_idx = idx

        return "\n".join(formatted)

