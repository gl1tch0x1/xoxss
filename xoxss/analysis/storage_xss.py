"""
Storage-based XSS discovery module.
Detects XSS in localStorage, sessionStorage, IndexedDB, and WebSQL with
strict provenance and data-flow verification to eliminate false positives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

from xoxss.analysis.framework_sinks import (
    is_framework_internal_sink,
    is_sanitizer_barrier,
    is_static_or_feature_detection,
)


class StorageType(Enum):
    """Browser storage types."""
    LOCALSTORAGE = "localStorage"
    SESSIONSTORAGE = "sessionStorage"
    INDEXEDDB = "indexeddb"
    WEBSQL = "websql"
    COOKIES = "cookies"


@dataclass
class StorageXSSVector:
    """XSS vector in browser storage."""
    storage_type: StorageType
    key: str
    payload_template: str
    description: str
    persistent: bool
    confidence: float
    source_api: str = ""
    sink_api: str = ""
    sink_snippet: str = ""
    attacker_reachable: bool = False
    sanitized: bool = False
    sanitizer: str = ""


# Attacker-controllable input sources that could write to storage
ATTACKER_INPUT_PATTERNS = [
    re.compile(r"\b(?:window\.|document\.)?location\s*\.\s*(?:search|hash|href|pathname)\b"),
    re.compile(r"\bURLSearchParams\b"),
    re.compile(r"\bwindow\s*\.\s*name\b"),
    re.compile(r"\b(?:event|e|evt|message)\s*\.\s*data\b"),
    re.compile(r"\bdocument\s*\.\s*referrer\b"),
]

# Sinks for stored data with capture of RHS expression
STORAGE_SINKS: List[Tuple[str, re.Pattern]] = [
    ("innerHTML", re.compile(r"\.\s*innerHTML\s*=\s*([^;\n]{1,500})", re.IGNORECASE)),
    ("outerHTML", re.compile(r"\.\s*outerHTML\s*=\s*([^;\n]{1,500})", re.IGNORECASE)),
    ("insertAdjacentHTML", re.compile(r"\.\s*insertAdjacentHTML\s*\(\s*[^,]+,\s*([^)\n]{1,500})\)", re.IGNORECASE)),
    ("document.write", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(\s*([^)\n]{1,500})\)", re.IGNORECASE)),
    ("eval", re.compile(r"(?<![\w$.])eval\s*\(\s*([^)\n]{1,500})\)", re.IGNORECASE)),
    ("Function", re.compile(r"\b(?:new\s+)?Function\s*\(\s*([^)\n]{1,500})\)", re.IGNORECASE)),
    ("srcdoc", re.compile(r"\.\s*srcdoc\s*=\s*([^;\n]{1,500})", re.IGNORECASE)),
    ("jquery.html", re.compile(r"\.\s*html\s*\(\s*([^)\n]{1,500})\)", re.IGNORECASE)),
]


class StorageXSSAnalyzer:
    """
    Storage-based XSS analyzer.
    Detects XSS vulnerabilities in browser storage mechanisms with verified
    data-flow bindings, provenance tracking, and framework runtime suppression.
    """

    def __init__(self) -> None:
        self._vectors: List[StorageXSSVector] = []

    def analyze(self, js_content: str) -> List[StorageXSSVector]:
        """
        Analyze JavaScript for storage XSS vectors with strict data-flow binding.

        Args:
            js_content: JavaScript source code

        Returns:
            List of verified XSS vectors
        """
        self._vectors = []
        if not js_content:
            return self._vectors

        # Check if the script contains an attacker-controlled entry point
        # capable of writing to browser storage
        attacker_reachable = any(pat.search(js_content) for pat in ATTACKER_INPUT_PATTERNS)

        # 1. Direct Nesting Check: sink = ...storage.getItem('key')...
        self._check_direct_storage_sinks(js_content, attacker_reachable)

        # 2. Variable Data-Flow Check: var x = storage.getItem('key'); ... sink = x
        self._check_variable_storage_flows(js_content, attacker_reachable)

        # 3. IndexedDB Promise / Callback Flow Check
        self._check_indexeddb_callback_flows(js_content, attacker_reachable)

        return self._vectors

    def _check_direct_storage_sinks(self, js_content: str, attacker_reachable: bool) -> None:
        """Detect direct assignments: el.innerHTML = localStorage.getItem('theme')."""
        for sink_name, sink_re in STORAGE_SINKS:
            for match in sink_re.finditer(js_content):
                rhs = match.group(1).strip()

                # Guard: static literal / feature detection filter
                if is_static_or_feature_detection(rhs):
                    continue

                # Guard: framework runtime internals (Vue 3, Alpine, React diffing)
                if is_framework_internal_sink(js_content, match.group(0), match.start()):
                    continue

                # Check if RHS directly calls storage
                storage_type: Optional[StorageType] = None
                key = "unknown"
                source_api = ""

                # localStorage direct read
                ls_m = re.search(
                    r"\b(?:window\.)?localStorage\s*\.\s*getItem\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
                    rhs,
                    re.IGNORECASE,
                )
                if ls_m:
                    storage_type = StorageType.LOCALSTORAGE
                    key = ls_m.group(1)
                    source_api = f"localStorage.getItem('{key}')"
                else:
                    ls_bracket = re.search(
                        r"\b(?:window\.)?localStorage\s*\[\s*['\"]([^'\"]+)['\"]\s*\]",
                        rhs,
                        re.IGNORECASE,
                    )
                    if ls_bracket:
                        storage_type = StorageType.LOCALSTORAGE
                        key = ls_bracket.group(1)
                        source_api = f"localStorage['{key}']"

                # sessionStorage direct read
                if not storage_type:
                    ss_m = re.search(
                        r"\b(?:window\.)?sessionStorage\s*\.\s*getItem\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
                        rhs,
                        re.IGNORECASE,
                    )
                    if ss_m:
                        storage_type = StorageType.SESSIONSTORAGE
                        key = ss_m.group(1)
                        source_api = f"sessionStorage.getItem('{key}')"
                    else:
                        ss_bracket = re.search(
                            r"\b(?:window\.)?sessionStorage\s*\[\s*['\"]([^'\"]+)['\"]\s*\]",
                            rhs,
                            re.IGNORECASE,
                        )
                        if ss_bracket:
                            storage_type = StorageType.SESSIONSTORAGE
                            key = ss_bracket.group(1)
                            source_api = f"sessionStorage['{key}']"

                if not storage_type:
                    continue

                # Sanitizer check
                sanitized, sanitizer = is_sanitizer_barrier(rhs)

                confidence = 0.2 if sanitized else (0.85 if attacker_reachable else 0.4)
                desc = (
                    f"XSS via {storage_type.value} key '{key}' reaching {sink_name}"
                    if not sanitized
                    else f"Sanitized flow from {storage_type.value} key '{key}' to {sink_name} ({sanitizer})"
                )

                self._vectors.append(
                    StorageXSSVector(
                        storage_type=storage_type,
                        key=key,
                        payload_template="<script>alert(1)</script>",
                        description=desc,
                        persistent=storage_type in [StorageType.LOCALSTORAGE, StorageType.INDEXEDDB, StorageType.WEBSQL],
                        confidence=confidence,
                        source_api=source_api,
                        sink_api=sink_name,
                        sink_snippet=match.group(0)[:200].strip(),
                        attacker_reachable=attacker_reachable,
                        sanitized=sanitized,
                        sanitizer=sanitizer,
                    )
                )

    def _check_variable_storage_flows(self, js_content: str, attacker_reachable: bool) -> None:
        """
        Detect variable-mediated flows:
        let val = localStorage.getItem('key');
        ...
        el.innerHTML = val;
        """
        # Find variable assignments from storage reads
        var_assign_re = re.compile(
            r"(?:(?:const|let|var)\s+)?([A-Za-z0-9_$]+)\s*=\s*"
            r"((?:window\.)?(?:localStorage|sessionStorage)\s*(?:\.\s*getItem\s*\(\s*['\"]([^'\"]+)['\"]\s*\)|\[\s*['\"]([^'\"]+)['\"]\s*\]))",
            re.IGNORECASE,
        )

        for match in var_assign_re.finditer(js_content):
            var_name = match.group(1)
            storage_expr = match.group(2)
            key = match.group(3) or match.group(4) or "unknown"

            # Avoid single-character or overly common minified variable collisions across huge bundles
            if len(var_name) <= 2 and var_name in {"a", "b", "c", "d", "e", "i", "t", "id", "db", "el"}:
                # Only follow short variables within a tight local window (max 800 chars)
                search_window_start = match.end()
                search_window_end = min(len(js_content), match.end() + 800)
            else:
                search_window_start = match.end()
                search_window_end = min(len(js_content), match.end() + 2500)

            window_code = js_content[search_window_start:search_window_end]
            storage_type = StorageType.LOCALSTORAGE if "localstorage" in storage_expr.lower() else StorageType.SESSIONSTORAGE
            source_api = f"{storage_type.value}.getItem('{key}')"

            # Look for sinks in the local window referencing var_name
            for sink_name, sink_re in STORAGE_SINKS:
                for sink_match in sink_re.finditer(window_code):
                    rhs = sink_match.group(1).strip()
                    # Verify var_name is in RHS as an exact identifier token
                    if not re.search(r"\b" + re.escape(var_name) + r"\b", rhs):
                        continue

                    if is_static_or_feature_detection(rhs):
                        continue

                    abs_pos = search_window_start + sink_match.start()
                    if is_framework_internal_sink(js_content, sink_match.group(0), abs_pos):
                        continue

                    sanitized, sanitizer = is_sanitizer_barrier(rhs)
                    confidence = 0.2 if sanitized else (0.8 if attacker_reachable else 0.35)

                    desc = (
                        f"XSS via {storage_type.value} key '{key}' reaching {sink_name}"
                        if not sanitized
                        else f"Sanitized flow from {storage_type.value} key '{key}' to {sink_name} ({sanitizer})"
                    )

                    self._vectors.append(
                        StorageXSSVector(
                            storage_type=storage_type,
                            key=key,
                            payload_template="<script>alert(1)</script>",
                            description=desc,
                            persistent=storage_type == StorageType.LOCALSTORAGE,
                            confidence=confidence,
                            source_api=source_api,
                            sink_api=sink_name,
                            sink_snippet=sink_match.group(0)[:200].strip(),
                            attacker_reachable=attacker_reachable,
                            sanitized=sanitized,
                            sanitizer=sanitizer,
                        )
                    )

    def _check_indexeddb_callback_flows(self, js_content: str, attacker_reachable: bool) -> None:
        """
        Detect IndexedDB flows strictly requiring:
        1) Genuine indexedDB open / objectStore call (not Set.add or classList.add)
        2) Data from cursor or request reaching an execution sink.
        """
        # Ensure script actually uses IndexedDB
        if not re.search(r"\b(?:window\.)?indexedDB\s*\.\s*open\b", js_content, re.IGNORECASE):
            return

        # Look for explicit objectStore reads
        store_read_re = re.compile(
            r"\.objectStore\s*\(\s*['\"]([^'\"]+)['\"]\s*\)\s*\.\s*(?:get|getAll|openCursor)\s*\(\s*([^)]*)\)",
            re.IGNORECASE,
        )

        for match in store_read_re.finditer(js_content):
            store_name = match.group(1)
            # Find the enclosing callback or promise handler
            window_start = match.end()
            window_end = min(len(js_content), window_start + 3000)
            window_code = js_content[window_start:window_end]

            # Look for onsuccess or .then handler receiving the event/result
            cb_match = re.search(
                r"(?:\.onsuccess\s*=\s*(?:function\s*)?\(([A-Za-z0-9_$]*)\)|\.then\s*\(\s*(?:function\s*)?\(([A-Za-z0-9_$]*)\))",
                window_code,
                re.IGNORECASE,
            )
            if not cb_match:
                continue

            param_name = cb_match.group(1) or cb_match.group(2) or ""
            cb_body = window_code[cb_match.end():min(len(window_code), cb_match.end() + 2000)]

            # Collect variables in callback body assigned from event / result
            cb_tainted_vars = {param_name} if param_name else set()
            for assign_m in re.finditer(
                r"(?:(?:const|let|var)\s+)?([A-Za-z0-9_$]+)\s*=\s*([^;\n]+)",
                cb_body,
            ):
                target_var = assign_m.group(1)
                assign_rhs = assign_m.group(2)
                if (param_name and re.search(r"\b" + re.escape(param_name) + r"\b", assign_rhs)) or "result" in assign_rhs:
                    cb_tainted_vars.add(target_var)

            # Check if any sink in the callback body receives param_name, result, or a tainted variable
            for sink_name, sink_re in STORAGE_SINKS:
                for sink_match in sink_re.finditer(cb_body):
                    rhs = sink_match.group(1).strip()
                    param_in_sink = any(
                        re.search(r"\b" + re.escape(v) + r"\b", rhs) for v in cb_tainted_vars if v
                    ) or ("result" in rhs)

                    if not param_in_sink:
                        continue

                    if is_static_or_feature_detection(rhs):
                        continue

                    abs_pos = window_start + cb_match.end() + sink_match.start()
                    if is_framework_internal_sink(js_content, sink_match.group(0), abs_pos):
                        continue

                    sanitized, sanitizer = is_sanitizer_barrier(rhs)
                    confidence = 0.2 if sanitized else (0.85 if attacker_reachable else 0.4)

                    desc = (
                        f"XSS via indexedDB store '{store_name}' reaching {sink_name}"
                        if not sanitized
                        else f"Sanitized flow from indexedDB store '{store_name}' to {sink_name} ({sanitizer})"
                    )

                    self._vectors.append(
                        StorageXSSVector(
                            storage_type=StorageType.INDEXEDDB,
                            key=store_name,
                            payload_template="<script>alert(1)</script>",
                            description=desc,
                            persistent=True,
                            confidence=confidence,
                            source_api=f"indexedDB.objectStore('{store_name}').get()",
                            sink_api=sink_name,
                            sink_snippet=sink_match.group(0)[:200].strip(),
                            attacker_reachable=attacker_reachable,
                            sanitized=sanitized,
                            sanitizer=sanitizer,
                        )
                    )

    def generate_test_payloads(
        self,
        vectors: List[StorageXSSVector],
        marker: str
    ) -> List[str]:
        """Generate test payloads for storage XSS."""
        payloads = []
        for vector in vectors:
            payload = vector.payload_template.replace("alert(1)", f"alert('{marker}')")
            payloads.append(payload)
        return list(set(payloads))

    def generate_storage_injection_script(
        self,
        storage_type: StorageType,
        key: str,
        marker: str
    ) -> str:
        """Generate JavaScript to inject payload into storage."""
        if storage_type == StorageType.LOCALSTORAGE:
            return f"localStorage.setItem('{key}', '<script>alert(\"{marker}\")</script>');"
        elif storage_type == StorageType.SESSIONSTORAGE:
            return f"sessionStorage.setItem('{key}', '<script>alert(\"{marker}\")</script>');"
        elif storage_type == StorageType.INDEXEDDB:
            return f"""
            const request = indexedDB.open('test', 1);
            request.onsuccess = (e) => {{
                const db = e.target.result;
                const tx = db.transaction(['store'], 'readwrite');
                tx.objectStore('store').put({{key: '{key}', value: '<script>alert(\"{marker}\")</script>'}});
            }};
            """
        else:
            return f"localStorage.setItem('{key}', '<script>alert(\"{marker}\")</script>');"

    def detect_cookie_xss(self, js_content: str) -> bool:
        """Detect if cookies are used in XSS-susceptible contexts."""
        patterns = [
            r"document\.cookie",
            r"Cookie:\s*=",
        ]
        return any(re.search(pat, js_content, re.IGNORECASE) for pat in patterns)

    def get_persistent_vectors(self) -> List[StorageXSSVector]:
        """Get only persistent storage XSS vectors."""
        return [v for v in self._vectors if v.persistent]

    def get_high_confidence_vectors(self, min_confidence: float = 0.7) -> List[StorageXSSVector]:
        """Get vectors with confidence above threshold."""
        return [v for v in self._vectors if v.confidence >= min_confidence]
