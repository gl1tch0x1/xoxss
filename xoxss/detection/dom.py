"""
DOM XSS analysis module.
"""

import re
from typing import List, Optional
from dataclasses import dataclass
from enum import Enum


class DOMSink(Enum):
    """DOM XSS sink types."""
    # --- Original ---
    INNER_HTML = "innerHTML"
    OUTER_HTML = "outerHTML"
    INSERT_ADJACENT_HTML = "insertAdjacentHTML"
    DOCUMENT_WRITE = "document.write"
    DOCUMENT_WRITELN = "document.writeln"
    EVAL = "eval"
    FUNCTION = "Function"
    SET_TIMEOUT = "setTimeout"
    SET_INTERVAL = "setInterval"
    LOCATION = "location"
    LOCATION_HREF = "location.href"
    LOCATION_HASH = "location.hash"
    LOCATION_SEARCH = "location.search"
    DOCUMENT_REFERRER = "document.referrer"
    WINDOW_NAME = "window.name"
    POST_MESSAGE = "postMessage"
    JQUERY_HTML = "jQuery.html"
    JQUERY_APPEND = "jQuery.append"
    JQUERY_PREPEND = "jQuery.prepend"
    JQUERY_REPLACE_WITH = "jQuery.replaceWith"
    JQUERY_AFTER = "jQuery.after"
    JQUERY_BEFORE = "jQuery.before"
    JQUERY_INSERT_AFTER = "jQuery.insertAfter"
    JQUERY_INSERT_BEFORE = "jQuery.insertBefore"
    SRCDOC = "srcdoc"
    FRAME_SRC = "frame.src"
    SCRIPT_SRC = "script.src"
    SET_HTML_UNSAFE = "setHTMLUnsafe"
    SET_HTML = "Element.setHTML"
    PARSE_HTML_UNSAFE = "parseHTMLUnsafe"
    CREATE_CONTEXTUAL_FRAGMENT = "createContextualFragment"
    PARSE_FROM_STRING = "parseFromString"
    EXEC_COMMAND = "execCommand(insertHTML)"
    WINDOW_OPEN = "window.open"
    IMPORT_SCRIPTS = "importScripts"
    WORKER = "Worker"
    SET_ATTRIBUTE = "setAttribute"

    # --- URL / navigation ---
    LOCATION_ASSIGN = "location.assign"
    LOCATION_REPLACE = "location.replace"

    # --- Shadow DOM / iframe ---
    SHADOW_ROOT_INNER_HTML = "shadowRoot.innerHTML"
    ATTACH_SHADOW_INNER_HTML = "attachShadow().innerHTML"
    CONTENT_DOCUMENT_WRITE = "contentDocument.write"
    CONTENT_WINDOW_DOCUMENT_WRITE = "contentWindow.document.write"

    # --- Attribute namespace ---
    SET_ATTRIBUTE_NS = "setAttributeNS"

    # --- CSS / stylesheet sinks ---
    STYLE_PROPERTY = "style.setProperty"
    STYLE_CSS_TEXT = "style.cssText"
    STYLE_BACKGROUND_IMAGE = "style.backgroundImage"
    CSS_STYLESHEET_REPLACE_SYNC = "CSSStyleSheet.replaceSync"
    ADOPTED_STYLESHEETS = "adoptedStyleSheets"
    INSERT_RULE = "insertRule"

    # --- Framework-specific template/JSX sinks ---
    REACT_DANGEROUSLY_SET_INNER_HTML = "dangerouslySetInnerHTML"
    VUE_V_HTML = "v-html"
    ANGULAR_INNER_HTML = "[innerHTML]"
    ANGULAR_NG_BIND_HTML = "ng-bind-html"
    ANGULAR_BYPASS_SECURITY_TRUST = "bypassSecurityTrust*"
    ALPINE_X_HTML = "x-html"
    HTMX_HX_ON = "hx-on"
    HTMX_HX_VALS = "hx-vals"
    HTMX_HX_HEADERS = "hx-headers"
    LIT_UNSAFE_HTML = "unsafeHTML"
    LIT_UNSAFE_SVG = "unsafeSVG"
    LIT_UNSAFE_CSS = "unsafeCSS"
    SVELTE_AT_HTML = "{@html}"


class DOMSource(Enum):
    """DOM XSS source types."""
    # --- Original ---
    LOCATION_HASH = "location.hash"
    LOCATION_SEARCH = "location.search"
    LOCATION_HREF = "location.href"
    DOCUMENT_URL = "document.URL"
    DOCUMENT_URI = "document.documentURI"
    DOCUMENT_REFERRER = "document.referrer"
    WINDOW_NAME = "window.name"
    POST_MESSAGE = "postMessage"
    LOCAL_STORAGE = "localStorage"
    SESSION_STORAGE = "sessionStorage"
    COOKIE = "document.cookie"
    HISTORY_STATE = "history.state"
    WEB_SOCKET = "WebSocket"
    WINDOW_OPENER = "window.opener"
    URL_SEARCH_PARAMS = "URLSearchParams"
    ANCESTOR_ORIGINS = "location.ancestorOrigins"
    MESSAGE_DATA = "messageEvent.data"
    CACHES = "caches"
    INDEXED_DB = "indexedDB"
    DATASET = "dataset"

    # --- Location components ---
    LOCATION_PATHNAME = "location.pathname"
    LOCATION_ORIGIN = "location.origin"
    LOCATION_HOSTNAME = "location.hostname"
    LOCATION_PROTOCOL = "location.protocol"
    LOCATION_PORT = "location.port"

    # --- Document metadata ---
    DOCUMENT_DOMAIN = "document.domain"
    DOCUMENT_BASE_URI = "document.baseURI"
    DOCUMENT_TITLE = "document.title"

    # --- Navigator surface ---
    NAVIGATOR_USER_AGENT = "navigator.userAgent"
    NAVIGATOR_LANGUAGE = "navigator.language"
    NAVIGATOR_CLIPBOARD_READ_TEXT = "navigator.clipboard.readText"
    NAVIGATOR_CLIPBOARD_READ = "navigator.clipboard.read"

    # --- Network response bodies ---
    FETCH_RESPONSE = "fetch response body"
    XHR_RESPONSE_TEXT = "xhr.responseText"
    EVENT_SOURCE = "EventSource"

    # --- Message channels ---
    MESSAGE_PORT = "MessagePort"
    BROADCAST_CHANNEL = "BroadcastChannel"
    WORKER_MESSAGE = "Worker.onmessage"
    SHARED_WORKER_MESSAGE = "SharedWorker.onmessage"
    SERVICE_WORKER_MESSAGE = "ServiceWorker message"
    MESSAGE_EVENT_ORIGIN = "messageEvent.origin"

    # --- Form / input / clipboard values ---
    INPUT_VALUE = "input.value"
    TEXTAREA_VALUE = "textarea.value"
    FILE_READER_RESULT = "FileReader.result"
    CLIPBOARD_DATA = "clipboardData"
    WINDOW_SELECTION = "window.getSelection"

    # --- History mutation ---
    HISTORY_PUSH_STATE = "history.pushState"
    HISTORY_REPLACE_STATE = "history.replaceState"

    # --- Cross-window ---
    OPENER_LOCATION = "opener.location"
    PARENT_LOCATION = "parent.location"
    TOP_LOCATION = "top.location"

    # --- WASM ---
    WASM_MEMORY = "wasm.memory"


@dataclass
class DOMSinkInfo:
    """Information about a DOM sink."""
    sink_type: DOMSink
    line_number: int
    context: str
    is_sanitized: bool
    sanitizer: Optional[str]
    taint_source: Optional[DOMSource]


@dataclass
class DOMSourceInfo:
    """Information about a DOM source."""
    source_type: DOMSource
    line_number: int
    context: str
    is_controlled: bool


@dataclass
class DOMTaintFlow:
    """Taint flow from source to sink."""
    source: DOMSourceInfo
    sink: DOMSinkInfo
    flow_path: List[str]
    confidence: float


class DOMAnalyzer:
    """
    Advanced DOM XSS analyzer.
    Detects taint flows from sources to sinks in JavaScript code.
    """

    # Sink patterns
        # Sink patterns
    SINK_PATTERNS = {
        # --- Original ---
        DOMSink.INNER_HTML: r'\.innerHTML\s*\+?=',
        DOMSink.OUTER_HTML: r'\.outerHTML\s*\+?=',
        DOMSink.INSERT_ADJACENT_HTML: r'\.insertAdjacentHTML\s*\(',
        DOMSink.DOCUMENT_WRITE: r'document\.write\s*\(',
        DOMSink.DOCUMENT_WRITELN: r'document\.writeln\s*\(',
        DOMSink.EVAL: r'\beval\s*\(',
        DOMSink.FUNCTION: r'new\s+Function\s*\(',
        DOMSink.SET_TIMEOUT: r'setTimeout\s*\(',
        DOMSink.SET_INTERVAL: r'setInterval\s*\(',
        DOMSink.LOCATION: r'\.location\s*=',
        DOMSink.LOCATION_HREF: r'\.location\.href\s*=',
        DOMSink.LOCATION_HASH: r'\.location\.hash\s*=',
        DOMSink.LOCATION_SEARCH: r'\.location\.search\s*=',
        # NOTE: document.referrer / window.name are pure *sources* (read-only);
        # listing them as sinks produced bogus 1.0-confidence self-flows for
        # every script that merely reads one of them.
        DOMSink.JQUERY_HTML: r'\$\([^)]*\)\.html\s*\(',
        DOMSink.JQUERY_APPEND: r'\$\([^)]*\)\.append\s*\(',
        DOMSink.JQUERY_PREPEND: r'\$\([^)]*\)\.prepend\s*\(',
        DOMSink.JQUERY_REPLACE_WITH: r'\$\([^)]*\)\.replaceWith\s*\(',
        DOMSink.JQUERY_AFTER: r'\$\([^)]*\)\.after\s*\(',
        DOMSink.JQUERY_BEFORE: r'\$\([^)]*\)\.before\s*\(',
        DOMSink.JQUERY_INSERT_AFTER: r'\$\([^)]*\)\.insertAfter\s*\(',
        DOMSink.JQUERY_INSERT_BEFORE: r'\$\([^)]*\)\.insertBefore\s*\(',
        DOMSink.SRCDOC: r'\.srcdoc\s*=',
        DOMSink.FRAME_SRC: r'\.src\s*=',
        DOMSink.SCRIPT_SRC: r'\.src\s*=',
        DOMSink.SET_HTML_UNSAFE: r'\.setHTMLUnsafe\s*\(',
        DOMSink.SET_HTML: r'\.setHTML\s*\(',
        DOMSink.PARSE_HTML_UNSAFE: r'\.parseHTMLUnsafe\s*\(',
        DOMSink.CREATE_CONTEXTUAL_FRAGMENT: r'createContextualFragment\s*\(',
        DOMSink.PARSE_FROM_STRING: r'\.parseFromString\s*\(',
        DOMSink.EXEC_COMMAND: r"""execCommand\s*\(\s*['"]insertHTML""",
        DOMSink.WINDOW_OPEN: r'window\.open\s*\(',
        DOMSink.IMPORT_SCRIPTS: r'importScripts\s*\(',
        DOMSink.WORKER: r'new\s+(?:Shared)?Worker\s*\(',
        DOMSink.SET_ATTRIBUTE: r"""\.setAttribute\s*\(\s*['"](?:href|src|srcdoc|action|formaction|style|on\w+)['"]""",

        # --- URL / navigation ---
        DOMSink.LOCATION_ASSIGN: r'location\.assign\s*\(',
        DOMSink.LOCATION_REPLACE: r'location\.replace\s*\(',

        # --- Shadow DOM / iframe ---
        DOMSink.SHADOW_ROOT_INNER_HTML: r'\.shadowRoot\s*\.\s*innerHTML\s*\+?=',
        DOMSink.ATTACH_SHADOW_INNER_HTML: r'attachShadow\s*\([^)]*\)\s*\.\s*innerHTML\s*\+?=',
        DOMSink.CONTENT_DOCUMENT_WRITE: r'\.contentDocument\s*\.\s*write(?:ln)?\s*\(',
        DOMSink.CONTENT_WINDOW_DOCUMENT_WRITE: r'\.contentWindow\s*\.\s*document\s*\.\s*write(?:ln)?\s*\(',

        # --- Attribute namespace ---
        DOMSink.SET_ATTRIBUTE_NS: r'\.setAttributeNS\s*\(',

        # --- CSS / stylesheet sinks ---
        DOMSink.STYLE_PROPERTY: r'\.style\s*\.\s*setProperty\s*\(',
        DOMSink.STYLE_CSS_TEXT: r'\.style\s*\.\s*cssText\s*=',
        DOMSink.STYLE_BACKGROUND_IMAGE: r'\.style\s*\.\s*backgroundImage\s*=',
        DOMSink.CSS_STYLESHEET_REPLACE_SYNC: r'\.replaceSync\s*\(',
        DOMSink.ADOPTED_STYLESHEETS: r'\.adoptedStyleSheets\s*=',
        DOMSink.INSERT_RULE: r'\.insertRule\s*\(',

        # --- Framework-specific template/JSX sinks ---
        DOMSink.REACT_DANGEROUSLY_SET_INNER_HTML: r'dangerouslySetInnerHTML',
        DOMSink.VUE_V_HTML: r'v-html\s*=',
        DOMSink.ANGULAR_INNER_HTML: r'\[innerHTML\]\s*=',
        DOMSink.ANGULAR_NG_BIND_HTML: r'ng-bind-html\s*=',
        DOMSink.ANGULAR_BYPASS_SECURITY_TRUST: r'\.bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(',
        DOMSink.ALPINE_X_HTML: r'x-html\s*=',
        DOMSink.HTMX_HX_ON: r'hx-on\s*[:=]',
        DOMSink.HTMX_HX_VALS: r'hx-vals\s*=',
        DOMSink.HTMX_HX_HEADERS: r'hx-headers\s*=',
        DOMSink.LIT_UNSAFE_HTML: r'unsafeHTML\s*\(',
        DOMSink.LIT_UNSAFE_SVG: r'unsafeSVG\s*\(',
        DOMSink.LIT_UNSAFE_CSS: r'unsafeCSS\s*\(',
        DOMSink.SVELTE_AT_HTML: r'\{@html',
    }

    # Source patterns
    SOURCE_PATTERNS = {
        # --- Original ---
        DOMSource.LOCATION_HASH: r'location\.hash',
        DOMSource.LOCATION_SEARCH: r'location\.search',
        DOMSource.LOCATION_HREF: r'location\.href',
        DOMSource.DOCUMENT_URL: r'document\.URL',
        DOMSource.DOCUMENT_URI: r'document\.documentURI',
        DOMSource.DOCUMENT_REFERRER: r'document\.referrer',
        DOMSource.WINDOW_NAME: r'window\.name',
        DOMSource.POST_MESSAGE: r'postMessage',
        DOMSource.LOCAL_STORAGE: r'localStorage',
        DOMSource.SESSION_STORAGE: r'sessionStorage',
        DOMSource.COOKIE: r'document\.cookie',
        DOMSource.HISTORY_STATE: r'history\.state',
        DOMSource.WEB_SOCKET: r'WebSocket',
        DOMSource.WINDOW_OPENER: r'window\.opener',
        DOMSource.URL_SEARCH_PARAMS: r'URLSearchParams',
        DOMSource.ANCESTOR_ORIGINS: r'location\.ancestorOrigins',
        DOMSource.MESSAGE_DATA: r'(?:message|event)\.data',
        DOMSource.CACHES: r'\bcaches\b',
        DOMSource.INDEXED_DB: r'\bindexedDB\b',
        DOMSource.DATASET: r'\.dataset\b',

        # --- Location components ---
        DOMSource.LOCATION_PATHNAME: r'location\.pathname',
        DOMSource.LOCATION_ORIGIN: r'location\.origin',
        DOMSource.LOCATION_HOSTNAME: r'location\.hostname',
        DOMSource.LOCATION_PROTOCOL: r'location\.protocol',
        DOMSource.LOCATION_PORT: r'location\.port\b',

        # --- Document metadata ---
        DOMSource.DOCUMENT_DOMAIN: r'document\.domain',
        DOMSource.DOCUMENT_BASE_URI: r'document\.baseURI',
        DOMSource.DOCUMENT_TITLE: r'document\.title',

        # --- Navigator surface ---
        DOMSource.NAVIGATOR_USER_AGENT: r'navigator\.userAgent',
        DOMSource.NAVIGATOR_LANGUAGE: r'navigator\.language',
        DOMSource.NAVIGATOR_CLIPBOARD_READ_TEXT: r'navigator\.clipboard\.readText',
        DOMSource.NAVIGATOR_CLIPBOARD_READ: r'navigator\.clipboard\.read\b',

        # --- Network response bodies ---
        DOMSource.FETCH_RESPONSE: r'fetch\s*\([^)]*\)\s*\.then\s*\([^)]*\.(?:text|json|blob|arrayBuffer)\s*\(',
        DOMSource.XHR_RESPONSE_TEXT: r'\.responseText\b',
        DOMSource.EVENT_SOURCE: r'new\s+EventSource\s*\(',

        # --- Message channels ---
        DOMSource.MESSAGE_PORT: r'\.port[12]\b',
        DOMSource.BROADCAST_CHANNEL: r'new\s+BroadcastChannel\s*\(',
        DOMSource.WORKER_MESSAGE: r'worker\s*\.\s*onmessage\b',
        DOMSource.SHARED_WORKER_MESSAGE: r'new\s+SharedWorker\s*\(',
        DOMSource.SERVICE_WORKER_MESSAGE: r'navigator\.serviceWorker',
        DOMSource.MESSAGE_EVENT_ORIGIN: r'(?:message|event)\.origin',

        # --- Form / input / clipboard values ---
        DOMSource.INPUT_VALUE: r'input\.value\b',
        DOMSource.TEXTAREA_VALUE: r'textarea\.value\b',
        DOMSource.FILE_READER_RESULT: r'reader\.result\b',
        DOMSource.CLIPBOARD_DATA: r'clipboardData',
        DOMSource.WINDOW_SELECTION: r'window\.getSelection\s*\(',

        # --- History mutation ---
        DOMSource.HISTORY_PUSH_STATE: r'history\.pushState',
        DOMSource.HISTORY_REPLACE_STATE: r'history\.replaceState',

        # --- Cross-window ---
        DOMSource.OPENER_LOCATION: r'opener\.location',
        DOMSource.PARENT_LOCATION: r'parent\.location',
        DOMSource.TOP_LOCATION: r'top\.location',

        # --- WASM ---
        DOMSource.WASM_MEMORY: r'(?:\.memory\.buffer|new\s+WebAssembly\.Memory)',
    }

    # Sanitizer patterns
    SANITIZER_PATTERNS = [
        r'DOMPurify\.sanitize',
        r'sanitize-html',
        r'sanitize',
        r'escape',
        r'encodeURI',
        r'encodeURIComponent',
        r'he\.encode',
        r'he\.escape',
        r'_\s*\.\s*escape',
        r'lodash\s*\.\s*escape',
        r'validator\s*\.\s*escape',
        r'xss-filters',
        r'js-xss',
        r'xss\s*\(',
        r'bleach\s*\.\s*clean',
        r'markupsafe\s*\.\s*escape',
        r'html\s*\.\s*escape',
        r'htmlspecialchars',
        r'htmlentities',
        r'strip_tags',
        r'esc_html',
        r'esc_attr',
        r'esc_url',
        r'Sanitizer\s*\.\s*sanitize',
        r'DomSanitizer',
        r'TrustedHTML',
        r'TrustedTypes',
        r'createTextNode',
        r'textContent\s*=',
        r'innerText\s*=',
    ]

    def __init__(self):
        self._sinks: List[DOMSinkInfo] = []
        self._sources: List[DOMSourceInfo] = []
        self._taint_flows: List[DOMTaintFlow] = []

    def analyze_javascript(self, js_code: str, url: str = "") -> List[DOMTaintFlow]:
        """
        Analyze JavaScript code for DOM XSS vulnerabilities.

        Args:
            js_code: JavaScript source code
            url: URL of the JavaScript file (for reporting)

        Returns:
            List of detected taint flows
        """
        self._sinks = []
        self._sources = []
        self._taint_flows = []

        lines = js_code.split('\n')

        # Detect sources
        for line_num, line in enumerate(lines, 1):
            for source_type, pattern in self.SOURCE_PATTERNS.items():
                if re.search(pattern, line):
                    is_controlled = self._is_controlled_source(line)
                    self._sources.append(DOMSourceInfo(
                        source_type=source_type,
                        line_number=line_num,
                        context=line.strip(),
                        is_controlled=is_controlled
                    ))

        # Detect sinks
        for line_num, line in enumerate(lines, 1):
            for sink_type, pattern in self.SINK_PATTERNS.items():
                if re.search(pattern, line):
                    is_sanitized = self._is_sanitized(line)
                    sanitizer = self._extract_sanitizer(line)
                    self._sinks.append(DOMSinkInfo(
                        sink_type=sink_type,
                        line_number=line_num,
                        context=line.strip(),
                        is_sanitized=is_sanitized,
                        sanitizer=sanitizer,
                        taint_source=None
                    ))

        # Analyze taint flows (simplified)
        self._analyze_taint_flows(lines)

        return self._taint_flows

    def _is_controlled_source(self, line: str) -> bool:
        """Check if a source is controlled by user input."""
        # Heuristic: if source is directly used without validation
        controlled_indicators = ['location.', 'document.', 'window.']
        return any(indicator in line for indicator in controlled_indicators)

    def _is_sanitized(self, line: str) -> bool:
        """Check if a sink input is sanitized."""
        for pattern in self.SANITIZER_PATTERNS:
            if re.search(pattern, line):
                return True
        return False

    def _extract_sanitizer(self, line: str) -> Optional[str]:
        """Extract the sanitizer function name from a line."""
        for pattern in self.SANITIZER_PATTERNS:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        return None

    def _analyze_taint_flows(self, lines: List[str]) -> None:
        """
        Analyze taint flows from sources to sinks.
        This is a simplified version - full implementation would use AST analysis.
        """
        for source in self._sources:
            for sink in self._sinks:
                # A source is not a flow into itself (reads-before-uses are
                # handled by the assignment requirement of the sink patterns).
                if sink.line_number == source.line_number and str(sink.sink_type) == str(source.source_type):
                    continue
                # Simple heuristic: if source and sink are in close proximity
                line_distance = abs(sink.line_number - source.line_number)
                if line_distance < 20:  # Within 20 lines
                    confidence = max(0.1, 1.0 - (line_distance / 20.0))

                    if not sink.is_sanitized:
                        self._taint_flows.append(DOMTaintFlow(
                            source=source,
                            sink=sink,
                            flow_path=[f"line {source.line_number} -> line {sink.line_number}"],
                            confidence=confidence
                        ))

    def get_risk_score(self, taint_flows: List[DOMTaintFlow]) -> float:
        """Calculate overall DOM XSS risk score."""
        if not taint_flows:
            return 0.0

        total_confidence = sum(flow.confidence for flow in taint_flows)
        unsanitized_count = sum(1 for flow in taint_flows if not flow.sink.is_sanitized)

        # Weight unsanitized flows higher
        score = (total_confidence / len(taint_flows)) * (1 + unsanitized_count)
        return min(1.0, score)

    def generate_dom_payload(self, flow: DOMTaintFlow, marker: str) -> str:
        """Generate a DOM XSS payload for a specific taint flow."""
        html_sinks = {
            # --- Original ---
            DOMSink.INNER_HTML,
            DOMSink.OUTER_HTML,
            DOMSink.INSERT_ADJACENT_HTML,
            DOMSink.DOCUMENT_WRITE,
            DOMSink.DOCUMENT_WRITELN,
            DOMSink.JQUERY_HTML,
            DOMSink.JQUERY_APPEND,
            DOMSink.JQUERY_PREPEND,
            DOMSink.JQUERY_REPLACE_WITH,
            DOMSink.JQUERY_AFTER,
            DOMSink.JQUERY_BEFORE,
            DOMSink.JQUERY_INSERT_AFTER,
            DOMSink.JQUERY_INSERT_BEFORE,
            DOMSink.SRCDOC,
            DOMSink.SET_HTML_UNSAFE,
            DOMSink.SET_HTML,
            DOMSink.PARSE_HTML_UNSAFE,
            DOMSink.CREATE_CONTEXTUAL_FRAGMENT,
            DOMSink.PARSE_FROM_STRING,
            DOMSink.EXEC_COMMAND,
            DOMSink.SET_ATTRIBUTE,

            # --- Shadow DOM / iframe write variants ---
            DOMSink.SHADOW_ROOT_INNER_HTML,
            DOMSink.ATTACH_SHADOW_INNER_HTML,
            DOMSink.CONTENT_DOCUMENT_WRITE,
            DOMSink.CONTENT_WINDOW_DOCUMENT_WRITE,

            # --- Attribute namespace ---
            DOMSink.SET_ATTRIBUTE_NS,

            # --- CSS injection (styled like HTML: markup that renders in the DOM) ---
            DOMSink.STYLE_PROPERTY,
            DOMSink.STYLE_CSS_TEXT,
            DOMSink.STYLE_BACKGROUND_IMAGE,
            DOMSink.CSS_STYLESHEET_REPLACE_SYNC,
            DOMSink.ADOPTED_STYLESHEETS,
            DOMSink.INSERT_RULE,
            DOMSink.LIT_UNSAFE_CSS,

            # --- Framework template/JSX sinks (attribute-shaped, HTML-context) ---
            DOMSink.REACT_DANGEROUSLY_SET_INNER_HTML,
            DOMSink.VUE_V_HTML,
            DOMSink.ANGULAR_INNER_HTML,
            DOMSink.ANGULAR_NG_BIND_HTML,
            DOMSink.ANGULAR_BYPASS_SECURITY_TRUST,
            DOMSink.ALPINE_X_HTML,
            DOMSink.HTMX_HX_ON,
            DOMSink.HTMX_HX_VALS,
            DOMSink.HTMX_HX_HEADERS,
            DOMSink.LIT_UNSAFE_HTML,
            DOMSink.LIT_UNSAFE_SVG,
            DOMSink.SVELTE_AT_HTML,

            # NOTE: FRAME_SRC and SCRIPT_SRC deliberately omitted — both are
            # matched by the same r'\.src\s*=' pattern, so including them here
            # (or in code_sinks) would double-report every `.src = ` assignment.
            # LOCATION_HASH / LOCATION_SEARCH / DOCUMENT_REFERRER / WINDOW_NAME
            # remain pure sources, not sinks.
        }

        code_sinks = {
            # --- Original ---
            DOMSink.EVAL,
            DOMSink.FUNCTION,
            DOMSink.SET_TIMEOUT,
            DOMSink.SET_INTERVAL,
            DOMSink.LOCATION_HREF,
            DOMSink.LOCATION,
            DOMSink.WINDOW_OPEN,
            DOMSink.IMPORT_SCRIPTS,
            DOMSink.WORKER,

            # --- Navigation variants (javascript: URL landing sites) ---
            DOMSink.LOCATION_ASSIGN,
            DOMSink.LOCATION_REPLACE,
        }

        if flow.sink.sink_type in html_sinks:
            return f"<img src=x onerror=window.__xoxss_dom_hits.push('{marker}')>"
        if flow.sink.sink_type in code_sinks:
            return f"window.__xoxss_dom_hits.push('{marker}')"
        if flow.sink.sink_type in (DOMSink.FRAME_SRC, DOMSink.SCRIPT_SRC):
            return f"javascript:window.__xoxss_dom_hits.push('{marker}')"
        return f"<script>window.__xoxss_dom_hits.push('{marker}')</script>"
