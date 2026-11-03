"""
DOM XSS analysis module.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class DOMSink(Enum):
    """DOM XSS sink types."""
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


class DOMSource(Enum):
    """DOM XSS source types."""
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
    SINK_PATTERNS = {
        DOMSink.INNER_HTML: r'\.innerHTML\s*=',
        DOMSink.OUTER_HTML: r'\.outerHTML\s*=',
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
        DOMSink.DOCUMENT_REFERRER: r'document\.referrer',
        DOMSink.WINDOW_NAME: r'window\.name',
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
    }

    # Source patterns
    SOURCE_PATTERNS = {
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
    }

    # Sanitizer patterns
    SANITIZER_PATTERNS = [
        r'DOMPurify\.sanitize',
        r'sanitize-html',
        r'sanitize',
        r'escape',
        r'encodeURI',
        r'encodeURIComponent',
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
        if flow.sink.sink_type in (DOMSink.INNER_HTML, DOMSink.OUTER_HTML):
            return f"<img src=x onerror=window.__xoxss_dom_hits.push('{marker}')>"
        elif flow.sink.sink_type == DOMSink.EVAL:
            return f"window.__xoxss_dom_hits.push('{marker}')"
        elif flow.sink.sink_type == DOMSink.LOCATION:
            return f"javascript:window.__xoxss_dom_hits.push('{marker}')"
        else:
            return f"<script>window.__xoxss_dom_hits.push('{marker}')</script>"
