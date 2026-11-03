"""
WebSocket XSS detection module.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class WebSocketSink(Enum):
    """WebSocket message sink types."""
    ONMESSAGE = "onmessage"
    MESSAGE_EVENT = "message_event"
    EVAL = "eval"
    INNERHTML = "innerHTML"
    DOCUMENT_WRITE = "document_write"


@dataclass
class WebSocketVulnerability:
    """WebSocket XSS vulnerability."""
    sink_type: WebSocketSink
    location: str
    payload: str
    description: str


class WebSocketAnalyzer:
    """
    Advanced WebSocket XSS analyzer.
    Detects XSS vulnerabilities in WebSocket message handlers.
    """

    # WebSocket sink patterns
    SINK_PATTERNS = {
        WebSocketSink.ONMESSAGE: [
            r'\.onmessage\s*=',
            r'addEventListener\s*\(\s*["\']message["\']',
        ],
        WebSocketSink.EVAL: [
            r'\beval\s*\(',
            r'new\s+Function\s*\(',
        ],
        WebSocketSink.INNERHTML: [
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
        ],
        WebSocketSink.DOCUMENT_WRITE: [
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
        ],
    }

    # WebSocket connection patterns
    CONNECTION_PATTERNS = [
        r'new\s+WebSocket\s*\(',
        r'new\s+Socket\s*\(',
        r'\.connect\s*\(',
    ]

    def __init__(self):
        self._cache: Dict[str, List[WebSocketVulnerability]] = {}

    def detect_websocket_usage(self, js_content: str) -> bool:
        """Check if WebSocket is used in the JavaScript."""
        for pattern in self.CONNECTION_PATTERNS:
            if re.search(pattern, js_content):
                return True
        return False

    def analyze_websocket_handlers(self, js_content: str, marker: str) -> List[WebSocketVulnerability]:
        """
        Analyze WebSocket message handlers for XSS vulnerabilities.

        Args:
            js_content: JavaScript source code
            marker: Unique marker for verification

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        if not self.detect_websocket_usage(js_content):
            return vulnerabilities

        # Check for onmessage handler
        if re.search(r'\.onmessage\s*=', js_content):
            # Check if data is used dangerously
            for sink_type, patterns in self.SINK_PATTERNS.items():
                if sink_type == WebSocketSink.ONMESSAGE:
                    continue
                for pattern in patterns:
                    if re.search(pattern, js_content):
                        vulnerabilities.append(WebSocketVulnerability(
                            sink_type=sink_type,
                            location="onmessage handler",
                            payload=self._generate_payload(sink_type, marker),
                            description=f"WebSocket message data flows into {sink_type.value}"
                        ))

        # Check for addEventListener('message')
        if re.search(r'addEventListener\s*\(\s*["\']message["\']', js_content):
            for sink_type, patterns in self.SINK_PATTERNS.items():
                if sink_type == WebSocketSink.ONMESSAGE:
                    continue
                for pattern in patterns:
                    if re.search(pattern, js_content):
                        vulnerabilities.append(WebSocketVulnerability(
                            sink_type=sink_type,
                            location="message event listener",
                            payload=self._generate_payload(sink_type, marker),
                            description=f"WebSocket message data flows into {sink_type.value}"
                        ))

        return vulnerabilities

    def _generate_payload(self, sink_type: WebSocketSink, marker: str) -> str:
        """Generate a WebSocket XSS payload."""
        if sink_type == WebSocketSink.INNERHTML:
            return f'<script>window.__xoxss_ws.push(\'{marker}\')</script>'
        elif sink_type == WebSocketSink.EVAL:
            return f'window.__xoxss_ws.push(\'{marker}\')'
        elif sink_type == WebSocketSink.DOCUMENT_WRITE:
            return f'<script>window.__xoxss_ws.push(\'{marker}\')</script>'
        else:
            return f'<script>window.__xoxss_ws.push(\'{marker}\')</script>'

    def generate_websocket_test_message(self, marker: str) -> str:
        """Generate a test WebSocket message."""
        return f'{{"data": "<script>window.__xoxss_ws.push(\'{marker}\')</script>"}}'

    def check_websocket_origin_validation(self, js_content: str) -> bool:
        """Check if WebSocket origin is validated."""
        origin_patterns = [
            r'origin',
            r'checkOrigin',
            r'validateOrigin',
        ]
        return any(re.search(pattern, js_content) for pattern in origin_patterns)
