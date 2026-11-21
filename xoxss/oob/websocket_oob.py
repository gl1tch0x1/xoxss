"""
WebSocket OOB XSS Detection Module.

Detects and exploits XSS via WebSocket channels:
- WebSocket message handler XSS
- WebSocket frame injection
- WebSocket callback exploitation
- Blind XSS via WebSocket
"""

import re
from typing import Dict, List, Set
from dataclasses import dataclass
from enum import Enum


class WebSocketExfiltrationMethod(Enum):
    """WebSocket exfiltration methods."""
    MESSAGE = "message"
    FRAME = "frame"
    BROADCAST = "broadcast"
    CALLBACK = "callback"
    EVENT = "event"


@dataclass
class WebSocketXSSVulnerability:
    """WebSocket-based XSS vulnerability."""
    method: WebSocketExfiltrationMethod
    payload: str
    callback_url: str
    severity: str
    context: str


class WebSocketOOBDetector:
    """
    Advanced WebSocket OOB XSS detector.
    Detects XSS vulnerabilities via WebSocket channels.
    """

    # WebSocket sink patterns
    WEBSOCKET_SINK_PATTERNS = {
        WebSocketExfiltrationMethod.MESSAGE: [
            r'addEventListener\s*\(\s*["\']message',
            r'onmessage\s*=',
            r'\.onmessage\s*=',
            r'websocket\.onmessage',
        ],
        WebSocketExfiltrationMethod.FRAME: [
            r'new\s+WebSocket\s*\(',
            r'WebSocket\s*\(',
            r'ws://',
            r'wss://',
        ],
        WebSocketExfiltrationMethod.BROADCAST: [
            r'postMessage\s*\(',
            r'broadcast\s*\(',
            r'emit\s*\(',
        ],
        WebSocketExfiltrationMethod.CALLBACK: [
            r'callback\s*=',
            r'oncallback\s*=',
            r'\.callback\s*=',
        ],
        WebSocketExfiltrationMethod.EVENT: [
            r'addEventListener\s*\(\s*["\']open',
            r'addEventListener\s*\(\(\s*["\']close',
            r'addEventListener\s*\(\s*["\']error',
        ],
    }

    # Dangerous WebSocket integration patterns
    DANGEROUS_PATTERNS = [
        r'innerHTML\s*=\s*.*websocket',
        r'outerHTML\s*=\s*.*websocket',
        r'eval\s*\(\s*.*websocket',
        r'new\s+Function\s*\(\s*.*websocket',
        r'document\.write\s*\(\s*.*websocket',
        r'setTimeout\s*\(\s*.*websocket',
        r'setInterval\s*\(\s*.*websocket',
        r'\.html\s*=\s*.*websocket',
        r'\.text\s*=\s*.*websocket',
    ]

    # WebSocket XSS payloads
    WEBSOCKET_XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ]

    def __init__(self):
        self._detected_sinks: Set[WebSocketExfiltrationMethod] = set()
        self._vulnerabilities: List[WebSocketXSSVulnerability] = []

    def detect_websocket_sinks(self, js_content: str) -> Set[WebSocketExfiltrationMethod]:
        """
        Detect WebSocket-related XSS sinks.

        Args:
            js_content: JavaScript source code

        Returns:
            Set of detected WebSocket sinks
        """
        detected = set()

        for method, patterns in self.WEBSOCKET_SINK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, js_content, re.IGNORECASE):
                    detected.add(method)
                    break

        self._detected_sinks = detected
        return detected

    def check_dangerous_integration(self, js_content: str, marker: str = "xoxss") -> List[WebSocketXSSVulnerability]:
        """
        Check for dangerous WebSocket integration patterns.

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
                    for payload in self.WEBSOCKET_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(WebSocketXSSVulnerability(
                            method=WebSocketExfiltrationMethod.MESSAGE,
                            payload=marked,
                            callback_url="detected",
                            severity="high",
                            context=f"Line {line_num}: Dangerous WebSocket integration"
                        ))

        return vulnerabilities

    def check_message_handler_xss(self, js_content: str, marker: str = "xoxss") -> List[WebSocketXSSVulnerability]:
        """
        Check for XSS in WebSocket message handlers.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for message event handlers
            if re.search(r'onmessage|addEventListener.*message', line, re.IGNORECASE):
                # Check if message data reaches DOM sink
                if re.search(r'innerHTML|outerHTML|document\.write|eval|new\s+Function|\.html\s*=', line, re.IGNORECASE):
                    for payload in self.WEBSOCKET_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(WebSocketXSSVulnerability(
                            method=WebSocketExfiltrationMethod.MESSAGE,
                            payload=marked,
                            callback_url="websocket",
                            severity="high",
                            context=f"Line {line_num}: WebSocket message handler XSS"
                        ))

        return vulnerabilities

    def check_frame_injection(self, js_content: str, marker: str = "xoxss") -> List[WebSocketXSSVulnerability]:
        """
        Check for WebSocket frame injection vulnerabilities.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for WebSocket send with user input
            if re.search(r'websocket\.send|ws\.send|socket\.send', line, re.IGNORECASE):
                # Check if user input is used
                if re.search(r'event\.|request\.|user|input|location\.|document\.', line, re.IGNORECASE):
                    for payload in self.WEBSOCKET_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(WebSocketXSSVulnerability(
                            method=WebSocketExfiltrationMethod.FRAME,
                            payload=marked,
                            callback_url="websocket_frame",
                            severity="medium",
                            context=f"Line {line_num}: WebSocket frame injection"
                        ))

        return vulnerabilities

    def check_callback_exploitation(self, js_content: str, marker: str = "xoxss") -> List[WebSocketXSSVulnerability]:
        """
        Check for WebSocket callback exploitation.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for callback registration
            if re.search(r'callback\s*=|oncallback\s*=', line, re.IGNORECASE):
                # Check if callback is user-controlled
                if re.search(r'event\.|request\.|user|input|location\.|document\.', line, re.IGNORECASE):
                    for payload in self.WEBSOCKET_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(WebSocketXSSVulnerability(
                            method=WebSocketExfiltrationMethod.CALLBACK,
                            payload=marked,
                            callback_url="websocket_callback",
                            severity="high",
                            context=f"Line {line_num}: WebSocket callback exploitation"
                        ))

        return vulnerabilities

    def scan_for_websocket_xss(
        self,
        js_content: str,
        callback_url: str = "wss://callback.attacker.com",
        marker: str = "xoxss"
    ) -> List[WebSocketXSSVulnerability]:
        """
        Scan for WebSocket XSS vulnerabilities.

        Args:
            js_content: JavaScript source code
            callback_url: WebSocket callback URL
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        self._vulnerabilities = []
        sinks = self.detect_websocket_sinks(js_content)

        if not sinks:
            return self._vulnerabilities

        # Check dangerous integration
        self._vulnerabilities.extend(self.check_dangerous_integration(js_content, marker))

        # Check message handler XSS
        if WebSocketExfiltrationMethod.MESSAGE in sinks:
            self._vulnerabilities.extend(self.check_message_handler_xss(js_content, marker))

        # Check frame injection
        if WebSocketExfiltrationMethod.FRAME in sinks:
            self._vulnerabilities.extend(self.check_frame_injection(js_content, marker))

        # Check callback exploitation
        if WebSocketExfiltrationMethod.CALLBACK in sinks:
            self._vulnerabilities.extend(self.check_callback_exploitation(js_content, marker))

        return self._vulnerabilities

    def assess_websocket_risk(self, vulnerabilities: List[WebSocketXSSVulnerability]) -> str:
        """Assess overall WebSocket XSS risk."""
        if not vulnerabilities:
            return "none"

        high_severity = [v for v in vulnerabilities if v.severity == "high"]
        if high_severity:
            return "critical"

        return "high"

    def get_websocket_summary(self) -> Dict[str, int]:
        """Get summary of WebSocket findings."""
        summary = {
            "total_vulnerabilities": len(self._vulnerabilities),
            "by_method": {
                "message": sum(1 for v in self._vulnerabilities if v.method == WebSocketExfiltrationMethod.MESSAGE),
                "frame": sum(1 for v in self._vulnerabilities if v.method == WebSocketExfiltrationMethod.FRAME),
                "broadcast": sum(1 for v in self._vulnerabilities if v.method == WebSocketExfiltrationMethod.BROADCAST),
                "callback": sum(1 for v in self._vulnerabilities if v.method == WebSocketExfiltrationMethod.CALLBACK),
                "event": sum(1 for v in self._vulnerabilities if v.method == WebSocketExfiltrationMethod.EVENT),
            },
        }
        return summary


__all__ = [
    "WebSocketExfiltrationMethod",
    "WebSocketOOBDetector",
    "WebSocketXSSVulnerability",
]
