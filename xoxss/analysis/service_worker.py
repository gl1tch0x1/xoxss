"""
Service Worker XSS detection module.
Detects XSS in Service Worker install handlers, fetch events, and cache poisoning.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class SWEventType(Enum):
    """Service Worker event types."""
    INSTALL = "install"
    ACTIVATE = "activate"
    FETCH = "fetch"
    MESSAGE = "message"
    PUSH = "push"
    SYNC = "sync"
    NOTIFICATIONCLICK = "notificationclick"


@dataclass
class SWVulnerability:
    """Service Worker XSS vulnerability."""
    event_type: SWEventType
    line: int
    code: str
    description: str
    severity: str
    payload_template: str


class ServiceWorkerAnalyzer:
    """
    Service Worker XSS analyzer.
    Detects XSS in Service Worker code and cache poisoning vectors.
    """

    # XSS patterns in Service Workers
    XSS_PATTERNS = {
        SWEventType.INSTALL: [
            r"addEventListener\s*\(\s*[\"']install[\"']",
            r"self\.addEventListener\(\s*[\"']install[\"']",
        ],
        SWEventType.FETCH: [
            r"addEventListener\s*\(\s*[\"']fetch[\"']",
            r"self\.addEventListener\(\s*[\"']fetch[\"']",
        ],
        SWEventType.MESSAGE: [
            r"addEventListener\s*\(\s*[\"']message[\"']",
            r"self\.addEventListener\(\s*[\"']message[\"']",
        ],
    }

    # Sink patterns
    SINK_PATTERNS = {
        "Response": r"new\s+Response\s*\(",
        "Cache": r"cache\.put\s*\(",
        "Clients": r"clients\.openWindow\s*\(",
        "ImportScripts": r"importScripts\s*\(",
        "Eval": r"\beval\s*\(",
    }

    # Cache poisoning patterns
    CACHE_POISONING_PATTERNS = [
        r"event\.respondWith\s*\(",
        r"cache\.match\s*\(",
        r"cache\.put\s*\(",
        r"new\s+Response\s*\(",
    ]

    def __init__(self):
        self._vulnerabilities: List[SWVulnerability] = []

    def analyze(self, sw_content: str, url: str = "") -> List[SWVulnerability]:
        """
        Analyze Service Worker code for XSS vulnerabilities.

        Args:
            sw_content: Service Worker JavaScript source
            url: URL of the Service Worker (for reporting)

        Returns:
            List of detected vulnerabilities
        """
        self._vulnerabilities = []
        lines = sw_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for XSS in event handlers
            for event_type, patterns in self.XSS_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check if user input reaches a sink
                        for sink_pattern in self.SINK_PATTERNS.values():
                            if re.search(sink_pattern, line, re.IGNORECASE):
                                self._vulnerabilities.append(SWVulnerability(
                                    event_type=event_type,
                                    line=line_num,
                                    code=line.strip(),
                                    description=f"User input may reach {sink_pattern} in {event_type.value} handler",
                                    severity="high",
                                    payload_template="<script>alert(document.cookie)</script>"
                                ))

            # Check for cache poisoning vectors
            for pattern in self.CACHE_POISONING_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if user-controlled input is used
                    if re.search(r"event\.request|request\.url|request\.headers", line, re.IGNORECASE):
                        self._vulnerabilities.append(SWVulnerability(
                                    event_type=SWEventType.FETCH,
                                    line=line_num,
                                    code=line.strip(),
                                    description="Cache poisoning via user-controlled request data",
                                    severity="medium",
                                    payload_template="malicious_response"
                                ))

        return self._vulnerabilities

    def detect_cache_poisoning(self, sw_content: str) -> bool:
        """Detect if the Service Worker is vulnerable to cache poisoning."""
        indicators = [
            r"event\.respondWith\s*\(",
            r"cache\.match\s*\(",
            r"cache\.put\s*\(",
            r"new\s+Response\s*\(",
        ]

        for pattern in indicators:
            if re.search(pattern, sw_content, re.IGNORECASE):
                return True

        return False

    def generate_test_payloads(self, vulnerabilities: List[SWVulnerability], marker: str) -> List[str]:
        """Generate test payloads for Service Worker XSS."""
        payloads = []

        for vuln in vulnerabilities:
            if vuln.event_type == SWEventType.FETCH:
                payloads.append(f"<script>fetch('/?{marker}')</script>")
            elif vuln.event_type == SWEventType.MESSAGE:
                payloads.append(f"postMessage('{marker}')")
            elif vuln.event_type == SWEventType.INSTALL:
                payloads.append(f"importScripts('{marker}')")

        return list(set(payloads))

    def get_service_worker_scope(self, sw_content: str) -> Optional[str]:
        """Extract the Service Worker scope from the code."""
        match = re.search(r"scope\s*:\s*['\"]([^'\"]+)['\"]", sw_content)
        if match:
            return match.group(1)
        return None
