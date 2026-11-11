"""
postMessage XSS detection module.
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class PostMessageSink(Enum):
    """postMessage sink types."""
    ONMESSAGE = "onmessage"
    MESSAGE_EVENT = "message_event"
    ADDEVENTLISTENER = "add_event_listener"


@dataclass
class PostMessageVulnerability:
    """postMessage XSS vulnerability."""
    sink_type: PostMessageSink
    has_origin_validation: bool
    origin_pattern: Optional[str]
    payload: str
    description: str


class PostMessageAnalyzer:
    """
    Advanced postMessage XSS analyzer.
    Detects XSS vulnerabilities in postMessage event handlers.
    """

    # postMessage sink patterns
    SINK_PATTERNS = {
        PostMessageSink.ONMESSAGE: [
            r'\.onmessage\s*=',
            r'\w+\.onmessage\s*=',
        ],
        PostMessageSink.MESSAGE_EVENT: [
            r'onmessage\s*=',
            r'\.on\s*\(\s*["\']message["\']',
        ],
        PostMessageSink.ADDEVENTLISTENER: [
            r'addEventListener\s*\(\s*["\']message["\']',
            r'window\.addEventListener\s*\(\s*["\']message["\']',
        ],
    }

    # Origin validation patterns
    ORIGIN_VALIDATION_PATTERNS = [
        r'\.origin',
        r'event\.origin',
        r'checkOrigin',
        r'validateOrigin',
        r'trustedOrigins',
    ]

    # Dangerous sink patterns
    DANGEROUS_SINKS = [
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'\beval\s*\(',
        r'new\s+Function\s*\(',
        r'document\.write\s*\(',
        r'location\s*=',
    ]

    def __init__(self):
        self._cache: Dict[str, List[PostMessageVulnerability]] = {}

    def detect_postmessage_usage(self, js_content: str) -> bool:
        """Check if postMessage is used in the JavaScript."""
        postmessage_patterns = [
            r'postMessage\s*\(',
            r'\.onmessage',
            r'addEventListener\s*\(\s*["\']message["\']',
        ]
        return any(re.search(pattern, js_content) for pattern in postmessage_patterns)

    def analyze_postmessage_handlers(self, js_content: str, marker: str) -> List[PostMessageVulnerability]:
        """
        Analyze postMessage event handlers for XSS vulnerabilities.

        Args:
            js_content: JavaScript source code
            marker: Unique marker for verification

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        if not self.detect_postmessage_usage(js_content):
            return vulnerabilities

        # Find all postMessage sinks
        for sink_type, patterns in self.SINK_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, js_content)
                for match in matches:
                    # Extract the handler code
                    handler_start = match.end()
                    handler_code = js_content[handler_start:handler_start + 500]

                    # Check for origin validation
                    has_origin_validation = self._check_origin_validation(handler_code)
                    origin_pattern = self._extract_origin_pattern(handler_code)

                    # Check for dangerous sinks
                    has_dangerous_sink = any(
                        re.search(dangerous, handler_code) for dangerous in self.DANGEROUS_SINKS
                    )

                    if has_dangerous_sink and not has_origin_validation:
                        vulnerabilities.append(PostMessageVulnerability(
                            sink_type=sink_type,
                            has_origin_validation=has_origin_validation,
                            origin_pattern=origin_pattern,
                            payload=self._generate_payload(marker),
                            description="postMessage handler lacks origin validation and uses dangerous sink"
                        ))

        return vulnerabilities

    def _check_origin_validation(self, handler_code: str) -> bool:
        """Check if the handler validates the message origin."""
        return any(re.search(pattern, handler_code) for pattern in self.ORIGIN_VALIDATION_PATTERNS)

    def _extract_origin_pattern(self, handler_code: str) -> Optional[str]:
        """Extract the origin validation pattern if present."""
        for pattern in self.ORIGIN_VALIDATION_PATTERNS:
            match = re.search(pattern, handler_code)
            if match:
                return match.group(0)
        return None

    def _generate_payload(self, marker: str) -> str:
        """Generate a postMessage XSS payload."""
        return f'window.postMessage("<script>window.__xoxss_pm.push(\'{marker}\')</script>", "*")'

    def generate_test_message(self, target_origin: str, marker: str) -> str:
        """Generate a test postMessage."""
        return f'''
        var iframe = document.createElement('iframe');
        iframe.src = '{target_origin}';
        document.body.appendChild(iframe);
        iframe.contentWindow.postMessage("<script>window.__xoxss_pm.push('{marker}')</script>", "*");
        '''

    def check_wildcard_origin(self, handler_code: str) -> bool:
        """Check if the handler accepts messages from any origin."""
        return '*' in handler_code and 'origin' not in handler_code

    def assess_postmessage_risk(self, vulnerabilities: List[PostMessageVulnerability]) -> str:
        """Assess overall postMessage XSS risk."""
        if not vulnerabilities:
            return "none"

        no_validation = [v for v in vulnerabilities if not v.has_origin_validation]
        if no_validation:
            return "high"

        return "medium"
