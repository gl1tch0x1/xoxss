"""
CORS (Cross-Origin Resource Sharing) analysis module.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class CORSIssueType(Enum):
    """CORS misconfiguration types."""
    WILDCARD_WITH_CREDENTIALS = "wildcard_with_credentials"
    REFLECTED_ORIGIN = "reflected_origin"
    NULL_ORIGIN = "null_origin"
    MISSING_CORS_HEADERS = "missing_cors_headers"
    OVERLY_PERMISSIVE = "overly_permissive"
    SENSITIVE_HEADERS_EXPOSED = "sensitive_headers_exposed"


@dataclass
class CORSIssue:
    """CORS misconfiguration issue."""
    issue_type: CORSIssueType
    severity: str
    description: str
    header: Optional[str]
    value: Optional[str]


@dataclass
class CORSAnalysis:
    """Complete CORS analysis."""
    is_misconfigured: bool
    issues: List[CORSIssue]
    headers: Dict[str, str]
    xss_exfiltration_risk: bool
    csrf_risk: bool


class CORSAnalyzer:
    """
    Advanced CORS analyzer.
    Analyzes CORS headers for misconfigurations and security risks.
    """

    CORS_HEADERS = [
        'access-control-allow-origin',
        'access-control-allow-credentials',
        'access-control-allow-methods',
        'access-control-allow-headers',
        'access-control-expose-headers',
        'access-control-max-age',
        'access-control-allow-private-network',
    ]

    SENSITIVE_HEADERS = [
        'authorization',
        'cookie',
        'set-cookie',
        'x-auth-token',
        'x-csrf-token',
    ]

    def __init__(self):
        self._cache: Dict[str, CORSAnalysis] = {}

    def analyze_cors(self, cors_headers: Dict[str, str]) -> CORSAnalysis:
        """
        Analyze CORS headers for misconfigurations.

        Args:
            cors_headers: Dictionary of CORS headers

        Returns:
            CORSAnalysis with detailed findings
        """
        headers_lower = {k.lower(): v for k, v in cors_headers.items()}
        issues = []

        # Check for wildcard origin with credentials
        origin = headers_lower.get('access-control-allow-origin', '')
        credentials = headers_lower.get('access-control-allow-credentials', '')

        if origin == '*' and credentials.lower() == 'true':
            issues.append(CORSIssue(
                issue_type=CORSIssueType.WILDCARD_WITH_CREDENTIALS,
                severity="high",
                description="Wildcard origin with credentials is invalid and dangerous",
                header="access-control-allow-origin",
                value=origin
            ))

        # Check for reflected origin
        if 'null' in origin or 'http://' in origin or 'https://' in origin:
            if origin != '*':
                issues.append(CORSIssue(
                    issue_type=CORSIssueType.REFLECTED_ORIGIN,
                    severity="medium",
                    description="Origin header appears to be reflected without validation",
                    header="access-control-allow-origin",
                    value=origin
                ))

        # Check for null origin
        if origin == 'null':
            issues.append(CORSIssue(
                issue_type=CORSIssueType.NULL_ORIGIN,
                severity="medium",
                description="Null origin allows local file access and other attacks",
                header="access-control-allow-origin",
                value=origin
            ))

        # Check for overly permissive methods
        methods = headers_lower.get('access-control-allow-methods', '')
        if methods:
            allowed_methods = [m.strip().upper() for m in methods.split(',')]
            dangerous_methods = ['DELETE', 'PUT', 'PATCH']
            for method in dangerous_methods:
                if method in allowed_methods:
                    issues.append(CORSIssue(
                        issue_type=CORSIssueType.OVERLY_PERMISSIVE,
                        severity="medium",
                        description=f"Allows dangerous method: {method}",
                        header="access-control-allow-methods",
                        value=method
                    ))

        # Check for exposed sensitive headers
        exposed = headers_lower.get('access-control-expose-headers', '')
        if exposed:
            exposed_headers = [h.strip().lower() for h in exposed.split(',')]
            for sensitive in self.SENSITIVE_HEADERS:
                if sensitive in exposed_headers:
                    issues.append(CORSIssue(
                        issue_type=CORSIssueType.SENSITIVE_HEADERS_EXPOSED,
                        severity="high",
                        description=f"Exposes sensitive header: {sensitive}",
                        header="access-control-expose-headers",
                        value=sensitive
                    ))

        # Check for missing CORS headers
        if not headers_lower:
            issues.append(CORSIssue(
                issue_type=CORSIssueType.MISSING_CORS_HEADERS,
                severity="info",
                description="No CORS headers present",
                header=None,
                value=None
            ))

        is_misconfigured = len(issues) > 0

        # Assess XSS exfiltration risk
        xss_exfiltration_risk = any(
            issue.issue_type in (CORSIssueType.WILDCARD_WITH_CREDENTIALS, CORSIssueType.REFLECTED_ORIGIN)
            for issue in issues
        )

        # Assess CSRF risk
        csrf_risk = credentials.lower() == 'true' and origin != '*'

        return CORSAnalysis(
            is_misconfigured=is_misconfigured,
            issues=issues,
            headers=cors_headers,
            xss_exfiltration_risk=xss_exfiltration_risk,
            csrf_risk=csrf_risk
        )

    def check_xss_data_exfiltration_risk(self, analysis: CORSAnalysis) -> bool:
        """Check if CORS misconfiguration could enable XSS data exfiltration."""
        return analysis.xss_exfiltration_risk

    def generate_test_origin(self, target_origin: str) -> str:
        """Generate a test origin for CORS testing."""
        return f"https://evil.com"

    def check_origin_reflection(self, response_headers: Dict[str, str], test_origin: str) -> bool:
        """
        Check if the origin is reflected in Access-Control-Allow-Origin.

        Args:
            response_headers: Response headers
            test_origin: Origin to test

        Returns:
            True if origin is reflected
        """
        acao = response_headers.get('Access-Control-Allow-Origin', '')
        return acao == test_origin

    def assess_cors_policy_strength(self, analysis: CORSAnalysis) -> str:
        """Assess the overall strength of CORS policy."""
        if not analysis.is_misconfigured:
            return "strong"

        critical_issues = [i for i in analysis.issues if i.severity == "high"]
        if critical_issues:
            return "weak"

        medium_issues = [i for i in analysis.issues if i.severity == "medium"]
        if medium_issues:
            return "moderate"

        return "acceptable"
