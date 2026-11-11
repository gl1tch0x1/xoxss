"""
Trusted Types analysis module.
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class TrustedTypesPolicy(Enum):
    """Trusted Types policy states."""
    ENFORCED = "enforced"
    NOT_ENFORCED = "not_enforced"
    PARTIAL = "partial"
    MISSING = "missing"


@dataclass
class TrustedTypesIssue:
    """Trusted Types configuration issue."""
    issue_type: str
    severity: str
    description: str
    directive: Optional[str]


@dataclass
class TrustedTypesAnalysis:
    """Complete Trusted Types analysis."""
    policy_state: TrustedTypesPolicy
    issues: List[TrustedTypesIssue]
    csp_header: str
    has_trusted_types_directive: bool
    requires_trusted_for: List[str]


class TrustedTypesAnalyzer:
    """
    Advanced Trusted Types analyzer.
    Analyzes Trusted Types CSP directive configuration.
    """

    # Sink functions that require trusted types
    TRUSTED_SINKS = [
        'innerHTML',
        'outerHTML',
        'insertAdjacentHTML',
        'document.write',
        'document.writeln',
        'Range.createContextualFragment',
    ]

    # Patterns that bypass Trusted Types
    BYPASS_PATTERNS = [
        r'innerHTML\s*=\s*TrustPolicy\.createHTML',
        r'outerHTML\s*=\s*TrustPolicy\.createHTML',
        r'insertAdjacentHTML\s*\(\s*["\']?\w+["\']?\s*,\s*TrustPolicy\.createHTML',
    ]

    def __init__(self):
        self._cache: Dict[str, TrustedTypesAnalysis] = {}

    def analyze_trusted_types(self, csp_header: str) -> TrustedTypesAnalysis:
        """
        Analyze Trusted Types CSP directive.

        Args:
            csp_header: Content-Security-Policy header value

        Returns:
            TrustedTypesAnalysis with detailed findings
        """
        issues = []
        has_trusted_types_directive = False
        requires_trusted_for = []

        # Parse CSP
        directives = {}
        for directive in csp_header.split(';'):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            directive_name = parts[0]
            values = parts[1:] if len(parts) > 1 else []
            directives[directive_name] = values

        # Check for require-trusted-types-for
        if 'require-trusted-types-for' in directives:
            has_trusted_types_directive = True
            requires_trusted_for = directives['require-trusted-types-for']

            # 'script' is the only sink directive in the Trusted Types spec
            if 'script' not in requires_trusted_for:
                issues.append(TrustedTypesIssue(
                    issue_type="missing_sink_coverage",
                    severity="medium",
                    description="require-trusted-types-for does not cover the 'script' sink",
                    directive="require-trusted-types-for"
                ))
        else:
            issues.append(TrustedTypesIssue(
                issue_type="missing_directive",
                severity="high",
                description="require-trusted-types-for directive is missing",
                directive="require-trusted-types-for"
            ))

        # Check for trusted-types directive
        if 'trusted-types' in directives:
            trusted_policies = directives['trusted-types']
            # A named allowlist ('trusted-types app-policy') is the *correct*
            # restrictive form; only a wildcard is permissive.
            if '*' in trusted_policies:
                issues.append(TrustedTypesIssue(
                    issue_type="permissive_policy",
                    severity="medium",
                    description="trusted-types allows any policy ('*')",
                    directive="trusted-types"
                ))
        else:
            issues.append(TrustedTypesIssue(
                issue_type="missing_policy",
                severity="high",
                description="trusted-types directive is missing",
                directive="trusted-types"
            ))

        # Determine policy state
        if has_trusted_types_directive and 'trusted-types' in directives:
            policy_state = TrustedTypesPolicy.ENFORCED
        elif has_trusted_types_directive:
            policy_state = TrustedTypesPolicy.PARTIAL
        else:
            policy_state = TrustedTypesPolicy.MISSING

        return TrustedTypesAnalysis(
            policy_state=policy_state,
            issues=issues,
            csp_header=csp_header,
            has_trusted_types_directive=has_trusted_types_directive,
            requires_trusted_for=requires_trusted_for
        )

    def check_trusted_types_bypass(self, js_content: str) -> List[str]:
        """Check for Trusted Types bypass patterns in JavaScript."""
        bypasses = []

        for pattern in self.BYPASS_PATTERNS:
            if re.search(pattern, js_content):
                bypasses.append(pattern)

        return bypasses

    def generate_trusted_types_payload(self, marker: str) -> str:
        """Generate a payload that might bypass Trusted Types."""
        return f"var policy = {{createHTML: (h) => h}}; var html = policy.createHTML('<img src=x onerror=window.__xoxss_tt.push(\\'{marker}\\')\">');"

    def assess_trusted_types_strength(self, analysis: TrustedTypesAnalysis) -> str:
        """Assess the overall strength of Trusted Types implementation."""
        if analysis.policy_state == TrustedTypesPolicy.ENFORCED:
            high_severity = [i for i in analysis.issues if i.severity == "high"]
            if not high_severity:
                return "strong"
            return "moderate"
        elif analysis.policy_state == TrustedTypesPolicy.PARTIAL:
            return "moderate"
        else:
            return "weak"
