"""
CORS (Cross-Origin Resource Sharing) analysis module.
"""

from typing import Dict, List, Optional
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
        # --- original -----------------------------------------------------
        'access-control-allow-origin',
        'access-control-allow-credentials',
        'access-control-allow-methods',
        'access-control-allow-headers',
        'access-control-expose-headers',
        'access-control-max-age',
        'access-control-allow-private-network',

        # --- added: request-side (preflight) ------------------------------
        'access-control-request-method',
        'access-control-request-headers',
        'access-control-request-private-network',

        # --- added: less common / newer CORS response directives ----------
        'access-control-allow-credential',            # singular — sometimes mis-typed
        'access-control-allow-origin-request-headers',# odd CDN variant seen in dumps
        'access-control-allow-original',
        'access-control-max-age',                     # duplicate-safe
        'access-control-request-headers',

        # --- added: "cross-origin" policy family ---------------------------
        'timing-allow-origin',
        'cross-origin-embedder-policy',
        'cross-origin-embedder-policy-report-only',
        'cross-origin-opener-policy',
        'cross-origin-opener-policy-report-only',
        'cross-origin-resource-policy',

        # --- added: CORS-adjacent ------------------------------------------
        'origin',                                     # request-side, echo-checks matter
        'vary',                                       # `vary: origin` is required for correct caching of CORS responses
        'content-security-policy',                    # CSP report + CORS mismatches are a classic IDOR signal
        'content-security-policy-report-only',
        'strict-transport-security',
        'x-frame-options',
        'x-permitted-cross-domain-policies',
        'x-domain-policy',                            # legacy Flash / crossdomain.xml
        'cross-domain-policy',                        # legacy Flash
        'x-domain-prefetch-control',
        'x-dns-prefetch-control',
        'referrer-policy',
        'permissions-policy',
        'feature-policy',

        # --- added: reverse-proxy / CDN variants that often mangle CORS ---
        'x-cors',
        'x-cors-enabled',
        'x-cors-headers',
        'x-frame-options-report-only',

        # --- added: non-standard / lower-cased / snake variants found in
        # raw header dumps (some scanners see pre-normalization bytes) -----
        'access_control_allow_origin',
        'access_control_allow_credentials',
        'access_control_allow_methods',
        'access_control_allow_headers',
        'access_control_expose_headers',
        'access_control_max_age',
        'accesscontrolalloworigin',
        'accesscontrolallowcredentials',
    ]

    SENSITIVE_HEADERS = [
        # --- original -----------------------------------------------------
        'authorization',
        'cookie',
        'set-cookie',
        'x-auth-token',
        'x-csrf-token',

        # --- added: HTTP auth family --------------------------------------
        'proxy-authorization',
        'www-authenticate',
        'proxy-authenticate',
        'authentication-info',
        'proxy-authentication-info',
        'cookie2',                                    # RFC 2965 legacy
        'set-cookie2',

        # --- added: API keys / tokens ------------------------------------
        'x-api-key',
        'api-key',
        'apikey',
        'api_token',
        'api-token',
        'x-api-token',
        'x-access-token',
        'x-refresh-token',
        'x-id-token',
        'x-session-token',
        'x-session-id',
        'x-auth',
        'x-auth-user',
        'x-authentication',
        'x-jwt',
        'x-jwt-token',
        'x-token',
        'x-bearer',
        'x-bearer-token',
        'bearer-token',
        'id-token',
        'access-token',
        'refresh-token',

        # --- added: CSRF / anti-forgery ----------------------------------
        'x-xsrf-token',
        'x-csrftoken',
        'x-csrf',
        'x-csrf-protection',
        'csrf-token',
        'xsrf-token',
        'x-antiforgery',
        '__requestverificationtoken',

        # --- added: user identity / role / tenant ------------------------
        'x-user-id',
        'x-userid',
        'x-user',
        'x-username',
        'x-user-name',
        'x-user-email',
        'x-email',
        'x-role',
        'x-roles',
        'x-user-role',
        'x-permissions',
        'x-user-permissions',
        'x-tenant-id',
        'x-tenant',
        'x-org-id',
        'x-organization-id',
        'x-client-id',
        'x-client-secret',
        'x-client-certificate',
        'x-client-assertion',

        # --- added: cloud / IAM credentials ------------------------------
        'x-amz-security-token',
        'x-amz-credential',
        'x-amz-signature',
        'x-amz-date',
        'x-amz-content-sha256',
        'x-amz-target',
        'x-amz-user-agent',
        'x-goog-user-project',
        'x-goog-api-key',
        'x-goog-authuser',
        'x-ms-client-request-id',
        'x-ms-return-client-request-id',
        'x-ms-token-aad-access-token',
        'x-ms-token-aad-id-token',
        'x-firebase-auth',
        'x-firebase-id-token',
        'x-firebase-gmpid',

        # --- added: framework / vendor auth ------------------------------
        'x-github-token',
        'x-gitlab-token',
        'x-slack-signature',
        'x-slack-request-timestamp',
        'x-twitter-auth-type',
        'x-okta-*',
        'x-okta-user',
        'x-auth0-*',
        'x-cloudflare-access-jwt',
        'cf-access-jwt-assertion',
        'cf-access-client-id',
        'cf-access-client-secret',
        'do-connecting-ip',
        'x-vercel-id',
        'x-vercel-signature',
        'x-netlify-id',
        'x-datadome-*',

        # --- added: IP / proxy identity ---------------------------------
        'x-forwarded-for',
        'x-forwarded-host',
        'x-forwarded-server',
        'x-forwarded-proto',
        'x-real-ip',
        'x-client-ip',
        'x-cluster-client-ip',
        'x-originating-ip',
        'forwarded',
        'via',
        'client-ip',

        # --- added: URL / method rewriting (SSRF / auth bypass signals) --
        'x-original-url',
        'x-rewrite-url',
        'x-original-host',
        'x-original-uri',
        'x-original-method',
        'x-host',
        'x-http-method-override',
        'x-method-override',
        'x-rewrite-method',

        # --- added: rate-limit / bot / WAF tokens -----------------------
        'x-ratelimit-key',
        'x-rate-limit-key',
        'x-ratelimit-token',
        'x-bot-token',
        'x-captcha-token',
        'x-turnstile-token',
        'x-recaptcha-token',
        'x-hcaptcha-token',
        'x-cloudflare-turnstile',

        # --- added: tracing / correlation (chain-of-trust leaks) --------
        'x-request-id',
        'x-correlation-id',
        'x-trace-id',
        'x-b3-traceid',
        'x-b3-spanid',
        'x-b3-sampled',
        'x-b3-parentspanid',
        'traceparent',
        'tracestate',
        'newrelic',
        'x-newrelic-id',
        'x-newrelic-transaction',
        'x-datadog-trace-id',
        'x-datadog-parent-id',
        'x-datadog-origin',
        'x-datadog-sampling-priority',

        # --- added: info-leak / fingerprinting headers ------------------
        'x-powered-by',
        'server',
        'x-aspnet-version',
        'x-aspnetmvc-version',
        'x-generator',
        'x-runtime',
        'x-version',
        'x-drupal-cache',
        'x-drupal-dynamic-cache',
        'x-varnish',
        'x-cache',
        'x-cache-hits',
        'x-served-by',
        'x-timer',
        'x-ua-compatible',
        'x-backend-server',
        'x-backend',
        'x-served-by-cluster',
        'x-envoy-upstream-service-time',
        'x-envoy-internal',
        'x-envoy-external-address',
        'x-envoy-decorator-operation',

        # --- added: cookie-related Set-Cookie sub-directives (when
        # scanned as standalone tokens in dumps) -------------------------
        'samesite',
        'httponly',
        'secure',
        'partitioned',
        'priority',
        '__host-',
        '__secure-',
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
        return "https://evil.com"

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
