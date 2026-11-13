"""
Framework-specific sink exploitation module.
Provides XSS bypass techniques for popular JavaScript frameworks.
"""

import re
from typing import List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class Framework(Enum):
    """JavaScript frameworks."""
    REACT = "react"
    VUE = "vue"
    ANGULAR = "angular"
    JQUERY = "jquery"
    SVELTE = "svelte"
    SOLID = "solid"
    ASTRO = "astro"
    NEXTJS = "nextjs"
    REMIX = "remix"


@dataclass
class FrameworkBypass:
    """Framework-specific XSS bypass technique."""
    framework: Framework
    technique: str
    payload_template: str
    description: str
    condition: str
    confidence: float


class FrameworkSinkExploiter:
    """
    Framework-specific sink exploitation detector.
    Detects and tests XSS bypasses for popular JavaScript frameworks.
    """

    # React bypasses
    REACT_BYPASSES = [
        FrameworkBypass(
            framework=Framework.REACT,
            technique="dangerouslySetInnerHTML",
            payload_template="<script>{m}</script>",
            description="React dangerouslySetInnerHTML bypass",
            condition="dangerouslySetInnerHTML usage",
            confidence=0.9
        ),
        FrameworkBypass(
            framework=Framework.REACT,
            technique="svg_onload",
            payload_template="<svg/onload={m}>",
            description="React SVG XSS via svgOnload",
            condition="React rendering SVG",
            confidence=0.8
        ),
        FrameworkBypass(
            framework=Framework.REACT,
            technique="template_literal",
            payload_template="{{{{constructor.prototype.constructor({m})()}}}}}",
            description="React template literal bypass",
            condition="React < 18 (template strings before sanitization)",
            confidence=0.7
        ),
    ]

    # Vue bypasses
    VUE_BYPASSES = [
        FrameworkBypass(
            framework=Framework.VUE,
            technique="v-html",
            payload_template="<script>{m}</script>",
            description="Vue v-html bypass",
            condition="v-html directive usage",
            confidence=0.9
        ),
        FrameworkBypass(
            framework=Framework.VUE,
            technique="v-bind_html",
            payload_template="<script>{m}</script>",
            description="Vue v-bind:html bypass",
            condition="v-bind:html directive usage",
            confidence=0.8
        ),
        FrameworkBypass(
            framework=Framework.VUE,
            technique="xss",
            payload_template="<script>{m}</script>",
            description="Vue XSS directive bypass",
            condition="XSS directive usage",
            confidence=0.9
        ),
    ]

    # Angular bypasses
    ANGULAR_BYPASSES = [
        FrameworkBypass(
            framework=Framework.ANGULAR,
            technique="bypassSecurityTrustHtml",
            payload_template="<script>{m}</script>",
            description="Angular bypassSecurityTrustHtml bypass",
            condition="Angular bypassSecurityTrustHtml usage",
            confidence=0.9
        ),
        FrameworkBypass(
            framework=Framework.ANGULAR,
            technique="sanitize-html",
            payload_template="<script>{m}</script>",
            description="Angular sanitize-html bypass",
            condition="Angular sanitizeHtml usage",
            confidence=0.8
        ),
        FrameworkBypass(
            framework=Framework.ANGULAR,
            technique="ng-bind-html",
            payload_template="<script>{m}</script>",
            description="Angular ng-bind-html bypass",
            condition="ng-bind-html directive usage",
            confidence=0.7
        ),
    ]

    # jQuery bypasses
    JQUERY_BYPASSES = [
        FrameworkBypass(
            framework=Framework.JQUERY,
            technique="html",
            payload_template="<script>{m}</script>",
            description="jQuery .html() bypass",
            condition="jQuery .html() usage",
            confidence=0.9
        ),
        FrameworkBypass(
            framework=Framework.JQUERY,
            technique="append",
            payload_template="<script>{m}</script>",
            description="jQuery .append() bypass",
            condition="jQuery .append() usage",
            confidence=0.9
        ),
        FrameworkBypass(
            framework=Framework.JQUERY,
            technique="parseHTML",
            payload_template="<script>{m}</script>",
            description="jQuery parseHTML bypass",
            condition="jQuery parseHTML usage",
            confidence=0.8
        ),
    ]

    def __init__(self):
        self._bypasses = {
            Framework.REACT: self.REACT_BYPASSES,
            Framework.VUE: self.VUE_BYPASSES,
            Framework.ANGULAR: self.ANGULAR_BYPASSES,
            Framework.JQUERY: self.JQUERY_BYPASSES,
        }

    def detect_framework(self, js_content: str) -> Optional[Framework]:
        """Detect which framework is being used."""
        framework_indicators = {
            Framework.REACT: r"React|ReactDOM|jsx|createClass|useState|useEffect|useRef",
            Framework.VUE: r"Vue\.|vue\.mount|v-if|v-for|v-html|v-bind",
            Framework.ANGULAR: r"angular\.|ng-controller|ng-bind|ng-href|ng-model",
            Framework.JQUERY: r"\$\(|jQuery\.fn",
            Framework.SVELTE: r"svelte|create_svelte_component",
            Framework.SOLID: r"SolidJS|createSignal",
            Framework.ASTRO: r"Astro|Astro\.fetchContent",
            Framework.NEXTJS: r"getServerSideProps|next/config",
            Framework.REMIX: r"remix:react-router|useLoaderData",
        }

        for framework, pattern in framework_indicators.items():
            if re.search(pattern, js_content, re.IGNORECASE):
                return framework
        return None

    def get_bypasses(self, framework: Framework) -> List[FrameworkBypass]:
        """Get XSS bypasses for a specific framework."""
        return self._bypasses.get(framework, [])

    def generate_bypass_payloads(
        self,
        framework: Framework,
        marker: str
    ) -> List[str]:
        """Generate XSS bypass payloads for a framework."""
        bypasses = self.get_bypasses(framework)
        payloads = []

        for bypass in bypasses:
            payload = bypass.payload_template.replace("{m}", marker)
            payloads.append(payload)

        return payloads

    def test_bypass_in_page(
        self,
        framework: Framework,
        html_content: str,
        marker: str
    ) -> List[FrameworkBypass]:
        """
        Test if framework bypasses are present in the page.

        Args:
            framework: Framework to test
            html_content: HTML content of the page
            marker: Unique marker for verification

        Returns:
            List of bypasses that may work based on detection
        """
        active_bypasses = []

        for bypass in self.get_bypasses(framework):
            # Check if the bypass condition is met
            if re.search(bypass.condition, html_content, re.IGNORECASE):
                active_bypasses.append(bypass)

        return active_bypasses

    def get_confidence_score(self, framework: Framework) -> float:
        """Get overall confidence score for framework XSS detection."""
        bypasses = self.get_bypasses(framework)
        if not bypasses:
            return 0.0

        total_confidence = sum(b.confidence for b in bypasses)
        return round(total_confidence / len(bypasses), 2)


# ---------------------------------------------------------------------------
# Framework Runtime & False-Positive Elimination Guards
# ---------------------------------------------------------------------------

_FRAMEWORK_INTERNAL_PATTERNS = [
    # Vue 3 runtime internals (insertStaticContent, patchProp, hostSetElementText, v-html directive runtime)
    re.compile(r"\b(?:insertStaticContent|patchProp|hostSetElementText|setElementText)\b"),
    re.compile(r"\bcreateVNode\s*\(|_createElementVNode\s*\("),
    re.compile(r"\b[A-Za-z0-9_$]+\.innerHTML\s*=\s*[A-Za-z0-9_$]+\s*\([^)]*\)"),  # Minified template compiler: Af.innerHTML = Ef(...)
    # Alpine.js runtime internals (x-html directive registration, evaluateLater wrapper)
    re.compile(r"\b(?:Alpine\.)?directive\s*\(\s*['\"]html['\"]"),
    re.compile(r"\bD\s*\(\s*['\"]html['\"]"),  # Minified Alpine: D('html', (e, ...))
    re.compile(r"\b['\"]html['\"],\s*\([A-Za-z0-9_$,\s{}:]+\)\s*=>"),
    re.compile(r"\b(?:evaluateLater|mutateDom)\b"),
    # React runtime internals (setInnerHTML, dangerouslySetInnerHTML definition in react-dom)
    re.compile(r"\bfunction\s+setInnerHTML\s*\("),
    re.compile(r"\bsetValueForProperty\b"),
    re.compile(r"\bsetInitialProperties\b"),
    re.compile(r"__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED"),
    # jQuery runtime internals (core method definitions on prototype)
    re.compile(r"jQuery\.fn\.(?:html|append|prepend|before|after|replaceWith)\s*="),
    re.compile(r"jQuery\.fn\.extend\s*\("),
    # Angular runtime internals (DomSanitizer implementation, SecurityContext)
    re.compile(r"\bDomSanitizerImpl\b"),
    re.compile(r"\bSecurityContext\.(?:HTML|SCRIPT|STYLE)\b"),
    re.compile(r"\b_sanitizeHtml\b"),
    # Svelte runtime internals
    re.compile(r"\bfunction\s+set_data\s*\("),
    re.compile(r"\bclaim_element\s*\("),
]

_STATIC_FEATURE_TEST_PATTERNS = [
    # Empty assignments
    re.compile(r"^\s*['\"`]?[ \t\r\n]*['\"`]?\s*$"),
    re.compile(r"^\s*(?:null|undefined|false|0)\s*$"),
    # Static string literals (single or double quoted, no variables)
    re.compile(r"^\s*['\"][^'\"]*['\"]\s*$"),
    # Static template literals without ${...} interpolations
    re.compile(r"^\s*`[^`$]*`\s*$"),
    # Polyfill / browser feature detection idiom (createElement('div').innerHTML = '<svg>')
    re.compile(r"document\.createElement\s*\(\s*['\"](?:div|template|table|svg|a|span)['\"]\s*\)"),
    re.compile(r"\.innerHTML\s*=\s*['\"]<(?:svg|table|div|link|input|form|xyz|a|tbody|tr)[^'\"]*['\"]"),
    re.compile(r"\b(?:checkClone|leadingWhitespace|support\.[a-zA-Z0-9_$]+)\b"),
]

_SANITIZER_PATTERNS = [
    ("DOMPurify", re.compile(r"\bDOMPurify\s*\.\s*sanitize\b")),
    ("sanitizeHtml", re.compile(r"\bsanitizeHtml\s*\(|\bsanitize\s*\(")),
    ("validator.escape", re.compile(r"\bvalidator\s*\.\s*escape\b")),
    ("escapeHtml", re.compile(r"\bescape(?:Html|HTML)\b")),
    ("encodeURIComponent", re.compile(r"\bencodeURIComponent\s*\(")),
    ("encodeURI", re.compile(r"\bencodeURI\s*\(")),
    ("TrustedTypes", re.compile(r"\bTrustedTypes\b|\bcreatePolicy\s*\(")),
    ("filterXSS", re.compile(r"\bfilterXSS\s*\(|\bxss\s*\(")),
]

_THIRD_PARTY_ANALYTICS_DOMAINS = (
    "googletagmanager.com",
    "google-analytics.com",
    "analytics.google.com",
    "cdn.segment.com",
    "widget.intercom.io",
    "js.intercomcdn.com",
    "connect.facebook.net",
    "static.hotjar.com",
    "script.hotjar.com",
    "static.cloudflareinsights.com",
    "browser.sentry-cdn.com",
    "cdn.amplitude.com",
    "api.mixpanel.com",
    "cdn.mxpnl.com",
    "bat.bing.com",
    "clarity.ms",
    "ads.linkedin.com",
    "snap.licdn.com",
    "analytics.tiktok.com",
    "ct.pinterest.com",
    "static.criteo.net",
    "datadoghq-browser-agent.com",
    "js-agent.newrelic.com",
    "rum.browser-intake-datadoghq.com",
)

_THIRD_PARTY_CONTENT_SIGNATURES = [
    re.compile(r"window\.dataLayer\s*=\s*window\.dataLayer\s*\|\|\s*\[\]"),
    re.compile(r"gtag\s*\(\s*['\"]config['\"]"),
    re.compile(r"fbq\s*\(\s*['\"]init['\"]"),
    re.compile(r"analytics\.load\s*\("),
    re.compile(r"window\.Intercom\s*\("),
    re.compile(r"hj\s*=\s*window\.hj\s*\|\|\s*function"),
]


def is_framework_internal_sink(code: str, snippet: str = "", offset: int = -1) -> bool:
    """
    Check if a DOM sink assignment is part of an internal framework runtime wrapper
    (Vue 3, Alpine.js, React, jQuery, Angular, Svelte) rather than an application-level vulnerability.
    """
    target = snippet or code
    if offset >= 0 and code:
        start = max(0, offset - 400)
        end = min(len(code), offset + 400)
        target = code[start:end]

    for pat in _FRAMEWORK_INTERNAL_PATTERNS:
        if pat.search(target):
            return True
    return False


def is_static_or_feature_detection(expr_or_snippet: str) -> bool:
    """
    Check if an assigned expression is a compile-time string literal, empty string,
    or browser polyfill feature detection check (zero external input).
    """
    expr = expr_or_snippet.strip()
    if not expr:
        return True

    # If snippet has an assignment, extract the right-hand side
    if "=" in expr and not expr.startswith("="):
        parts = expr.split("=", 1)
        # Check if LHS was innerHTML or outerHTML
        if re.search(r"\b(?:innerHTML|outerHTML)\s*$", parts[0]):
            expr = parts[1].strip().rstrip(";").strip()

    for pat in _STATIC_FEATURE_TEST_PATTERNS:
        if pat.search(expr):
            return True

    return False


def is_sanitizer_barrier(expr_or_code: str) -> Tuple[bool, str]:
    """
    Detect whether an expression passes through a recognized sanitizer or encoding barrier.
    """
    for name, pat in _SANITIZER_PATTERNS:
        if pat.search(expr_or_code):
            return True, name
    return False, ""


def is_third_party_analytics(url: str, content: str = "") -> bool:
    """
    Check whether a script is a known third-party tracking, analytics, or tag-manager script.
    """
    if url:
        lowered = url.lower()
        if any(domain in lowered for domain in _THIRD_PARTY_ANALYTICS_DOMAINS):
            return True

    if content:
        for pat in _THIRD_PARTY_CONTENT_SIGNATURES:
            if pat.search(content):
                return True

    return False

