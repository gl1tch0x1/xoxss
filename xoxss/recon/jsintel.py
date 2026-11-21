"""
JavaScript intelligence: endpoints, parameters, secrets, source maps and DOM
taint flows.

Modern web apps hide most of their attack surface in bundles.  This module
turns a JavaScript blob into structured intel the crawler and injector can use:
new endpoints, hidden parameter names, API hosts, WebSocket/GraphQL channels,
leaked credentials and source -> sink flows.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

from xoxss.analysis.ast_taint import TaintFlow, analyze_javascript


_SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", "high"),
    ("aws_secret_key", r"(?i)aws_?secret(?:_access)?_?key['\"\s:=]{1,12}([A-Za-z0-9/+=]{40})", "critical"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", "high"),
    ("stripe_secret", r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b", "critical"),
    ("stripe_publishable", r"\bpk_(?:live|test)_[0-9A-Za-z]{16,}\b", "medium"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "critical"),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "critical"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "high"),
    ("sendgrid_key", r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b", "critical"),
    ("twilio_key", r"\bSK[0-9a-fA-F]{32}\b", "high"),
    ("mailgun_key", r"\bkey-[0-9a-zA-Z]{32}\b", "high"),
    ("firebase_url", r"https://[a-z0-9-]+\.firebaseio\.com", "medium"),
    ("firebase_key", r"(?i)firebase[^0-9A-Za-z]{0,8}(AIza[0-9A-Za-z_-]{35})", "high"),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "medium"),
    ("heroku_key", r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "low"),
    ("basic_auth_url", r"\bhttps?://[^/\s:'\"]+:[^/\s'\"]+@[^\s'\"]+", "high"),
    ("bearer_token", r"(?i)bearer\s+([A-Za-z0-9._~+/=-]{18,})", "high"),
    ("generic_secret", r"(?i)(?:api[_-]?key|secret|passwd|password|auth[_-]?token|access[_-]?token)['\"]?\s*[:=]\s*['\"]([^'\"]{12,})['\"]", "medium"),
    # --- cloud / SaaS credentials -------------------------------------------
    ("gcp_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", "high"),
    ("gcp_oauth", r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "medium"),
    ("azure_storage", r"\bDefaultEndpointsProtocol=https?://[a-z0-9]+\.blob\.core\.windows\.net", "high"),
    ("azure_sas", r"(?i)(?:sig|se|sp|sv|sr)=[A-Za-z0-9%_-]{8,}", "medium"),
    ("digitalocean_token", r"\bdop_v1_[a-f0-9]{64}\b", "critical"),
    ("digitalocean_pat", r"\bdop_v1_[a-f0-9]{64}\b", "critical"),
    ("heroku_api", r"(?i)heroku[_-]?(?:api[_-]?)?key['\"\s:=]{1,12}([0-9a-f-]{36})", "high"),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b", "critical"),
    ("pypi_token", r"\bpypi-[A-Za-z0-9_-]{16,}\b", "critical"),
    ("rubygems_token", r"\brg_[A-Za-z0-9]{16,}\b", "high"),
    ("discord_token", r"\b[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b", "critical"),
    ("discord_webhook", r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "high"),
    ("telegram_bot", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", "critical"),
    ("slack_app_token", r"\bxapp-[0-9A-Za-z-]{10,}\b", "critical"),
    ("slack_config_token", r"\bxoxe\.[0-9A-Za-z-]{10,}\b", "critical"),
    ("openai_key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b", "critical"),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", "critical"),
    ("huggingface_token", r"\bhf_[A-Za-z0-9]{30,}\b", "high"),
    ("replicate_token", r"\br8_[A-Za-z0-9]{20,}\b", "high"),
    ("groq_key", r"\bgsk_[A-Za-z0-9]{20,}\b", "high"),
    ("cohere_key", r"\b[A-Za-z0-9]{40}\b(?=[^\n]{0,40}cohere)", "medium"),
    ("shopify_token", r"\bshpat_[a-f0-9]{32}\b", "critical"),
    ("shopify_access", r"\bshpca_[a-f0-9]{32}\b", "critical"),
    ("shopify_shared", r"\bshpss_[a-f0-9]{32}\b", "critical"),
    ("square_token", r"\bsq0atp-[A-Za-z0-9_-]{22}\b|\bsq0csp-[A-Za-z0-9_-]{43}\b", "critical"),
    ("paypal_token", r"\bA21AA[A-Za-z0-9_-]{60,}\b", "high"),
    ("razorpay_key", r"\brzp_(?:live|test)_[A-Za-z0-9]{14}\b", "high"),
    ("braintree_key", r"(?i)braintree[_-]?(?:public|private)[_-]?key['\"\s:=]{1,12}([A-Za-z0-9]{16})", "medium"),
    ("paypal_secret", r"(?i)paypal[_-]?(?:secret|client[_-]?secret)['\"\s:=]{1,12}([A-Za-z0-9_-]{20,})", "critical"),
    ("twilio_sid", r"\bAC[a-f0-9]{32}\b", "high"),
    ("mailchimp_key", r"\b[a-f0-9]{32}-us\d+\b", "high"),
    ("postmark_key", r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b", "medium"),
    ("mandrill_key", r"\b[A-Za-z0-9]{26}-[A-Za-z0-9_-]{24}\b", "high"),
    ("sendinblue_key", r"\bxkeysib-[A-Za-z0-9_-]{40,}\b", "high"),
    ("mailjet_key", r"(?i)mailjet[_-]?(?:api[_-]?)?key['\"\s:=]{1,12}([a-f0-9]{32})", "high"),
    ("aws_session", r"\bASIA[0-9A-Z]{16}\b", "high"),
    ("aws_mws", r"\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "critical"),
    ("gcp_service_account", r'"type"\s*:\s*"service_account"', "critical"),
    ("gcp_private_key", r'"private_key"\s*:\s*"-----BEGIN', "critical"),
    ("supabase_url", r"https://[a-z0-9]+\.supabase\.co", "medium"),
    ("supabase_key", r"\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b", "critical"),
    ("vercel_token", r"\b[A-Za-z0-9]{24}\.[A-Za-z0-9]{24}\b", "medium"),
    ("netlify_token", r"\bnfp_[A-Za-z0-9]{20,}\b", "critical"),
    ("cloudflare_api", r"(?i)cloudflare[_-]?(?:api[_-]?)?token['\"\s:=]{1,12}([A-Za-z0-9_-]{37})", "critical"),
    ("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{22,}\b", "critical"),
    ("github_oauth", r"\bgho_[A-Za-z0-9]{36}\b", "critical"),
    ("github_app", r"\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b", "critical"),
    ("github_refresh", r"\bghr_[A-Za-z0-9]{36}\b", "critical"),
    ("gitlab_pat", r"\bglpat-[A-Za-z0-9_-]{20,}\b", "critical"),
    ("bitbucket_token", r"\bATBB[A-Za-z0-9]{20,}\b", "critical"),
    ("bitbucket_app", r"(?i)bitbucket[_-]?(?:app[_-]?)?password['\"\s:=]{1,12}([A-Za-z0-9]{16,})", "high"),
    ("dockerhub_token", r"\bdckr_pat_[A-Za-z0-9_-]{27}\b", "critical"),
    ("jfrog_token", r"(?i)jfrog[_-]?(?:access[_-]?)?token['\"\s:=]{1,12}([A-Za-z0-9]{20,})", "high"),
    ("sonarqube_token", r"\bsqu_[A-Za-z0-9_-]{40}\b", "critical"),
    ("sentry_token", r"\bsntrys_[A-Za-z0-9_-]{20,}\b|\b[a-f0-9]{32}\b", "medium"),
    ("newrelic_key", r"\bNRAK-[A-Z0-9]{27}\b|\bNRBR-[A-Z0-9]{19}\b|\bNRAL-[A-Z0-9]{32}\b", "high"),
    ("pagerduty_token", r"\bu\+[^\s]{20,}\b", "high"),
    ("opsgenie_key", r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b", "medium"),
    ("splunk_token", r"(?i)splunk[_-]?(?:hec[_-]?)?token['\"\s:=]{1,12}([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", "high"),
    ("vault_token", r"\bhvs\.[A-Za-z0-9_-]{20,}\b|\bs\.[A-Za-z0-9]{20,}\b", "critical"),
    ("consul_token", r"(?i)consul[_-]?(?:acl[_-]?)?token['\"\s:=]{1,12}([a-f0-9]{36})", "high"),
    ("terraform_token", r"(?i)terraform[_-]?(?:cloud[_-]?)?token['\"\s:=]{1,12}([A-Za-z0-9]{20,})", "high"),
    ("kubernetes_token", r"\beyJhbGciOiJSUzI1NiIsImtpZCI6", "critical"),
    ("docker_config", r'"auths"\s*:\s*\{[^}]*"auth"', "critical"),
    ("ssh_private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----", "critical"),
    ("pgp_private_key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "critical"),
    ("age_private_key", r"AGE-SECRET-KEY-1[0-9A-Z]{58}", "critical"),
    ("wireguard_key", r"\[Interface\][^\[]*PrivateKey", "high"),
]

_ENDPOINT_RE = re.compile(
    r"""(?:
        ["'`](?P<quoted>(?:https?://|//|/)[^"'`\s<>]{2,300})["'`]
      | \burl\s*\(\s*["']?(?P<css>(?:https?://|/)[^)"'\s]{2,300})
      | \b(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open|\.navigate)\s*\(\s*["'](?P<fetch>[^"']{2,300})["']
    )""",
    re.X | re.I,
)

_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.\[\]-]{0,60})=")
_GET_PARAM_RE = re.compile(
    r"(?:searchParams|params|query|urlParams)\s*\.\s*get\s*\(\s*['\"]([A-Za-z_$][\w$.-]{0,60})['\"]",
    re.I,
)
_GET_PARAMETER_RE = re.compile(
    r"\b(?:getParameter|getQueryParam|queryParam|param)\s*\(\s*['\"]([A-Za-z_$][\w$.-]{0,60})['\"]",
    re.I,
)
_OBJECT_PARAM_RE = re.compile(
    r"(?:params|query|data|body|filters)\s*[:=]\s*\{([^{}]{0,600})\}", re.I | re.S
)
# Global-window access: ``window.NAME = ...`` assignments and bracket reads.
_WINDOW_ASSIGN_RE = re.compile(
    r"\bwindow\s*\.\s*([A-Za-z_$][\w$]{0,60})\s*=(?!=)", re.I
)
_WINDOW_BRACKET_RE = re.compile(
    r"""\bwindow\s*\[\s*['"]([A-Za-z_$][\w$.-]{0,60})['"]\s*\]"""
)
# ``Object.keys(window)`` / ``getOwnPropertyNames(window)`` enumerate globals.
_WINDOW_ENUM_RE = re.compile(
    r"Object\s*\.\s*(?:keys|getOwnPropertyNames)\s*\(\s*window\s*\)", re.I
)
_WINDOW_GLOBAL_BLOCKLIST = {
    "alert", "atob", "blur", "btoa", "caches", "cancelAnimationFrame", "close",
    "closed", "confirm", "console", "crypto", "customElements", "decodeURI",
    "decodeURIComponent", "devicePixelRatio", "document", "encodeURI",
    "encodeURIComponent", "event", "fetch", "frames", "getComputedStyle",
    "getSelection", "history", "indexedDB", "innerHeight", "innerWidth",
    "isSecureContext", "length", "localStorage", "location", "matchMedia",
    "name", "navigator", "open", "opener", "origin", "outerHeight",
    "outerWidth", "parent", "performance", "postMessage", "print", "prompt",
    "queueMicrotask", "requestAnimationFrame", "screen", "scroll", "scrollBy",
    "scrollTo", "scrollX", "scrollY", "self", "sessionStorage", "setInterval",
    "setTimeout", "speechSynthesis", "status", "stop", "structuredClone",
    "top", "window", "XMLHttpRequest", "__xoxss_hits", "__xoxss_init",
}
_WINDOW_GLOBAL_BLOCKLIST_LOWER = {item.lower() for item in _WINDOW_GLOBAL_BLOCKLIST}
_GRAPHQL_RE = re.compile(
    r"([\"'`])(?:https?://[^\"'`\s]+|/[^\"'`\s]*)?/graphql(?:/[^\"'`\s]*)?\1|"
    r"([\"'`])https?://[^\"'`\s]+/graphql[^\"'`\s]*\2",
    re.I,
)
_WS_RE = re.compile(r"""["'`](wss?://[^"'`\s<>]{3,300})["'`]""", re.I)
_SOURCEMAP_RE = re.compile(
    r"//[#@]\s*sourceMappingURL=([^\s'\"]+)", re.I
)
_CHUNK_RE = re.compile(
    r"""(?:["'`])([A-Za-z0-9_./-]+\.(?:js|mjs|chunk\.js|bundle\.js))(?:\?[^"'`]*)?\1"""
)
_SCRIPT_SRC_RE = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>", re.I
)
_INLINE_SCRIPT_RE = re.compile(
    # Browsers accept whitespace and attributes in the closing tag
    # (`</script >`, `</script foo="bar">`), so extraction must too or inline
    # payload analysis silently misses scripts.
    r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script\b[^>]*>", re.I | re.S
)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_INPUT_NAME_RE = re.compile(
    r"<(?:input|textarea|select|button)\b[^>]*\bname\s*=\s*['\"]([^'\"]+)['\"]", re.I
)
_ATTR_URL_RE = re.compile(
    r"""(?:href|src|action|data-url|data-href|formaction)\s*=\s*["']([^"']{2,400})["']""",
    re.I,
)
_JSON_ENDPOINT_RE = re.compile(
    r"""(?:"|')((?:/|https?://)[^"'<>]{2,200}/(?:api|v\d+|graphql|rest|rpc)[^"'<>]*)["']""",
    re.I,
)
# Additional client-side request surfaces not covered by _ENDPOINT_RE.
_EVENTSOURCE_RE = re.compile(
    r"""\bnew\s+EventSource\s*\(\s*["'`]([^"'`]{2,300})["'`]""", re.I
)
_SEND_BEACON_RE = re.compile(
    r"""\b(?:navigator\.)?sendBeacon\s*\(\s*["'`]([^"'`]{2,300})["'`]""", re.I
)
_DYNAMIC_IMPORT_RE = re.compile(
    r"""\bimport\s*\(\s*["'`]([^"'`]{2,300})["'`]\s*\)"""
)
_LOCATION_METHOD_RE = re.compile(
    r"""\b(?:window\.)?location\.(?:assign|replace)\s*\(\s*["'`]([^"'`]{2,300})["'`]""",
    re.I,
)
_SCRIPT_CREATE_RE = re.compile(
    r"""\.(?:src|href)\s*=\s*["'`]([^"'`]{2,300})["'`][^;]{0,120}(?:appendChild|insertBefore)""",
    re.I | re.S,
)
_WORKER_RE = re.compile(
    r"""\bnew\s+(?:Worker|SharedWorker)\s*\(\s*["'`]([^"'`]{2,300})["'`]""", re.I
)
_SERVICE_WORKER_RE = re.compile(
    r"""\.register\s*\(\s*["'`]([^"'`]{2,300})["'`]"""
)
_MANIFEST_RE = re.compile(
    r"""<link[^>]+rel=["']manifest["'][^>]+href=["']([^"']+)["']""", re.I
)
_PREFETCH_RE = re.compile(
    r"""<link[^>]+rel=["'](?:prefetch|preload|modulepreload|dns-prefetch|preconnect)["'][^>]+href=["']([^"']+)["']""",
    re.I,
)
_JSONP_SCRIPT_RE = re.compile(
    r"""<script[^>]+src=["']([^"']*(?:callback|jsonp|cb|_cb)[^"']*)["']""", re.I
)
_IFRAME_SRC_RE = re.compile(
    r"""<iframe[^>]+src=["']([^"']{2,300})["']""", re.I
)
_OBJECT_DATA_RE = re.compile(
    r"""<object[^>]+data=["']([^"']{2,300})["']""", re.I
)
_EMBED_SRC_RE = re.compile(
    r"""<embed[^>]+src=["']([^"']{2,300})["']""", re.I
)
_FORM_ACTION_RE = re.compile(
    r"""<form[^>]+action=["']([^"']{2,300})["']""", re.I
)
_BUTTON_FORM_ACTION_RE = re.compile(
    r"""<(?:button|input)[^>]+formaction=["']([^"']{2,300})["']""", re.I
)
_META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv=["']refresh["'][^>]+content=["'][^"']*url=([^"']+)["']""",
    re.I,
)
_BASE_HREF_RE = re.compile(
    r"""<base[^>]+href=["']([^"']{2,300})["']""", re.I
)

_STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".wav",
    ".ogg", ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".css", ".map",
}

_SECRET_VALUE_MASK_THRESHOLD = 8


@dataclass
class SecretHit:
    kind: str
    value: str
    severity: str
    line: int
    source: str = ""
    context: str = ""

    def masked(self) -> str:
        value = self.value
        if len(value) <= _SECRET_VALUE_MASK_THRESHOLD:
            return "*" * len(value)
        return f"{value[:4]}…{value[-4:]}"

    def to_dict(self, *, reveal: bool = False) -> Dict[str, Any]:
        """Serialise for reports.

        Secret values are masked by default: reports are copied into tickets,
        chats and client deliverables, and a leaked credential is a live
        incident.  ``reveal=True`` is only for the operator's own terminal
        export (``--show-secrets``).
        """
        return {
            "kind": self.kind,
            "value": self.value if reveal else self.masked(),
            "masked": self.masked(),
            "redacted": not reveal,
            "severity": self.severity,
            "line": self.line,
            "source": self.source,
            "context": self.context,
        }


@dataclass
class JSIntel:
    """Structured intelligence extracted from one JavaScript resource."""

    url: str = ""
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    exposures: List[SecretHit] = field(default_factory=list)
    graphql: List[str] = field(default_factory=list)
    websockets: List[str] = field(default_factory=list)
    sourcemaps: List[str] = field(default_factory=list)
    chunks: List[str] = field(default_factory=list)
    dom_flows: List[TaintFlow] = field(default_factory=list)
    inline_scripts: int = 0
    size: int = 0

    def merge(self, other: "JSIntel") -> None:
        self.endpoints = list(dict.fromkeys([*self.endpoints, *other.endpoints]))
        self.parameters = list(dict.fromkeys([*self.parameters, *other.parameters]))
        self.graphql = list(dict.fromkeys([*self.graphql, *other.graphql]))
        self.websockets = list(dict.fromkeys([*self.websockets, *other.websockets]))
        self.sourcemaps = list(dict.fromkeys([*self.sourcemaps, *other.sourcemaps]))
        self.chunks = list(dict.fromkeys([*self.chunks, *other.chunks]))
        self.dom_flows.extend(other.dom_flows)
        key = lambda hit: (hit.kind, hit.value, hit.source)  # noqa: E731
        existing = {key(hit) for hit in self.exposures}
        for hit in other.exposures:
            if key(hit) not in existing:
                self.exposures.append(hit)
        self.size += other.size

    @property
    def secrets(self) -> List[SecretHit]:
        """Backwards-compatible alias for :attr:`exposures`."""
        return self.exposures

    @secrets.setter
    def secrets(self, value: List[SecretHit]) -> None:
        self.exposures = list(value or ())

    def to_dict(self, *, reveal: bool = False) -> Dict[str, Any]:
        return {
            "url": self.url,
            "endpoints": list(self.endpoints),
            "parameters": list(self.parameters),
            "secrets": [hit.to_dict(reveal=reveal) for hit in self.exposures],
            "graphql": list(self.graphql),
            "websockets": list(self.websockets),
            "sourcemaps": list(self.sourcemaps),
            "chunks": list(self.chunks),
            "dom_flows": [flow.to_dict() for flow in self.dom_flows],
            "inline_scripts": self.inline_scripts,
            "size": self.size,
        }


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _context(text: str, offset: int, limit: int = 160) -> str:
    start = max(0, offset - limit // 3)
    end = min(len(text), offset + limit)
    return re.sub(r"\s+", " ", text[start:end]).strip()[:limit]


def extract_secrets(js: str, source: str = "") -> List[SecretHit]:
    hits: List[SecretHit] = []
    seen: Set[Tuple[str, str]] = set()
    for kind, pattern, severity in _SECRET_PATTERNS:
        try:
            matches = re.finditer(pattern, js or "", flags=0)
        except re.error:
            continue
        for match in matches:
            value = match.group(1) if match.groups() else match.group(0)
            value = (value or "").strip()
            if not value or len(value) < 6:
                continue
            if kind == "generic_secret" and _entropy(value) < 3.0:
                continue
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                SecretHit(
                    kind=kind,
                    value=value,
                    severity=severity,
                    line=_line_of(js, match.start()),
                    source=source,
                    context=_context(js, match.start()),
                )
            )
    return hits


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_like_endpoint(value: str) -> bool:
    if not value or len(value) > 400:
        return False
    if value.startswith(("data:", "mailto:", "tel:", "javascript:", "blob:")):
        return False
    path = urlsplit(value).path.lower()
    if path.endswith(tuple(_STATIC_EXTENSIONS)):
        return False
    if path in ("", "/") and not urlsplit(value).query:
        return False
    return True


def _absolute(value: str, base: str) -> str:
    value = value.strip()
    if value.startswith("//"):
        return "https:" + value
    if re.match(r"^https?://", value, re.I):
        return value
    if not base:
        return value
    try:
        parts = urlsplit(base)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        return urljoin(origin, value)
    except Exception:
        return value


# Single-capture-group patterns that each yield one URL/path candidate.
_SINGLE_GROUP_ENDPOINT_RES = (
    _EVENTSOURCE_RE,
    _SEND_BEACON_RE,
    _DYNAMIC_IMPORT_RE,
    _LOCATION_METHOD_RE,
    _SCRIPT_CREATE_RE,
    _WORKER_RE,
    _SERVICE_WORKER_RE,
    _JSONP_SCRIPT_RE,
)


def extract_endpoints(js: str, base_url: str = "") -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()

    def _add(value: str) -> None:
        value = (value or "").strip().strip("'\"`")
        if not value or not _looks_like_endpoint(value):
            return
        url = _absolute(value, base_url)
        key = url.split("#", 1)[0]
        if key in seen:
            return
        seen.add(key)
        found.append(url)

    for match in _ENDPOINT_RE.finditer(js or ""):
        _add(match.group("quoted") or match.group("css") or match.group("fetch") or "")
    for match in _JSON_ENDPOINT_RE.finditer(js or ""):
        _add(match.group(1))
    for pattern in _SINGLE_GROUP_ENDPOINT_RES:
        for match in pattern.finditer(js or ""):
            _add(match.group(1))
    return found


def extract_parameters(js: str) -> List[str]:
    names: List[str] = []
    seen: Set[str] = set()

    def add(name: str) -> None:
        name = (name or "").strip()
        if not name or len(name) > 80:
            return
        if name.lower() in {"true", "false", "null", "undefined", "function"}:
            return
        if name not in seen:
            seen.add(name)
            names.append(name)

    for pattern in (_PARAM_RE, _GET_PARAM_RE, _GET_PARAMETER_RE):
        for match in pattern.finditer(js or ""):
            add(match.group(1))
    for match in _OBJECT_PARAM_RE.finditer(js or ""):
        body = match.group(1)
        for key in re.findall(r"['\"]?([A-Za-z_$][\w$.-]{0,60})['\"]?\s*:", body):
            add(key)
    # DOM clobbering / global state: window.NAME, window['NAME'] and globals
    # enumerated with Object.keys(window).  Reserved browser properties are
    # filtered so the crawler does not fuzz document/navigator/location.
    for match in _WINDOW_ASSIGN_RE.finditer(js or ""):
        name = match.group(1)
        if name.lower() not in _WINDOW_GLOBAL_BLOCKLIST_LOWER:
            add(name)
    for match in _WINDOW_BRACKET_RE.finditer(js or ""):
        name = match.group(1)
        if name.lower() not in _WINDOW_GLOBAL_BLOCKLIST_LOWER:
            add(name)
    if _WINDOW_ENUM_RE.search(js or ""):
        # Enumeration itself exposes no names statically; record the sentinel so
        # the browser-side miner can expand it at runtime.
        add("__window_keys__")
    return names


def extract_graphql(js: str, base_url: str = "") -> List[str]:
    endpoints: List[str] = []
    for match in _GRAPHQL_RE.finditer(js or ""):
        value = match.group(0).strip("'\"`")
        url = _absolute(value, base_url)
        if url not in endpoints:
            endpoints.append(url)
    return endpoints


def extract_websockets(js: str) -> List[str]:
    return list(dict.fromkeys(_WS_RE.findall(js or "")))


def extract_sourcemaps(js: str, base_url: str = "") -> List[str]:
    urls: List[str] = []
    for match in _SOURCEMAP_RE.finditer(js or ""):
        value = match.group(1).strip()
        if value.startswith("data:"):
            continue
        url = _absolute(value, base_url)
        if url not in urls:
            urls.append(url)
    return urls


def extract_chunks(js: str, base_url: str = "") -> List[str]:
    chunks: List[str] = []
    for match in _CHUNK_RE.finditer(js or ""):
        value = match.group(1)
        url = _absolute(value, base_url)
        if url not in chunks:
            chunks.append(url)
    return chunks


def sources_from_sourcemap(data: str, base_url: str = "") -> Tuple[List[str], List[str]]:
    """Return ``(source_urls, source_contents)`` from a source map JSON blob."""
    try:
        payload = json.loads(data)
    except Exception:
        return [], []
    if not isinstance(payload, dict):
        return [], []
    sources: List[str] = []
    contents: List[str] = []
    for index, source in enumerate(payload.get("sources", []) or []):
        url = _absolute(str(source), base_url)
        if url:
            sources.append(url)
        source_content = None
        raw_contents = payload.get("sourcesContent") or []
        if isinstance(raw_contents, list) and index < len(raw_contents):
            source_content = raw_contents[index]
        if isinstance(source_content, str) and source_content:
            contents.append(source_content)
    return sources, contents


def extract_script_urls(html: str, base_url: str = "") -> List[str]:
    urls: List[str] = []
    for match in _SCRIPT_SRC_RE.finditer(html or ""):
        url = _absolute(match.group(1), base_url)
        if url and url not in urls:
            urls.append(url)
    return urls


def extract_inline_scripts(html: str) -> List[str]:
    return [match.group(1) for match in _INLINE_SCRIPT_RE.finditer(html or "") if match.group(1)]


def extract_html_parameters(html: str) -> List[str]:
    names: List[str] = []
    seen: Set[str] = set()
    for match in _INPUT_NAME_RE.finditer(html or ""):
        name = match.group(1).strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    for query in re.findall(r"""[?&]([A-Za-z_][\w.-]{0,60})=""", html or ""):
        if query not in seen:
            seen.add(query)
            names.append(query)
    return names


# HTML attribute-surface patterns feeding extract_attr_urls.
_HTML_URL_RES = (
    _MANIFEST_RE,
    _PREFETCH_RE,
    _JSONP_SCRIPT_RE,
    _IFRAME_SRC_RE,
    _OBJECT_DATA_RE,
    _EMBED_SRC_RE,
    _FORM_ACTION_RE,
    _BUTTON_FORM_ACTION_RE,
    _META_REFRESH_RE,
    _BASE_HREF_RE,
)


def extract_attr_urls(html: str, base_url: str = "") -> List[str]:
    urls: List[str] = []
    for pattern in (_ATTR_URL_RE, *_HTML_URL_RES):
        for match in pattern.finditer(html or ""):
            value = match.group(1).strip()
            if not value or value.startswith(("data:", "mailto:", "tel:", "javascript:", "#")):
                continue
            url = _absolute(value, base_url)
            if url and url not in urls:
                urls.append(url)
    return urls


def analyze_javascript_intel(
    js: str,
    base_url: str = "",
    *,
    source: str = "",
    include_dom: bool = True,
) -> JSIntel:
    intel = JSIntel(url=source or base_url, size=len(js or ""))
    intel.endpoints = extract_endpoints(js, base_url)
    intel.parameters = extract_parameters(js)
    intel.exposures = extract_secrets(js, source or base_url)
    intel.graphql = extract_graphql(js, base_url)
    intel.websockets = extract_websockets(js)
    intel.sourcemaps = extract_sourcemaps(js, base_url)
    intel.chunks = extract_chunks(js, base_url)
    if include_dom:
        intel.dom_flows = analyze_javascript(js, source or base_url)
    return intel


__all__ = [
    "JSIntel",
    "SecretHit",
    "analyze_javascript_intel",
    "extract_attr_urls",
    "extract_chunks",
    "extract_endpoints",
    "extract_graphql",
    "extract_html_parameters",
    "extract_inline_scripts",
    "extract_parameters",
    "extract_script_urls",
    "extract_secrets",
    "extract_sourcemaps",
    "extract_websockets",
    "sources_from_sourcemap",
]
