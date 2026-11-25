"""Creative post-scan probes.

The main scanner walks parameters and payloads.  These probes cover primitives
that are easy to miss but frequently chain into XSS:

* open redirects (``next``/``url``/``return`` parameters)
* host-header injection and cache poisoning
* CRLF / response splitting
* permissive CORS
* JSONP callbacks
* GraphQL introspection
* static DOM source-to-sink flows
* postMessage handlers without origin checks
* exposed source maps and secrets in JavaScript

Every probe is read-only, bounded, and records evidence.  A probe result is a
*lead* unless the evidence is direct (for example a 302 ``Location`` header
containing the marker).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from xoxss.core.finding import Finding

_LOGGER = logging.getLogger(__name__)

MARKER = "xoxss.invalid"
MARKER_URL = f"https://{MARKER}/"
OPEN_REDIRECT_VALUES = (
    f"//{MARKER}/",
    MARKER_URL,
    f"/\\{MARKER}",
    f"////{MARKER}",
)
REDIRECT_PARAMS = (
    "next",
    "url",
    "redirect",
    "redirect_uri",
    "return",
    "return_to",
    "continue",
    "dest",
    "destination",
    "target",
    "r",
    "u",
    "goto",
)
CALLBACK_PARAMS = ("callback", "jsonp", "cb", "jsoncallback")
HOST_HEADERS = (
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Original-Host",
    "X-Rewrite-URL",
    "X-Original-URL",
    "Forwarded",
)

_SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_SCRIPT_SRC_RE = re.compile(
    r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE
)
_META_REFRESH_RE = re.compile(
    r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh[\"']?[^>]+content\s*=\s*[\"']([^\"']+)",
    re.IGNORECASE,
)

_SOURCE_PATTERNS = (
    r"location\s*\.\s*(?:hash|search|href)",
    r"document\s*\.\s*(?:URL|documentURI|referrer)",
    r"window\s*\.\s*name",
    r"postMessage",
    r"(?:local|session)Storage",
    r"document\s*\.\s*cookie",
)
_SINK_PATTERNS = (
    r"innerHTML",
    r"outerHTML",
    r"insertAdjacentHTML",
    r"document\s*\.\s*write",
    r"\beval\s*\(",
    r"\bFunction\s*\(",
    r"\bsetTimeout\s*\(",
    r"\bsetAttribute\s*\(",
    r"srcdoc",
    r"location\s*=",
)
_SOURCE_RE = re.compile("|".join(_SOURCE_PATTERNS), re.IGNORECASE)
_SINK_RE = re.compile("|".join(_SINK_PATTERNS), re.IGNORECASE)
_MESSAGE_RE = re.compile(
    r"addEventListener\s*\(\s*[\"']message[\"']", re.IGNORECASE
)
_ORIGIN_RE = re.compile(r"(?:event|e|msg|message)\s*\.\s*origin", re.IGNORECASE)

_SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern[str], str], ...] = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high"),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "high"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium"),
    (
        "Generic API key",
        re.compile(r"\b(?:api[_-]?key|apikey|access[_-]?token)\b\s*[:=]\s*[\"'][^\"']{16,}[\"']", re.IGNORECASE),
        "medium",
    ),
)


class BudgetExceeded(RuntimeError):
    """Raised internally when the probe request budget is exhausted."""


@dataclass
class ProbeResult:
    """A single probe outcome."""

    kind: str
    url: str
    parameter: str = ""
    method: str = "GET"
    payload: str = ""
    evidence: str = ""
    detail: str = ""
    confidence: str = "low"
    context: str = ""
    tags: List[str] = field(default_factory=list)
    request: Dict[str, Any] = field(default_factory=dict)
    response_status: int = 0
    response_excerpt: str = ""

    def to_finding(self) -> Finding:
        return Finding(
            kind=self.kind,
            url=self.url,
            parameter=self.parameter,
            method=self.method,
            payload=self.payload,
            evidence=self.evidence,
            confidence=self.confidence,
            confidence_rationale=self.detail,
            context=self.context,
            detail=self.detail,
            tags=list(self.tags),
            source="auto",
            subkey=self.kind,
            request=dict(self.request),
            response_status=self.response_status,
            response_excerpt=self.response_excerpt,
        )


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    result: List[Tuple[str, str]] = []
    for key, current in pairs:
        if key == name:
            result.append((key, value))
            replaced = True
        else:
            result.append((key, current))
    if not replaced:
        result.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(result), parts.fragment))


def _location(response: Any) -> str:
    return str(response.header("location", "") or "")


def _has_marker(value: str) -> bool:
    return MARKER in (value or "").lower()


def _excerpt(text: str, needle: str, radius: int = 160) -> str:
    index = (text or "").lower().find(needle.lower())
    if index == -1:
        return (text or "")[: radius * 2]
    start = max(0, index - radius)
    end = min(len(text), index + len(needle) + radius)
    return text[start:end]


def _scripts(html: str, base_url: str) -> Tuple[List[str], List[str]]:
    inline = [match.group(1) for match in _SCRIPT_RE.finditer(html or "")]
    external = [
        urljoin(base_url, match.group(1))
        for match in _SCRIPT_SRC_RE.finditer(html or "")
    ]
    return inline, external


def analyze_dom_flows(html: str, base_url: str = "") -> List[ProbeResult]:
    """Return static source-to-sink leads from inline JavaScript."""
    inline, _external = _scripts(html, base_url)
    results: List[ProbeResult] = []
    for index, script in enumerate(inline):
        sources = {match.group(0) for match in _SOURCE_RE.finditer(script)}
        sinks = {match.group(0) for match in _SINK_RE.finditer(script)}
        if not sources or not sinks:
            continue
        results.append(
            ProbeResult(
                kind="DOM XSS (static source-to-sink)",
                url=base_url,
                evidence=(
                    f"inline script #{index + 1}: sources={sorted(sources)[:4]} "
                    f"sinks={sorted(sinks)[:4]}"
                ),
                detail=(
                    "A DOM source and a dangerous sink appear in the same inline "
                    "script. Static evidence only; confirm with a browser and a "
                    "crafted fragment/query."
                ),
                confidence="low",
                context="dom",
                tags=["dom", "static", "source-to-sink"],
                response_excerpt=_excerpt(script, sorted(sinks)[0]),
            )
        )
    return results


def analyze_postmessage(html: str, base_url: str = "") -> List[ProbeResult]:
    """Return postMessage handlers that reach a sink without an origin check."""
    inline, _external = _scripts(html, base_url)
    results: List[ProbeResult] = []
    for index, script in enumerate(inline):
        for match in _MESSAGE_RE.finditer(script):
            window = script[match.start(): match.start() + 1200]
            if not _SINK_RE.search(window):
                continue
            origin_checked = bool(_ORIGIN_RE.search(window))
            sink = _SINK_RE.search(window)
            results.append(
                ProbeResult(
                    kind=(
                        "postMessage to DOM sink (origin unchecked)"
                        if not origin_checked
                        else "postMessage to DOM sink (origin checked)"
                    ),
                    url=base_url,
                    evidence=(
                        f"inline script #{index + 1}: "
                        f"{sink.group(0) if sink else 'sink'} within 1200 chars of "
                        f"a message listener; origin check={'yes' if origin_checked else 'no'}"
                    ),
                    detail=(
                        "A message event handler reaches a dangerous DOM sink. "
                        + (
                            "No event.origin validation was found nearby; an "
                            "attacker page may be able to drive the sink."
                            if not origin_checked
                            else "An origin check was found nearby; verify it is strict."
                        )
                    ),
                    confidence="medium" if not origin_checked else "low",
                    context="dom",
                    tags=["postmessage", "dom"],
                    response_excerpt=_excerpt(window, sink.group(0) if sink else "message"),
                )
            )
    return results


def find_secrets(text: str, url: str = "") -> List[ProbeResult]:
    """Return high-signal secret matches from JavaScript text."""
    results: List[ProbeResult] = []
    for name, pattern, confidence in _SECRET_PATTERNS:
        for match in pattern.finditer(text or ""):
            value = match.group(0)
            results.append(
                ProbeResult(
                    kind=f"Secret in JavaScript ({name})",
                    url=url,
                    evidence=f"{name} matched at offset {match.start()}",
                    detail=(
                        "A credential-shaped value is shipped to the browser. "
                        "Rotate it if it is live; it is not an XSS finding by itself."
                    ),
                    confidence=confidence,
                    tags=["secret", "javascript"],
                    response_excerpt=_excerpt(text, value[:32]),
                )
            )
            if len(results) >= 20:
                return results
    return results


class AutoProbeRunner:
    """Run bounded creative probes against a surface inventory."""

    def __init__(
        self,
        http: Any,
        console: Any,
        surface: Any,
        *,
        budget: int = 400,
        max_urls: int = 120,
        concurrency: int = 6,
        marker: str = MARKER,
    ) -> None:
        self.http = http
        self.console = console
        self.surface = surface
        self.budget = max(20, int(budget))
        self.max_urls = max(1, int(max_urls))
        self.concurrency = max(1, int(concurrency))
        self.marker = marker
        self.requests = 0
        self._seen: Set[Tuple[str, str, str, str]] = set()
        self._semaphore = asyncio.Semaphore(self.concurrency)

    async def _get(
        self, url: str, *, headers: Optional[Dict[str, str]] = None, allow_redirects: bool = False
    ) -> Optional[Any]:
        if self.requests >= self.budget:
            return None
        self.requests += 1
        try:
            return await self.http.get(
                url, headers=headers, allow_redirects=allow_redirects, cache=False
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _LOGGER.debug("auto probe GET failed for %s: %s", url, exc)
            return None

    async def _post(
        self, url: str, *, json_body: Dict[str, Any]
    ) -> Optional[Any]:
        if self.requests >= self.budget:
            return None
        self.requests += 1
        try:
            return await self.http.post(url, json_body=json_body)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _LOGGER.debug("auto probe POST failed for %s: %s", url, exc)
            return None

    def _add(self, results: List[ProbeResult], result: ProbeResult) -> None:
        key = (result.kind, result.url, result.parameter, result.payload)
        if key in self._seen:
            return
        self._seen.add(key)
        results.append(result)

    async def run(self) -> List[ProbeResult]:
        urls = self.surface.ranked_urls(self.max_urls)
        results: List[ProbeResult] = []
        tasks = [self._probe_url(url, results) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)
        self.console.info(
            f"auto probes: {len(results)} lead(s) from {len(urls)} URL(s), "
            f"{self.requests} request(s)",
            important=False,
        )
        return results

    async def _probe_url(self, url: str, results: List[ProbeResult]) -> None:
        async with self._semaphore:
            if self.requests >= self.budget:
                return
            response = await self._get(url, allow_redirects=True)
            if response is None or getattr(response, "error", None):
                return
            html = str(getattr(response, "text", "") or "")
            status = int(getattr(response, "status", 0) or 0)

            for result in analyze_dom_flows(html, url):
                self._add(results, result)
            for result in analyze_postmessage(html, url):
                self._add(results, result)

            params = self.surface.params_for(url)
            await self._probe_open_redirect(url, params, results)
            await self._probe_host_header(url, results)
            await self._probe_cache(url, results)
            await self._probe_crlf(url, params, results)
            await self._probe_cors(url, results)
            await self._probe_jsonp(url, params, results)
            await self._probe_graphql(url, results)

            if status and 200 <= status < 400:
                await self._probe_scripts(url, html, results)

    async def _probe_open_redirect(
        self, url: str, params: Sequence[str], results: List[ProbeResult]
    ) -> None:
        candidates = [name for name in params if name.lower() in REDIRECT_PARAMS]
        for name in candidates[:6]:
            for value in OPEN_REDIRECT_VALUES[:2]:
                target = _with_param(url, name, value)
                response = await self._get(target)
                if response is None or getattr(response, "error", None):
                    continue
                location = _location(response)
                if _has_marker(location):
                    self._add(
                        results,
                        ProbeResult(
                            kind="Open redirect",
                            url=target,
                            parameter=name,
                            payload=value,
                            evidence=f"HTTP {getattr(response, 'status', 0)} Location: {location}",
                            detail=(
                                "The parameter controls a redirect target. This can "
                                "be chained with XSS (javascript:/data: redirects), "
                                "OAuth token theft, or phishing."
                            ),
                            confidence="high",
                            context="url",
                            tags=["open-redirect", "chain"],
                            response_status=int(getattr(response, "status", 0) or 0),
                        ),
                    )
                    return
                body = str(getattr(response, "text", "") or "")
                refresh = _META_REFRESH_RE.search(body)
                # The refresh must be driven by the marker, not merely present
                # on the page (a stored payload can add one).
                if refresh and _has_marker(refresh.group(1)):
                    self._add(
                        results,
                        ProbeResult(
                            kind="Open redirect (meta refresh)",
                            url=target,
                            parameter=name,
                            payload=value,
                            evidence="response body contains a meta refresh with the marker",
                            detail="Client-side redirect controlled by the parameter.",
                            confidence="medium",
                            context="html",
                            tags=["open-redirect", "chain"],
                            response_status=int(getattr(response, "status", 0) or 0),
                        ),
                    )
                    return

    async def _probe_host_header(self, url: str, results: List[ProbeResult]) -> None:
        for header in HOST_HEADERS:
            value = f"{self.marker}" if header != "Forwarded" else f"host={self.marker}"
            response = await self._get(url, headers={header: value}, allow_redirects=False)
            if response is None or getattr(response, "error", None):
                continue
            text = str(getattr(response, "text", "") or "")
            location = _location(response)
            reflected_body = _has_marker(text)
            reflected_location = _has_marker(location)
            if not (reflected_body or reflected_location):
                continue
            self._add(
                results,
                ProbeResult(
                    kind="Host header injection",
                    url=url,
                    parameter=header,
                    payload=value,
                    evidence=(
                        f"{header}: {value} reflected in "
                        + ("Location header" if reflected_location else "response body")
                    ),
                    detail=(
                        "The application trusts a client-supplied host header. "
                        "This can poison password-reset links, caches, and "
                        "absolute URLs rendered into HTML."
                    ),
                    confidence="high" if reflected_location else "medium",
                    context="header",
                    tags=["host-header", "cache", "chain"],
                    response_status=int(getattr(response, "status", 0) or 0),
                    response_excerpt=_excerpt(text, self.marker),
                ),
            )
            return

    async def _probe_cache(self, url: str, results: List[ProbeResult]) -> None:
        headers = {
            "X-Forwarded-Host": self.marker,
            "X-Forwarded-Scheme": "http",
            "X-Forwarded-Proto": "http",
        }
        response = await self._get(url, headers=headers, allow_redirects=False)
        if response is None or getattr(response, "error", None):
            return
        text = str(getattr(response, "text", "") or "")
        cache_headers = {
            name: str(response.header(name, "") or "")
            for name in ("age", "x-cache", "cf-cache-status", "via", "x-served-by")
        }
        cache_hit = any(
            value and value.lower() not in ("bypass", "miss", "dynamic")
            for value in cache_headers.values()
        )
        if not (_has_marker(text) or _has_marker(_location(response))):
            return
        self._add(
            results,
            ProbeResult(
                kind="Cache poisoning (host header reflected)",
                url=url,
                parameter="X-Forwarded-Host",
                payload=self.marker,
                evidence=(
                    "marker reflected; cache headers="
                    + json.dumps({k: v for k, v in cache_headers.items() if v})
                ),
                detail=(
                    "A forwarded-host header reaches the response. If the response "
                    "is cacheable, an attacker can persist the poisoned markup for "
                    "other users (web cache poisoning -> stored XSS)."
                ),
                confidence="medium" if cache_hit else "low",
                context="header",
                tags=["cache-poisoning", "host-header", "chain"],
                response_status=int(getattr(response, "status", 0) or 0),
                response_excerpt=_excerpt(text, self.marker),
            ),
        )

    async def _probe_crlf(
        self, url: str, params: Sequence[str], results: List[ProbeResult]
    ) -> None:
        payload = f"%0d%0aX-Xoxss-Probe%3a%20{self.marker}"
        for name in params[:8]:
            target = _with_param(url, name, payload)
            response = await self._get(target)
            if response is None or getattr(response, "error", None):
                continue
            injected = str(response.header("x-xoxss-probe", "") or "")
            if injected:
                self._add(
                    results,
                    ProbeResult(
                        kind="CRLF injection / response splitting",
                        url=target,
                        parameter=name,
                        payload=payload,
                        evidence=f"injected response header X-Xoxss-Probe: {injected}",
                        detail=(
                            "The parameter is written into the response headers "
                            "without CRLF sanitisation. This enables response "
                            "splitting, header injection, and reflected XSS."
                        ),
                        confidence="high",
                        context="header",
                        tags=["crlf", "response-splitting", "header-injection"],
                        response_status=int(getattr(response, "status", 0) or 0),
                    ),
                )
                return

    async def _probe_cors(self, url: str, results: List[ProbeResult]) -> None:
        origin = f"https://{self.marker}"
        response = await self._get(url, headers={"Origin": origin}, allow_redirects=True)
        if response is None or getattr(response, "error", None):
            return
        allow_origin = str(response.header("access-control-allow-origin", "") or "")
        credentials = str(response.header("access-control-allow-credentials", "") or "").lower()
        if allow_origin not in (origin, "*"):
            return
        self._add(
            results,
            ProbeResult(
                kind="CORS misconfiguration",
                url=url,
                parameter="Origin",
                payload=origin,
                evidence=(
                    f"Access-Control-Allow-Origin: {allow_origin}; "
                    f"credentials: {credentials or 'no'}"
                ),
                detail=(
                    "A cross-origin response is readable from an attacker origin. "
                    "Combined with an XSS or authenticated JSON endpoint, this "
                    "exposes user data to script."
                ),
                confidence="high" if allow_origin == origin and credentials == "true" else "medium",
                context="header",
                tags=["cors", "chain"],
                response_status=int(getattr(response, "status", 0) or 0),
            ),
        )

    async def _probe_jsonp(
        self, url: str, params: Sequence[str], results: List[ProbeResult]
    ) -> None:
        candidates = [name for name in params if name.lower() in CALLBACK_PARAMS]
        if not candidates:
            candidates = list(CALLBACK_PARAMS[:2])
        for name in candidates[:3]:
            callback = "xoxss123"
            target = _with_param(url, name, callback)
            response = await self._get(target)
            if response is None or getattr(response, "error", None):
                continue
            content_type = str(response.header("content-type", "") or "").lower()
            text = str(getattr(response, "text", "") or "")
            if "javascript" not in content_type and "ecmascript" not in content_type:
                continue
            if not re.search(rf"\b{re.escape(callback)}\s*\(", text):
                continue
            self._add(
                results,
                ProbeResult(
                    kind="JSONP callback",
                    url=target,
                    parameter=name,
                    payload=callback,
                    evidence=f"Content-Type: {content_type}; body calls {callback}(...)",
                    detail=(
                        "The endpoint wraps JSON in a caller-controlled callback. "
                        "An attacker page can include it as a script and read the "
                        "data, or use a javascript: callback where the browser allows it."
                    ),
                    confidence="medium",
                    context="javascript",
                    tags=["jsonp", "script-inclusion"],
                    response_status=int(getattr(response, "status", 0) or 0),
                    response_excerpt=text[:300],
                ),
            )
            return

    async def _probe_graphql(self, url: str, results: List[ProbeResult]) -> None:
        parts = urlsplit(url)
        candidates = [
            url,
            urlunsplit((parts.scheme, parts.netloc, "/graphql", "", "")),
            urlunsplit((parts.scheme, parts.netloc, "/api/graphql", "", "")),
        ]
        query = {"query": "{__schema{types{name kind}}}"}
        for candidate in dict.fromkeys(candidates):
            response = await self._post(candidate, json_body=query)
            if response is None or getattr(response, "error", None):
                continue
            text = str(getattr(response, "text", "") or "")
            try:
                data = json.loads(text)
            except (TypeError, ValueError):
                continue
            if isinstance(data, dict) and "__schema" in (data.get("data") or {}):
                self._add(
                    results,
                    ProbeResult(
                        kind="GraphQL introspection enabled",
                        url=candidate,
                        method="POST",
                        payload=query["query"],
                        evidence="introspection returned __schema",
                        detail=(
                            "The GraphQL schema is exposed. Enumerate mutations and "
                            "arguments, then test string arguments for stored or "
                            "reflected XSS."
                        ),
                        confidence="low",
                        context="graphql",
                        tags=["graphql", "introspection"],
                        response_status=int(getattr(response, "status", 0) or 0),
                        response_excerpt=text[:300],
                    ),
                )
                return

    async def _probe_scripts(
        self, page_url: str, html: str, results: List[ProbeResult]
    ) -> None:
        _inline, external = _scripts(html, page_url)
        for script_url in external[:6]:
            response = await self._get(script_url, allow_redirects=True)
            if response is None or getattr(response, "error", None):
                continue
            text = str(getattr(response, "text", "") or "")
            if not text:
                continue
            for result in find_secrets(text, script_url):
                self._add(results, result)
            await self._probe_source_map(script_url, results)

    async def _probe_source_map(
        self, script_url: str, results: List[ProbeResult]
    ) -> None:
        map_url = script_url.split("?", 1)[0] + ".map"
        response = await self._get(map_url, allow_redirects=True)
        if response is None or getattr(response, "error", None):
            return
        text = str(getattr(response, "text", "") or "")
        if '"sourcesContent"' not in text and '"sources"' not in text:
            return
        self._add(
            results,
            ProbeResult(
                kind="Source map exposed",
                url=map_url,
                evidence="source map JSON is publicly readable",
                detail=(
                    "Original source is exposed. Review it for hidden endpoints, "
                    "client-side sinks and credentials."
                ),
                confidence="low",
                tags=["source-map", "disclosure"],
                response_status=int(getattr(response, "status", 0) or 0),
                response_excerpt=text[:300],
            ),
        )


__all__ = [
    "AutoProbeRunner",
    "BudgetExceeded",
    "ProbeResult",
    "analyze_dom_flows",
    "analyze_postmessage",
    "find_secrets",
]
