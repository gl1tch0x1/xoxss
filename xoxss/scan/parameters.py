"""
Parameter intelligence: collector-style URL harvesting and batched reflection
probing with dynamic controls and response-delta bisection.

Two upstream ideas are implemented here:

* **collector** (thenurhabib/collector) – pull historic URLs for a domain from
  the Wayback CDX API (optionally including subdomains), then extract every GET
  parameter name and the URLs that use it.
* **Batched reflection probing** – group unique markers into bounded requests,
  compare against two benign controls, and bisect only when a response changes
  without revealing which candidate caused it. Directly reflected markers are
  attributed exactly, while dynamic pages are flagged for cautious triage.

The result is a ranked list of parameter candidates with reflection evidence
that can be fed into the main scanner or triaged on its own.
"""

from __future__ import annotations

import asyncio
import copy
from difflib import SequenceMatcher
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from xoxss.detection.context import ContextDetector


class HttpLike(Protocol):  # pragma: no cover
    async def get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        cache: bool = False,
    ) -> Any: ...

    async def post(
        self,
        url: str,
        *,
        data: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Any: ...


class ConsoleLike(Protocol):  # pragma: no cover
    def info(self, message: str, important: bool = False) -> None: ...
    def warn(self, message: str, important: bool = True) -> None: ...
    def debug(self, message: str) -> None: ...
    def ok(self, message: str, important: bool = True) -> None: ...


HIGH_VALUE_PARAMETERS: Set[str] = {
    "q", "query", "search", "s", "keyword", "keywords", "term", "text",
    "url", "uri", "link", "redirect", "redirect_uri", "return", "returnurl",
    "next", "continue", "target", "dest", "destination", "callback", "cb",
    "ref", "referer", "referrer", "file", "filename", "path", "template",
    "view", "page", "id", "uid", "user", "userid", "account", "name",
    "email", "message", "msg", "comment", "content", "body", "title",
    "lang", "language", "locale", "callback", "jsonp", "format", "output",
    "html", "raw", "preview", "embed", "iframe", "widget", "share",
    "source", "src", "href", "image", "avatar", "theme", "debug", "test",
}

STATIC_EXTENSIONS: Tuple[str, ...] = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".css",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3",
    ".wav", ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
)


def parameter_risk(name: str) -> str:
    """Classify a parameter name for prioritisation (high / normal / low)."""
    lowered = (name or "").strip().lower()
    if not lowered:
        return "low"
    if lowered in HIGH_VALUE_PARAMETERS:
        return "high"
    if any(token in lowered for token in ("redirect", "callback", "return", "next", "url", "file", "path", "template")):
        return "high"
    if lowered.startswith(("utm_", "ga_", "_ga", "fbclid", "gclid", "mc_")):
        return "low"
    return "normal"


def _clean_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if url.startswith("//"):
        url = "https:" + url
    if not url.lower().startswith(("http://", "https://")):
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if not parts.netloc:
        return ""
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, parts.fragment))


def _query_pairs(url: str) -> List[Tuple[str, str]]:
    try:
        return parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return []


@dataclass
class ParameterCandidate:
    """One parameter name plus collection and reflection evidence."""

    name: str
    count: int = 0
    urls: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    sample_url: str = ""
    risk: str = "normal"
    reflected: bool = False
    context: str = ""
    status: int = 0
    method: str = "GET"
    probe_url: str = ""
    marker: str = ""
    evidence: str = ""
    executable: bool = False
    baseline_similarity: Optional[float] = None
    baseline_dynamic: bool = False

    def add(self, url: str, source: str = "") -> None:
        self.count += 1
        if len(self.urls) < 25 and url not in self.urls:
            self.urls.append(url)
        if not self.sample_url:
            self.sample_url = url
        if source and source not in self.sources:
            self.sources.append(source)

    def key(self) -> str:
        return self.name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "count": self.count,
            "risk": self.risk,
            "urls": list(self.urls),
            "sources": list(self.sources),
            "sample_url": self.sample_url,
            "reflected": self.reflected,
            "context": self.context,
            "status": self.status,
            "method": self.method,
            "probe_url": self.probe_url,
            "marker": self.marker,
            "evidence": self.evidence,
            "executable": self.executable,
            "baseline_similarity": self.baseline_similarity,
            "baseline_dynamic": self.baseline_dynamic,
        }


@dataclass
class ParameterReport:
    domain: str = ""
    urls: List[str] = field(default_factory=list)
    candidates: List[ParameterCandidate] = field(default_factory=list)
    sources: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def reflected(self) -> List[ParameterCandidate]:
        return [candidate for candidate in self.candidates if candidate.reflected]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "urls": list(self.urls),
            "sources": dict(self.sources),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "errors": list(self.errors),
        }


class ParameterHarvester:
    """Collect URLs and extract/rank their parameter names."""

    def __init__(
        self,
        http: HttpLike,
        console: ConsoleLike,
        *,
        limit: int = 5000,
        timeout: float = 25.0,
    ):
        self.http = http
        self.console = console
        self.limit = max(1, limit)
        self.timeout = max(4.0, timeout)

    # -- collector-style Wayback harvesting -------------------------------------
    @staticmethod
    def parse_wayback(text: str, domain: str = "") -> List[str]:
        rows: List[str] = []
        stripped = (text or "").strip()
        if not stripped:
            return rows
        if stripped.startswith("["):
            try:
                payload = json.loads(stripped)
                for item in payload:
                    if isinstance(item, list) and item:
                        rows.append(str(item[0]))
                    elif isinstance(item, dict):
                        rows.append(str(item.get("original") or item.get("url") or ""))
                    elif isinstance(item, str):
                        rows.append(item)
            except Exception:
                rows.extend(stripped.splitlines())
        else:
            rows.extend(stripped.splitlines())
        domain = (domain or "").lower().strip(".")
        seen: Set[str] = set()
        urls: List[str] = []
        for row in rows:
            url = _clean_url(row)
            if not url:
                continue
            host = (urlsplit(url).hostname or "").lower()
            if domain and not (host == domain or host.endswith("." + domain)):
                continue
            if urlsplit(url).path.lower().endswith(STATIC_EXTENSIONS) and not urlsplit(url).query:
                continue
            key = url.split("#", 1)[0]
            if key in seen:
                continue
            seen.add(key)
            urls.append(url)
            if len(urls) >= 20000:
                break
        return urls

    async def wayback(self, domain: str, include_subdomains: bool = True) -> List[str]:
        """Query the Wayback CDX API the same way collector does."""
        domain = (domain or "").strip().lower()
        if not domain:
            return []
        patterns = [f"*.{domain}/*", f"{domain}/*"] if include_subdomains else [f"{domain}/*"]
        errors: List[str] = []
        for pattern in patterns:
            query = urlencode(
                {
                    "url": pattern,
                    "output": "list",
                    "fl": "original",
                    "collapse": "urlkey",
                    "filter": "statuscode:200",
                    "limit": str(self.limit),
                }
            )
            url = f"https://web.archive.org/cdx/search/cdx?{query}"
            try:
                response = await asyncio.wait_for(
                    self.http.get(url, allow_redirects=True, cache=False),
                    timeout=self.timeout,
                )
            except Exception as exc:
                errors.append(str(exc)[:160])
                continue
            if getattr(response, "error", None):
                errors.append(str(response.error)[:160])
                continue
            status = int(getattr(response, "status", 0) or 0)
            if status >= 400:
                errors.append(f"CDX HTTP {status}")
                continue
            urls = self.parse_wayback(getattr(response, "text", "") or "", domain)
            if urls:
                self.console.info(
                    f"collector: {len(urls)} historic URL(s) from Wayback "
                    f"({'subdomains' if include_subdomains else 'host only'})"
                )
                return urls[: self.limit]
        if errors:
            self.console.debug(f"Wayback harvesting failed: {'; '.join(errors)[:300]}")
        return []

    # -- extraction --------------------------------------------------------------
    def harvest(self, urls: Iterable[str], *, domain: str = "", source: str = "") -> ParameterReport:
        report = ParameterReport(domain=domain)
        seen_urls: Set[str] = set()
        by_name: Dict[str, ParameterCandidate] = {}
        for raw in urls:
            url = _clean_url(raw)
            if not url:
                continue
            key = url.split("#", 1)[0]
            if key in seen_urls:
                continue
            seen_urls.add(key)
            report.urls.append(url)
            pairs = _query_pairs(url)
            if pairs:
                report.sources[source or "input"] = report.sources.get(source or "input", 0) + 1
            for name, _value in pairs:
                name = (name or "").strip()
                if not name or len(name) > 80:
                    continue
                candidate = by_name.get(name)
                if candidate is None:
                    candidate = ParameterCandidate(
                        name=name, risk=parameter_risk(name)
                    )
                    by_name[name] = candidate
                    report.candidates.append(candidate)
                candidate.add(url, source or "input")
            if len(report.urls) >= self.limit:
                break
        report.candidates.sort(
            key=lambda item: (
                {"high": 0, "normal": 1, "low": 2}.get(item.risk, 3),
                -item.count,
                item.name,
            )
        )
        return report

    def from_pairs(
        self,
        url: str,
        pairs: Sequence[Tuple[str, str]],
        *,
        source: str = "post",
    ) -> ParameterReport:
        """Build candidates from an explicit POST body (Gxss ``-d`` style)."""
        report = ParameterReport(urls=[url])
        for name, _value in pairs:
            name = (name or "").strip()
            if not name:
                continue
            candidate = ParameterCandidate(name=name, risk=parameter_risk(name))
            candidate.add(url, source)
            report.candidates.append(candidate)
        report.sources[source] = 1
        report.candidates.sort(
            key=lambda item: (
                {"high": 0, "normal": 1, "low": 2}.get(item.risk, 3),
                item.name,
            )
        )
        return report

    def from_names(
        self,
        url: str,
        names: Iterable[str],
        *,
        source: str = "external",
    ) -> ParameterReport:
        """Adapt externally discovered names to the scanner's ranked model."""
        clean = _clean_url(url)
        report = ParameterReport(urls=[clean] if clean else [])
        seen: Set[str] = set()
        for raw_name in names:
            name = str(raw_name or "").strip()
            if not clean or not name or len(name) > 80 or name in seen:
                continue
            seen.add(name)
            candidate = ParameterCandidate(name=name, risk=parameter_risk(name))
            candidate.add(clean, source)
            report.candidates.append(candidate)
        report.sources[source] = 1 if report.candidates else 0
        report.candidates.sort(
            key=lambda item: (
                {"high": 0, "normal": 1, "low": 2}.get(item.risk, 3), item.name
            )
        )
        return report


class ReflectionProbe:
    """Batch-first reflection checker with adaptive bisection for behavior deltas."""

    def __init__(
        self,
        http: HttpLike,
        console: ConsoleLike,
        *,
        marker: str = "XoxssReflect",
        concurrency: int = 10,
        urls_per_param: int = 3,
        batch_size: int = 100,
    ):
        self.http = http
        self.console = console
        raw_marker = (marker or "XoxssReflect").strip() or "XoxssReflect"
        self.marker = "".join(char for char in raw_marker if char.isalnum()) or "XoxssReflect"
        self.concurrency = max(1, concurrency)
        self.urls_per_param = max(1, urls_per_param)
        self.batch_size = min(100, max(1, int(batch_size)))
        self.detector = ContextDetector()

    def _new_marker(self) -> str:
        # Gxss uses a plain alphanumeric marker.  UUID suffix avoids matching
        # text that already existed on the page.
        return f"{self.marker}{uuid.uuid4().hex[:8]}"

    async def probe_candidates(
        self,
        candidates: Sequence[ParameterCandidate],
        *,
        data: str = "",
    ) -> List[ParameterCandidate]:
        if data:
            try:
                json_body = json.loads(data)
            except Exception:
                json_body = None
            if isinstance(json_body, dict):
                return await self._probe_json_batches(candidates, json_body)
            try:
                post_pairs = parse_qsl(data, keep_blank_values=True)
            except Exception:
                post_pairs = None
            if post_pairs:
                return await self._probe_form_batches(candidates, post_pairs)
            self.console.warn("POST reflection data could not be parsed; falling back to GET")
        return await self._probe_get_batches(candidates)

    @staticmethod
    def _base_key(url: str) -> Tuple[str, str, str]:
        parts = urlsplit(url)
        return parts.scheme.lower(), parts.netloc.lower(), parts.path or "/"

    @staticmethod
    def _query_url(
        base_url: str,
        existing: Sequence[Tuple[str, str]],
        values: Dict[str, str],
    ) -> str:
        replaced = [(key, value) for key, value in existing if key not in values]
        replaced.extend(values.items())
        parts = urlsplit(base_url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(replaced), parts.fragment))

    @staticmethod
    def _normalized_body(text: str, markers: Sequence[str]) -> str:
        for marker in markers:
            text = text.replace(marker, "<XOXSS_MARKER>")
        return text[:50000]

    def _response_changed(self, response: Any, baselines: Sequence[Any], markers: Sequence[str], dynamic: bool) -> bool:
        if not baselines:
            return False
        status = int(getattr(response, "status", 0) or 0)
        content_type = str(getattr(response, "headers", {}).get("content-type", "")).split(";", 1)[0].lower()
        body = self._normalized_body(str(getattr(response, "text", "") or ""), markers)
        threshold = 0.90 if dynamic else 0.965
        changed_against: List[bool] = []
        for baseline in baselines:
            base_status = int(getattr(baseline, "status", 0) or 0)
            base_type = str(getattr(baseline, "headers", {}).get("content-type", "")).split(";", 1)[0].lower()
            base_body = self._normalized_body(str(getattr(baseline, "text", "") or ""), markers)
            if status != base_status or (content_type and base_type and content_type != base_type):
                changed_against.append(True)
                continue
            similarity = SequenceMatcher(None, body, base_body, autojunk=True).ratio()
            changed = similarity < threshold
            length_delta = abs(len(body) - len(base_body))
            if length_delta > max(48, int(max(len(body), len(base_body), 1) * (0.12 if dynamic else 0.06))):
                changed = True
            changed_against.append(changed)
        # Dynamic pages must differ from both controls before a noisy response
        # is allowed to trigger a potentially expensive bisection tree.
        return bool(changed_against) and all(changed_against)

    @staticmethod
    def _json_leaf_paths(value: Any) -> Dict[str, Tuple[Any, ...]]:
        """Map readable dotted/indexed paths to mutable JSON leaf paths."""
        paths: Dict[str, Tuple[Any, ...]] = {}

        def visit(node: Any, segments: Tuple[Any, ...], label: str) -> None:
            if isinstance(node, dict):
                for key, child in node.items():
                    child_label = f"{label}.{key}" if label else str(key)
                    visit(child, (*segments, key), child_label)
            elif isinstance(node, list):
                for index, child in enumerate(node):
                    visit(child, (*segments, index), f"{label}[{index}]")
            else:
                paths[label] = segments

        visit(value, (), "")
        return paths

    @staticmethod
    def _set_json_path(document: Dict[str, Any], path: Sequence[Any], value: str) -> None:
        node: Any = document
        for segment in path[:-1]:
            node = node[segment]
        node[path[-1]] = value

    async def _probe_json_batches(
        self, candidates: Sequence[ParameterCandidate], document: Dict[str, Any]
    ) -> List[ParameterCandidate]:
        """Batch and bisect top-level or nested JSON body leaves."""
        paths = self._json_leaf_paths(document)
        groups: Dict[Tuple[str, ...], Dict[str, Any]] = {}
        for candidate in candidates:
            candidate.reflected = False
            if candidate.name not in paths:
                candidate.evidence = "JSON body property not present"
                continue
            url = candidate.sample_url or next(iter(candidate.urls), "")
            if not url:
                candidate.evidence = "no endpoint URL available for JSON body probe"
                continue
            key = self._base_key(url)
            group = groups.setdefault(key, {"url": url, "candidates": {}})
            group["candidates"][candidate.name] = candidate

        semaphore = asyncio.Semaphore(self.concurrency)

        async def probe_group(group: Dict[str, Any]) -> None:
            url = str(group["url"])
            by_name: Dict[str, ParameterCandidate] = group["candidates"]
            baselines: List[Any] = []
            async with semaphore:
                for _ in range(2):
                    # Preserve the application's JSON schema during controls;
                    # changing a field or injecting an unknown key would skew
                    # the response-delta baseline we are trying to measure.
                    try:
                        response = await self.http.post(
                            url,
                            json_body=copy.deepcopy(document),
                            headers={"Content-Type": "application/json"},
                            allow_redirects=False,
                        )
                    except Exception:
                        continue
                    if not getattr(response, "error", None):
                        baselines.append(response)
                baseline_similarity: Optional[float] = None
                baseline_dynamic = len(baselines) < 2
                if len(baselines) == 2:
                    first = self._normalized_body(str(getattr(baselines[0], "text", "") or ""), [])
                    second = self._normalized_body(str(getattr(baselines[1], "text", "") or ""), [])
                    baseline_similarity = SequenceMatcher(None, first, second, autojunk=True).ratio()
                    baseline_dynamic = (
                        getattr(baselines[0], "status", 0) != getattr(baselines[1], "status", 0)
                        or baseline_similarity < 0.985
                    )
                for candidate in by_name.values():
                    candidate.baseline_similarity = baseline_similarity
                    candidate.baseline_dynamic = baseline_dynamic
                    candidate.method = "POST"
                    candidate.probe_url = url

                async def probe_bucket(bucket: Sequence[ParameterCandidate]) -> None:
                    if not bucket:
                        return
                    markers = {item.name: self._new_marker() for item in bucket}
                    body = copy.deepcopy(document)
                    for name, marker in markers.items():
                        self._set_json_path(body, paths[name], marker)
                    try:
                        response = await self.http.post(
                            url,
                            json_body=body,
                            headers={"Content-Type": "application/json"},
                            allow_redirects=False,
                        )
                    except Exception as exc:
                        for item in bucket:
                            item.evidence = f"batched JSON request failed: {str(exc)[:240]}"
                        return
                    if getattr(response, "error", None):
                        for item in bucket:
                            item.evidence = f"batched JSON request failed: {str(response.error)[:240]}"
                        return
                    text = str(getattr(response, "text", "") or "")
                    remaining: List[ParameterCandidate] = []
                    reflected_names: Set[str] = set()
                    for item in bucket:
                        marker = markers[item.name]
                        item.status = int(getattr(response, "status", 0) or 0)
                        if marker in text:
                            reflected_names.add(item.name)
                            item.marker = marker
                            item.reflected = True
                            index = text.find(marker)
                            try:
                                analysis = self.detector.detect_context(text, index, marker)
                                item.context = analysis.context_type.name.lower()
                                context = f", context {item.context}, confidence {analysis.confidence:.2f}"
                            except Exception:
                                context = ""
                            item.evidence = f"unique JSON batch marker reflected (HTTP {item.status}{context})"
                        else:
                            remaining.append(item)
                    if not remaining:
                        return
                    if reflected_names:
                        for item in remaining:
                            item.evidence = "no unique marker reflection in this JSON batch; other properties reflected"
                        return
                    if self._response_changed(response, baselines, list(markers.values()), baseline_dynamic):
                        if len(remaining) > 1:
                            midpoint = len(remaining) // 2
                            await probe_bucket(remaining[:midpoint])
                            await probe_bucket(remaining[midpoint:])
                        else:
                            remaining[0].evidence = (
                                f"JSON property changed the response without reflecting its marker "
                                f"(HTTP {remaining[0].status})"
                            )
                    else:
                        for item in remaining:
                            item.evidence = f"JSON marker not reflected; no response delta (HTTP {item.status})"

                ordered = sorted(by_name.values(), key=lambda item: (item.risk != "high", item.name))
                for offset in range(0, len(ordered), self.batch_size):
                    await probe_bucket(ordered[offset:offset + self.batch_size])

        results = await asyncio.gather(
            *(probe_group(group) for group in groups.values()), return_exceptions=True
        )
        for group, result in zip(groups.values(), results):
            if isinstance(result, Exception):
                self.console.warn(f"JSON parameter batch failed for {group['url']}: {str(result)[:200]}")
        reflected = sum(candidate.reflected for candidate in candidates)
        if candidates:
            self.console.info(
                f"Batched JSON reflection probe: {reflected}/{len(candidates)} reflecting property(s)",
                important=False,
            )
        return list(candidates)

    async def _probe_form_batches(
        self, candidates: Sequence[ParameterCandidate], post_pairs: Sequence[Tuple[str, str]]
    ) -> List[ParameterCandidate]:
        """Batch and bisect URL-encoded form fields, mirroring GET/JSON probing."""
        groups: Dict[Tuple[str, ...], Dict[str, Any]] = {}
        field_names = {name for name, _value in post_pairs}
        for candidate in candidates:
            candidate.reflected = False
            if candidate.name not in field_names:
                candidate.evidence = "form field not present in POST body"
                continue
            url = candidate.sample_url or next(iter(candidate.urls), "")
            if not url:
                candidate.evidence = "no endpoint URL available for form body probe"
                continue
            # Query parameters can affect the POST endpoint's behavior, so
            # only combine forms that share the full request URL.
            parts = urlsplit(url)
            key = (*self._base_key(url), parts.query)
            group = groups.setdefault(key, {"url": url, "candidates": {}})
            group["candidates"][candidate.name] = candidate

        semaphore = asyncio.Semaphore(self.concurrency)
        base_body = dict(post_pairs)

        async def probe_group(group: Dict[str, Any]) -> None:
            url = str(group["url"])
            by_name: Dict[str, ParameterCandidate] = group["candidates"]
            baselines: List[Any] = []
            async with semaphore:
                for _ in range(2):
                    try:
                        response = await self.http.post(
                            url, data=dict(base_body), allow_redirects=False,
                        )
                    except Exception:
                        continue
                    if not getattr(response, "error", None):
                        baselines.append(response)

                baseline_similarity: Optional[float] = None
                baseline_dynamic = len(baselines) < 2
                if len(baselines) == 2:
                    first = self._normalized_body(str(getattr(baselines[0], "text", "") or ""), [])
                    second = self._normalized_body(str(getattr(baselines[1], "text", "") or ""), [])
                    baseline_similarity = SequenceMatcher(None, first, second, autojunk=True).ratio()
                    baseline_dynamic = (
                        getattr(baselines[0], "status", 0) != getattr(baselines[1], "status", 0)
                        or baseline_similarity < 0.985
                    )
                for candidate in by_name.values():
                    candidate.baseline_similarity = baseline_similarity
                    candidate.baseline_dynamic = baseline_dynamic
                    candidate.method = "POST"
                    candidate.probe_url = url

                async def probe_bucket(bucket: Sequence[ParameterCandidate]) -> None:
                    if not bucket:
                        return
                    markers = {item.name: self._new_marker() for item in bucket}
                    body = dict(base_body)
                    body.update(markers)
                    try:
                        response = await self.http.post(
                            url, data=body, allow_redirects=False,
                        )
                    except Exception as exc:
                        for item in bucket:
                            item.evidence = f"batched form request failed: {str(exc)[:240]}"
                        return
                    if getattr(response, "error", None):
                        for item in bucket:
                            item.evidence = f"batched form request failed: {str(response.error)[:240]}"
                        return

                    text = str(getattr(response, "text", "") or "")
                    remaining: List[ParameterCandidate] = []
                    reflected_names: Set[str] = set()
                    for item in bucket:
                        item.status = int(getattr(response, "status", 0) or 0)
                        marker = markers[item.name]
                        if marker in text:
                            reflected_names.add(item.name)
                            item.marker = marker
                            item.reflected = True
                            index = text.find(marker)
                            try:
                                analysis = self.detector.detect_context(text, index, marker)
                                item.context = analysis.context_type.name.lower()
                                context = f", context {item.context}, confidence {analysis.confidence:.2f}"
                            except Exception:
                                context = ""
                            item.evidence = f"unique form batch marker reflected (HTTP {item.status}{context})"
                        else:
                            remaining.append(item)

                    if not remaining:
                        return
                    if reflected_names:
                        for item in remaining:
                            item.evidence = "no unique marker reflection in this form batch; other fields reflected"
                        return
                    if self._response_changed(response, baselines, list(markers.values()), baseline_dynamic):
                        if len(remaining) > 1:
                            midpoint = len(remaining) // 2
                            await probe_bucket(remaining[:midpoint])
                            await probe_bucket(remaining[midpoint:])
                        else:
                            remaining[0].evidence = (
                                "form field changed the response without reflecting its marker "
                                f"(HTTP {remaining[0].status})"
                            )
                    else:
                        for item in remaining:
                            item.evidence = f"form marker not reflected; no response delta (HTTP {item.status})"

                ordered = sorted(by_name.values(), key=lambda item: (item.risk != "high", item.name))
                for offset in range(0, len(ordered), self.batch_size):
                    await probe_bucket(ordered[offset:offset + self.batch_size])

        results = await asyncio.gather(
            *(probe_group(group) for group in groups.values()), return_exceptions=True
        )
        for group, result in zip(groups.values(), results):
            if isinstance(result, Exception):
                self.console.warn(f"Form parameter batch failed for {group['url']}: {str(result)[:200]}")
        reflected = sum(candidate.reflected for candidate in candidates)
        if candidates:
            self.console.info(
                f"Batched form reflection probe: {reflected}/{len(candidates)} reflecting field(s)",
                important=False,
            )
        return list(candidates)

    async def _probe_get_batches(
        self, candidates: Sequence[ParameterCandidate]
    ) -> List[ParameterCandidate]:
        """Probe up to 100 distinct names/request; bisect only buckets with a response delta."""
        groups: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        candidate_groups: Dict[Tuple[str, str, str], Dict[str, ParameterCandidate]] = {}
        for candidate in candidates:
            candidate.reflected = False
            urls = candidate.urls or ([candidate.sample_url] if candidate.sample_url else [])
            for url in urls[: self.urls_per_param]:
                try:
                    parts = urlsplit(_clean_url(url))
                except ValueError:
                    continue
                if not parts.scheme or not parts.netloc:
                    continue
                key = self._base_key(url)
                entry = groups.setdefault(key, {"url": url, "pairs": []})
                existing = entry["pairs"]
                for pair in _query_pairs(url):
                    if pair not in existing:
                        existing.append(pair)
                candidate_groups.setdefault(key, {})[candidate.name] = candidate

        semaphore = asyncio.Semaphore(self.concurrency)

        async def probe_group(key: Tuple[str, str, str]) -> None:
            group = groups[key]
            base_url = str(group["url"])
            existing: List[Tuple[str, str]] = list(group["pairs"])
            by_name = candidate_groups[key]
            control_name = "__xoxss_control_" + uuid.uuid4().hex[:8]
            baselines: List[Any] = []
            control_markers = [self._new_marker(), self._new_marker()]
            async with semaphore:
                for marker in control_markers:
                    control_url = self._query_url(base_url, existing, {control_name: marker})
                    try:
                        response = await self.http.get(control_url, allow_redirects=False, cache=False)
                    except Exception:
                        continue
                    if not getattr(response, "error", None):
                        baselines.append(response)
                baseline_similarity: Optional[float] = None
                baseline_dynamic = len(baselines) < 2
                if len(baselines) == 2:
                    first_body = self._normalized_body(str(getattr(baselines[0], "text", "") or ""), control_markers)
                    second_body = self._normalized_body(str(getattr(baselines[1], "text", "") or ""), control_markers)
                    baseline_similarity = SequenceMatcher(None, first_body, second_body, autojunk=True).ratio()
                    baseline_dynamic = (
                        getattr(baselines[0], "status", 0) != getattr(baselines[1], "status", 0)
                        or baseline_similarity < 0.985
                    )
                for candidate in by_name.values():
                    if candidate.baseline_similarity is None:
                        candidate.baseline_similarity = baseline_similarity
                    candidate.baseline_dynamic = baseline_dynamic

                async def probe_bucket(bucket: Sequence[ParameterCandidate]) -> None:
                    if not bucket:
                        return
                    markers = {item.name: self._new_marker() for item in bucket}
                    probe_url = self._query_url(base_url, existing, markers)
                    try:
                        response = await self.http.get(probe_url, allow_redirects=False, cache=False)
                    except Exception as exc:
                        for item in bucket:
                            item.evidence = f"batched request failed: {exc}"[:300]
                        return
                    if getattr(response, "error", None):
                        for item in bucket:
                            item.evidence = f"batched request failed: {response.error}"[:300]
                        return
                    text = str(getattr(response, "text", "") or "")
                    remaining: List[ParameterCandidate] = []
                    reflected_names: Set[str] = set()
                    for item in bucket:
                        marker = markers[item.name]
                        item.method = "GET"
                        item.probe_url = probe_url
                        item.status = int(getattr(response, "status", 0) or 0)
                        if marker in text:
                            reflected_names.add(item.name)
                            item.reflected = True
                            index = text.find(marker)
                            try:
                                analysis = self.detector.detect_context(text, index, marker)
                                item.context = analysis.context_type.name.lower()
                                context_evidence = f", context {item.context}, confidence {analysis.confidence:.2f}"
                            except Exception:
                                context_evidence = ""
                            item.evidence = f"unique batch marker reflected (HTTP {item.status}{context_evidence})"
                        else:
                            remaining.append(item)
                    if not remaining:
                        return
                    if reflected_names:
                        for item in remaining:
                            item.evidence = (
                                "no unique marker reflection in this batch; "
                                "other parameters in the batch reflected"
                            )
                        return
                    changed = self._response_changed(response, baselines, list(markers.values()), baseline_dynamic)
                    if changed and len(remaining) > 1:
                        midpoint = len(remaining) // 2
                        await probe_bucket(remaining[:midpoint])
                        await probe_bucket(remaining[midpoint:])
                    elif changed:
                        remaining[0].evidence = (
                            f"parameter changed the batched response without reflecting its marker "
                            f"(HTTP {remaining[0].status})"
                        )
                    else:
                        for item in remaining:
                            item.evidence = f"marker not reflected; no response delta (HTTP {item.status})"

                ordered = sorted(by_name.values(), key=lambda item: (item.risk != "high", item.name))
                buckets: List[List[ParameterCandidate]] = []
                current: List[ParameterCandidate] = []
                for item in ordered:
                    candidate_bucket = [*current, item]
                    marker_values = {
                        candidate.name: "X" * 20 for candidate in candidate_bucket
                    }
                    candidate_url = self._query_url(base_url, existing, marker_values)
                    if current and (
                        len(candidate_bucket) > self.batch_size or len(candidate_url) > 6000
                    ):
                        buckets.append(current)
                        current = [item]
                    else:
                        current = candidate_bucket
                    if len(current) == 1:
                        single_url = self._query_url(
                            base_url, existing, {item.name: "X" * 20}
                        )
                        if len(single_url) > 6000:
                            item.evidence = "candidate URL exceeds the 6000-character batch safety limit"
                            current = []
                if current:
                    buckets.append(current)
                for bucket in buckets:
                    await probe_bucket(bucket)

        group_results = await asyncio.gather(
            *(probe_group(key) for key in groups), return_exceptions=True
        )
        for key, result in zip(groups, group_results):
            if isinstance(result, Exception):
                self.console.warn(
                    f"Parameter batch failed for {groups[key]['url']}: {str(result)[:200]}"
                )
        result = list(candidates)
        reflected = sum(1 for item in result if item.reflected)
        if result:
            self.console.info(
                f"Batched reflection probe: {reflected}/{len(result)} reflecting parameter(s) "
                f"(batch size {self.batch_size})",
                important=False,
            )
        return result


__all__ = [
    "HIGH_VALUE_PARAMETERS",
    "ParameterCandidate",
    "ParameterReport",
    "ParameterHarvester",
    "ReflectionProbe",
    "parameter_risk",
]
