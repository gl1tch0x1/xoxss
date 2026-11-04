"""
Parameter intelligence: collector-style URL harvesting and Gxss-style
per-parameter reflection probing.

Two upstream ideas are implemented here:

* **collector** (thenurhabib/collector) – pull historic URLs for a domain from
  the Wayback CDX API (optionally including subdomains), then extract every GET
  parameter name and the URLs that use it.
* **Gxss** (KathanP19/Gxss) – test parameters *one at a time* by substituting a
  unique marker, requesting the URL without following redirects, and checking
  whether the marker is reflected.  This avoids the classic "replace every
  parameter at once" blind spot.

The result is a ranked list of parameter candidates with reflection evidence
that can be fed into the main scanner or triaged on its own.
"""

from __future__ import annotations

import asyncio
from difflib import SequenceMatcher
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from xoxss.detection.context import ContextDetector


try:  # pragma: no cover - structural typing
    from typing import Protocol
except Exception:  # pragma: no cover
    Protocol = object  # type: ignore


class HttpLike(Protocol):  # pragma: no cover
    async def get(self, url: str, **kwargs: Any) -> Any: ...
    async def post(self, url: str, **kwargs: Any) -> Any: ...


class ConsoleLike(Protocol):  # pragma: no cover
    def info(self, message: str, important: bool = True) -> None: ...
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


def _replace_parameter(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = [(key, value if key == name else val) for key, val in pairs]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(replaced, doseq=True), parts.fragment)
    )


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
    """Gxss-style one-parameter-at-a-time reflection checker."""

    def __init__(
        self,
        http: HttpLike,
        console: ConsoleLike,
        *,
        marker: str = "XoxssReflect",
        concurrency: int = 10,
        urls_per_param: int = 3,
    ):
        self.http = http
        self.console = console
        raw_marker = (marker or "XoxssReflect").strip() or "XoxssReflect"
        self.marker = "".join(char for char in raw_marker if char.isalnum()) or "XoxssReflect"
        self.concurrency = max(1, concurrency)
        self.urls_per_param = max(1, urls_per_param)
        self.detector = ContextDetector()

    def _new_marker(self) -> str:
        # Gxss uses a plain alphanumeric marker.  UUID suffix avoids matching
        # text that already existed on the page.
        return f"{self.marker}{uuid.uuid4().hex[:8]}"

    async def _baseline(
        self,
        url: str,
        name: str,
        post_pairs: Optional[Sequence[Tuple[str, str]]],
    ) -> Tuple[Optional[float], bool]:
        """Compare two benign controls to measure page noise before probing."""
        controls = (self._new_marker(), self._new_marker())
        responses: List[Any] = []
        for control in controls:
            try:
                if post_pairs is None:
                    response = await self.http.get(
                        _replace_parameter(url, name, control),
                        allow_redirects=False,
                        cache=False,
                    )
                else:
                    body = [(key, control if key == name else value) for key, value in post_pairs]
                    response = await self.http.post(
                        url, data=dict(body), allow_redirects=False,
                    )
                if getattr(response, "error", None):
                    return None, True
                responses.append(response)
            except Exception:
                return None, True
        first, second = responses
        first_status = int(getattr(first, "status", 0) or 0)
        second_status = int(getattr(second, "status", 0) or 0)
        first_body = (getattr(first, "text", "") or "").replace(controls[0], "<CONTROL>")
        second_body = (getattr(second, "text", "") or "").replace(controls[1], "<CONTROL>")
        similarity = SequenceMatcher(None, first_body[:50_000], second_body[:50_000]).ratio()
        return similarity, first_status != second_status or similarity < 0.985

    async def probe_candidates(
        self,
        candidates: Sequence[ParameterCandidate],
        *,
        data: str = "",
    ) -> List[ParameterCandidate]:
        semaphore = asyncio.Semaphore(self.concurrency)
        post_pairs: Optional[List[Tuple[str, str]]] = None
        if data:
            try:
                post_pairs = parse_qsl(data, keep_blank_values=True)
            except Exception:
                post_pairs = []
            if not post_pairs:
                self.console.warn("POST reflection data could not be parsed; falling back to GET")
                post_pairs = None

        async def probe(candidate: ParameterCandidate) -> ParameterCandidate:
            async with semaphore:
                marker = self._new_marker()
                if post_pairs is not None:
                    names = {name for name, _value in post_pairs}
                    if candidate.name not in names:
                        return candidate
                    urls = [candidate.sample_url]
                else:
                    urls = []
                    for url in candidate.urls or [candidate.sample_url]:
                        if url and url not in urls and _query_pairs(url):
                            urls.append(url)
                    urls = urls[: self.urls_per_param]
                if not urls:
                    return candidate

                baseline_url = (
                    candidate.sample_url if post_pairs is not None else urls[0]
                )
                candidate.baseline_similarity, candidate.baseline_dynamic = await self._baseline(
                    baseline_url, candidate.name, post_pairs
                )

                candidate.marker = marker
                last_status = 0
                for request_url in urls:
                    if post_pairs is not None:
                        body = [
                            (name, marker if name == candidate.name else value)
                            for name, value in post_pairs
                        ]
                        try:
                            response = await self.http.post(
                                request_url,
                                data=dict(body),
                                allow_redirects=False,
                            )
                        except Exception as exc:
                            candidate.evidence = f"request failed: {exc}"[:300]
                            continue
                        candidate.method = "POST"
                        candidate.probe_url = request_url
                    else:
                        probe_url = _replace_parameter(request_url, candidate.name, marker)
                        try:
                            response = await self.http.get(probe_url, allow_redirects=False)
                        except Exception as exc:
                            candidate.evidence = f"request failed: {exc}"[:300]
                            continue
                        candidate.method = "GET"
                        candidate.probe_url = probe_url

                    if getattr(response, "error", None):
                        candidate.evidence = f"request failed: {response.error}"[:300]
                        continue

                    body_text = getattr(response, "text", "") or ""
                    last_status = int(getattr(response, "status", 0) or 0)
                    candidate.status = last_status
                    if marker not in body_text:
                        candidate.evidence = f"marker not reflected (HTTP {last_status})"
                        continue

                    candidate.reflected = True
                    index = body_text.find(marker)
                    try:
                        analysis = self.detector.detect_context(body_text, index, marker)
                        candidate.context = analysis.context_type.name.lower()
                        evidence = (
                            f"parameter value reflected (HTTP {candidate.status}, "
                            f"context {candidate.context}, "
                            f"confidence {analysis.confidence:.2f})"
                        )
                    except Exception:
                        evidence = f"parameter value reflected (HTTP {candidate.status})"
                    candidate.evidence = evidence
                    if candidate.baseline_dynamic:
                        candidate.evidence += "; control responses were dynamic; review the baseline before triage"
                    candidate.executable = False  # reflection is not execution
                    break
                if not candidate.reflected:
                    candidate.reflected = False
                    candidate.status = last_status
                    if not candidate.evidence:
                        candidate.evidence = f"marker not reflected (HTTP {last_status})"
                return candidate

        results = await asyncio.gather(*(probe(item) for item in candidates), return_exceptions=True)
        updated: List[ParameterCandidate] = []
        for item in results:
            if isinstance(item, ParameterCandidate):
                updated.append(item)
        reflected = sum(1 for item in updated if item.reflected)
        if updated:
            self.console.info(
                f"Gxss-style reflection probe: {reflected}/{len(updated)} reflecting parameter(s)",
                important=False,
            )
        return updated


__all__ = [
    "HIGH_VALUE_PARAMETERS",
    "ParameterCandidate",
    "ParameterReport",
    "ParameterHarvester",
    "ReflectionProbe",
    "parameter_risk",
]
