"""
Passive URL collection for a domain.

Given a bare domain, historic URL datasets are the fastest way to discover
parameterised endpoints that are not linked from the current homepage.  This
module wraps Wayback CDX, Common Crawl, urlscan, OTX and (when installed) the
``gau`` / ``waybackurls`` binaries.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Sequence, Set, Tuple
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

class HttpLike(Protocol):  # pragma: no cover
    async def get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        cache: bool = False,
    ) -> Any: ...


class ConsoleLike(Protocol):  # pragma: no cover
    def info(self, message: str, important: bool = False) -> None: ...
    def warn(self, message: str, important: bool = True) -> None: ...
    def debug(self, message: str) -> None: ...


@dataclass
class PassiveURLReport:
    domain: str
    urls: List[str] = field(default_factory=list)
    sources: Dict[str, List[str]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "urls": list(self.urls),
            "sources": {key: list(value) for key, value in self.sources.items()},
            "errors": list(self.errors),
            "parameters": list(self.parameters),
        }


def normalize_url(url: str, base: str = "") -> str:
    url = (url or "").strip().strip('"\'')
    if not url:
        return ""
    if url.startswith("//"):
        url = "https:" + url
    if not re.match(r"^https?://", url, re.I):
        if base:
            from urllib.parse import urljoin

            url = urljoin(base, url)
        else:
            return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return ""
    # Normalise host casing and drop default ports; keep query order intact.
    netloc = parts.netloc.lower()
    if netloc.endswith(":80") and parts.scheme == "http":
        netloc = netloc[:-3]
    if netloc.endswith(":443") and parts.scheme == "https":
        netloc = netloc[:-4]
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, parts.fragment))


def _host_in_domain(host: str, domain: str) -> bool:
    host = (host or "").lower().strip(".")
    return host == domain or host.endswith("." + domain)


def filter_scope(
    urls: Iterable[str],
    domain: str,
    scope_filter: Optional[Callable[[str], bool]] = None,
) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for raw in urls:
        url = normalize_url(raw)
        if not url:
            continue
        parts = urlsplit(url)
        if not _host_in_domain(parts.hostname or "", domain):
            continue
        if scope_filter is not None:
            try:
                if not scope_filter(url):
                    continue
            except Exception:
                continue
        key = url.split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        result.append(url)
    return result


def parse_wayback(text: str, domain: str) -> List[str]:
    urls: List[str] = []
    try:
        rows = json.loads(text)
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, list) and row:
                    urls.append(str(row[0]))
                elif isinstance(row, dict):
                    urls.append(str(row.get("original") or row.get("url") or ""))
    except Exception:
        urls.extend(line.strip() for line in (text or "").splitlines() if line.strip())
    return filter_scope(urls, domain)


def parse_commoncrawl(text: str, domain: str) -> List[str]:
    urls: List[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:
            urls.append(line)
            continue
        if isinstance(row, dict):
            urls.append(str(row.get("url") or row.get("filename") or ""))
    return filter_scope(urls, domain)


def parse_urlscan_urls(text: str, domain: str) -> List[str]:
    urls: List[str] = []
    try:
        data = json.loads(text)
        for row in data.get("results", []) or []:
            page = row.get("page") or {}
            urls.append(str(page.get("url") or ""))
            task = row.get("task") or {}
            urls.append(str(task.get("url") or ""))
    except Exception:
        urls.extend(line.strip() for line in (text or "").splitlines())
    return filter_scope(urls, domain)


def parse_otx_urls(text: str, domain: str) -> List[str]:
    urls: List[str] = []
    try:
        data = json.loads(text)
        for row in data.get("url_list", []) or []:
            urls.append(str(row.get("url") or ""))
    except Exception:
        urls.extend(line.strip() for line in (text or "").splitlines())
    return filter_scope(urls, domain)


def parse_line_urls(text: str, domain: str) -> List[str]:
    return filter_scope((line.strip() for line in (text or "").splitlines()), domain)


def extract_query_parameters(urls: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    params: List[str] = []
    for url in urls:
        try:
            query = urlsplit(url).query
        except ValueError:
            continue
        for name, _value in parse_qsl(query, keep_blank_values=True):
            name = name.strip()
            if name and name not in seen:
                seen.add(name)
                params.append(name)
    return params


class PassiveURLCollector:
    """Fetch historic URLs for a domain from several free sources."""

    def __init__(
        self,
        http: HttpLike,
        console: ConsoleLike,
        *,
        sources: Optional[Sequence[str]] = None,
        timeout: float = 25.0,
        limit: int = 3000,
    ):
        self.http = http
        self.console = console
        self.timeout = max(5.0, timeout)
        self.limit = max(1, limit)
        self.sources = [
            source.strip().lower()
            for source in (
                sources
                or ("wayback", "commoncrawl", "urlscan", "otx")
            )
            if source.strip()
        ]

    async def _fetch(self, url: str) -> str:
        try:
            response = await asyncio.wait_for(self.http.get(url, allow_redirects=True), timeout=self.timeout)
        except Exception as exc:
            raise RuntimeError(str(exc)) from exc
        if getattr(response, "error", None):
            raise RuntimeError(str(response.error))
        return getattr(response, "text", "") or ""

    async def _wayback(self, domain: str) -> List[str]:
        # Domain is user-supplied (target list): encode it or a stray space or
        # '<' breaks the CDX query outright.
        safe_domain = quote(domain, safe="")
        url = (
            "https://web.archive.org/cdx/search/cdx?url=*."
            f"{safe_domain}&output=json&fl=original&collapse=urlkey&filter=statuscode:200"
            f"&limit={self.limit}"
        )
        return parse_wayback(await self._fetch(url), domain)

    async def _commoncrawl(self, domain: str) -> List[str]:
        collinfo = await self._fetch("https://index.commoncrawl.org/collinfo.json")
        index_url = ""
        try:
            collections = json.loads(collinfo)
            if isinstance(collections, list) and collections:
                index_url = str(collections[0].get("cdx-api") or "")
        except Exception:
            pass
        if not index_url:
            raise RuntimeError("could not resolve the latest Common Crawl index")
        sep = "&" if "?" in index_url else "?"
        url = f"{index_url}{sep}url=*.{quote(domain, safe='')}&output=json&limit={self.limit}"
        return parse_commoncrawl(await self._fetch(url), domain)

    async def _urlscan(self, domain: str) -> List[str]:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
        return parse_urlscan_urls(await self._fetch(url), domain)

    async def _otx(self, domain: str) -> List[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit={self.limit}"
        return parse_otx_urls(await self._fetch(url), domain)

    async def collect(
        self,
        domain: str,
        *,
        scope_filter: Optional[Callable[[str], bool]] = None,
    ) -> PassiveURLReport:
        report = PassiveURLReport(domain=domain)
        handlers = {
            "wayback": self._wayback,
            "commoncrawl": self._commoncrawl,
            "urlscan": self._urlscan,
            "otx": self._otx,
        }

        async def run(name: str) -> Tuple[str, List[str], Optional[str]]:
            handler = handlers.get(name)
            if handler is None:
                return name, [], "unknown source"
            try:
                return name, await handler(domain), None
            except Exception as exc:
                return name, [], str(exc)[:180]

        results = await asyncio.gather(*(run(name) for name in self.sources))
        urls: List[str] = []
        seen: Set[str] = set()
        for name, found, error in results:
            if error:
                report.errors.append(f"{name}: {error}")
                self.console.debug(f"Passive URL source {name} failed: {error}")
            filtered = filter_scope(found, domain, scope_filter)
            report.sources[name] = filtered[: self.limit]
            self.console.debug(f"Passive URL source {name}: {len(filtered)} URL(s)")
            for url in filtered:
                key = url.split("#", 1)[0]
                if key in seen:
                    continue
                seen.add(key)
                urls.append(url)
                if len(urls) >= self.limit:
                    break
            if len(urls) >= self.limit:
                break

        report.urls = urls
        report.parameters = extract_query_parameters(urls)
        if urls:
            self.console.info(
                f"Passive URLs: {len(urls)} unique URL(s), "
                f"{len(report.parameters)} parameter name(s)"
            )
        return report


__all__ = [
    "PassiveURLReport",
    "PassiveURLCollector",
    "normalize_url",
    "filter_scope",
    "parse_wayback",
    "parse_commoncrawl",
    "parse_urlscan_urls",
    "parse_otx_urls",
    "parse_line_urls",
    "extract_query_parameters",
]
