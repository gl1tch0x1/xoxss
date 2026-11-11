"""Breadth-first crawler engine.

The spider lives here as a mixin so :class:`xoxss.scanner.XSSScanner` keeps its
public methods (``prepare_urls``, ``discover_seeds``, ``crawl``) while the BFS
queue, sitemap walker and endpoint recorder stay out of the scanner module.
"""

from __future__ import annotations

import asyncio
from collections import Counter
import gzip
import html as html_lib
import io
import re
from typing import Any, List, Optional, Sequence, Set, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

from xoxss.utils.helpers import truncate
from xoxss.utils.urlpolicy import (
    looks_like_dangerous,
    looks_like_scan_target,
    normalize_scan_url as normalize_url,
    url_cluster_key,
)

# Common paths probed by ``--discover-paths`` (kept intentionally small and safe: GET only).
COMMON_ENDPOINTS: Tuple[str, ...] = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/rest",
    "/admin",
    "/login",
    "/signin",
    "/search",
    "/find",
    "/query",
    "/upload",
    "/profile",
    "/account",
    "/user",
    "/users",
    "/settings",
    "/dashboard",
    "/contact",
    "/feedback",
    "/comment",
    "/comments",
    "/posts",
    "/post",
    "/news",
    "/blog",
    "/article",
    "/download",
    "/redirect",
    "/callback",
    "/oauth",
    "/sso",
    "/status",
    "/health",
    "/swagger.json",
    "/openapi.json",
    "/api/docs",
    "/docs",
    "/debug",
    "/test",
    "/.well-known/security.txt",
)


class CrawlerMixin:
    """BFS crawl helpers mixed into :class:`xoxss.scanner.XSSScanner`."""

    # Attributes/methods supplied by XSSScanner.  Declared here so the mixin can
    # be type-checked in isolation without importing the 7k-line coordinator.
    args: Any
    console: Any
    scope: Any
    state: Any
    stats: Any
    target: str
    endpoints: Any
    endpoint_sources: Any
    recon_seeds: Any
    http: Any
    pool: Any
    vulnerable_libs: Any
    _mined_params: Any
    _stop: Any
    _endpoints_from_scripts: Any
    _endpoints_from_js_file: Any
    discover_browser_requests: Any

    async def prepare_urls(self) -> List[str]:
        recon = await self.recon_seeds()
        if not self.args.crawl:
            combined = list(dict.fromkeys([self.target, *recon]))
            return combined[: max(1, self.args.max_urls)]
        self.console.info(
            f"Crawling {self.target} (depth {self.args.crawl_depth}, max {self.args.max_urls})"
        )
        # Recon seeds first so a tight --max-urls budget still covers the
        # passive/JS/OpenAPI surface the operator explicitly asked for.
        seeds = [*recon, *(await self.discover_seeds())]
        urls = await self.crawl(seeds)
        if self.pool and getattr(self.args, "browser_discovery", False):
            observed = await self.discover_browser_requests(urls)
            urls = list(dict.fromkeys([*urls, *observed]))[: max(1, self.args.max_urls)]
        if self.target not in urls:
            urls.insert(0, self.target)
        self.state.extra["endpoints"] = sorted(self.endpoints)[:5000]
        self.state.extra["endpoint_sources"] = {
            endpoint: sorted(sources)
            for endpoint, sources in list(self.endpoint_sources.items())[:5000]
        }
        self.console.ok(
            f"Crawl complete: {len(urls)} URL(s), {len(self.endpoints)} endpoint(s)",
            important=False,
        )
        return urls

    async def discover_seeds(self) -> List[str]:
        """Collect extra crawl seeds from robots.txt, sitemaps and common paths."""
        seeds: List[str] = []
        parts = urlsplit(self.target)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))

        if getattr(self.args, "discover", True):
            sitemap_urls: List[str] = []
            robots = await self.http.get(urljoin(origin, "/robots.txt"), cache=True)
            if robots.ok and robots.text:
                for line in robots.text.splitlines():
                    key, _, value = line.partition(":")
                    key = key.strip().lower()
                    value = value.strip()
                    if not value:
                        continue
                    if key == "sitemap":
                        sitemap_urls.append(value)
                    elif key in ("allow", "disallow"):
                        # Wildcard and root-only rules are not concrete endpoints.
                        if value != "/" and "*" not in value and "$" not in value:
                            seeds.append(urljoin(origin, value))
            sitemap_urls.append(urljoin(origin, "/sitemap.xml"))
            seeds.extend(await self.parse_sitemaps(sitemap_urls))
            if seeds:
                self.console.debug(f"Seed discovery produced {len(seeds)} candidate(s)")

        if getattr(self.args, "discover_paths", False):
            seeds.extend(await self.probe_common_endpoints(origin))

        result: List[str] = []
        seen: Set[str] = set()
        for url in seeds:
            if not url or not self.scope.in_scope(url) or looks_like_dangerous(url):
                continue
            if not looks_like_scan_target(url, fuzz_params=True):
                continue
            normalized = normalize_url(url)
            if normalized in seen:
                continue
            seen.add(normalized)
            result.append(url)
            self._record_endpoint(url, "seed")
        return result

    async def parse_sitemaps(
        self,
        urls: Sequence[str],
        max_sitemaps: int = 10,
        max_urls: int = 2000,
    ) -> List[str]:
        found: List[str] = []
        queue: List[str] = [url for url in dict.fromkeys(urls) if url]
        visited: Set[str] = set()
        while queue and len(visited) < max_sitemaps and len(found) < max_urls:
            sitemap_url = queue.pop(0)
            if sitemap_url in visited:
                continue
            visited.add(sitemap_url)
            response = await self.http.get(sitemap_url, cache=True)
            if response.error or not response.text:
                continue
            text = response.text[:2_000_000]
            if sitemap_url.lower().endswith(".gz") or response.raw.startswith(b"\x1f\x8b"):
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(response.raw)) as compressed:
                        decoded = compressed.read(2_000_001)
                    if len(decoded) > 2_000_000:
                        self.console.debug(f"Ignoring oversized compressed sitemap: {sitemap_url}")
                        continue
                    text = decoded.decode("utf-8", "replace")
                except (OSError, EOFError) as exc:
                    self.console.debug(f"Could not decode compressed sitemap {sitemap_url}: {exc}")
                    continue
            locations = [
                html_lib.unescape(loc.strip())
                for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I)
            ]
            locations = [urljoin(sitemap_url, location) for location in locations]
            if "<sitemapindex" in text.lower():
                for location in locations:
                    if location not in visited:
                        queue.append(location)
            else:
                for location in locations:
                    found.append(location)
                    if len(found) >= max_urls:
                        break
        return found

    async def probe_common_endpoints(self, origin: str) -> List[str]:
        paths: List[str] = list(COMMON_ENDPOINTS)
        wordlist = getattr(self.args, "endpoint_wordlist", None)
        if wordlist:
            try:
                with open(wordlist, "r", encoding="utf-8-sig", errors="replace") as handle:
                    for line in handle:
                        entry = line.strip()
                        if entry and not entry.startswith("#"):
                            paths.append(entry if entry.startswith("/") else "/" + entry)
            except OSError as exc:
                self.console.warn(f"Cannot read endpoint wordlist {wordlist}: {exc}")

        targets: List[str] = []
        seen: Set[str] = set()
        for path in paths:
            candidate = urljoin(origin, path)
            if candidate not in seen:
                seen.add(candidate)
                targets.append(candidate)

        self.console.info(f"Probing {len(targets)} common endpoint path(s)")
        semaphore = asyncio.Semaphore(max(1, min(10, self.args.concurrency)))

        async def probe(candidate: str) -> Optional[str]:
            async with semaphore:
                response = await self.http.get(candidate, allow_redirects=False, cache=True)
                if response.error:
                    return None
                if response.status in (200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405):
                    return response.url or candidate
                return None

        results = await asyncio.gather(*(probe(candidate) for candidate in targets), return_exceptions=True)
        found: List[str] = []
        for item in results:
            if isinstance(item, str):
                found.append(item)
                self._record_endpoint(item, "wordlist")
        if found:
            self.console.debug(f"Common-path probing found {len(found)} endpoint(s)")
        return found

    def _record_endpoint(self, url: str, source: str = "crawl") -> None:
        try:
            normalized = normalize_url(url)
        except ValueError:
            return
        if not self.scope.in_scope(normalized) or looks_like_dangerous(normalized):
            return
        if not looks_like_scan_target(normalized, fuzz_params=True):
            return
        self.endpoint_sources.setdefault(normalized, set()).add(source)
        if normalized in self.endpoints:
            return
        self.endpoints.add(normalized)
        self.stats.endpoints = len(self.endpoints)
        self.console.debug(f"Endpoint [{source}]: {truncate(normalized, 130)}")

    async def _crawl_page(self, url: str, depth: int) -> List[str]:
        # Imported lazily: these helpers live in the scanner module, which mixes
        # this class in and would otherwise create an import cycle.
        from xoxss.scanner import (
            HAS_BS4,
            HAS_RECON,
            _soup,
            check_vulnerable_libs,
            extract_attr_urls,
            extract_endpoints_from_text,
            extract_html_parameters,
            extract_scripts,
        )

        response = await self.http.get(url, cache=True)
        if response.error or not response.text:
            return []
        text = response.text[:3_000_000]
        content_type = response.header("content-type", "").lower()
        links: List[str] = []
        is_html = "html" in content_type or text.lstrip().startswith("<")
        if is_html and HAS_BS4:
            soup = _soup(text)
            links.extend(self._links_from_soup(soup, url))
            if HAS_RECON and extract_attr_urls is not None:
                links.extend(extract_attr_urls(text, url))
            if HAS_RECON and extract_html_parameters is not None:
                discovered = self._mined_params.setdefault(url, [])
                for name in extract_html_parameters(text):
                    if name not in discovered:
                        discovered.append(name)

            # Check script tags for vulnerable libraries
            scripts = extract_scripts(url, text)
            if getattr(self.args, "check_libs", True):
                for script in scripts:
                    if not script.inline:
                        vulns = check_vulnerable_libs(script.url)
                        for vuln in vulns:
                            if vuln not in self.vulnerable_libs:
                                self.vulnerable_libs.append(vuln)
                                self.console.warn(
                                    f"Vulnerable library: {vuln.name} {vuln.version} ({vuln.severity}) - {vuln.cve} @ {truncate(vuln.url, 80)}"
                                )

            links.extend(await self._endpoints_from_scripts(scripts, url))
        else:
            links.extend(extract_endpoints_from_text(text, url))

        try:
            from xoxss.crawler.spa import SPACrawler

            spa = SPACrawler()
            for route in spa.discover_routes(text, html_content=text if is_html else ""):
                route_url = urljoin(url, route.path)
                if self.scope.in_scope(route_url):
                    links.append(route_url)
        except Exception:
            pass

        # Follow .js files that were reached through links (not only <script src>).
        for link in list(links):
            path = urlsplit(link).path.lower()
            if path.endswith((".js", ".mjs")) and self.scope.in_scope(link):
                links.extend(await self._endpoints_from_js_file(link))
        for link in links:
            self._record_endpoint(link, "crawl")
        self.console.debug(f"Crawled {truncate(url, 120)} (depth {depth})")
        return links

    def _links_from_soup(self, soup: Any, page_url: str) -> List[str]:
        links: List[str] = []
        for tag in soup.find_all(["a", "area", "link"], href=True):
            href = tag.get("href")
            if isinstance(href, str):
                links.append(urljoin(page_url, href))
        for tag in soup.find_all(["iframe", "frame"], src=True):
            src = tag.get("src")
            if isinstance(src, str):
                links.append(urljoin(page_url, src))
        for tag in soup.find_all("form", action=True):
            action = tag.get("action")
            if isinstance(action, str):
                links.append(urljoin(page_url, action))
        for tag in soup.find_all("object", data=True):
            data = tag.get("data")
            if isinstance(data, str):
                links.append(urljoin(page_url, data))
        for tag in soup.find_all("meta", attrs={"http-equiv": True}):
            if str(tag.get("http-equiv", "")).lower() == "refresh":
                match = re.search(r"url\s*=\s*['\"]?([^'\"\s;]+)", str(tag.get("content", "")), re.I)
                if match:
                    links.append(urljoin(page_url, match.group(1)))
        return links

    async def crawl(self, seeds: Optional[Sequence[str]] = None) -> List[str]:
        limit = max(1, self.args.max_urls)
        depth_limit = max(1, self.args.crawl_depth)
        seen: Set[str] = set()
        ordered: List[str] = []
        frontier: List[str] = []
        cluster_counts: Counter[str] = Counter()
        max_cluster_samples = max(1, int(getattr(self.args, "cluster_limit", 5)))

        for candidate in [self.target, *(seeds or [])]:
            if len(ordered) >= limit or self._stop.is_set():
                break
            if not candidate or not self.scope.in_scope(candidate) or looks_like_dangerous(candidate):
                continue
            if not looks_like_scan_target(candidate, fuzz_params=True):
                continue
            normalized = normalize_url(candidate)
            if normalized in seen:
                continue
            cluster = url_cluster_key(candidate)
            if cluster_counts[cluster] >= max_cluster_samples:
                continue
            cluster_counts[cluster] += 1
            seen.add(normalized)
            ordered.append(candidate)
            frontier.append(candidate)
            self._record_endpoint(candidate, "seed")

        for depth in range(depth_limit):
            if not frontier or len(ordered) >= limit or self._stop.is_set():
                break
            results = await asyncio.gather(
                *(self._crawl_page(url, depth) for url in frontier),
                return_exceptions=True,
            )
            next_frontier: List[str] = []
            for result in results:
                if isinstance(result, BaseException) or not result:
                    continue
                for link in result:
                    if len(ordered) >= limit or self._stop.is_set():
                        break
                    link = link.split("#", 1)[0]
                    if not link or link.startswith(("mailto:", "tel:", "javascript:", "data:")):
                        continue
                    if not self.scope.in_scope(link) or looks_like_dangerous(link):
                        continue
                    if not looks_like_scan_target(
                        link, fuzz_params=bool(getattr(self.args, "fuzz_params", False))
                    ):
                        continue
                    normalized = normalize_url(link)
                    if normalized in seen:
                        continue
                    cluster = url_cluster_key(link)
                    if cluster_counts[cluster] >= max_cluster_samples:
                        continue
                    cluster_counts[cluster] += 1
                    seen.add(normalized)
                    ordered.append(link)
                    next_frontier.append(link)
                    self._record_endpoint(link, "crawl")
            frontier = next_frontier
            self.state.extra["discovered"] = ordered[:limit]
            self.console.debug(
                f"Crawl depth {depth + 1}/{depth_limit}: {len(ordered)} URL(s), "
                f"{len(self.endpoints)} endpoint(s)"
            )
        return ordered


__all__ = ["COMMON_ENDPOINTS", "CrawlerMixin"]
