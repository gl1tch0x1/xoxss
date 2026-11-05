"""Tests for the extracted BFS crawler engine."""

import asyncio
import threading
from types import SimpleNamespace

from xoxss.engine.crawler import COMMON_ENDPOINTS, CrawlerMixin
from xoxss.scanner import COMMON_ENDPOINTS as SCANNER_COMMON_ENDPOINTS
from xoxss.scanner import Console, Scope, XSSScanner


class _StubScanner(CrawlerMixin):
    def __init__(self, pages=None):
        self.target = "https://app.test/"
        self.args = SimpleNamespace(
            max_urls=50,
            crawl_depth=2,
            fuzz_params=False,
            concurrency=2,
            discover=True,
            discover_paths=False,
            crawl=True,
        )
        self.scope = Scope("https://app.test")
        self._stop = threading.Event()
        self.endpoints = set()
        self.endpoint_sources = {}
        self.stats = SimpleNamespace(endpoints=0)
        self.console = Console(quiet=True)
        self.state = SimpleNamespace(extra={})
        self.pages = pages or {}
        self.checked = []

    async def _crawl_page(self, url, depth):
        self.checked.append((url, depth))
        return self.pages.get(url, [])

    async def recon_seeds(self):
        return ["https://app.test/recon?q=1"]


def test_scanner_uses_the_extracted_crawler():
    assert SCANNER_COMMON_ENDPOINTS is COMMON_ENDPOINTS
    assert XSSScanner.prepare_urls is CrawlerMixin.prepare_urls
    assert XSSScanner.crawl is CrawlerMixin.crawl
    assert XSSScanner.discover_seeds is CrawlerMixin.discover_seeds


def test_bfs_respects_scope_danger_and_dedup():
    stub = _StubScanner(
        {
            "https://app.test/": [
                "https://app.test/a",
                "https://app.test/b",
                "https://evil.test/out",
                "https://app.test/logout",
            ],
            "https://app.test/a": ["https://app.test/c", "https://app.test/b"],
            "https://app.test/b": ["https://app.test/a"],
        }
    )
    ordered = asyncio.run(stub.crawl())
    assert ordered == [
        "https://app.test/",
        "https://app.test/a",
        "https://app.test/b",
        "https://app.test/c",
    ]
    assert ("https://app.test/", 0) in stub.checked
    assert all(not url.startswith("https://evil.test") for url in ordered)
    assert "https://app.test/logout" not in ordered
    assert stub.state.extra["discovered"] == ordered


def test_bfs_stops_at_depth_limit():
    stub = _StubScanner(
        {
            "https://app.test/": ["https://app.test/one"],
            "https://app.test/one": ["https://app.test/two"],
            "https://app.test/two": ["https://app.test/three"],
        }
    )
    ordered = asyncio.run(stub.crawl())
    # depth=2 crawls the seed and one link level; /two is discovered but not fetched.
    assert ordered == [
        "https://app.test/",
        "https://app.test/one",
        "https://app.test/two",
    ]
    assert ("https://app.test/two", 1) not in stub.checked


def test_prepare_urls_without_crawl_uses_recon_seeds():
    stub = _StubScanner()
    stub.args.crawl = False
    urls = asyncio.run(stub.prepare_urls())
    assert urls == ["https://app.test/", "https://app.test/recon?q=1"]


class _FakeResponse:
    def __init__(self, text="", status=200, url=""):
        self.text = text
        self.status = status
        self.url = url
        self.raw = b""
        self.error = None

    @property
    def ok(self):
        return self.error is None and 200 <= self.status < 400

    def header(self, name, default=""):
        return default


class _FakeHttp:
    def __init__(self):
        self.urls = []

    async def get(self, url, **_kwargs):
        self.urls.append(url)
        if url.endswith("/robots.txt"):
            return _FakeResponse(
                "User-agent: *\nDisallow: /private\nSitemap: https://app.test/sitemap.xml\n",
                url=url,
            )
        if url.endswith("/sitemap.xml"):
            return _FakeResponse(
                "<urlset><url><loc>https://app.test/page?q=1</loc></url></urlset>",
                url=url,
            )
        return _FakeResponse("", url=url)


def test_discover_seeds_reads_robots_and_sitemaps():
    stub = _StubScanner()
    stub.http = _FakeHttp()
    seeds = asyncio.run(stub.discover_seeds())
    assert "https://app.test/private" in seeds
    assert "https://app.test/page?q=1" in seeds
    assert any(url.endswith("/robots.txt") for url in stub.http.urls)
    assert any(url.endswith("/sitemap.xml") for url in stub.http.urls)
