"""Tests for browser recovery, URL clustering, kxss/wfuzz adapters, and SPA crawl."""

import asyncio
from types import SimpleNamespace

from xoxss.core.browser import BrowserPool
from xoxss.engine.crawler import CrawlerMixin
from xoxss.scanner import Console, Scope
from xoxss.tools.external import parse_kxss, parse_wfuzz_json
from xoxss.utils.urlpolicy import url_cluster_key


def test_url_cluster_key_normalises_dynamic_query_values():
    url1 = "https://example.com/items?id=1&sort=asc"
    url2 = "https://example.com/items?id=99999&sort=desc"
    url3 = "https://example.com/items?category=shoes"

    # url1 and url2 share the same parameter schema (id + sort)
    assert url_cluster_key(url1) == url_cluster_key(url2)
    assert url_cluster_key(url1) == "https://example.com/items?id&sort"

    # url3 has a different parameter schema
    assert url_cluster_key(url3) == "https://example.com/items?category"
    assert url_cluster_key(url1) != url_cluster_key(url3)


def test_parse_kxss_extracts_unfiltered_characters():
    sample = (
        "URL: https://target.test/search?q=test Param: q Unfiltered: [\" < > ']\n"
        "https://target.test/view?file=x Param: file Unfiltered: [>]\n"
    )
    parsed = parse_kxss(sample)
    assert len(parsed) == 2
    assert parsed[0] == ("https://target.test/search?q=test", "q", "\"<>'")
    assert parsed[1] == ("https://target.test/view?file=x", "file", ">")


def test_parse_wfuzz_json_creates_external_findings():
    sample = (
        '[{"url": "https://target.test/?FUZZ=1", "payload": "admin", "code": 200},'
        ' {"url": "https://target.test/?FUZZ=2", "payload": "secret", "code": 404}]\n'
    )
    findings = parse_wfuzz_json(sample)
    assert len(findings) == 1
    assert findings[0].tool == "wfuzz"
    assert findings[0].url == "https://target.test/?FUZZ=1"
    assert findings[0].payload == "admin"
    assert findings[0].evidence == "HTTP 200"


def test_browser_pool_discards_and_restarts_dead_worker():
    class CrashedBrowser:
        def __init__(self):
            self.navigation_count = 0
            self.alive = True
            self.stops = 0
            self.starts = 0

        async def start(self):
            self.starts += 1
            self.alive = True
            return True

        async def stop(self):
            self.stops += 1
            self.alive = False

        def is_alive(self):
            return self.alive

    async def run():
        engine = CrashedBrowser()
        pool = BrowserPool(Console(quiet=True), 1, lambda: engine, recycle_after=100)
        await pool.start()

        # Simulate a crash inside the borrow block
        try:
            async with pool.borrow() as borrowed:
                borrowed.alive = False  # process crashed
                raise RuntimeError("browser disconnected")
        except RuntimeError:
            pass

        # Verify engine was stopped and restarted due to death
        assert engine.stops >= 1
        assert engine.starts >= 2

        await pool.stop()

    asyncio.run(run())


def test_crawler_clusters_repetitive_query_parameters():
    class _Stub(CrawlerMixin):
        def __init__(self):
            self.target = "https://app.test/"
            self.args = SimpleNamespace(
                max_urls=100,
                crawl_depth=1,
                fuzz_params=False,
                concurrency=2,
                cluster_limit=2,  # max 2 samples per cluster
            )
            self.scope = Scope("https://app.test")
            self._stop = asyncio.Event()
            self.endpoints = set()
            self.endpoint_sources = {}
            self.stats = SimpleNamespace(endpoints=0)
            self.console = Console(quiet=True)
            self.state = SimpleNamespace(extra={})

        async def _crawl_page(self, url, depth):
            # Returns 10 URLs with identical parameter schema
            return [f"https://app.test/item?id={i}" for i in range(10)]

    stub = _Stub()
    ordered = asyncio.run(stub.crawl())

    # Only 2 item samples should be queued instead of 10
    item_urls = [u for u in ordered if "/item?id=" in u]
    assert len(item_urls) == 2


def test_browser_pool_caps_excessive_workers():
    pool = BrowserPool(Console(quiet=True), 50, lambda: None)
    assert pool.size == BrowserPool.MAX_CONCURRENT_WORKERS
    assert pool.size <= 8


def test_wfuzz_parameter_discovery_integration():
    from unittest.mock import AsyncMock
    from xoxss.tools.external import ExternalToolkit, ExternalFinding

    toolkit = ExternalToolkit(Console(quiet=True))
    toolkit.tools = {"wfuzz"}
    toolkit.fuzz_wfuzz = AsyncMock(return_value=[
        ExternalFinding(tool="wfuzz", url="https://app.test/search", parameter="query", evidence="HTTP 200")
    ])

    results = asyncio.run(toolkit.parameters(["https://app.test/search"]))
    assert "https://app.test/search" in results
    assert "query" in results["https://app.test/search"]


