"""Directory-fuzzer behaviour: catch-all suppression, recursion and dedupe."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from xoxss.scan.fuzzer import DirFuzzer, expand_paths, _soft_404_signature


class FakeResponse:
    def __init__(self, status: int = 200, text: str = "", url: str = "", error: Optional[str] = None):
        self.status = status
        self.text = text
        self.url = url
        self.headers: Dict[str, str] = {"content-type": "text/html"}
        self.error = error


class FakeHttp:
    def __init__(self, handler: Any) -> None:
        self.handler = handler
        self.calls: List[str] = []

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(url)
        return self.handler(url)


class FakeConsole:
    def debug(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def info(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def ok(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def warn(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def error(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_soft_404_signature_ignores_nonces_and_timestamps() -> None:
    first = "<h1>Not found</h1><p>request 8f3a91ccd2 and 1729982123</p>"
    second = "<h1>Not found</h1><p>request 0b7e4d1aa9 and 1729999999</p>"
    first_sig = _soft_404_signature(200, first)
    second_sig = _soft_404_signature(200, second)
    assert first_sig[2] == second_sig[2]


def test_soft_404_signature_keeps_real_content_distinct() -> None:
    assert _soft_404_signature(200, "Admin console")[2] != _soft_404_signature(
        200, "Customer dashboard"
    )[2]


def test_expand_paths_applies_extensions_and_deduplicates() -> None:
    paths = expand_paths(["admin", "/admin", "index.php"], extensions=(".php", ".bak"))
    assert paths == ["admin", "admin.php", "admin.bak", "index.php", "index.php.bak"]


def test_catch_all_pages_are_suppressed_regardless_of_status() -> None:
    def handler(url: str) -> FakeResponse:
        # Every path returns the same soft-200 page with a per-request nonce.
        return FakeResponse(200, "<h1>Nothing here</h1><p>trace 0123456789abcdef</p>", url)

    http = FakeHttp(handler)
    fuzzer = DirFuzzer(http, FakeConsole(), concurrency=4)
    fuzzer.words = ["admin", "api", "missing"]
    assert run(fuzzer.discover("https://target.test")) == []


def test_real_pages_are_kept_and_recursion_reaches_children() -> None:
    def handler(url: str) -> FakeResponse:
        path = url.split("target.test", 1)[1]
        if path.startswith("/admin"):
            return FakeResponse(200, "<h1>Admin console</h1><a href='/x'>menu</a>", url)
        if path.startswith("/api"):
            return FakeResponse(200, "<h1>API index</h1><p>docs</p>", url)
        return FakeResponse(404, "Not found", url)

    http = FakeHttp(handler)
    fuzzer = DirFuzzer(http, FakeConsole(), concurrency=4)
    fuzzer.words = ["admin", "api"]
    results = run(fuzzer.discover("https://target.test", recursive=True, max_depth=2))
    urls = sorted({item.url for item in results})
    # The child probe reuses the directory word list under each hit.
    assert "https://target.test/admin/admin" in urls
    assert "https://target.test/api/api" in urls
    assert len(urls) == len(set(urls))


def test_recursion_stops_at_max_depth() -> None:
    def handler(url: str) -> FakeResponse:
        path = urlsplit(url).path
        if path in {"/a", "/a/a"}:
            return FakeResponse(200, "<h1>Directory</h1><a href='/x'>menu</a>", url)
        return FakeResponse(404, "Not found", url)

    http = FakeHttp(handler)
    fuzzer = DirFuzzer(http, FakeConsole(), concurrency=4)
    fuzzer.words = ["a"]
    results = run(fuzzer.discover("https://target.test", recursive=True, max_depth=1))
    # Depth 1 probes /a/a but does not enqueue /a/a/ for a third level.
    urls = {item.url for item in results}
    assert "https://target.test/a" in urls
    assert "https://target.test/a/a" in urls
    assert "https://target.test/a/a/a" not in urls


def test_probes_are_never_sent_twice() -> None:
    def handler(url: str) -> FakeResponse:
        if url.endswith("/panel"):
            return FakeResponse(200, "<h1>Panel</h1><p>secret</p>", url)
        return FakeResponse(404, "Not found", url)

    http = FakeHttp(handler)
    fuzzer = DirFuzzer(http, FakeConsole(), concurrency=4)
    fuzzer.words = ["panel", "panel/"]
    run(fuzzer.discover("https://target.test", recursive=True, max_depth=2))
    probes = [url for url in http.calls if "/panel" in url]
    assert len(probes) == len(set(probes))


def test_errors_are_ignored_without_stopping_the_run() -> None:
    def handler(url: str) -> FakeResponse:
        if url.endswith("/broken"):
            return FakeResponse(200, "", url, error="timeout")
        if url.endswith("/ok"):
            return FakeResponse(200, "<h1>OK</h1><p>content</p>", url)
        return FakeResponse(404, "Not found", url)

    fuzzer = DirFuzzer(FakeHttp(handler), FakeConsole(), concurrency=2)
    fuzzer.words = ["broken", "ok"]
    results = run(fuzzer.discover("https://target.test"))
    assert [item.url for item in results] == ["https://target.test/ok"]
