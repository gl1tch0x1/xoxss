"""Post-crawl fuzzing phase: seeds, budgets and queue integration."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from xoxss.core.finding import ScanStats
from xoxss.core.scope import Scope
from xoxss.scan.fuzz_phase import _directory_roots, run_fuzz_phase


class FakeResponse:
    def __init__(
        self,
        status: int = 200,
        text: str = "",
        url: str = "",
        error: Optional[str] = None,
    ) -> None:
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
    def __init__(self) -> None:
        self.lines: List[str] = []

    def rule(self, title: str) -> None:
        self.lines.append(title)

    def debug(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def info(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.lines.append(str(message))

    def ok(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.lines.append(str(message))

    def warn(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.lines.append(str(message))

    def error(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.lines.append(str(message))


class FakeScanner:
    def __init__(self, http: FakeHttp, endpoints: Optional[set] = None) -> None:
        self.http = http
        self.console = FakeConsole()
        self.scope = Scope("https://target.test")
        self.stats = ScanStats()
        self.endpoints = endpoints or set()
        self.state = SimpleNamespace(extra={})
        self._mined_params: Dict[str, List[str]] = {}
        self.discovered_param_names: List[str] = []
        self.args = SimpleNamespace(
            timeout=5.0,
            concurrency=4,
            endpoint_wordlist=None,
            fuzz_extensions=("",),
            fuzz_recursive=False,
            crawl_depth=2,
            fuzz_budget=50,
            fuzz_targets=1,
            fuzz_words=1,
            fuzz_param_targets=1,
            fuzz_param_limit=1,
        )
        self.recorded: List[tuple[str, str]] = []
        self.recon_errors: List[tuple[str, Exception]] = []

    def _record_endpoint(self, url: str, source: str = "crawl") -> None:
        self.recorded.append((url, source))

    def _record_recon_error(self, label: str, error: Exception) -> None:
        self.recon_errors.append((label, error))


def test_directory_roots_deduplicate_shallow_first() -> None:
    roots = _directory_roots(
        [
            "https://target.test/app/page",
            "https://target.test/app/other",
            "https://target.test/app/deep/page",
            "https://target.test/",
        ],
        limit=10,
    )
    assert roots[0] == "https://target.test/"
    assert roots.count("https://target.test/app/") == 1


def test_fuzz_phase_discovers_paths_and_hidden_parameters() -> None:
    def handler(url: str) -> FakeResponse:
        if url.endswith("/admin"):
            return FakeResponse(200, "<h1>Admin</h1><p>panel</p>", url)
        if "q=xoxss" in url:
            return FakeResponse(200, "<p>xoxss</p>", url)
        if "/app/page" in url:
            return FakeResponse(404, "Not found", url)
        return FakeResponse(404, "Not found", url)

    http = FakeHttp(handler)
    scanner = FakeScanner(http)

    new_urls = asyncio.run(
        run_fuzz_phase(scanner, ["https://target.test/app/page"])
    )

    assert "https://target.test/app/admin" in new_urls
    assert "https://target.test/app/page?q=1" in new_urls
    assert scanner.stats.fuzzed_paths == 1
    assert scanner.stats.discovered_params >= 1
    assert scanner.state.extra["fuzz_results"][0]["url"] == "https://target.test/app/admin"
    assert scanner._mined_params["https://target.test/app/page"] == ["q"]
    assert all(source == "fuzz" for _url, source in scanner.recorded)


def test_fuzz_phase_ignores_out_of_scope_candidates() -> None:
    http = FakeHttp(lambda url: FakeResponse(404, "Not found", url))
    scanner = FakeScanner(http, endpoints={"https://evil.invalid/app"})

    assert asyncio.run(run_fuzz_phase(scanner, ["https://evil.invalid/app"])) == []
    assert http.calls == []
