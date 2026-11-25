"""Post-scan probes and static DOM/postMessage analysis."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from xoxss.auto.probes import (
    AutoProbeRunner,
    analyze_dom_flows,
    analyze_postmessage,
    find_secrets,
)
from xoxss.auto.surface import SurfaceInventory


class FakeResponse:
    def __init__(
        self,
        url: str,
        *,
        status: int = 200,
        headers: Optional[Dict[str, str]] = None,
        text: str = "",
    ) -> None:
        self.url = url
        self.status = status
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}
        self.text = text
        self.error: Optional[str] = None

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class FakeHttp:
    def __init__(self) -> None:
        self.calls: List[str] = []

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(url)
        if "next=" in url and "xoxss.invalid" in url:
            return FakeResponse(
                url,
                status=302,
                headers={"location": "https://xoxss.invalid/"},
            )
        return FakeResponse(url, text="<html><body>ok</body></html>")

    async def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(url)
        return FakeResponse(url, status=404, text="not found")


def test_static_dom_flow_is_detected() -> None:
    html = (
        "<html><script>"
        "var q = location.hash; document.getElementById('x').innerHTML = q;"
        "</script></html>"
    )
    results = analyze_dom_flows(html, "https://t.test/")
    assert results
    assert results[0].kind.startswith("DOM XSS (static")
    assert results[0].confidence == "low"


def test_postmessage_without_origin_check_is_flagged() -> None:
    html = (
        "<script>window.addEventListener('message', function(e){"
        "document.body.innerHTML = e.data;});</script>"
    )
    results = analyze_postmessage(html, "https://t.test/")
    assert results
    assert "origin unchecked" in results[0].kind
    assert results[0].confidence == "medium"


def test_postmessage_with_origin_check_is_downgraded() -> None:
    html = (
        "<script>window.addEventListener('message', function(e){"
        "if (e.origin !== 'https://trusted.test') return;"
        "document.body.innerHTML = e.data;});</script>"
    )
    results = analyze_postmessage(html, "https://t.test/")
    assert results
    assert results[0].confidence == "low"


def test_secret_scanner_finds_aws_key() -> None:
    results = find_secrets("var key = 'AKIAABCDEFGHIJKLMNOP';", "https://t.test/app.js")
    assert results
    assert "AWS access key" in results[0].kind


def test_probe_runner_detects_open_redirect() -> None:
    surface = SurfaceInventory(
        target="https://t.test/",
        urls=["https://t.test/?next=/home"],
        parameters={"https://t.test/?next=/home": ["next"]},
    )
    http = FakeHttp()
    runner = AutoProbeRunner(
        http,
        _Console(),
        surface,
        budget=40,
        max_urls=1,
        concurrency=2,
    )
    results = asyncio.run(runner.run())
    assert any(result.kind == "Open redirect" for result in results)
    assert runner.requests > 0


class _MetaRefreshHttp:
    def __init__(self, content: str) -> None:
        self.content = content

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        return FakeResponse(
            url,
            text=f'<html><head><meta http-equiv="refresh" content="{self.content}"></head></html>',
        )


def test_meta_refresh_without_marker_is_not_an_open_redirect() -> None:
    surface = SurfaceInventory(target="https://t.test/", urls=["https://t.test/"])
    runner = AutoProbeRunner(
        _MetaRefreshHttp("0;url=/home"), _Console(), surface, budget=5
    )
    results: List[Any] = []
    asyncio.run(runner._probe_open_redirect("https://t.test/?next=/x", ["next"], results))
    assert results == []


def test_meta_refresh_with_marker_is_an_open_redirect() -> None:
    surface = SurfaceInventory(target="https://t.test/", urls=["https://t.test/"])
    runner = AutoProbeRunner(
        _MetaRefreshHttp("0;url=//xoxss.invalid/"), _Console(), surface, budget=5
    )
    results: List[Any] = []
    asyncio.run(runner._probe_open_redirect("https://t.test/?next=/x", ["next"], results))
    assert len(results) == 1
    assert results[0].kind == "Open redirect (meta refresh)"


class _Console:
    def info(self, *args: Any, **kwargs: Any) -> None:
        pass

    def warn(self, *args: Any, **kwargs: Any) -> None:
        pass

    def debug(self, *args: Any, **kwargs: Any) -> None:
        pass
