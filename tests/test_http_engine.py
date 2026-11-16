"""Integration tests for :class:`xoxss.core.http.HttpEngine`.

These exercise the real aiohttp transport against a loopback server started
inside the test, so retry/backoff, redirect scoping, truncation and caching are
covered without touching the network or the standalone benchmark fixtures.
"""

from __future__ import annotations

import asyncio
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterator, Tuple
from urllib.parse import urlsplit

import pytest

from xoxss.core.finding import ScanStats
from xoxss.core.http import HttpEngine, HttpResponse


class StubConsole:
    """Minimal console surface used by the HTTP engine."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def debug(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.messages.append(str(message))

    def info(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.messages.append(str(message))

    def warn(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.messages.append(str(message))

    def error(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.messages.append(str(message))

    def success(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.messages.append(str(message))


class _Handler(BaseHTTPRequestHandler):
    server_version = "XoxssTest/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    # -- helpers ---------------------------------------------------------
    def _send(
        self,
        body: bytes = b"",
        status: int = 200,
        content_type: str = "text/html; charset=utf-8",
        headers: Dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length else b""

    # -- routing ---------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        state = self.server.state  # type: ignore[attr-defined]

        if path == "/ok":
            self._send(b"ok")
        elif path == "/echo":
            payload = "|".join(
                [
                    self.headers.get("X-Test", ""),
                    self.headers.get("Cookie", ""),
                    self.headers.get("User-Agent", ""),
                ]
            )
            self._send(payload.encode("utf-8"))
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/redirect-external":
            self.send_response(302)
            self.send_header("Location", "https://example.invalid/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/redirect-loop":
            self.send_response(302)
            self.send_header("Location", "/redirect-loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/retry":
            state["retry_hits"] += 1
            if state["retry_hits"] <= state["retry_failures"]:
                self._send(b"busy", status=503, headers={"Retry-After": "0"})
            else:
                self._send(b"recovered")
        elif path == "/slow":
            time.sleep(0.8)
            self._send(b"slow")
        elif path == "/big":
            self._send(b"x" * 4096)
        else:
            self._send(b"missing", status=404)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        body = self._read_body()
        content_type = self.headers.get("Content-Type", "")
        if path == "/echo":
            payload = f"{content_type}\n{body.decode('utf-8', 'replace')}"
            self._send(payload.encode("utf-8"))
        else:
            self._send(b"missing", status=404)


class FixtureServer:
    """Loopback HTTP server with per-test counters."""

    def __init__(self) -> None:
        self.state: Dict[str, int] = {"retry_hits": 0, "retry_failures": 2}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        self.server.state = self.state  # type: ignore[attr-defined]
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.thread.start()

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def url(self, path: str) -> str:
        return self.base_url + path

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.fixture()
def fixture_server() -> Iterator[FixtureServer]:
    server = FixtureServer()
    try:
        yield server
    finally:
        server.close()


def run_case(scenario: Any, **engine_kwargs: Any) -> Tuple[Any, ScanStats]:
    """Run ``scenario(engine)`` against a started engine and return its result."""
    stats = ScanStats()

    async def runner() -> Any:
        engine = HttpEngine(StubConsole(), stats, **engine_kwargs)
        await engine.start()
        try:
            return await scenario(engine)
        finally:
            await engine.close()

    return asyncio.run(runner()), stats


def test_get_returns_body_status_and_headers(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(fixture_server.url("/ok"))

    result, stats = run_case(scenario)
    assert result.status == 200
    assert result.text == "ok"
    assert result.ok is True
    assert result.error is None
    assert result.header("content-type").startswith("text/html")
    assert result.request_method == "GET"
    assert stats.requests == 1


def test_extra_headers_cookies_and_user_agent_are_sent(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(
            fixture_server.url("/echo"),
            headers={"X-Test": "sentinel"},
        )

    result, _ = run_case(
        scenario,
        headers={"Accept-Language": "en"},
        cookies={"benchmark_session": "authorized"},
    )
    assert result.status == 200
    parts = result.text.split("|")
    assert parts[0] == "sentinel"
    assert "benchmark_session=authorized" in parts[1]
    assert parts[2].startswith("Mozilla/5.0")


def test_post_json_body_is_forwarded(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.post(
            fixture_server.url("/echo"),
            json_body={"q": "<script>alert(1)</script>"},
        )

    result, _ = run_case(scenario)
    assert result.status == 200
    assert "application/json" in result.text
    assert '"q": "<script>alert(1)</script>"' in result.text


def test_same_origin_redirect_is_followed(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(fixture_server.url("/redirect"))

    result, stats = run_case(scenario)
    assert result.status == 200
    assert result.text == "ok"
    assert result.url.endswith("/ok")
    # Both the redirect and the final hop are counted.
    assert stats.requests == 2


def test_external_redirect_is_refused(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(fixture_server.url("/redirect-external"))

    result, _ = run_case(scenario)
    assert result.status == 302
    assert "outside the request origin" in (result.error or "")


def test_redirect_loop_is_bounded(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(fixture_server.url("/redirect-loop"))

    result, _ = run_case(scenario)
    assert "too many redirects" in (result.error or "")


def test_redirect_scope_blocks_initial_request(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(fixture_server.url("/ok"))

    result, stats = run_case(scenario, redirect_scope=lambda _url: False)
    assert result.error == "request target is outside the configured scan scope"
    assert stats.errors == 1
    assert stats.requests == 0


def test_retry_status_is_retried_until_success(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(fixture_server.url("/retry"))

    result, stats = run_case(scenario, retries=2)
    assert result.status == 200
    assert result.text == "recovered"
    assert fixture_server.state["retry_hits"] == 3
    assert stats.blocked == 2


def test_retry_budget_exhaustion_returns_last_status(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(fixture_server.url("/retry"))

    fixture_server.state["retry_failures"] = 10
    result, stats = run_case(scenario, retries=1)
    assert result.status == 503
    assert result.text == "busy"
    assert stats.blocked == 1


def test_oversized_response_is_truncated(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(fixture_server.url("/big"))

    result, stats = run_case(scenario, max_response_bytes=1024)
    assert result.status == 200
    assert result.truncated is True
    assert len(result.raw) == 1024
    assert stats.truncated_responses == 1


def test_timeout_is_reported_as_an_error(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(fixture_server.url("/slow"))

    result, stats = run_case(scenario, timeout=0.2, retries=0)
    assert result.error is not None
    assert stats.errors == 1


def test_cache_avoids_duplicate_requests(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> Tuple[HttpResponse, HttpResponse]:
        first = await engine.get(fixture_server.url("/ok"), cache=True)
        second = await engine.get(fixture_server.url("/ok"), cache=True)
        return first, second

    (first, second), stats = run_case(scenario)
    assert first.from_cache is False
    assert second.from_cache is True
    assert second.text == first.text
    assert stats.requests == 1


def test_missing_path_returns_not_found(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(fixture_server.url("/missing"))

    result, _ = run_case(scenario)
    assert result.status == 404
    assert result.ok is False


def test_request_records_reproducible_details(fixture_server: FixtureServer) -> None:
    async def scenario(engine: HttpEngine) -> HttpResponse:
        return await engine.get(fixture_server.url("/echo"), headers={"X-Test": "kept"})

    result, _ = run_case(scenario)
    request = result.request_dict("q")
    assert request["method"] == "GET"
    assert request["url"].endswith("/echo")
    assert request["headers"].get("X-Test") == "kept"
