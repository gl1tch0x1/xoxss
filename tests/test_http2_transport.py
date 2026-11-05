"""Tests for the optional curl_cffi HTTP/2 transport and its aiohttp fallback."""

import asyncio
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from xoxss.core import http as http_module
from xoxss.core.http import HttpEngine
from xoxss.scanner import Console, ScanStats


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    calls = Counter()

    def log_message(self, *_args):  # keep pytest output clean
        pass

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/redirect-out"):
            self._send(302, b"", {"Location": "https://example.com/elsewhere"})
            return
        if self.path.startswith("/redirect"):
            self._send(302, b"", {"Location": "/ok"})
            return
        if self.path.startswith("/big"):
            self._send(200, b"x" * 4096)
            return
        if self.path.startswith("/status/"):
            try:
                status = int(self.path.rsplit("/", 1)[-1])
            except ValueError:
                status = 500
            self._send(status, b"status")
            return
        if self.path.startswith("/counted"):
            _Handler.calls["counted"] += 1
            self._send(200, f"count={_Handler.calls['counted']}".encode())
            return
        self._send(200, b"<html>ok curl transport</html>")


@pytest.fixture()
def local_server():
    _Handler.calls.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _engine(**kwargs):
    return HttpEngine(Console(quiet=True), ScanStats(), retries=0, timeout=5.0, **kwargs)


def test_http2_flag_selects_curl_transport_when_available():
    if not http_module.CURL_AVAILABLE:
        pytest.skip("curl_cffi is not installed")
    engine = _engine(http2=True)
    assert engine.transport == "curl"


def test_impersonate_selects_curl_transport_when_available():
    if not http_module.CURL_AVAILABLE:
        pytest.skip("curl_cffi is not installed")
    engine = _engine(impersonate="chrome124")
    assert engine.transport == "curl"


def test_http2_falls_back_to_aiohttp_when_curl_missing(monkeypatch):
    monkeypatch.setattr(http_module, "CURL_AVAILABLE", False)
    engine = _engine(http2=True, impersonate="chrome124")
    assert engine.transport == "aiohttp"
    assert engine.http2 is False
    assert engine.impersonate is None


def test_invalid_impersonate_profile_falls_back_to_aiohttp(local_server):
    if not http_module.CURL_AVAILABLE:
        pytest.skip("curl_cffi is not installed")

    async def run():
        engine = _engine(impersonate="not-a-real-profile")
        try:
            return engine, await engine.get(f"{local_server}/ok")
        finally:
            await engine.close()

    engine, response = asyncio.run(run())
    assert engine.transport == "aiohttp"
    assert response.status == 200
    assert "ok curl transport" in response.text


def test_curl_transport_get_and_redirect(local_server):
    if not http_module.CURL_AVAILABLE:
        pytest.skip("curl_cffi is not installed")

    async def run():
        engine = _engine(http2=True, impersonate=None)
        try:
            direct = await engine.get(f"{local_server}/ok")
            redirect = await engine.get(f"{local_server}/redirect")
            return direct, redirect
        finally:
            await engine.close()

    direct, redirect = asyncio.run(run())
    assert direct.status == 200
    assert "ok curl transport" in direct.text
    assert direct.error is None
    assert redirect.status == 200
    assert redirect.url.endswith("/ok")


def test_curl_transport_truncates_large_bodies(local_server):
    if not http_module.CURL_AVAILABLE:
        pytest.skip("curl_cffi is not installed")

    async def run():
        engine = _engine(http2=True, max_response_bytes=1024)
        try:
            return await engine.get(f"{local_server}/big")
        finally:
            await engine.close()

    response = asyncio.run(run())
    assert response.status == 200
    assert response.truncated is True
    assert len(response.raw) == 1024


def test_curl_transport_cache_avoids_second_request(local_server):
    if not http_module.CURL_AVAILABLE:
        pytest.skip("curl_cffi is not installed")

    async def run():
        engine = _engine(http2=True)
        try:
            first = await engine.get(f"{local_server}/counted", cache=True)
            second = await engine.get(f"{local_server}/counted", cache=True)
            return first, second
        finally:
            await engine.close()

    first, second = asyncio.run(run())
    assert first.text == "count=1"
    assert second.text == "count=1"
    assert second.from_cache is True


def test_aiohttp_fallback_still_works(local_server, monkeypatch):
    monkeypatch.setattr(http_module, "CURL_AVAILABLE", False)

    async def run():
        engine = _engine(http2=True)
        try:
            return await engine.get(f"{local_server}/ok")
        finally:
            await engine.close()

    response = asyncio.run(run())
    assert response.status == 200
    assert "ok curl transport" in response.text


def test_curl_transport_out_of_scope_redirect_is_rejected(local_server):
    if not http_module.CURL_AVAILABLE:
        pytest.skip("curl_cffi is not installed")

    async def run():
        engine = _engine(http2=True)
        try:
            return await engine.get(f"{local_server}/redirect-out")
        finally:
            await engine.close()

    response = asyncio.run(run())
    assert response.status == 302
    assert "redirect target is outside" in (response.error or "")
