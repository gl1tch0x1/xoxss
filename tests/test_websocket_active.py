"""Tests for active WebSocket frame injection."""

import asyncio
import socket

import pytest

pytest.importorskip("aiohttp")

from aiohttp import WSMsgType, web

from xoxss.analysis.websocket import (
    WebSocketActiveProbe,
    extract_websocket_urls,
    websocket_http_equivalent,
)


def _console():
    class Console:
        def info(self, *args, **kwargs):
            pass

        def warn(self, *args, **kwargs):
            pass

        def debug(self, *args, **kwargs):
            pass

        def ok(self, *args, **kwargs):
            pass

    return Console()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def _echo(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    async for message in ws:
        if message.type == WSMsgType.TEXT:
            await ws.send_str(message.data)
        elif message.type == WSMsgType.ERROR:
            break
    return ws


async def _silent(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    async for message in ws:  # consume frames without replying
        if message.type == WSMsgType.ERROR:
            break
    return ws


async def _run_server(handler):
    app = web.Application()
    app.router.add_get("/ws", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"ws://127.0.0.1:{port}/ws"


def test_active_probe_records_reflection():
    async def scenario():
        runner, url = await _run_server(_echo)
        try:
            probe = WebSocketActiveProbe(_console(), timeout=5.0, frame_timeout=0.5)
            marker = "wsmarker123"
            hits = await probe.probe(url, markers=[marker])
            return url, marker, hits
        finally:
            await runner.cleanup()

    url, marker, hits = asyncio.run(scenario())
    assert hits
    hit = hits[0]
    assert hit.error == ""
    assert hit.reflected is True
    assert marker in hit.response
    assert hit.url == url
    assert "reflected" in hit.evidence.lower()
    # The echo wraps the marker in ``<script>`` inside a JSON body, so the
    # marker is genuinely in script context.
    assert hit.context in ("html", "json", "script", "unknown")


def test_active_probe_does_not_claim_reflection_without_echo():
    async def scenario():
        runner, url = await _run_server(_silent)
        try:
            probe = WebSocketActiveProbe(_console(), timeout=5.0, frame_timeout=0.2)
            return await probe.probe(url, markers=["absent-marker"])
        finally:
            await runner.cleanup()

    hits = asyncio.run(scenario())
    assert hits
    assert all(hit.reflected is False for hit in hits)
    assert all("not reflected" in hit.evidence for hit in hits)


def test_active_probe_reports_connection_failure():
    async def scenario():
        probe = WebSocketActiveProbe(_console(), timeout=3.0, frame_timeout=0.2)
        return await probe.probe(
            f"ws://127.0.0.1:{_free_port()}/ws", markers=["marker"]
        )

    hits = asyncio.run(scenario())
    assert hits
    assert hits[0].reflected is False
    assert hits[0].error


def test_active_probe_requires_markers():
    async def scenario():
        probe = WebSocketActiveProbe(_console(), timeout=1.0)
        return await probe.probe("ws://127.0.0.1:1/ws", markers=[])

    assert asyncio.run(scenario()) == []


def test_extract_websocket_urls_resolves_relative_endpoints():
    js = (
        "var a = new WebSocket('wss://socket.example.test/live');\n"
        "var b = new WebSocket('/ws/root');\n"
        "var c = new WebSocket('//edge.example.test/stream');\n"
        "var d = new WebSocket('relative/socket');\n"
        "var e = new WebSocket(`tmpl`);\n"
    )
    urls = extract_websocket_urls(js, "https://app.example.test/app/page.js")
    assert "wss://socket.example.test/live" in urls
    assert "wss://app.example.test/ws/root" in urls
    assert "wss://edge.example.test/stream" in urls
    assert "wss://app.example.test/app/relative/socket" in urls
    assert all("tmpl" not in url for url in urls)


def test_extract_websocket_urls_uses_ws_for_http_pages():
    urls = extract_websocket_urls("new WebSocket('/feed')", "http://app.test/index.html")
    assert urls == ["ws://app.test/feed"]


def test_websocket_http_equivalent_maps_scheme():
    assert websocket_http_equivalent("wss://app.test/socket?x=1") == "https://app.test/socket?x=1"
    assert websocket_http_equivalent("ws://app.test:8080/socket") == "http://app.test:8080/socket"
    assert websocket_http_equivalent("wss://app.test") == "https://app.test/"
