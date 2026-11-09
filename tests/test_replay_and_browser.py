"""Replay helpers and smart headed/headless resolution."""

import asyncio
import json
import os
import sys
from types import SimpleNamespace
from urllib.parse import quote

from aiohttp import web

from xoxss.core.browser import (
    BrowserEngine,
    chromium_candidates,
    detect_chromium_binary,
    HOOK_JS,
)
from xoxss.scanner import (
    Console,
    Finding,
    _replay_request_args,
    _replay_token,
    load_replay_finding,
    reflection_confidence,
    resolve_headless,
    run_replay,
)
from xoxss.scan.reflection import ReflectionInfo


def _args(**overrides):
    defaults = dict(
        replay="",
        replay_report=None,
        report_dir=".",
        no_browser=False,
        headless=False,
        show_browser=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_load_replay_finding_matches_id_prefix(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "finding_id": "abc123def456",
                        "kind": "Reflected XSS",
                        "request": {"method": "GET", "url": "https://example.test/?q=1"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    args = _args(replay="abc123", replay_report=str(report))

    item, path, error = load_replay_finding(args)

    assert error == ""
    assert item["finding_id"] == "abc123def456"
    assert path == report


def test_load_replay_finding_reports_unknown_id(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"findings": [{"finding_id": "aaaa", "url": "https://example.test/"}]}),
        encoding="utf-8",
    )
    item, path, error = load_replay_finding(
        _args(replay="zzzz", replay_report=str(report))
    )

    assert item is None
    assert path == report
    assert "no finding matches" in error


def test_load_replay_finding_errors_without_reports(tmp_path):
    item, path, error = load_replay_finding(_args(replay="abc", report_dir=str(tmp_path)))

    assert item is None
    assert path is None
    assert "no JSON report" in error


def test_load_replay_finding_derives_ids_for_legacy_reports(tmp_path):
    legacy = {
        "kind": "Reflected XSS (HTTP evidence)",
        "url": "https://example.test/search?q=payload",
        "parameter": "q",
        "method": "GET",
        "payload": "<script>alert(1)</script>",
        "source": "query",
    }
    expected = Finding(**legacy).finding_id
    report = tmp_path / "legacy.json"
    report.write_text(json.dumps({"findings": [legacy]}), encoding="utf-8")

    item, path, error = load_replay_finding(
        _args(replay=expected[:8], replay_report=str(report))
    )

    assert error == ""
    assert item == legacy
    assert path == report


def test_run_replay_reproduces_an_http_finding_end_to_end(tmp_path):
    payload = "<script>alert(1)</script>"

    async def scenario() -> int:
        app = web.Application()

        async def handler(request: web.Request) -> web.Response:
            return web.Response(
                text=f"<html><body>{request.query.get('q', '')}</body></html>",
                content_type="text/html",
            )

        app.router.add_get("/", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        try:
            port = site._server.sockets[0].getsockname()[1]
            url = f"http://127.0.0.1:{port}/?q={quote(payload)}"
            report = tmp_path / "report.json"
            report.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "finding_id": "abc123def456",
                                "kind": "Reflected XSS (HTTP evidence)",
                                "url": url,
                                "parameter": "q",
                                "method": "GET",
                                "payload": payload,
                                "source": "query",
                                "request": {
                                    "method": "GET",
                                    "url": url,
                                    "headers": {},
                                    "body": "",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            args = _args(
                replay="abc123",
                replay_report=str(report),
                no_browser=True,
                confirm="http",
                timeout=5.0,
            )
            return await run_replay(args, Console(quiet=True))
        finally:
            await runner.cleanup()

    assert asyncio.run(scenario()) == 0


def test_replay_request_args_uses_structured_request():
    item = {
        "method": "POST",
        "url": "https://example.test/page",
        "request": {
            "method": "POST",
            "url": "https://example.test/api",
            "headers": {"Content-Type": "application/json", "Cookie": "[REDACTED]"},
            "body": '{"q":"<script>"}',
        },
    }

    method, url, headers, body = _replay_request_args(item)

    assert method == "POST"
    assert url == "https://example.test/api"
    assert headers == {"Content-Type": "application/json"}
    assert body == '{"q":"<script>"}'


def test_replay_request_args_falls_back_to_curl_poc():
    item = {
        "method": "GET",
        "url": "",
        "poc_curl": "curl -sk 'https://example.test/search?q=x' -H 'X-Test: yes'",
    }

    method, url, headers, _body = _replay_request_args(item)

    assert method == "GET"
    assert url == "https://example.test/search?q=x"
    assert headers["X-Test"] == "yes"


def test_replay_token_prefers_the_longest_marker():
    payload = "<img src=x onerror=window.__xoxss_hits.push('zabcdefghi')>"
    assert _replay_token(payload) == "zabcdefghi"
    assert _replay_token("<script>alert(1)</script>") == "<script>alert(1)</script>"


def test_replay_token_prefers_the_js_marker_comment_over_page_words():
    payload = (
        "<script>javascript:/*zabc123456*/"
        "window.__xoxss_hits.push('zabc123456')</script>"
    )

    assert _replay_token(payload) == "zabc123456"


def test_replay_token_decodes_a_fromcharcode_marker():
    payload = "String.fromCharCode(122,97,98,99,49,50,51,52,53,54)"

    assert _replay_token(payload) == "zabc123456"


def test_replay_token_ignores_a_payload_gadget_fromcharcode():
    payload = "String.fromCharCode(97,108,101,114,116);/*zabc123456*/"

    assert _replay_token(payload) == "zabc123456"


def _executable_info(**overrides):
    defaults = dict(
        reflected=True, context="html", executable=True, raw_specials=["<"]
    )
    defaults.update(overrides)
    return ReflectionInfo(**defaults)


def test_reflection_confidence_distinguishes_disabled_from_unconfirmed():
    disabled = reflection_confidence(
        _executable_info(), requested=False, available=True, content_type="text/html"
    )
    assert disabled[0] == "high"
    assert "disabled" in disabled[1]

    unavailable = reflection_confidence(
        _executable_info(), requested=True, available=False, content_type="text/html"
    )
    assert unavailable[0] == "high"
    assert "no browser worker" in unavailable[1]

    unconfirmed = reflection_confidence(
        _executable_info(), requested=True, available=True, content_type="text/html"
    )
    assert unconfirmed[0] == "medium"
    assert "did not observe execution" in unconfirmed[1]


def test_reflection_confidence_marks_gate_failures_and_inert_reflections():
    gated = reflection_confidence(
        _executable_info(context="json"),
        requested=True,
        available=True,
        content_type="text/html",
    )
    assert gated[0] == "medium"
    assert "prequalification" in gated[1]

    inert = reflection_confidence(
        ReflectionInfo(reflected=True, context="comment", executable=False),
        requested=True,
        available=True,
        content_type="text/html",
    )
    assert inert[0] == "low"


def test_resolve_headless_honours_explicit_flags(monkeypatch):
    args = _args()
    resolve_headless(args, {"--headless"})
    assert args.headless is True

    args = _args()
    resolve_headless(args, {"--show-browser"})
    assert args.headless is False

    args = _args(no_browser=True)
    resolve_headless(args, set())
    assert args.headless is True


def test_resolve_headless_keeps_a_preset_headless_choice(monkeypatch):
    # God mode pins headless internally; the TTY default must not reopen a
    # visible window behind the operator's back.
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(os, "name", "nt")
    args = _args(headless=True)

    resolve_headless(args, set())

    assert args.headless is True


def test_resolve_headless_defaults_to_headless_under_ci(monkeypatch):
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(isatty=lambda: True))
    args = _args()

    resolve_headless(args, set())

    assert args.headless is True


def test_resolve_headless_defaults_to_headed_on_an_interactive_terminal(monkeypatch):
    monkeypatch.delenv("CI", raising=False)
    for name in ("GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "TF_BUILD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(os, "name", "nt")
    args = _args()

    resolve_headless(args, set())

    assert args.headless is False


def test_chromium_candidates_honour_environment(monkeypatch, tmp_path):
    binary = tmp_path / "chromium"
    binary.write_text("", encoding="utf-8")
    monkeypatch.setenv("XOXSS_CHROMIUM", str(binary))

    candidates = chromium_candidates()

    assert candidates[0] == str(binary)
    assert detect_chromium_binary() == str(binary)


def test_hook_js_records_dom_paths():
    assert "describeNode" in HOOK_JS
    assert "dom_path" in HOOK_JS


def test_match_returns_sink_and_dom_path():
    data = {
        "hits": [],
        "alerts": [],
        "dialogs": [],
        "errors": [],
        "sinks": [
            {
                "sink": "innerHTML",
                "value": "TOKEN",
                "dom_path": "body > div#app > span:nth-child(2)",
            }
        ],
        "html": "<span>TOKEN</span>",
    }

    hit = BrowserEngine._match(data, "TOKEN")

    assert hit is not None
    assert hit["sink"] == "innerHTML"
    assert hit["dom_path"] == "body > div#app > span:nth-child(2)"
    assert hit["executed"] == "no"


def test_match_returns_none_without_the_token():
    assert BrowserEngine._match({"hits": ["other"], "html": ""}, "TOKEN") is None
