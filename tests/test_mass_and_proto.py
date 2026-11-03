"""Tests for the mass mode, runtime prototype-pollution chain and packaging extras."""

import asyncio
import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from xoxss.analysis.proto_pollution import (
    build_proto_exploit,
    build_proto_probes,
    gadget_exploit_names,
)
from xoxss.scanner import (
    Console,
    PayloadEngine,
    XSSScanner,
    build_parser,
    run_doctor,
    run_mass,
)


# --------------------------------------------------------------------------------------
# Prototype pollution helpers
# --------------------------------------------------------------------------------------


def test_proto_probes_cover_query_and_fragment():
    probes = build_proto_probes("https://app.test/page?keep=1#route", "MARK1")
    assert len(probes) == 6
    parameters = {probe.parameter for _url, probe in probes}
    assert "__proto__[xoxss]" in parameters
    assert "constructor[prototype][xoxss]" in parameters

    query_urls = [url for url, probe in probes if probe.location == "query"]
    fragment_urls = [url for url, probe in probes if probe.location == "fragment"]
    assert all("keep=1" in url and "MARK1" in url for url in query_urls)
    assert all("#route" in url and "MARK1" in url for url in fragment_urls)
    assert all("keep=1" in url for url in fragment_urls)


def test_proto_gadget_exploit_urls_are_gadget_specific():
    url, pairs = build_proto_exploit("https://app.test/?x=1", "jQuery", "PG1")
    assert "__proto__%5Burl%5D" in url
    assert "data%3A" in url
    assert "__proto__%5BdataType%5D=script" in url
    assert len(pairs) == 2

    vue_url, vue_pairs = build_proto_exploit("https://app.test/", "Vue", "PG2")
    assert "__proto__%5Btemplate%5D" in vue_url
    assert any("alert" in value for _name, value in vue_pairs)

    assert build_proto_exploit("https://app.test/", "unknown", "PG3") == ("", [])


def test_gadget_name_mapping_deduplicates_and_ignores_unknowns():
    names = gadget_exploit_names(
        [
            {"name": "jQuery", "version": "3.7.1"},
            {"name": "Vue", "version": "2.7"},
            {"name": "NotAGadget"},
            "DOMPurify",
            {"name": "jQuery"},
        ]
    )
    assert names == ["jQuery", "Vue", "DOMPurify"]


def test_proto_pollution_without_browser_warns_once():
    scanner = object.__new__(XSSScanner)
    scanner.pool = None
    scanner._proto_warned = False
    scanner._proto_tested = set()

    class FakeConsole:
        def __init__(self):
            self.warnings = 0

        def warn(self, *_args, **_kwargs):
            self.warnings += 1

        def debug(self, *_args, **_kwargs):
            pass

    scanner.console = FakeConsole()
    asyncio.run(scanner.test_proto_pollution("https://app.test/"))
    asyncio.run(scanner.test_proto_pollution("https://app.test/"))
    assert scanner.console.warnings == 1


# --------------------------------------------------------------------------------------
# Mass mode against a local server
# --------------------------------------------------------------------------------------


VULNERABLE_PAGE = b"""<html><body>
<div id="out"></div>
<script>
(function () {
  var params = new URLSearchParams(location.search);
  var value = params.get('__proto__[xoxss]') || params.get('__proto__.xoxss');
  if (!value) { return; }
  function merge(target, source) {
    for (var key in source) {
      if (source[key] && typeof source[key] === 'object') {
        if (!target[key]) { target[key] = {}; }
        merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  merge({}, JSON.parse('{"__proto__":' + JSON.stringify({xoxss: value}) + '}'));
})();
</script>
</body></html>"""

SAFE_PAGE = b"""<html><body>
<script>
(function () {
  var params = new URLSearchParams(location.search);
  var value = params.get('__proto__[xoxss]') || params.get('__proto__.xoxss');
  var box = document.getElementById('out');
  if (box) { box.textContent = value || ''; }
})();
</script>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        values = [
            value
            for group in parse_qs(parts.query, keep_blank_values=True).values()
            for value in group
        ]
        query = "".join(values)
        if parts.path == "/vulnerable":
            body = VULNERABLE_PAGE
        elif parts.path == "/safe":
            body = SAFE_PAGE
        else:
            body = (
                f"<html><body><div id=out>{html.escape(query)}</div>"
                f"<div>{query}</div></body></html>"
            ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()


def _mass_args(target, jsonl, extra=()):
    return build_parser().parse_args(
        [
            target,
            "--mass",
            "--no-remote-payloads",
            "--quiet",
            "--jsonl",
            str(jsonl),
            "--timeout",
            "5",
            "--concurrency",
            "2",
            *extra,
        ]
    )


def test_mass_mode_reports_executable_reflection(server, tmp_path):
    jsonl = tmp_path / "hits.jsonl"
    args = _mass_args(f"{server}/?q=hello", jsonl)
    code, actionable = asyncio.run(run_mass(args, Console(quiet=True)))
    assert code == 0
    assert actionable >= 1
    rows = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines()]
    assert rows
    assert all(row["parameter"] == "q" for row in rows)
    assert all(row["kind"].startswith("Reflected XSS") for row in rows)
    assert rows[0]["confidence"] == "high"


def test_mass_mode_ignores_dom_only_reflections(server, tmp_path):
    safe_jsonl = tmp_path / "escaped.jsonl"
    # /safe writes the parameter through textContent, so the payload never
    # reaches HTML and must not be reported as reflected XSS.
    args = _mass_args(f"{server}/safe?q=hello", safe_jsonl)
    code, actionable = asyncio.run(run_mass(args, Console(quiet=True)))
    assert code == 0
    assert actionable == 0
    assert not safe_jsonl.read_text(encoding="utf-8").strip()


def test_mass_mode_adds_fallback_parameters(server, tmp_path):
    jsonl = tmp_path / "fallback.jsonl"
    args = _mass_args(f"{server}/search", jsonl)
    args.mass_params = "term,keyword"
    code, actionable = asyncio.run(run_mass(args, Console(quiet=True)))
    assert code == 0
    assert actionable >= 1
    rows = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines()]
    assert rows
    assert rows[0]["parameter"] == "term"


# --------------------------------------------------------------------------------------
# Prototype pollution, end to end in a real browser
# --------------------------------------------------------------------------------------


@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("playwright"),
    reason="playwright is not installed",
)
def test_proto_pollution_runtime_confirmation(server):
    from xoxss.core.browser import BrowserPool, PlaywrightEngine

    args = build_parser().parse_args(
        [
            f"{server}/vulnerable",
            "--quiet",
            "--no-state",
            "--no-remote-payloads",
            "--browser",
            "playwright",
            "--headless",
            "--proto-pollution",
        ]
    )
    scanner = XSSScanner(f"{server}/vulnerable", args, Console(quiet=True))
    scanner.pool = BrowserPool(
        scanner.console,
        1,
        lambda: PlaywrightEngine(
            scanner.console, kind="playwright", headless=True, page_timeout=15.0, insecure=True
        ),
    )

    async def scenario():
        started = await scanner.pool.start()
        if not started:
            pytest.skip("no browser available")
        try:
            await scanner.test_proto_pollution(f"{server}/vulnerable")
        finally:
            await scanner.pool.stop()

    asyncio.run(scenario())
    kinds = [finding.kind for finding in scanner.findings]
    assert any(kind.startswith("Prototype Pollution") for kind in kinds), kinds
    confirmed = [
        finding
        for finding in scanner.findings
        if finding.kind == "Prototype Pollution (confirmed)"
    ]
    assert confirmed
    assert "__proto__" in confirmed[0].parameter
    assert confirmed[0].evidence.startswith("Object.prototype.xoxss")


@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("playwright"),
    reason="playwright is not installed",
)
def test_proto_pollution_negative_control(server):
    pytest.importorskip("playwright.async_api")
    from xoxss.core.browser import BrowserPool, PlaywrightEngine

    args = build_parser().parse_args(
        [f"{server}/safe", "--quiet", "--no-state", "--no-remote-payloads", "--headless"]
    )
    scanner = XSSScanner(f"{server}/safe", args, Console(quiet=True))
    scanner.pool = BrowserPool(
        scanner.console,
        1,
        lambda: PlaywrightEngine(
            scanner.console, kind="playwright", headless=True, page_timeout=15.0, insecure=True
        ),
    )

    async def scenario():
        if not await scanner.pool.start():
            pytest.skip("no browser available")
        try:
            await scanner.test_proto_pollution(f"{server}/safe")
        finally:
            await scanner.pool.stop()

    asyncio.run(scenario())
    assert [finding for finding in scanner.findings if "Prototype" in finding.kind] == []


# --------------------------------------------------------------------------------------
# Payload corpus and doctor
# --------------------------------------------------------------------------------------


def test_payload_corpus_txt_json_and_directory(tmp_path):
    console = Console(quiet=True)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "nested").mkdir()
    (corpus / "set.txt").write_text(
        "# comment\nscript|<svg onload=alert(1)>\nplain<img src=x>\n", encoding="utf-8"
    )
    (corpus / "nested" / "set.json").write_text(
        json.dumps(
            [
                {"payload": "<iframe srcdoc=x>", "context": "html"},
                "url|javascript:alert(1)",
            ]
        ),
        encoding="utf-8",
    )
    engine = PayloadEngine(console, corpus_dirs=[str(corpus)])
    all_payloads = {payload for values in engine.payloads.values() for payload in values}
    assert "<svg onload=alert(1)>" in engine.payloads["script"]
    # Context-tagged payloads must also remain available to unknown contexts.
    assert "<svg onload=alert(1)>" in engine.payloads["generic"]
    assert "<iframe srcdoc=x>" in engine.payloads["html"]
    assert "javascript:alert(1)" in engine.payloads["url"]
    assert "plain<img src=x>" in all_payloads
    # A repeated load must not duplicate entries.
    before = len(engine.payloads["html"])
    engine._load_file(str(corpus / "nested" / "set.json"))
    assert len(engine.payloads["html"]) == before


def test_doctor_reports_ready_without_browser(tmp_path):
    args = build_parser().parse_args(
        [
            "--doctor",
            "--no-browser",
            "--state-dir",
            str(tmp_path / "state"),
            "--quiet",
        ]
    )
    assert run_doctor(Console(quiet=True), args) == 0


def test_packaging_metadata_declares_entry_point_and_extras():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'xoxss = "xoxss.scanner:main"' in pyproject
    assert 'interactsh = ["cryptography>=42"]' in pyproject
    assert 'requires-python = ">=3.9"' in pyproject
    assert not (root / "setup.py").exists()
