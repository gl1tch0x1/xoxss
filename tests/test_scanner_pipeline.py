"""In-process end-to-end coverage for the scanner coordinator."""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

from xoxss.core.config import ScanConfig
from xoxss.scan.injection import InjectionPoint
from xoxss.scan.reflection import analyze_reflection
from xoxss.scanner import XSSScanner
from xoxss.utils.console import Console


class ReflectionHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        value = parse_qs(parsed.query).get("q", [""])[0]
        if parsed.path == "/reflect":
            body = f"<main>{value}</main>"
        elif parsed.path == "/extended":
            body = (
                "<html><body>"
                "<my-widget data-x='1'></my-widget>"
                "<template id='t'><div></div></template>"
                "<script>document.execCommand('copy');</script>"
                "</body></html>"
            )
        elif parsed.path == "/escaped":
            import html

            body = f"<main>{html.escape(value)}</main>"
        else:
            body = "<main>fixture</main>"
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.fixture
def reflection_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ReflectionHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    ("path", "expect_finding"),
    [("/reflect?q=hello", True), ("/escaped?q=hello", False)],
)
def test_scanner_run_and_reports(
    reflection_server: str,
    tmp_path: Path,
    path: str,
    expect_finding: bool,
) -> None:
    report_dir = tmp_path / "reports"
    config = ScanConfig(
        target=reflection_server + path,
        no_browser=True,
        no_state=True,
        no_resume=True,
        remote_payloads=False,
        payload_catalog=False,
        lazy_payloads=False,
        discover=False,
        crawl=False,
        dom=False,
        ast_analysis=False,
        check_libs=False,
        threads=1,
        concurrency=2,
        max_payloads=8,
        timeout=3,
        retries=0,
        report="json",
        report_dir=str(report_dir),
        state_dir=str(tmp_path / "state"),
    )
    scanner = XSSScanner(
        config.target,
        config,
        Console(quiet=True, log_file=None),
    )

    findings = asyncio.run(scanner.run())

    assert bool(findings) is expect_finding
    assert scanner.http.session is None
    assert scanner.pool is None
    reports = list(report_dir.glob("*-latest.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    assert report["verification"]["browser_requested"] is False
    assert bool(report["findings"]) is expect_finding


class _FakeVuln:
    def __init__(self, **fields: object) -> None:
        self.__dict__.update(fields)


class _FakeDetector:
    """Stand-in for an extended detector returning canned vuln objects."""

    def __init__(self, vulns: list) -> None:
        self._vulns = vulns

    def scan_for_template_injection(self, *_args: object, **_kwargs: object) -> list:
        return list(self._vulns)


def _extended_config(target: str, tmp_path: Path, **overrides: object) -> ScanConfig:
    base: dict = dict(
        no_browser=True,
        no_state=True,
        no_resume=True,
        remote_payloads=False,
        payload_catalog=False,
        lazy_payloads=False,
        discover=False,
        crawl=False,
        dom=False,
        ast_analysis=False,
        check_libs=False,
        threads=1,
        concurrency=2,
        max_payloads=4,
        timeout=3,
        retries=0,
        report="json",
        report_dir=str(tmp_path / "reports"),
        state_dir=str(tmp_path / "state"),
    )
    base.update(overrides)
    return ScanConfig(target=target, **base)  # type: ignore[arg-type]


def test_extended_surface_analysis_emits_low_confidence_leads(
    reflection_server: str,
    tmp_path: Path,
) -> None:
    """Detector vulns must surface as deduplicated low-confidence leads."""
    vuln = _FakeVuln(
        severity="high",
        injection_point="template",
        context="html_body",
        payload="{{7*7}}",
        framework="jinja2",
    )
    config = _extended_config(reflection_server + "/extended", tmp_path)
    scanner = XSSScanner(config.target, config, Console(quiet=True, log_file=None))
    # Duplicate objects exercise the add_finding dedupe path.
    scanner.extended_detectors["template_injection"] = _FakeDetector([vuln, vuln])

    findings = asyncio.run(scanner.run())

    extended = [f for f in findings if f.source == "extended"]
    assert len(extended) == 1, "identical vulns must dedupe to one lead"
    finding = extended[0]
    assert finding.confidence == "low"
    assert finding.kind == "Template injection"
    assert finding.parameter == "template"
    assert "extended" in finding.tags
    assert finding.confidence_rationale
    assert "severity=high" in finding.detail


def test_extended_analysis_can_be_disabled(
    reflection_server: str,
    tmp_path: Path,
) -> None:
    vuln = _FakeVuln(
        severity="medium",
        injection_point="template",
        context="html_body",
        payload="{{7*7}}",
    )
    config = _extended_config(
        reflection_server + "/extended", tmp_path, extended_analysis=False
    )
    scanner = XSSScanner(config.target, config, Console(quiet=True, log_file=None))
    scanner.extended_detectors["template_injection"] = _FakeDetector([vuln])

    findings = asyncio.run(scanner.run())

    assert not [f for f in findings if f.source == "extended"]


# -- stored XSS verification -------------------------------------------------


class _StubResponse:
    def __init__(self, text: str, status: int = 200) -> None:
        self.text = text
        self.status = status
        self.error = ""

    def header(self, name: str, default: str = "") -> str:
        return "text/html; charset=utf-8" if name.lower() == "content-type" else default


class _StubHttp:
    """Minimal async HTTP stub keyed by URL -> queued responses."""

    def __init__(self, routes: dict) -> None:
        self._routes = {url: list(texts) for url, texts in routes.items()}
        self.calls: list = []

    async def get(self, url: str, **_kwargs: object) -> _StubResponse:
        self.calls.append(url)
        queue = self._routes.get(url)
        if not queue:
            return _StubResponse("<html><body>none</body></html>")
        text = queue.pop(0) if len(queue) > 1 else queue[0]
        return _StubResponse(text)


def _stored_scanner(tmp_path: Path, http: _StubHttp) -> XSSScanner:
    config = _extended_config(
        "http://127.0.0.1:9/submit", tmp_path, stored=True, stored_pages=5
    )
    scanner = XSSScanner(config.target, config, Console(quiet=True, log_file=None))
    scanner.http = http  # type: ignore[assignment]
    return scanner


_STORED_TOKEN = "ST0REDTOK3N"
_STORED_PAYLOAD = f"<script>alert('{_STORED_TOKEN}')</script>"
_STORED_PAGE_HTML = f"<html><body><script>alert('{_STORED_TOKEN}')</script></body></html>"


def test_check_stored_skips_urls_carrying_the_token(tmp_path: Path) -> None:
    """A candidate URL containing the payload reflects it trivially — that is
    request reflection, not persistence, and must not count as a stored hit."""
    contaminated = f"http://127.0.0.1:9/comments?q={_STORED_TOKEN}"
    http = _StubHttp({contaminated: [_STORED_PAGE_HTML]})
    scanner = _stored_scanner(tmp_path, http)
    point = InjectionPoint(
        url="http://127.0.0.1:9/submit",
        method="POST",
        param="comment",
        page_url=contaminated,
    )

    result = asyncio.run(
        scanner.check_stored(point, _STORED_TOKEN, _STORED_PAYLOAD)
    )

    assert result is None
    assert contaminated not in http.calls


def test_check_stored_stable_reflection(tmp_path: Path) -> None:
    """Executable reflection on two independent fetches = stable persistence."""
    page = "http://127.0.0.1:9/comments"
    http = _StubHttp({page: [_STORED_PAGE_HTML, _STORED_PAGE_HTML]})
    scanner = _stored_scanner(tmp_path, http)
    point = InjectionPoint(
        url="http://127.0.0.1:9/submit",
        method="POST",
        param="comment",
        page_url=page,
    )

    result = asyncio.run(
        scanner.check_stored(point, _STORED_TOKEN, _STORED_PAYLOAD)
    )

    assert result == page
    assert scanner._stored_hit_stable is True
    assert scanner._stored_hit_info is not None
    assert scanner._stored_hit_info.executable is True
    # Two fetches: initial check + stability re-check.
    assert http.calls.count(page) == 2


def test_check_stored_unstable_reflection(tmp_path: Path) -> None:
    """Reflection seen once but gone on re-fetch is flagged unstable."""
    page = "http://127.0.0.1:9/comments"
    clean = "<html><body>no marker here</body></html>"
    http = _StubHttp({page: [_STORED_PAGE_HTML, clean]})
    scanner = _stored_scanner(tmp_path, http)
    point = InjectionPoint(
        url="http://127.0.0.1:9/submit",
        method="POST",
        param="comment",
        page_url=page,
    )

    result = asyncio.run(
        scanner.check_stored(point, _STORED_TOKEN, _STORED_PAYLOAD)
    )

    # Hit is still reported (caller decides), but stability is recorded False.
    assert result == page
    assert scanner._stored_hit_stable is False


def test_failed_stored_check_does_not_poison_later_payloads(tmp_path: Path) -> None:
    """A payload that is not stored must not stop later payloads from being
    checked; otherwise a persisted later payload is mislabelled as reflected."""
    page = "http://127.0.0.1:9/comments"
    http = _StubHttp({page: ["<html><body>no marker</body></html>"]})
    scanner = _stored_scanner(tmp_path, http)
    point = InjectionPoint(
        url="http://127.0.0.1:9/submit",
        method="POST",
        param="comment",
        page_url=page,
    )
    info = analyze_reflection(
        "<html><body>no marker</body></html>",
        _STORED_TOKEN,
        _STORED_PAYLOAD,
        "text/html",
    )

    result = asyncio.run(
        scanner._test_stored_candidate(
            point,
            _STORED_PAYLOAD,
            _STORED_TOKEN,
            _StubResponse("<html><body>no marker</body></html>"),
            info,
        )
    )

    assert result is False
    assert point.key() not in scanner._stored_checked
    assert scanner._stored_attempts[point.key()] == 1


def test_confirm_in_browser_relabels_persisted_post_as_stored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Confirmed POST execution whose payload survives a fresh GET is stored
    XSS, never reflected XSS."""
    from types import SimpleNamespace

    from xoxss.core.finding import CONFIRMED_EXECUTION
    from xoxss.scan.reflection import analyze_reflection

    page = "http://127.0.0.1:9/comments"
    http = _StubHttp({page: [_STORED_PAGE_HTML]})
    scanner = _stored_scanner(tmp_path, http)
    point = InjectionPoint(
        url=page, method="POST", param="comment", page_url=page
    )
    info = analyze_reflection(
        _STORED_PAGE_HTML, _STORED_TOKEN, _STORED_PAYLOAD, "text/html"
    )

    async def fake_validate(*_args: object, **_kwargs: object) -> object:
        return SimpleNamespace(
            status=CONFIRMED_EXECUTION,
            evidence=f"js-executed: {_STORED_TOKEN}",
            dialog_text="",
            screenshot="",
        )

    monkeypatch.setattr(scanner, "validate_execution", fake_validate)

    finding = asyncio.run(
        scanner.confirm_in_browser(
            point, _STORED_PAYLOAD, _STORED_TOKEN, info, "text/html"
        )
    )

    assert finding is not None
    assert finding.kind == "Stored XSS (confirmed)"
    assert finding.url == page
    assert point.key() in scanner._stored_checked


# -- --min-confidence report filter -------------------------------------------


def test_min_confidence_filters_report_findings(tmp_path: Path) -> None:
    """The report floor hides low leads but never drops them from collection."""
    from xoxss.core.finding import Finding

    config = _extended_config("http://127.0.0.1:9/", tmp_path, min_confidence="high")
    scanner = XSSScanner(config.target, config, Console(quiet=True, log_file=None))
    for confidence in ("low", "medium", "high", "confirmed"):
        scanner.add_finding(
            Finding(
                kind=f"Test {confidence}",
                url="http://127.0.0.1:9/x",
                parameter="q",
                method="GET",
                payload="p",
                evidence="e",
                confidence=confidence,
                subkey=f"t-{confidence}",
                source="test",
            )
        )

    assert len(scanner.findings) == 4
    reported = scanner.report_findings
    assert {f.confidence for f in reported} == {"high", "confirmed"}

    # Report writers see the same filtered view.
    from xoxss.reports.common import iter_report_findings

    assert len(iter_report_findings(scanner)) == 2


def test_min_confidence_unset_returns_everything(tmp_path: Path) -> None:
    from xoxss.core.finding import Finding

    config = _extended_config("http://127.0.0.1:9/", tmp_path)
    scanner = XSSScanner(config.target, config, Console(quiet=True, log_file=None))
    scanner.add_finding(
        Finding(
            kind="Low lead",
            url="http://127.0.0.1:9/x",
            parameter="q",
            method="GET",
            payload="p",
            evidence="e",
            confidence="low",
            subkey="t-low",
            source="test",
        )
    )
    assert scanner.report_findings == scanner.findings


# -- mXSS / DOM-clobbering payload delivery ------------------------------------


def test_page_key_strips_query_and_fragment(tmp_path: Path) -> None:
    config = _extended_config("http://127.0.0.1:9/", tmp_path)
    scanner = XSSScanner(config.target, config, Console(quiet=True, log_file=None))
    assert (
        scanner._page_key("HTTP://Example.com:80/a/b?x=1#frag")
        == "http://example.com:80/a/b"
    )


def test_clobber_templates_match_point_page(tmp_path: Path) -> None:
    config = _extended_config("http://127.0.0.1:9/", tmp_path)
    scanner = XSSScanner(config.target, config, Console(quiet=True, log_file=None))
    scanner._clobber_props["http://127.0.0.1:9/page"] = {"location", "config"}
    point = InjectionPoint(
        url="http://127.0.0.1:9/page?q=1",
        method="GET",
        param="q",
        page_url="http://127.0.0.1:9/page",
    )

    templates = scanner._clobber_templates_for_point(point)

    assert len(templates) == 2
    assert all("{t}" in template for template in templates)
    assert any('id="location"' in template for template in templates)


def test_clobber_templates_empty_without_page_match(tmp_path: Path) -> None:
    config = _extended_config("http://127.0.0.1:9/", tmp_path)
    scanner = XSSScanner(config.target, config, Console(quiet=True, log_file=None))
    scanner._clobber_props["http://127.0.0.1:9/other"] = {"location"}
    point = InjectionPoint(
        url="http://127.0.0.1:9/page?q=1",
        method="GET",
        param="q",
        page_url="http://127.0.0.1:9/page",
    )
    assert scanner._clobber_templates_for_point(point) == []


def test_mxss_for_point_matches_page_url(tmp_path: Path) -> None:
    config = _extended_config("http://127.0.0.1:9/", tmp_path)
    scanner = XSSScanner(config.target, config, Console(quiet=True, log_file=None))
    sentinel = object()
    scanner._mxss_analysis["http://127.0.0.1:9/app"] = sentinel
    point = InjectionPoint(
        url="http://127.0.0.1:9/api/submit",
        method="POST",
        param="comment",
        page_url="http://127.0.0.1:9/app#main",
    )
    assert scanner._mxss_for_point(point) is sentinel
    assert scanner._mxss_for_point(
        InjectionPoint(url="http://127.0.0.1:9/none", method="GET", param="x")
    ) is None
