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
    base = dict(
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
