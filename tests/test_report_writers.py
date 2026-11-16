"""Report writers: structure, escaping and version consistency.

The writers only need a handful of scanner attributes, so a stub object keeps
these tests fast and free of network/browser dependencies while still exercising
the real rendering code.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import xoxss
from xoxss.core.finding import Finding, ScanStats
from xoxss.reports.common import VERSION
from xoxss.reports.html import write_html_report
from xoxss.reports.json import report_payload, write_json_report
from xoxss.reports.markdown import write_markdown_report
from xoxss.reports.sarif import build_sarif_document, sarif_rule_id, write_sarif_file

PAYLOAD = "<script>alert(1)</script>"


class StubWaf:
    def __init__(self) -> None:
        self.names: List[str] = ["Cloudflare"]
        self.blocking: bool = False

    def label(self) -> str:
        return "Cloudflare (not blocking)"


def make_finding() -> Finding:
    return Finding(
        kind="Reflected XSS",
        url="https://example.com/search?q=x",
        parameter="q",
        method="GET",
        payload=PAYLOAD,
        evidence="payload reflected verbatim",
        confidence="confirmed",
        context="html",
        poc_url=f"https://example.com/search?q={PAYLOAD}",
        request={"method": "GET", "url": "https://example.com/search?q=x", "headers": {"Cookie": "session=secret"}, "body": ""},
        char_matrix={"<": "raw", ">": "raw"},
    )


class StubScanner:
    """Everything the report renderers read from ``XSSScanner``."""

    def __init__(self) -> None:
        self.target = "https://example.com/?q=<x>"
        self.args = SimpleNamespace(
            no_browser=False,
            crawl=True,
            browser_discovery=True,
            stored=True,
            dom_source_probes=True,
            external_tools=True,
            auth_state=None,
            headers=None,
            cookies=None,
        )
        self.pool = SimpleNamespace(engines=[])
        self.stats = ScanStats()
        self.stats.requests = 17
        self.stats.urls_total = 3
        self.stats.urls_done = 3
        self.stats.payloads = 42
        self.stats.points = 5
        self.stats.errors = 1
        self.stats.urls_failed = 1
        self.state = SimpleNamespace(
            extra={
                "recon_errors": ["passive: timeout"],
                "browser_discovered_requests": [{"url": "https://example.com/api"}],
                "endpoint_sources": {},
                "external_parameters": {},
            },
            url_status={
                "https://example.com/": {"status": "ok"},
                "https://example.com/missing": {"status": "failed"},
            },
        )
        self.waf = StubWaf()
        self.endpoints = {"https://example.com/", "https://example.com/api"}
        self.mutation_findings = [
            {
                "name": "<b>wrap</b>",
                "parameter": "q",
                "url": "https://example.com/",
                "evidence": "reflection wrapped in <b>",
            }
        ]
        self.subdomains = ["a.example.com"]
        self.passive_urls = ["https://example.com/old"]
        self.api_operations: List[Any] = []
        self.external_summary: Dict[str, Any] = {}
        self.js_intel: List[Any] = []
        self.oob = SimpleNamespace(to_dict=lambda: {"enabled": True})
        self.external_findings: List[Any] = []
        self.vulnerable_libs = [
            SimpleNamespace(
                name="jquery",
                version="1.12.4",
                cve="CVE-2020-11022",
                severity="medium",
                url="https://example.com/<unsafe>",
            )
        ]
        self.jsonp_findings = [
            {
                "url": "https://example.com/jsonp",
                "callback_param": "cb",
                "poc_url": f"https://example.com/jsonp?cb={PAYLOAD}",
                "evidence": "callback reflected",
            }
        ]
        self.csp_issues = [{"url": "https://example.com/", "issues": ["unsafe-inline"]}]
        self.cors_issues = [{"url": "https://example.com/api", "issues": ["origin reflected"]}]
        self.proto_pollution_findings: List[Any] = []
        self.trusted_types_issues = [{"url": "https://example.com/", "issues": ["no policy"]}]
        self.dom_clobber_findings = [
            {
                "url": "https://example.com/",
                "type": "form",
                "property": "<clobber>",
                "element": "<img name=x>",
                "severity": "high",
            }
        ]
        self.postmessage_findings = [
            {
                "url": "https://example.com/app.js",
                "sink": "innerHTML",
                "origin_validated": False,
                "description": "no origin check",
            }
        ]
        self.websocket_findings = [
            {
                "url": "https://example.com/ws.js",
                "sink": "onmessage",
                "location": "<handler>",
                "description": "unsanitised frame",
            }
        ]
        self.file_upload_findings = [{"url": "https://example.com/upload?next=<x>"}]
        self.graphql_endpoints = [{"url": "https://example.com/graphql", "introspection": True}]
        self.blind_markers = [{"marker": "m1"}]
        self.findings = [make_finding()]


def test_json_report_has_expected_shape(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    write_json_report(path, StubScanner())  # type: ignore[arg-type]

    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["tool"] == "XOX$$"
    assert document["version"] == xoxss.__version__
    assert document["target"].startswith("https://example.com/")
    assert document["endpoint_count"] == 2
    assert document["waf"] == ["Cloudflare"]
    assert document["findings"][0]["payload"] == PAYLOAD
    assert document["verification"]["http_errors"] == 1
    assert document["coverage"]["url_status_counts"] == {"ok": 1, "failed": 1}
    assert document["coverage"]["failed_urls"][0]["url"].endswith("/missing")


def test_json_report_records_partial_coverage_notes() -> None:
    scanner = StubScanner()
    scanner.args.browser_discovery = False
    scanner.args.external_tools = False
    document = report_payload(scanner)  # type: ignore[arg-type]
    notes = "\n".join(document["coverage_notes"])
    assert "SPA route" in notes
    assert "external recon" in notes
    assert "recon source(s) failed" in notes
    assert "did not complete" in notes
    # Browser was requested but no worker started.
    assert "no browser worker" in notes


def test_json_report_serialises_but_does_not_escape() -> None:
    # JSON is a data format: the payload stays literal so tooling can replay it.
    document = report_payload(StubScanner())  # type: ignore[arg-type]
    assert document["findings"][0]["payload"] == PAYLOAD
    json.dumps(document)


def test_markdown_report_renders_sections(tmp_path: Path) -> None:
    path = tmp_path / "report.md"
    write_markdown_report(path, StubScanner())  # type: ignore[arg-type]
    text = path.read_text(encoding="utf-8")

    assert text.startswith("# XOX$$ scan report")
    assert "**Target:**" in text
    assert "## Coverage notes" in text
    assert "## Input transformation observations" in text
    assert "## Vulnerable JavaScript Libraries" in text
    assert "## JSONP XSS Findings" in text
    assert "## XSS Findings" in text
    assert "input transformation observations" in text.lower()


def test_html_report_escapes_attacker_controlled_data(tmp_path: Path) -> None:
    path = tmp_path / "report.html"
    write_html_report(path, StubScanner())  # type: ignore[arg-type]
    text = path.read_text(encoding="utf-8")

    assert text.startswith("<!DOCTYPE html>")
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "<img name=x>" not in text
    assert "&lt;img name=x&gt;" in text
    # A forged target must not break out of the title/header.
    assert "?q=<x>" not in text
    assert "?q=&lt;x&gt;" in text


def test_html_report_includes_coverage_notes(tmp_path: Path) -> None:
    scanner = StubScanner()
    scanner.args.no_browser = True
    path = tmp_path / "report.html"
    write_html_report(path, scanner)  # type: ignore[arg-type]
    text = path.read_text(encoding="utf-8")
    assert "Coverage notes" in text
    assert "Browser execution verification was disabled" in text


def test_sarif_rule_ids_are_stable_and_slugged() -> None:
    assert sarif_rule_id("Reflected XSS") == "xoxss/reflected-xss"
    assert sarif_rule_id("DOM XSS (innerHTML)") == "xoxss/dom-xss"
    assert sarif_rule_id("!!!").startswith("xoxss/")


def test_sarif_document_maps_confidence_to_level() -> None:
    confirmed = make_finding()
    low = make_finding()
    low.confidence = "low"
    document = build_sarif_document(
        [confirmed, low],
        target="https://example.com",
        waf_names=["Cloudflare"],
        duration_seconds=1.234,
        endpoint_count=2,
        truncated_responses=1,
        blind_markers=[{"marker": "m1"}],
    )

    run = document["runs"][0]
    assert document["version"] == "2.1.0"
    assert run["invocations"][0]["properties"]["target"] == "https://example.com"
    assert run["invocations"][0]["properties"]["truncatedResponses"] == 1
    assert [result["level"] for result in run["results"]] == ["error", "note"]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["xoxss/reflected-xss"]
    assert run["results"][0]["partialFingerprints"]["xoxssFinding/v1"]
    assert run["properties"]["blindMarkers"] == [{"marker": "m1"}]


def test_sarif_tool_version_tracks_package_by_default() -> None:
    # Regression: the default argument was the literal "2.0.0" and drifted.
    document = build_sarif_document([], target="https://example.com")
    assert document["runs"][0]["tool"]["driver"]["version"] == VERSION
    assert VERSION == xoxss.__version__


def test_sarif_writer_round_trips(tmp_path: Path) -> None:
    document = build_sarif_document([make_finding()], target="https://example.com")
    path = tmp_path / "report.sarif"
    write_sarif_file(path, document)
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == "2.1.0"
