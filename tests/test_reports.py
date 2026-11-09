import json
from types import SimpleNamespace

from xoxss.reports.html import write_html_report
from xoxss.reports.json import write_json_report
from xoxss.reports.markdown import write_markdown_report
from xoxss.reports.sarif import build_sarif_document
from xoxss.scanner import Finding, ScanStats, WAFReport


def _scanner():
    return SimpleNamespace(
        args=SimpleNamespace(
            no_browser=True,
            crawl=False,
            browser_discovery=False,
            stored=False,
            dom_source_probes=False,
            external_tools=False,
            auth_state=None,
            headers=None,
            cookies=None,
        ),
        pool=None,
        stats=ScanStats(),
        target="https://example.test/",
        state=SimpleNamespace(extra={}, url_status={}),
        waf=WAFReport(),
        endpoints=set(),
        findings=[],
        mutation_findings=[
            {
                "name": "unicode<probe>",
                "url": "https://example.test/?q=1",
                "parameter": "q",
                "evidence": "observed <normalized> delimiter",
            }
        ],
        vulnerable_libs=[],
        jsonp_findings=[],
        csp_issues=[],
        cors_issues=[],
        trusted_types_issues=[],
        dom_clobber_findings=[],
        postmessage_findings=[],
        websocket_findings=[],
        file_upload_findings=[],
        graphql_endpoints=[],
        api_operations=[],
        subdomains=[],
        passive_urls=[],
        external_summary="",
        js_intel=[],
        external_findings=[],
        proto_pollution_findings=[],
        blind_markers=[],
        oob=None,
    )


def test_json_markdown_and_html_reports_include_transformation_observations(tmp_path):
    scanner = _scanner()
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    html_path = tmp_path / "report.html"

    write_json_report(json_path, scanner)
    write_markdown_report(markdown_path, scanner)
    write_html_report(html_path, scanner)

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["transformation_observations"][0]["name"] == "unicode<probe>"
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "Input transformation observations" in markdown
    assert "not XSS findings by themselves" in markdown
    html = html_path.read_text(encoding="utf-8")
    assert "&lt;probe&gt;" in html
    assert "&lt;normalized&gt;" in html
    assert "not XSS findings by themselves" in html


def _finding(screenshot: str = "") -> Finding:
    return Finding(
        kind="Reflected XSS",
        url="https://example.test/?q=x",
        parameter="q",
        method="GET",
        payload="<script>alert(1)</script>",
        evidence="executed in browser",
        confidence="confirmed",
        context="html",
        screenshot=screenshot,
    )


def test_html_report_embeds_screenshot_lightbox(tmp_path):
    shots = tmp_path / "screenshots"
    shots.mkdir()
    image = shots / "token.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n")

    scanner = _scanner()
    scanner.screenshot_dir = shots
    scanner.findings = [_finding(str(image))]
    path = tmp_path / "report.html"

    write_html_report(path, scanner)
    html = path.read_text(encoding="utf-8")

    # Thumbnail button + dialog lightbox markup, with a relative image URL.
    assert 'class="screenshot-thumb"' in html
    assert 'data-screenshot=' in html
    assert 'class="lightbox"' in html
    assert "token.png" in html
    assert "<img" in html
    # Findings table still renders, and the PoC block is intact.
    assert "Proof of Concept" in html


def test_html_report_falls_back_when_screenshot_is_outside_state_dir(tmp_path):
    shots = tmp_path / "screenshots"
    shots.mkdir()
    outside = tmp_path / "elsewhere" / "secret.png"
    outside.parent.mkdir()
    outside.write_bytes(b"\x89PNG\r\n\x1a\n")

    scanner = _scanner()
    scanner.screenshot_dir = shots
    scanner.findings = [_finding(str(outside))]
    path = tmp_path / "report.html"

    write_html_report(path, scanner)
    html = path.read_text(encoding="utf-8")

    # Never inline arbitrary local files: the path stays as escaped text.
    assert 'class="screenshot-thumb"' not in html
    assert "data-screenshot=" not in html
    assert "secret.png" in html


def test_html_report_creates_missing_report_directory(tmp_path):
    target = tmp_path / "nested" / "reports" / "report.html"
    write_html_report(target, _scanner())
    assert target.is_file()


def test_reports_render_request_response_sink_and_oob_evidence(tmp_path):
    finding = Finding(
        kind="Reflected XSS (HTTP evidence)",
        url="https://example.test/profile",
        parameter="bio",
        method="POST",
        payload="<img src=x onerror=alert(1)>",
        evidence="browser confirmed execution",
        confidence="confirmed",
        confidence_rationale="The marker reached an instrumented sink.",
        context="html",
        source="form",
        request={
            "method": "POST",
            "url": "https://example.test/profile",
            "headers": {"Cookie": "[REDACTED]", "Content-Type": "application/x-www-form-urlencoded"},
            "body": "bio=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E&csrf=%5BREDACTED%5D",
            "redacted": True,
        },
        response_status=200,
        response_excerpt="...<div><img src=x onerror=alert(1)></div>...",
        sink="innerHTML",
        dom_path="body > div#profile > img:nth-child(2)",
        oob={
            "callback": "https://oob.test/abc",
            "page_url": "https://victim.test/admin",
            "cookies": ["session=[REDACTED]"],
            "timestamp": "2026-11-07T10:00:00+00:00",
        },
    )
    scanner = _scanner()
    scanner.findings = [finding]
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    html_path = tmp_path / "report.html"

    write_json_report(json_path, scanner)
    write_markdown_report(markdown_path, scanner)
    write_html_report(html_path, scanner)

    data = json.loads(json_path.read_text(encoding="utf-8"))
    serialized = data["findings"][0]
    assert serialized["finding_id"] == finding.finding_id
    assert serialized["source"] == "form"
    assert serialized["request"]["headers"]["Cookie"] == "[REDACTED]"
    assert serialized["response_status"] == 200
    assert serialized["response_excerpt"].startswith("...<div>")
    assert serialized["sink"] == "innerHTML"
    assert serialized["dom_path"].startswith("body >")
    assert serialized["oob"]["page_url"] == "https://victim.test/admin"
    assert serialized["poc_curl"].startswith("curl")

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "Finding ID" in markdown
    assert "Request headers" in markdown
    assert "Response excerpt" in markdown
    assert "innerHTML" in markdown
    assert "OOB callback" in markdown
    assert "curl PoC" in markdown or "```bash" in markdown

    html = html_path.read_text(encoding="utf-8")
    assert "Finding ID" in html
    assert "Request headers" in html
    assert "Response excerpt" in html
    assert "innerHTML" in html
    assert "OOB callback" in html
    assert "curl PoC" in html

    result = build_sarif_document([finding], target="https://example.test/")[
        "runs"
    ][0]["results"][0]
    properties = result["properties"]
    assert properties["findingId"] == finding.finding_id
    assert properties["source"] == "form"
    assert properties["sink"] == "innerHTML"
    assert properties["domPath"].startswith("body >")
    assert properties["responseExcerpt"].startswith("...<div>")
    assert properties["request"]["headers"]["Cookie"] == "[REDACTED]"
    assert properties["oob"]["page_url"] == "https://victim.test/admin"
    assert properties["pocCurl"].startswith("curl")
