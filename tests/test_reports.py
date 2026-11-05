import json
from types import SimpleNamespace

from xoxss.reports.html import write_html_report
from xoxss.reports.json import write_json_report
from xoxss.reports.markdown import write_markdown_report
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
