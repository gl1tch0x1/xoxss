import json
from types import SimpleNamespace

from xoxss.reports.html import write_html_report
from xoxss.reports.json import write_json_report
from xoxss.reports.markdown import write_markdown_report
from xoxss.scanner import ScanStats, WAFReport


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
