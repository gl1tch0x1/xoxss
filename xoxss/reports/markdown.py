"""Markdown scan report renderer."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from xoxss.reports.common import APP_NAME, fmt_duration
from xoxss.reports.json import report_payload

if TYPE_CHECKING:
    from xoxss.scanner import XSSScanner


def write_markdown_report(path: Path, scanner: XSSScanner) -> None:
    data = report_payload(scanner)
    lines = [
        f"# {APP_NAME} scan report",
        "",
        f"- **Target:** `{scanner.target}`",
        f"- **Finished:** {data['finished']}",
        f"- **Duration:** {fmt_duration(scanner.stats.elapsed)}",
        f"- **URLs scanned:** {scanner.stats.urls_done}/{scanner.stats.urls_total}",
        f"- **URLs failed:** {scanner.stats.urls_failed}",
        f"- **WAF:** {scanner.waf.label()}",
        f"- **Requests:** {scanner.stats.requests}",
        f"- **Endpoints discovered:** {len(scanner.endpoints)}",
        f"- **Injection points:** {scanner.stats.points}",
        f"- **Payloads sent:** {scanner.stats.payloads}",
        f"- **Vulnerable libraries:** {len(scanner.vulnerable_libs)}",
        f"- **JSONP findings:** {len(scanner.jsonp_findings)}",
        f"- **CSP issues:** {len(scanner.csp_issues)}",
        f"- **CORS issues:** {len(scanner.cors_issues)}",
        f"- **XSS Findings:** {len(scanner.findings)}",
        "",
    ]
    if data.get("coverage_notes"):
        lines += ["## Coverage notes", ""]
        lines.extend(f"- {note}" for note in data["coverage_notes"])
        lines.append("")
    if scanner.mutation_findings:
        lines += ["## Input transformation observations", ""]
        for item in scanner.mutation_findings[:100]:
            lines.append(
                f"- `{item['name']}` on `{item['parameter']}` at `{item['url']}`: {item['evidence']}"
            )
        lines += ["", "These observations are not XSS findings by themselves.", ""]

    if scanner.trusted_types_issues:
        lines += ["## Trusted Types issues", "",
                  "| # | URL | Issue |", "|---|-----|-------|"]
        for index, item in enumerate(scanner.trusted_types_issues, 1):
            lines.append(f"| {index} | {item['url']} | {'; '.join(item['issues'])} |")
        lines += [""]

    if scanner.dom_clobber_findings:
        lines += ["## DOM clobbering", "",
                  "| # | URL | Type | Property | Element | Severity |",
                  "|---|-----|------|----------|---------|----------|"]
        for index, item in enumerate(scanner.dom_clobber_findings, 1):
            lines.append(
                f"| {index} | {item['url']} | {item['type']} | {item['property']} "
                f"| {item['element'].replace('|', '%7C')} | {item['severity']} |"
            )
        lines += [""]

    if scanner.postmessage_findings:
        lines += ["## postMessage sinks", "",
                  "| # | Script | Sink | Origin validated | Description |",
                  "|---|--------|------|------------------|-------------|"]
        for index, item in enumerate(scanner.postmessage_findings, 1):
            origin = "yes" if item['origin_validated'] else "**no**"
            lines.append(
                f"| {index} | {item['url']} | {item['sink']} | {origin} "
                f"| {item['description'].replace('|', '%7C')} |"
            )
        lines += [""]

    if scanner.websocket_findings:
        lines += ["## WebSocket sinks", "",
                  "| # | Script | Sink | Snippet | Description |", "|---|--------|------|---------|-------------|"]
        for index, item in enumerate(scanner.websocket_findings, 1):
            lines.append(
                f"| {index} | {item['url']} | {item['sink']} "
                f"| {item['location'].replace('|', '%7C')} "
                f"| {item['description'].replace('|', '%7C')} |"
            )
        lines += [""]

    if scanner.file_upload_findings:
        lines += ["## File upload forms", ""]
        for item in scanner.file_upload_findings:
            lines.append(f"- {item['url']}")
        lines += [""]

    if scanner.graphql_endpoints:
        lines += ["## GraphQL endpoints", "",
                  "| # | URL | Introspection open |", "|---|-----|--------------------|"]
        for index, item in enumerate(scanner.graphql_endpoints, 1):
            lines.append(
                f"| {index} | {item['url']} | {'**yes**' if item['introspection'] else 'no'} |"
            )
        lines += [""]

    if scanner.vulnerable_libs:
        lines += [
            "## Vulnerable JavaScript Libraries",
            "",
            "| # | Library | Version | Severity | CVE | URL |",
            "|---|---------|---------|----------|-----|-----|",
        ]
        for index, lib in enumerate(scanner.vulnerable_libs, 1):
            url = lib.url.replace("|", "%7C")
            lines.append(
                f"| {index} | {lib.name} | {lib.version} | {lib.severity} | {lib.cve} | {url} |"
            )
        lines += [""]

    if scanner.jsonp_findings:
        lines += [
            "## JSONP XSS Findings",
            "",
            "| # | URL | Callback Parameter | PoC URL | Evidence |",
            "|---|-----|-------------------|---------|---------|",
        ]
        for index, finding in enumerate(scanner.jsonp_findings, 1):
            url = finding['url'].replace("|", "%7C")
            poc = str(finding.get('poc_url', '') or '').replace("|", "%7C")
            lines.append(
                f"| {index} | {url} | {finding['callback_param']} | {poc} | {finding['evidence'][:80]} |"
            )
        lines += [""]

    if scanner.csp_issues:
        lines += [
            "## CSP Bypass Opportunities",
            "",
            "| # | URL | Issues |",
            "|---|-----|-------|",
        ]
        for index, issue in enumerate(scanner.csp_issues, 1):
            url = issue['url'].replace("|", "%7C")
            issues_str = ", ".join(issue['issues'][:2])
            lines.append(f"| {index} | {url} | {issues_str} |")
        lines += [""]

    if scanner.cors_issues:
        lines += [
            "## CORS Misconfigurations",
            "",
            "| # | URL | Issues |",
            "|---|-----|-------|",
        ]
        for index, issue in enumerate(scanner.cors_issues, 1):
            url = issue['url'].replace("|", "%7C")
            issues_str = ", ".join(issue['issues'][:2])
            lines.append(f"| {index} | {url} | {issues_str} |")
        lines += [""]

    if scanner.findings:
        lines += [
            "## XSS Findings",
            "",
            "| # | ID | Severity | Type | Method | Parameter | URL |",
            "|---|----|----------|------|--------|-----------|-----|",
        ]
        for index, finding in enumerate(scanner.findings, 1):
            url = finding.url.replace("|", "%7C")
            lines.append(
                f"| {index} | `{finding.finding_id}` | {finding.confidence} | {finding.kind} | "
                f"{finding.method} | `{finding.parameter}` | {url} |"
            )
        lines += ["", "## Details", ""]
        for index, finding in enumerate(scanner.findings, 1):
            lines += [
                f"### {index}. {finding.kind} ({finding.confidence})",
                "",
                f"- **Finding ID:** `{finding.finding_id}`",
                f"- **URL:** {finding.url}",
                f"- **Parameter:** `{finding.parameter}` ({finding.method})",
                f"- **Source:** {finding.source or 'n/a'}",
                f"- **Context:** {finding.context or 'n/a'}",
                f"- **Evidence:** {finding.evidence or 'n/a'}",
                f"- **Confidence:** {finding.confidence_rationale or 'n/a'}",
                f"- **Detail:** {finding.detail or 'n/a'}",
            ]
            if finding.char_matrix:
                groups: dict = {}
                for char, status in finding.char_matrix.items():
                    groups.setdefault(status, []).append(char)
                rendered_matrix = "; ".join(
                    f"{status}: {''.join(chars)}" for status, chars in groups.items()
                )
                lines.append(f"- **Character matrix:** {rendered_matrix}")
            if finding.sink:
                lines.append(
                    f"- **Sink:** `{finding.sink}`"
                    + (f" at `{finding.dom_path}`" if finding.dom_path else "")
                )
            if finding.request:
                request = finding.request
                lines.append(
                    f"- **Request:** `{request.get('method', finding.method)} "
                    f"{request.get('url', finding.url)}`"
                )
                request_headers = request.get("headers") or {}
                if request_headers:
                    rendered = "; ".join(
                        f"{name}: {value}" for name, value in request_headers.items()
                    )
                    lines.append(f"- **Request headers:** `{rendered}`")
                if request.get("body"):
                    lines += ["", "```http", str(request["body"]), "```", ""]
            if finding.response_status:
                lines.append(f"- **Response status:** {finding.response_status}")
            if finding.response_excerpt:
                lines += ["", "**Response excerpt** (around the marker):", "", "```html", finding.response_excerpt, "```", ""]
            if finding.oob:
                oob = finding.oob
                lines.append(f"- **OOB callback:** {oob.get('callback', 'n/a')}")
                if oob.get("page_url"):
                    lines.append(f"- **Callback page URL:** {oob['page_url']}")
                if oob.get("cookies"):
                    lines.append(f"- **Callback cookies:** {'; '.join(oob['cookies'])}")
                if oob.get("timestamp"):
                    lines.append(f"- **Callback time:** {oob['timestamp']}")
            if finding.poc_url:
                lines.append(f"- **PoC URL:** {finding.poc_url}")
            else:
                lines.append("- **PoC URL:** n/a")
            if finding.poc_curl:
                lines += ["", "```bash", finding.poc_curl, "```", ""]
            elif finding.poc_command:
                lines += ["", "```bash", finding.poc_command, "```", ""]
            if finding.poc_html:
                lines.append(
                    "- **Browser form PoC:** base64 data URL "
                    f"({len(finding.poc_html)} chars) included in the JSON report"
                )
            lines += [
                f"- **Screenshot:** {finding.screenshot or 'n/a'}",
                "",
                "```html",
                finding.payload,
                "```",
                "",
            ]
    else:
        lines.append("No XSS findings.")
    path.write_text("\n".join(lines), encoding="utf-8")
