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
            "| # | Severity | Type | Method | Parameter | URL |",
            "|---|----------|------|--------|-----------|-----|",
        ]
        for index, finding in enumerate(scanner.findings, 1):
            url = finding.url.replace("|", "%7C")
            lines.append(
                f"| {index} | {finding.confidence} | {finding.kind} | {finding.method} | "
                f"`{finding.parameter}` | {url} |"
            )
        lines += ["", "## Details", ""]
        for index, finding in enumerate(scanner.findings, 1):
            lines += [
                f"### {index}. {finding.kind} ({finding.confidence})",
                "",
                f"- **URL:** {finding.url}",
                f"- **Parameter:** `{finding.parameter}` ({finding.method})",
                f"- **Context:** {finding.context or 'n/a'}",
                f"- **Evidence:** {finding.evidence or 'n/a'}",
                f"- **Detail:** {finding.detail or 'n/a'}",
            ]
            if finding.poc_url:
                lines.append(f"- **PoC URL:** {finding.poc_url}")
            else:
                lines.append("- **PoC URL:** n/a")
            if finding.poc_command:
                lines += ["", "```bash", finding.poc_command, "```", ""]
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
