"""Self-contained HTML scan report renderer."""

from __future__ import annotations

import html as html_lib
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, List
from urllib.parse import quote

from xoxss.reports.common import APP_NAME, VERSION, fmt_duration, now_iso, truncate
from xoxss.reports.json import report_payload

if TYPE_CHECKING:
    from xoxss.scanner import XSSScanner


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 32px; background: #0b0f14; color: #d7e0ea;
         font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  h1 { font-size: 22px; margin: 0 0 4px; color: #6ee7ff; letter-spacing: 1px; }
  .sub { color: #7c8b9c; margin-bottom: 24px; font-size: 13px; }
  .cards { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 24px; }
  .card { background: #121922; border: 1px solid #1e2a37; border-radius: 8px; padding: 10px 16px; }
  .card .k { font-size: 11px; color: #7c8b9c; text-transform: uppercase; letter-spacing: 1px; }
  .card .v { font-size: 16px; margin-top: 2px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #1e2a37; vertical-align: top; }
  th { color: #7c8b9c; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
  tr:hover td { background: #10171f; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }
  .confirmed { background: #064e3b; color: #6ee7b7; }
  .high { background: #14532d; color: #86efac; }
  .medium { background: #78350f; color: #fcd34d; }
  .low { background: #334155; color: #cbd5e1; }
  code { color: #93c5fd; word-break: break-all; }
  .poc-block { background: #121922; border: 1px solid #1e2a37; border-radius: 8px;
               padding: 12px 16px 4px; margin-bottom: 8px; break-inside: avoid; }
  .poc-block h3 { font-size: 14px; color: #6ee7ff; margin: 4px 0 10px; }
  .poc-block table { table-layout: fixed; }
  .poc-block th { width: 140px; }
  .screenshot-thumb { display: block; max-width: min(720px, 100%); padding: 0; border: 1px solid #26384b;
                      border-radius: 6px; background: #0b0f14; cursor: zoom-in; overflow: hidden; }
  .screenshot-thumb img { display: block; max-width: 100%; max-height: 280px; object-fit: contain; }
  .screenshot-thumb:focus-visible, .lightbox-close:focus-visible { outline: 2px solid #6ee7ff; outline-offset: 3px; }
  .screenshot-caption { margin-top: 6px; color: #7c8b9c; font-size: 11px; }
  .lightbox { width: min(96vw, 1500px); max-width: none; max-height: 94vh; padding: 44px 12px 12px;
              border: 1px solid #334155; border-radius: 8px; background: #080b10; color: #d7e0ea; }
  .lightbox::backdrop { background: rgb(0 0 0 / 84%); }
  .lightbox img { display: block; max-width: 100%; max-height: calc(94vh - 64px); margin: auto; object-fit: contain; }
  .lightbox-close { position: absolute; top: 8px; right: 10px; padding: 6px 10px; border: 1px solid #334155;
                    border-radius: 5px; background: #121922; color: #d7e0ea; cursor: pointer; }
  .empty { padding: 24px; border: 1px dashed #1e2a37; border-radius: 8px; color: #7c8b9c; }
  footer { margin-top: 28px; color: #55657a; font-size: 12px; }
</style>
</head>
<body>
<h1>__TITLE__</h1>
<div class="sub">Target <code>__TARGET__</code> &middot; generated __DATE__ by __APPNAME__ v__VERSION__</div>
<div class="cards">__CARDS__</div>
__CONTENT__
<dialog class="lightbox" id="screenshot-lightbox" aria-label="Expanded browser evidence screenshot">
  <button class="lightbox-close" type="button" aria-label="Close screenshot">Close</button>
  <img alt="Expanded browser evidence screenshot">
</dialog>
<script>
(() => {
  const dialog = document.getElementById('screenshot-lightbox');
  if (!dialog) return;
  const image = dialog.querySelector('img');
  document.addEventListener('click', (event) => {
    const trigger = event.target.closest('[data-screenshot]');
    if (trigger) {
      image.src = trigger.dataset.screenshot;
      dialog.showModal();
    } else if (event.target.closest('.lightbox-close')) {
      dialog.close();
    }
  });
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.addEventListener('close', () => { image.removeAttribute('src'); });
})();
</script>
<footer>Automated result. Manually validate every finding before reporting.</footer>
</body>
</html>
"""


def _card(label: str, value: Any) -> str:
    return f'<div class="card"><div class="k">{html_lib.escape(str(label))}</div><div class="v">{html_lib.escape(str(value))}</div></div>'


def write_html_report(path: Path, scanner: XSSScanner) -> None:
    cards = "".join(
        [
            _card("Duration", fmt_duration(scanner.stats.elapsed)),
            _card("URLs", f"{scanner.stats.urls_done}/{scanner.stats.urls_total}"),
            _card("URLs failed", scanner.stats.urls_failed),
            _card("Endpoints", len(scanner.endpoints)),
            _card("Requests", scanner.stats.requests),
            _card("Payloads", scanner.stats.payloads),
            _card("WAF", scanner.waf.label()),
            _card("Vulnerable libs", len(scanner.vulnerable_libs)),
            _card("JSONP", len(scanner.jsonp_findings)),
            _card("CSP issues", len(scanner.csp_issues)),
            _card("CORS issues", len(scanner.cors_issues)),
            _card("Trusted Types", len(scanner.trusted_types_issues)),
            _card("DOM clobbering", len(scanner.dom_clobber_findings)),
            _card("postMessage", len(scanner.postmessage_findings)),
            _card("WebSocket", len(scanner.websocket_findings)),
            _card("Upload forms", len(scanner.file_upload_findings)),
            _card("GraphQL", len(scanner.graphql_endpoints)),
            _card("XSS Findings", len(scanner.findings)),
        ]
    )

    content_parts = []

    coverage_notes = report_payload(scanner).get("coverage_notes", [])
    if coverage_notes:
        content_parts.append(
            "<h2>Coverage notes</h2><ul>"
            + "".join(f"<li>{html_lib.escape(str(note))}</li>" for note in coverage_notes)
            + "</ul>"
        )

    if scanner.mutation_findings:
        rows = "".join(
            "<li><code>" + html_lib.escape(str(item.get("name", "")))
            + "</code> on <code>" + html_lib.escape(str(item.get("parameter", "")))
            + "</code>: " + html_lib.escape(str(item.get("evidence", ""))) + "</li>"
            for item in scanner.mutation_findings[:100]
        )
        content_parts.append(
            "<h2>Input transformation observations</h2><ul>" + rows + "</ul>"
            "<p>These observations are not XSS findings by themselves.</p>"
        )

    if scanner.vulnerable_libs:
        lib_rows = []
        for lib in scanner.vulnerable_libs:
            lib_rows.append(
                "<tr>"
                f'<td><span class="badge {html_lib.escape(lib.severity)}">'
                f"{html_lib.escape(lib.severity)}</span></td>"
                f"<td>{html_lib.escape(lib.name)}</td>"
                f"<td>{html_lib.escape(lib.version)}</td>"
                f"<td>{html_lib.escape(lib.cve)}</td>"
                f"<td><code>{html_lib.escape(truncate(lib.url, 300))}</code></td>"
                "</tr>"
            )
        content_parts.append(
            "<h2>Vulnerable JavaScript Libraries</h2>"
            "<table><thead><tr><th>Severity</th><th>Library</th><th>Version</th><th>CVE</th><th>URL</th></tr></thead>"
            "<tbody>" + "".join(lib_rows) + "</tbody></table>"
        )

    if scanner.jsonp_findings:
        jsonp_rows = []
        for finding in scanner.jsonp_findings:
            jsonp_rows.append(
                "<tr>"
                f"<td><code>{html_lib.escape(truncate(finding['url'], 300))}</code></td>"
                f"<td>{html_lib.escape(finding['callback_param'])}</td>"
                f"<td><code>{html_lib.escape(truncate(finding.get('poc_url', ''), 300))}</code></td>"
                f"<td>{html_lib.escape(truncate(finding['evidence'], 300))}</td>"
                "</tr>"
            )
        content_parts.append(
            "<h2>JSONP XSS Findings</h2>"
            "<table><thead><tr><th>URL</th><th>Callback Parameter</th><th>PoC URL</th><th>Evidence</th></tr></thead>"
            "<tbody>" + "".join(jsonp_rows) + "</tbody></table>"
        )

    if scanner.csp_issues:
        csp_rows = []
        for issue in scanner.csp_issues:
            issues_str = html_lib.escape(", ".join(issue['issues'][:2]))
            csp_rows.append(
                "<tr>"
                f"<td><code>{html_lib.escape(truncate(issue['url'], 300))}</code></td>"
                f"<td>{issues_str}</td>"
                "</tr>"
            )
        content_parts.append(
            "<h2>CSP Bypass Opportunities</h2>"
            "<table><thead><tr><th>URL</th><th>Issues</th></tr></thead>"
            "<tbody>" + "".join(csp_rows) + "</tbody></table>"
        )

    if scanner.cors_issues:
        cors_rows = []
        for issue in scanner.cors_issues:
            issues_str = html_lib.escape(", ".join(issue['issues'][:2]))
            cors_rows.append(
                "<tr>"
                f"<td><code>{html_lib.escape(truncate(issue['url'], 300))}</code></td>"
                f"<td>{issues_str}</td>"
                "</tr>"
            )
        content_parts.append(
            "<h2>CORS Misconfigurations</h2>"
            "<table><thead><tr><th>URL</th><th>Issues</th></tr></thead>"
            "<tbody>" + "".join(cors_rows) + "</tbody></table>"
        )

    if scanner.trusted_types_issues:
        tt_rows = []
        for item in scanner.trusted_types_issues:
            tt_rows.append(
                "<tr>"
                f"<td><code>{html_lib.escape(truncate(item['url'], 300))}</code></td>"
                f"<td>{html_lib.escape(' | '.join(item['issues'][:3]))}</td>"
                "</tr>"
            )
        content_parts.append(
            "<h2>Trusted Types Issues</h2>"
            "<table><thead><tr><th>URL</th><th>Issues</th></tr></thead>"
            "<tbody>" + "".join(tt_rows) + "</tbody></table>"
        )

    if scanner.dom_clobber_findings:
        clob_rows = []
        for item in scanner.dom_clobber_findings:
            clob_rows.append(
                "<tr>"
                f'<td><span class="badge {html_lib.escape(item["severity"])}">'
                f"{html_lib.escape(item['severity'])}</span></td>"
                f"<td>{html_lib.escape(item['type'])}</td>"
                f"<td><code>{html_lib.escape(item['property'])}</code></td>"
                f"<td><code>{html_lib.escape(truncate(item['element'], 160))}</code></td>"
                f"<td><code>{html_lib.escape(truncate(item['url'], 300))}</code></td>"
                "</tr>"
            )
        content_parts.append(
            "<h2>DOM Clobbering</h2>"
            "<table><thead><tr><th>Severity</th><th>Type</th><th>Property</th>"
            "<th>Element</th><th>URL</th></tr></thead>"
            "<tbody>" + "".join(clob_rows) + "</tbody></table>"
        )

    if scanner.postmessage_findings:
        pm_rows = []
        for item in scanner.postmessage_findings:
            origin = "yes" if item['origin_validated'] else '<span class="badge high">no</span>'
            pm_rows.append(
                "<tr>"
                f"<td><code>{html_lib.escape(truncate(item['url'], 300))}</code></td>"
                f"<td>{html_lib.escape(item['sink'])}</td>"
                f"<td>{origin}</td>"
                f"<td>{html_lib.escape(truncate(item['description'], 220))}</td>"
                "</tr>"
            )
        content_parts.append(
            "<h2>postMessage Sinks</h2>"
            "<table><thead><tr><th>Script</th><th>Sink</th><th>Origin Validated</th>"
            "<th>Description</th></tr></thead>"
            "<tbody>" + "".join(pm_rows) + "</tbody></table>"
        )

    if scanner.websocket_findings:
        ws_rows = []
        for item in scanner.websocket_findings:
            ws_rows.append(
                "<tr>"
                f"<td><code>{html_lib.escape(truncate(item['url'], 300))}</code></td>"
                f"<td>{html_lib.escape(item['sink'])}</td>"
                f"<td><code>{html_lib.escape(truncate(item['location'], 200))}</code></td>"
                f"<td>{html_lib.escape(truncate(item['description'], 220))}</td>"
                "</tr>"
            )
        content_parts.append(
            "<h2>WebSocket Sinks</h2>"
            "<table><thead><tr><th>Script</th><th>Sink</th><th>Location</th>"
            "<th>Description</th></tr></thead>"
            "<tbody>" + "".join(ws_rows) + "</tbody></table>"
        )

    if scanner.file_upload_findings:
        upload_rows = []
        for item in scanner.file_upload_findings:
            upload_rows.append(
                f'<tr><td><code>{html_lib.escape(truncate(item["url"], 300))}</code></td></tr>'
            )
        content_parts.append(
            "<h2>File Upload Forms</h2>"
            "<table><thead><tr><th>URL</th></tr></thead>"
            "<tbody>" + "".join(upload_rows) + "</tbody></table>"
        )

    if scanner.graphql_endpoints:
        gql_rows = []
        for item in scanner.graphql_endpoints:
            flag = '<span class="badge high">enabled</span>' if item['introspection'] else "off"
            gql_rows.append(
                "<tr>"
                f"<td><code>{html_lib.escape(truncate(item['url'], 300))}</code></td>"
                f"<td>{flag}</td>"
                "</tr>"
            )
        content_parts.append(
            "<h2>GraphQL Endpoints</h2>"
            "<table><thead><tr><th>URL</th><th>Introspection</th></tr></thead>"
            "<tbody>" + "".join(gql_rows) + "</tbody></table>"
        )

    if scanner.findings:
        rows = []
        for finding in scanner.findings:
            poc_cell = (
                html_lib.escape(truncate(finding.poc_url, 300))
                if finding.poc_url
                else html_lib.escape(truncate(finding.poc_curl or finding.poc_command, 160))
            )
            rows.append(
                "<tr>"
                f'<td><code>{html_lib.escape(finding.finding_id)}</code></td>'
                f'<td><span class="badge {html_lib.escape(finding.confidence)}">'
                f"{html_lib.escape(finding.confidence)}</span></td>"
                f"<td>{html_lib.escape(finding.kind)}</td>"
                f"<td>{html_lib.escape(finding.method)}</td>"
                f"<td><code>{html_lib.escape(finding.parameter)}</code></td>"
                f"<td><code>{html_lib.escape(truncate(finding.url, 300))}</code></td>"
                f"<td><code>{html_lib.escape(truncate(finding.payload, 300))}</code></td>"
                f"<td><code>{poc_cell}</code></td>"
                f"<td>{html_lib.escape(truncate(finding.evidence, 300))}</td>"
                "</tr>"
            )
        content_parts.append(
            "<h2>XSS Findings</h2>"
            "<table><thead><tr><th>ID</th><th>Severity</th><th>Type</th><th>Method</th>"
            "<th>Parameter</th><th>URL</th><th>Payload</th><th>PoC</th><th>Evidence</th></tr></thead>"
            "<tbody>" + "".join(rows) + "</tbody></table>"
        )

        details: List[str] = [
            "<h2>Proof of Concept</h2>",
            "<p>Each block reproduces the finding: run the <code>curl</code> command "
            "or open the PoC URL. Requests are redacted so reports stay shareable; "
            "supply your own session with <code>--headers</code>/<code>--cookies</code> "
            "when replaying a finding with <code>--replay</code>.</p>",
            "",
        ]
        for index, finding in enumerate(scanner.findings, 1):
            detail_rows = [
                f"<tr><th>Finding ID</th><td><code>{html_lib.escape(finding.finding_id)}</code></td></tr>",
                f"<tr><th>Type</th><td>{html_lib.escape(finding.kind)} "
                f'<span class="badge {html_lib.escape(finding.confidence)}">'
                f"{html_lib.escape(finding.confidence)}</span></td></tr>",
                f"<tr><th>Target</th><td><code>{html_lib.escape(finding.url)}</code></td></tr>",
                f"<tr><th>Parameter</th><td><code>{html_lib.escape(finding.parameter)}</code>"
                f" ({html_lib.escape(finding.method)}, source: {html_lib.escape(finding.source or 'n/a')}, "
                f"context: {html_lib.escape(finding.context or 'n/a')})</td></tr>",
                f"<tr><th>Confidence</th><td>{html_lib.escape(finding.confidence_rationale or 'n/a')}</td></tr>",
                f"<tr><th>Evidence</th><td>{html_lib.escape(truncate(finding.evidence or finding.detail, 500))}</td></tr>",
                f"<tr><th>Payload</th><td><code>{html_lib.escape(truncate(finding.payload, 400))}</code></td></tr>",
            ]
            if finding.char_matrix:
                groups: Any = {}
                for char, status in finding.char_matrix.items():
                    groups.setdefault(status, []).append(char)
                rendered_matrix = "; ".join(
                    f"{status}: {''.join(chars)}" for status, chars in groups.items()
                )
                detail_rows.append(
                    f"<tr><th>Character matrix</th><td><code>{html_lib.escape(rendered_matrix)}</code></td></tr>"
                )
            if finding.sink:
                sink_text = f"<code>{html_lib.escape(finding.sink)}</code>"
                if finding.dom_path:
                    sink_text += f" at <code>{html_lib.escape(finding.dom_path)}</code>"
                detail_rows.append(f"<tr><th>Sink</th><td>{sink_text}</td></tr>")
            if finding.request:
                request = finding.request
                request_line = (
                    f"{request.get('method', finding.method)} {request.get('url', finding.url)}"
                )
                detail_rows.append(
                    f"<tr><th>Request</th><td><code>{html_lib.escape(request_line)}</code></td></tr>"
                )
                request_headers = request.get("headers") or {}
                if request_headers:
                    rendered = "\n".join(
                        f"{name}: {value}" for name, value in request_headers.items()
                    )
                    detail_rows.append(
                        f"<tr><th>Request headers</th><td><pre>{html_lib.escape(rendered)}</pre></td></tr>"
                    )
                if request.get("body"):
                    detail_rows.append(
                        f"<tr><th>Request body</th><td><pre>{html_lib.escape(str(request['body']))}</pre></td></tr>"
                    )
            if finding.response_status:
                detail_rows.append(
                    f"<tr><th>Response status</th><td>{finding.response_status}</td></tr>"
                )
            if finding.response_excerpt:
                detail_rows.append(
                    f"<tr><th>Response excerpt</th><td><pre>{html_lib.escape(finding.response_excerpt)}</pre></td></tr>"
                )
            if finding.oob:
                oob = finding.oob
                oob_lines = [f"callback: {oob.get('callback', 'n/a')}"]
                if oob.get("page_url"):
                    oob_lines.append(f"page: {oob['page_url']}")
                if oob.get("cookies"):
                    oob_lines.append(f"cookies: {'; '.join(oob['cookies'])}")
                if oob.get("timestamp"):
                    oob_lines.append(f"time: {oob['timestamp']}")
                detail_rows.append(
                    f"<tr><th>OOB callback</th><td><pre>{html_lib.escape(chr(10).join(oob_lines))}</pre></td></tr>"
                )
            if finding.poc_url:
                detail_rows.append(
                    f'<tr><th>PoC URL</th><td><a href="{html_lib.escape(finding.poc_url, quote=True)}">'
                    f"<code>{html_lib.escape(finding.poc_url)}</code></a></td></tr>"
                )
            if finding.poc_curl:
                detail_rows.append(
                    f"<tr><th>curl PoC</th><td><pre>{html_lib.escape(finding.poc_curl)}</pre></td></tr>"
                )
            elif finding.poc_command:
                detail_rows.append(
                    f"<tr><th>PoC command</th><td><code>{html_lib.escape(finding.poc_command)}</code></td></tr>"
                )
            if finding.poc_html:
                detail_rows.append(
                    f'<tr><th>Browser form PoC</th><td><a href="{html_lib.escape(finding.poc_html, quote=True)}">'
                    "Open self-contained form PoC</a></td></tr>"
                )
            if finding.screenshot:
                screenshot = Path(finding.screenshot).expanduser()
                if not screenshot.is_absolute():
                    screenshot = Path.cwd() / screenshot
                screenshot_root = None
                try:
                    screenshot = screenshot.resolve()
                    screenshot_root = Path(
                        getattr(scanner, "screenshot_dir", Path.cwd())
                    ).expanduser().resolve()
                    report_dir = path.parent.resolve()
                    relative = os.path.relpath(screenshot, report_dir).replace(os.sep, "/")
                    image_url = quote(relative, safe="/:@-._~")
                except (OSError, ValueError):
                    image_url = ""
                is_scanner_screenshot = (
                    screenshot_root is not None
                    and (screenshot_root == screenshot or screenshot_root in screenshot.parents)
                )
                if (
                    image_url
                    and is_scanner_screenshot
                    and screenshot.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".gif"}
                    and screenshot.is_file()
                ):
                    escaped_url = html_lib.escape(image_url, quote=True)
                    screenshot_markup = (
                        f'<button class="screenshot-thumb" type="button" data-screenshot="{escaped_url}" '
                        f'aria-label="Expand browser evidence for finding {index}">'
                        f'<img src="{escaped_url}" alt="Browser evidence for finding {index}" loading="lazy"></button>'
                        '<div class="screenshot-caption">Select image to expand</div>'
                    )
                else:
                    screenshot_markup = f"<code>{html_lib.escape(finding.screenshot)}</code>"
                detail_rows.append(f"<tr><th>Screenshot</th><td>{screenshot_markup}</td></tr>")
            details.append(
                f'<div class="poc-block"><h3>{index}. {html_lib.escape(finding.kind)}'
                f" - {html_lib.escape(finding.parameter or finding.url)}</h3>"
                "<table><tbody>" + "".join(detail_rows) + "</tbody></table></div><br>"
            )
        content_parts.append("".join(details))

    if not content_parts:
        content = '<div class="empty">No XSS findings were confirmed.</div>'
    else:
        content = "<br>".join(content_parts)

    document = (
        HTML_TEMPLATE.replace("__TITLE__", f"{APP_NAME} scan report")
        .replace("__TARGET__", html_lib.escape(scanner.target))
        .replace("__DATE__", now_iso())
        .replace("__APPNAME__", APP_NAME)
        .replace("__VERSION__", VERSION)
        .replace("__CARDS__", cards)
        .replace("__CONTENT__", content)
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
