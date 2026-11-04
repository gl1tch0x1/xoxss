"""JSON report data model and writer."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict

from xoxss.reports.common import APP_NAME, VERSION, now_iso

if TYPE_CHECKING:
    from xoxss.scanner import XSSScanner


def report_payload(scanner: XSSScanner) -> Dict[str, Any]:
    args = getattr(scanner, "args", None)
    pool = getattr(scanner, "pool", None)
    browser_requested = not bool(getattr(args, "no_browser", False))
    browser_available = bool(pool and pool.engines)
    coverage_notes = []
    if not browser_requested:
        coverage_notes.append("Browser execution verification was disabled by configuration")
    elif not browser_available:
        coverage_notes.append("Browser execution verification was requested but no browser worker started")
    if scanner.stats.truncated_responses:
        coverage_notes.append(
            f"{scanner.stats.truncated_responses} response(s) were truncated at the configured byte limit"
        )
    if scanner.stats.errors:
        coverage_notes.append(
            f"{scanner.stats.errors} HTTP request(s) failed; affected endpoints may have incomplete coverage"
        )
    return {
        "tool": APP_NAME,
        "version": VERSION,
        "target": scanner.target,
        "finished": now_iso(),
        "duration_seconds": round(scanner.stats.elapsed, 2),
        "coverage_notes": coverage_notes,
        "verification": {
            "browser_requested": browser_requested,
            "browser_available": browser_available,
            "browser_checks": scanner.stats.browser_checks,
            "http_errors": scanner.stats.errors,
            "truncated_responses": scanner.stats.truncated_responses,
        },
        "waf": scanner.waf.names,
        "waf_blocking": scanner.waf.blocking,
        "stats": asdict(scanner.stats),
        "endpoint_count": len(scanner.endpoints),
        "endpoints": sorted(scanner.endpoints)[:5000],
        "recon": {
            "subdomains": scanner.subdomains[:5000],
            "passive_urls": scanner.passive_urls[:5000],
            "openapi_operations": [
                operation.to_dict() for operation in scanner.api_operations[:500]
            ],
            "external_tools": scanner.external_summary,
            "js_intel": [intel.to_dict() for intel in scanner.js_intel[:25]],
        },
        "oob": scanner.oob.to_dict() if scanner.oob is not None else {},
        "external_findings": [item.to_dict() for item in scanner.external_findings],
        "vulnerable_libraries": [
            {
                "name": lib.name,
                "version": lib.version,
                "cve": lib.cve,
                "severity": lib.severity,
                "url": lib.url,
            }
            for lib in scanner.vulnerable_libs
        ],
        "jsonp_findings": scanner.jsonp_findings,
        "csp_issues": scanner.csp_issues,
        "cors_issues": scanner.cors_issues,
        "proto_pollution_sources": scanner.proto_pollution_findings,
        "trusted_types_issues": scanner.trusted_types_issues,
        "dom_clobbering": scanner.dom_clobber_findings,
        "postmessage": scanner.postmessage_findings,
        "websocket": scanner.websocket_findings,
        "file_upload": scanner.file_upload_findings,
        "graphql": scanner.graphql_endpoints,
        "blind_markers": scanner.blind_markers,
        "findings": [finding.to_dict() for finding in scanner.findings],
    }


def write_json_report(path: Path, scanner: XSSScanner) -> None:
    path.write_text(json.dumps(report_payload(scanner), indent=2, ensure_ascii=False), encoding="utf-8")
