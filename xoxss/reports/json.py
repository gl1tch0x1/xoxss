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
    if not bool(getattr(args, "crawl", False)):
        coverage_notes.append("Crawling was disabled; only the target and enabled recon seeds were scanned")
    if not bool(getattr(args, "browser_discovery", False)):
        coverage_notes.append("Runtime SPA route and XHR/fetch discovery was disabled")
    if not bool(getattr(args, "stored", False)):
        coverage_notes.append("Stored-XSS follow-up checks were disabled")
    if not bool(getattr(args, "dom_source_probes", False)):
        coverage_notes.append("Storage, window.name, and postMessage DOM source probes were disabled")
    if not bool(getattr(args, "external_tools", False)):
        coverage_notes.append("Optional external recon and verification tools were disabled")
    if not getattr(args, "auth_state", None) and not (
        getattr(args, "headers", None) or getattr(args, "cookies", None)
    ):
        coverage_notes.append("No authenticated session material was supplied; access-controlled routes may be missing")
    if scanner.stats.truncated_responses:
        coverage_notes.append(
            f"{scanner.stats.truncated_responses} response(s) were truncated at the configured byte limit"
        )
    if scanner.stats.errors:
        coverage_notes.append(
            f"{scanner.stats.errors} HTTP request(s) failed; affected endpoints may have incomplete coverage"
        )
    if scanner.stats.urls_failed:
        coverage_notes.append(
            f"{scanner.stats.urls_failed} URL(s) did not complete and remain retryable in the checkpoint"
        )
    if scanner.mutation_findings:
        coverage_notes.append(
            f"{len(scanner.mutation_findings)} response transformation(s) were observed; these are signals, not XSS findings"
        )
    recon_errors = scanner.state.extra.get("recon_errors", [])
    if recon_errors:
        coverage_notes.append(f"{len(recon_errors)} optional recon source(s) failed; successful sources continued")
    statuses = getattr(scanner.state, "url_status", {})
    status_counts: Dict[str, int] = {}
    for status in statuses.values():
        name = str(status.get("status", "unknown")) if isinstance(status, dict) else "unknown"
        status_counts[name] = status_counts.get(name, 0) + 1
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
        "coverage": {
            "url_status_counts": status_counts,
            "failed_urls": [
                {"url": url, **status}
                for url, status in statuses.items()
                if isinstance(status, dict) and status.get("status") == "failed"
            ][:5000],
            "recon_errors": recon_errors[:100] if isinstance(recon_errors, list) else [],
            "browser_discovered_requests": scanner.state.extra.get("browser_discovered_requests", [])[:5000],
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
            "endpoint_sources": scanner.state.extra.get("endpoint_sources", {}),
            "external_parameters": scanner.state.extra.get("external_parameters", {}),
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
        "transformation_observations": scanner.mutation_findings[:1000],
    }


def write_json_report(path: Path, scanner: XSSScanner) -> None:
    path.write_text(json.dumps(report_payload(scanner), indent=2, ensure_ascii=False), encoding="utf-8")
