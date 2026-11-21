"""
Team collaboration export - a deduplicated, stable-ID triage bundle.

Groups findings by their dedupe key so repeated scan runs produce the same
finding IDs, lets teams assign status/ownership, and emits a JSON artifact
that can be diffed between scans or imported into issue trackers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict

from xoxss.core.compliance import finding_dedupe_fingerprint
from xoxss.reports.common import APP_NAME, VERSION, field_getter, iter_report_findings, now_iso

if TYPE_CHECKING:
    from xoxss.scanner import XSSScanner

VALID_STATUSES = ("open", "triaged", "confirmed", "false_positive", "fixed", "accepted_risk")


def collaboration_bundle(scanner: "XSSScanner") -> Dict[str, Any]:
    """Build the deduplicated triage bundle for the current findings."""
    findings = iter_report_findings(scanner)

    groups: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        get = field_getter(finding)
        kind = str(get("kind"))
        dedupe_method = getattr(finding, "dedupe_key", None)
        dedupe_key = str(
            dedupe_method()
            if callable(dedupe_method)
            else finding_dedupe_fingerprint(finding)
        )
        group = groups.setdefault(
            dedupe_key,
            {
                "dedupeKey": dedupe_key,
                "findingId": str(get("finding_id", "") or finding_dedupe_fingerprint(finding)),
                "kind": kind,
                "url": str(get("url", "")),
                "parameter": str(get("parameter", "")),
                "method": str(get("method", "GET")),
                "occurrences": 0,
                "bestConfidence": "low",
                "status": str(get("status", "open") or "open"),
                "assignedTo": str(get("assigned_to", "") or ""),
                "triagedAt": str(get("triaged_at", "") or ""),
                "notes": str(get("notes", "") or ""),
                "evidence": [],
            },
        )
        group["occurrences"] += 1
        # Keep the strongest confidence observed for this dedupe group.
        rank = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}
        conf = str(get("confidence", "low"))
        if rank.get(conf, 0) > rank.get(group["bestConfidence"], 0):
            group["bestConfidence"] = conf
        evidence = str(get("evidence", "") or get("detail", ""))[:300]
        if evidence and evidence not in group["evidence"]:
            group["evidence"].append(evidence)

    items = sorted(groups.values(), key=lambda g: (-g["occurrences"], g["kind"], g["url"]))
    return {
        "tool": APP_NAME,
        "version": VERSION,
        "generated": now_iso(),
        "target": getattr(scanner, "target", ""),
        "schemaVersion": 1,
        "validStatuses": list(VALID_STATUSES),
        "counts": {
            "rawFindings": len(findings),
            "uniqueIssues": len(items),
            "open": sum(1 for g in items if g["status"] == "open"),
            "triaged": sum(1 for g in items if g["status"] != "open"),
        },
        "issues": items,
    }


def write_collaboration_report(path: Path, scanner: "XSSScanner") -> None:
    path.write_text(
        json.dumps(collaboration_bundle(scanner), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


__all__ = [
    "VALID_STATUSES",
    "collaboration_bundle",
    "write_collaboration_report",
]
