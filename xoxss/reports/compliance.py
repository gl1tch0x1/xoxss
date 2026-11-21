"""
Compliance reporting - maps findings to OWASP Top 10 2021, PCI DSS 4.0 and
the HIPAA Security Rule so scan output can be attached to audit evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List

from xoxss.core.compliance import (
    HIPAA,
    OWASP_TOP10,
    PCI_DSS,
    compliance_for_kind,
    cwe_for_kind,
    cvss_for_finding,
    finding_dedupe_fingerprint,
    secondary_cwes,
)
from xoxss.reports.common import field_getter, iter_report_findings, now_iso

if TYPE_CHECKING:
    from xoxss.scanner import XSSScanner


def _iter_findings(scanner: "XSSScanner") -> List[Any]:
    return iter_report_findings(scanner)


def compliance_records(scanner: "XSSScanner") -> List[Dict[str, Any]]:
    """One compliance record per finding with CWE/CVSS/framework mappings."""
    records: List[Dict[str, Any]] = []
    for finding in _iter_findings(scanner):
        get = field_getter(finding)
        kind = str(get("kind"))
        records.append(
            {
                "findingId": str(get("finding_id", "") or finding_dedupe_fingerprint(finding)),
                "kind": kind,
                "url": str(get("url", "")),
                "parameter": str(get("parameter", "")),
                "method": str(get("method", "GET")),
                "confidence": str(get("confidence", "medium")),
                "cwe": cwe_for_kind(kind),
                "secondaryCwes": secondary_cwes(kind),
                "cvss": cvss_for_finding(finding),
                "frameworks": compliance_for_kind(kind),
                "status": str(get("status", "open") or "open"),
                "assignedTo": str(get("assigned_to", "") or ""),
                "triagedAt": str(get("triaged_at", "") or ""),
                "notes": str(get("notes", "") or ""),
            }
        )
    return records


def compliance_summary(scanner: "XSSScanner") -> Dict[str, Any]:
    """Aggregate counts per framework control - the audit-evidence view."""
    records = compliance_records(scanner)

    def _bucket(framework: str, table: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
        controls: Dict[str, Dict[str, Any]] = {}
        for rec in records:
            control = rec["frameworks"][framework]
            cid = control["id"]
            entry = controls.setdefault(
                cid,
                {"id": cid, "name": control["name"], "count": 0, "findingIds": []},
            )
            entry["count"] += 1
            entry["findingIds"].append(rec["findingId"])
        ordered = [controls[k] for k in sorted(controls)]
        for entry in ordered:
            entry["findingIds"] = entry["findingIds"][:50]
        return ordered

    return {
        "generated": now_iso(),
        "target": getattr(scanner, "target", ""),
        "frameworks": {
            "owasp_top10_2021": _bucket("owasp", OWASP_TOP10),
            "pci_dss_4_0": _bucket("pci_dss", PCI_DSS),
            "hipaa_security_rule": _bucket("hipaa", HIPAA),
        },
        "totals": {
            "findings": len(records),
            "confirmed": sum(1 for r in records if r["confidence"] == "confirmed"),
            "high": sum(1 for r in records if r["confidence"] == "high"),
            "criticalCvss": sum(1 for r in records if r["cvss"]["severity"] == "critical"),
        },
        "records": records,
    }


def write_compliance_report(path: Path, scanner: "XSSScanner") -> None:
    """Write the compliance mapping as JSON (machine-readable audit evidence)."""
    path.write_text(
        json.dumps(compliance_summary(scanner), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


__all__ = [
    "compliance_records",
    "compliance_summary",
    "write_compliance_report",
]
