"""
SARIF v2.1.0 export.

GitHub Code Scanning, GitLab Security Dashboard, SonarQube and DefectDojo all
ingest this format, so ``--report sarif`` plugs XOX$$ into CI security gates.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

# SARIF severity mapping.  "note" still surfaces in GitHub code scanning.
SARIF_LEVELS = {
    "confirmed": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _truncate(text: Any, limit: int = 300) -> str:
    value = str(text or "")
    return value if len(value) <= limit else value[: limit - 1] + "\u2026"


def sarif_rule_id(kind: str) -> str:
    """Stable SARIF rule id for a finding family (e.g. ``xoxss/reflected-xss``)."""
    family = kind.split(" (")[0]
    slug = re.sub(r"[^a-z0-9]+", "-", family.lower()).strip("-")
    return f"xoxss/{slug or 'finding'}"


def _finding_key(finding: Any) -> str:
    key = getattr(finding, "key", None)
    if callable(key):
        try:
            return str(key())
        except Exception:
            pass
    raw = "|".join(
        str(getattr(finding, name, ""))
        for name in ("kind", "url", "parameter", "method")
    )
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()


def build_sarif_document(
    findings: Sequence[Any],
    *,
    target: str,
    waf_names: Iterable[str] = (),
    duration_seconds: float = 0.0,
    endpoint_count: int = 0,
    blind_markers: Optional[Sequence[Dict[str, Any]]] = None,
    tool_name: str = "XOX$$",
    tool_version: str = "2.0.0",
    information_uri: str = "https://github.com/example/xoxss",
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a SARIF v2.1.0 document for a completed scan."""
    rules: Dict[str, Dict[str, Any]] = {}
    rule_order: List[str] = []
    results: List[Dict[str, Any]] = []

    for finding in findings:
        kind = str(getattr(finding, "kind", "finding"))
        confidence = str(getattr(finding, "confidence", "medium"))
        rule_id = sarif_rule_id(kind)
        level = SARIF_LEVELS.get(confidence, "warning")

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": kind.split(" (")[0],
                "shortDescription": {"text": kind},
                "fullDescription": {
                    "text": (
                        "XOX$$ detected a cross-site scripting condition. "
                        "Review the injection point and apply context-aware output encoding."
                    )
                },
                "helpUri": "https://owasp.org/www-community/attacks/xss/",
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": ["security", "xss", "owasp-a03"],
                    "precision": "high" if confidence in ("confirmed", "high") else "medium",
                },
            }
            rule_order.append(rule_id)

        evidence = getattr(finding, "evidence", "") or getattr(finding, "detail", "")
        method = str(getattr(finding, "method", "GET"))
        parameter = str(getattr(finding, "parameter", ""))
        url = str(getattr(finding, "url", target))
        poc_url = str(getattr(finding, "poc_url", "") or "")
        poc_command = str(getattr(finding, "poc_command", "") or "")

        message_text = (
            f"{kind} via {method} parameter '{parameter}': "
            f"{_truncate(evidence or 'reflected payload')}"
        )
        if poc_url:
            message_text += f" | PoC: {_truncate(poc_url, 400)}"
        if poc_command:
            message_text += f" | PoC command: {_truncate(poc_command, 400)}"

        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_order.index(rule_id),
                "level": level,
                "message": {
                    "text": message_text
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": url},
                            "region": {"startLine": 1, "startColumn": 1},
                        },
                        "logicalLocations": [
                            {"name": f"{method} {parameter}", "kind": "parameter"}
                        ],
                    }
                ],
                "properties": {
                    "parameter": parameter,
                    "method": method,
                    "confidence": confidence,
                    "context": getattr(finding, "context", ""),
                    "payload": getattr(finding, "payload", ""),
                    "evidence": getattr(finding, "evidence", ""),
                    "detail": getattr(finding, "detail", ""),
                    "screenshot": getattr(finding, "screenshot", ""),
                    "pocUrl": poc_url,
                    "pocCommand": poc_command,
                    "timestamp": getattr(finding, "timestamp", ""),
                },
                "partialFingerprints": {"xoxssFinding/v1": _finding_key(finding)},
            }
        )

    end_time = timestamp or datetime.now(timezone.utc).isoformat()
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": information_uri,
                        "rules": [rules[rule_id] for rule_id in rule_order],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": end_time,
                        "properties": {
                            "target": target,
                            "waf": list(waf_names),
                            "durationSeconds": round(duration_seconds, 2),
                            "endpoints": endpoint_count,
                        },
                    }
                ],
                "results": results,
                "properties": {
                    "target": target,
                    "blindMarkers": list(blind_markers or []),
                },
            }
        ],
    }


def write_sarif_file(path: Path, document: Dict[str, Any]) -> None:
    import json

    Path(path).write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
