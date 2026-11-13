"""
Finding data models, confidence grading, deduplication, and scan statistics.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from xoxss.core.evidence import (
    canonical_finding_url,
    finding_curl,
    finding_id as make_finding_id,
)
from xoxss.scan.reflection import (
    ReflectionInfo,
    browser_prequalified,
    http_executable,
)
from xoxss.utils.helpers import now_iso


# Validation outcomes (execution-based validation pipeline)
CONFIRMED_EXECUTION = "CONFIRMED_EXECUTION"
REJECTED = "REJECTED"
UNVERIFIED = "UNVERIFIED"

# Classifications for non-confirmed candidates
FALSE_POSITIVE = "FALSE_POSITIVE"
NEEDS_MANUAL_TEST = "NEEDS_MANUAL_TEST"

CONFIDENCE_LEVELS = ("confirmed", "high", "medium", "low")
CONFIDENCE_RANK = {level: len(CONFIDENCE_LEVELS) - index for index, level in enumerate(CONFIDENCE_LEVELS)}


def reflection_confidence(
    info: ReflectionInfo,
    *,
    requested: bool,
    available: bool,
    content_type: str = "",
) -> Tuple[str, str, str]:
    """Classify an HTTP-reflection finding as ``(confidence, rationale, detail)``.

    The distinction that matters is *why* a browser did not confirm execution:
    verification disabled, no browser worker available, the candidate failed
    the prequalification gate, or a browser ran and found nothing.
    """
    prequalified = browser_prequalified(info, content_type)
    if not info.executable:
        return (
            "low",
            f"Reflection was observed but is inert: "
            f"{info.inert_reason or info.context}.",
            "Reflection is not executable in this context",
        )
    if not prequalified:
        return (
            "low",
            "The payload survived verbatim but the response cannot be rendered "
            "as an executable document (context or MIME type).",
            "Reflection is not browser-executable (context/MIME)",
        )
    if not http_executable(info, content_type):
        return (
            "low",
            "The payload survived verbatim but the response is served as plain "
            "text, which browsers do not parse as markup.",
            "Reflection MIME type is not an executable document (text/plain)",
        )
    if not requested:
        return (
            "high",
            "The payload's delimiters survived verbatim in an executable "
            "context; browser verification was disabled.",
            "HTTP evidence only (browser verification disabled)",
        )
    if available:
        return (
            "medium",
            "A browser was available and this candidate passed the execution "
            "gate, but the browser did not observe execution.",
            "Browser verification attempted but did not confirm execution",
        )
    return (
        "high",
        "Browser verification was requested but no browser worker was "
        "available; the payload's delimiters survived verbatim in an "
        "executable context.",
        "Browser verification unavailable",
    )


@dataclass
class Finding:
    """Core vulnerability finding model."""
    kind: str
    url: str
    parameter: str
    method: str
    payload: str
    evidence: str = ""
    confidence: str = "confirmed"  # confirmed | high | medium | low
    confidence_rationale: str = ""
    context: str = ""
    detail: str = ""
    screenshot: str = ""
    poc_url: str = ""
    poc_command: str = ""
    poc_html: str = ""
    request: Dict[str, Any] = field(default_factory=dict)
    response_status: int = 0
    response_excerpt: str = ""
    poc_curl: str = ""
    sink: str = ""
    dom_path: str = ""
    char_matrix: Dict[str, str] = field(default_factory=dict)
    oob: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    param_source: str = "discovered"  # discovered | fuzzed
    finding_id: str = ""
    subkey: str = ""
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=now_iso)

    def __post_init__(self) -> None:
        if not isinstance(self.request, dict):
            self.request = {}
        if not isinstance(self.oob, dict):
            self.oob = {}
        if not isinstance(self.char_matrix, dict):
            self.char_matrix = {}
        if not self.subkey:
            self.subkey = ""
        if not self.finding_id:
            self.finding_id = make_finding_id(self.key())
        if not self.poc_curl:
            self.poc_curl = finding_curl(self)

    def key(self) -> str:
        family = self.kind.split(" (")[0]
        url = canonical_finding_url(self.url, self.source)
        raw = "|".join([family, url, self.parameter, self.method, self.source, self.subkey])
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()

    def dedupe_key(self) -> str:
        """Coarser identity used to upgrade/suppress duplicate issues."""
        family = self.kind.split(" (")[0]
        if family == "DOM XSS":
            parts = urlsplit(self.url)
            page = urlunsplit(
                (parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", "", "")
            )
            return hashlib.sha1(
                f"{family}|{page}".encode("utf-8", "replace")
            ).hexdigest()
        return self.key()

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if not result["finding_id"]:
            result["finding_id"] = make_finding_id(self.key())
        if not result["poc_curl"]:
            result["poc_curl"] = finding_curl(self)
        if not result["confidence_rationale"]:
            result["confidence_rationale"] = {
                "confirmed": "Direct confirmation evidence was recorded for this finding.",
                "high": "Strong technical evidence was recorded; browser execution was not recorded for this finding.",
                "medium": "A supporting signal was observed without direct execution proof.",
                "low": "A heuristic signal needs manual validation.",
            }.get(self.confidence, "Confidence was not classified; review the evidence manually.")
        return result


def meets_fail_threshold(findings: Any, threshold: Optional[str]) -> bool:
    """Return True when ``findings`` should fail the process for ``threshold``."""
    if not threshold:
        return False
    if isinstance(findings, int):
        return findings > 0
    items = list(findings or [])
    if not items:
        return False
    if threshold == "any":
        return True
    floor = CONFIDENCE_RANK.get(threshold, 0)
    for item in items:
        confidence = (
            item.get("confidence", "low")
            if isinstance(item, dict)
            else getattr(item, "confidence", "low")
        )
        if CONFIDENCE_RANK.get(str(confidence or "low").strip().lower(), 0) >= floor:
            return True
    return False


def enforce_finding_policy(finding: Finding) -> bool:
    """Normalise confidence and reject claims that are not evidence-backed."""
    if not (finding.kind or "").strip() or not (finding.url or "").strip():
        return False

    confidence = (finding.confidence or "").strip().lower()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "low"

    has_evidence = any(
        (
            (finding.evidence or "").strip(),
            (finding.response_excerpt or "").strip(),
            (finding.screenshot or "").strip(),
            bool(finding.oob),
            bool(finding.request),
        )
    )
    if confidence == "confirmed" and not has_evidence:
        confidence = "high"
        finding.confidence_rationale = (
            "Downgraded from confirmed: no execution evidence was recorded."
        )
    elif confidence == "high" and not has_evidence:
        confidence = "medium"
        finding.confidence_rationale = (
            "Downgraded from high: no request or response evidence was recorded."
        )

    if finding.source in ("header", "cookie", "ast", "websocket") or finding.kind.startswith(
        ("DOM XSS (taint flow)", "DOM XSS (static candidate)", "Header XSS", "Cookie XSS", "WebSocket")
    ):
        if confidence in ("confirmed", "high", "medium"):
            confidence = "low"
            if not finding.confidence_rationale:
                finding.confidence_rationale = (
                    "Static or unconfirmed lead classified as low confidence (informational)."
                )

    finding.confidence = confidence
    return True


@dataclass
class ValidationResult:
    """Result of browser execution validation."""
    status: str  # CONFIRMED_EXECUTION | REJECTED | UNVERIFIED
    classification: Optional[str] = None  # FALSE_POSITIVE | NEEDS_MANUAL_TEST | None
    reason: str = ""
    evidence: str = ""
    dialog_text: Optional[str] = None
    in_dom: bool = False
    in_response: bool = False
    screenshot: str = ""


@dataclass
class ScanStats:
    """Aggregated scan statistics."""
    requests: int = 0
    errors: int = 0
    truncated_responses: int = 0
    blocked: int = 0
    payloads: int = 0
    points: int = 0
    urls_total: int = 0
    urls_done: int = 0
    urls_failed: int = 0
    findings: int = 0
    browser_checks: int = 0
    endpoints: int = 0
    js_files: int = 0
    secrets: int = 0
    subdomains: int = 0
    passive_urls: int = 0
    fuzzed_paths: int = 0
    discovered_params: int = 0
    ast_flows: int = 0
    oob_registered: int = 0
    oob_hits: int = 0
    external_findings: int = 0
    false_positives: int = 0
    rejected_candidates: int = 0
    needs_manual_test: int = 0
    rejections: Dict[str, int] = field(default_factory=dict)
    started: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.started


__all__ = [
    "now_iso",
    "CONFIRMED_EXECUTION",
    "REJECTED",
    "UNVERIFIED",
    "FALSE_POSITIVE",
    "NEEDS_MANUAL_TEST",
    "CONFIDENCE_LEVELS",
    "CONFIDENCE_RANK",
    "reflection_confidence",
    "Finding",
    "meets_fail_threshold",
    "enforce_finding_policy",
    "ValidationResult",
    "ScanStats",
]

