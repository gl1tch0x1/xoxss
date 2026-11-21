"""
Compliance and taxonomy mappings for XSS findings.

Provides CWE, CVSS v3.1 and framework control mappings (OWASP Top 10 2021,
PCI DSS 4.0, HIPAA Security Rule) used by SARIF export and the compliance
report.  Everything here is pure data + lookups - no I/O - so it can be unit
tested and reused by every renderer.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# CWE mappings
# ---------------------------------------------------------------------------
# Primary CWE per finding family.  ``kind`` strings may carry a suffix like
# ``"DOM XSS (taint flow)"`` - matching is done on the family prefix.

_CWE_RULES: Tuple[Tuple[str, Tuple[str, ...], str], ...] = [
    # (family prefix, match substrings, CWE id)
    ("Reflected XSS", (), "CWE-79"),
    ("DOM XSS", (), "CWE-79"),
    ("Stored XSS", (), "CWE-79"),
    ("Blind XSS", (), "CWE-79"),
    ("Mutation XSS", (), "CWE-79"),
    ("mXSS", (), "CWE-79"),
    ("Header XSS", (), "CWE-79"),
    ("Cookie XSS", (), "CWE-79"),
    ("Template Injection", (), "CWE-94"),
    ("HTTP Parameter Pollution", (), "CWE-436"),
    ("Prototype Pollution", (), "CWE-1321"),
    ("CRLF", (), "CWE-113"),
    ("Response Splitting", (), "CWE-113"),
    ("Open Redirect", (), "CWE-601"),
    ("DOM Clobbering", (), "CWE-79"),
    ("WebSocket XSS", (), "CWE-79"),
    ("Service Worker", (), "CWE-79"),
    ("File Upload", (), "CWE-434"),
    ("JSONP", (), "CWE-346"),
    ("CORS", (), "CWE-942"),
    ("CSP", (), "CWE-693"),
    ("GraphQL", (), "CWE-89"),
    ("PostMessage", (), "CWE-346"),
    ("Trusted Types", (), "CWE-693"),
    ("WASM", (), "CWE-79"),
    ("Clipboard", (), "CWE-79"),
    ("Web Component", (), "CWE-79"),
    ("Dangling Markup", (), "CWE-79"),
    ("Subdomain Takeover", (), "CWE-284"),
    ("Sensitive Data", (), "CWE-200"),
    ("Secret", (), "CWE-798"),
    ("JWT", (), "CWE-347"),
]

# Keyword -> CWE fallback for unmatched families
_CWE_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("xss", "CWE-79"),
    ("script", "CWE-79"),
    ("injection", "CWE-89"),
    ("redirect", "CWE-601"),
    ("crlf", "CWE-113"),
    ("cors", "CWE-942"),
    ("csp", "CWE-693"),
    ("graphql", "CWE-89"),
    ("upload", "CWE-434"),
    ("pollution", "CWE-1321"),
    ("secret", "CWE-798"),
    ("token", "CWE-798"),
    ("jwt", "CWE-347"),
    ("subdomain", "CWE-284"),
    ("takeover", "CWE-284"),
)


def _family(kind: str) -> str:
    return str(kind or "").split(" (")[0].strip().lower()


def cwe_for_kind(kind: str) -> str:
    """Return the primary CWE identifier for a finding family."""
    family = _family(kind)
    for prefix, _subs, cwe in _CWE_RULES:
        if family == prefix.lower():
            return cwe
    # prefix match (e.g. "dom xss" inside longer names)
    for prefix, _subs, cwe in _CWE_RULES:
        if prefix.lower() in family:
            return cwe
    for keyword, cwe in _CWE_KEYWORDS:
        if keyword in family:
            return cwe
    return "CWE-79"  # all XOXSS findings are XSS-class by default


def secondary_cwes(kind: str) -> List[str]:
    """Additional CWEs worth tagging for richer triage."""
    family = _family(kind)
    extra: List[str] = []
    if "xss" in family or "dom" in family:
        extra.append("CWE-116")  # Improper Encoding or Escaping of Output
    if "blind" in family:
        extra.append("CWE-200")  # Exposure of Sensitive Information
    if "stored" in family or "cookie" in family:
        extra.append("CWE-79")
    if "redirect" in family:
        extra.append("CWE-601")
    return sorted(set(extra) - {cwe_for_kind(kind)})


# ---------------------------------------------------------------------------
# CVSS v3.1 estimation
# ---------------------------------------------------------------------------
# XSS is network-reachable by definition; the interesting knobs are
# privileges required, user interaction, scope and impact.

_CONFIDENCE_TO_IMPACT: Dict[str, Tuple[str, str, str]] = {
    # confidence -> (integrity, confidentiality, availability) impact ratings
    "confirmed": ("H", "L", "N"),
    "high": ("H", "L", "N"),
    "medium": ("L", "N", "N"),
    "low": ("L", "N", "N"),
}


def cvss_vector(
    kind: str,
    confidence: str = "medium",
    *,
    stored: bool = False,
    oob: bool = False,
) -> str:
    """Build a CVSS v3.1 base vector string for a finding."""
    # AV:N - always network.  PR:N for reflected/DOM; PR:L for stored/auth'd
    # contexts where a session is needed.  UI:R required for XSS execution.
    pr = "L" if stored else "N"
    ui = "R"
    s = "U"
    # Stored + blind (fires in admin panel) widens scope impact.
    if stored or oob:
        s = "C"
    ii, ci, ai = _CONFIDENCE_TO_IMPACT.get(confidence, _CONFIDENCE_TO_IMPACT["medium"])
    return f"CVSS:3.1/AV:N/AC:L/PR:{pr}/UI:{ui}/S:{s}/C:{ci}/I:{ii}/A:{ai}"


def cvss_base_score(vector: str) -> float:
    """Compute a CVSS v3.1 base score from a vector string.

    Implements the official specification formula.  Keeps the dependency
    footprint at zero - scoring is ~40 lines of arithmetic.
    """
    metrics: Dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics.get("AV", "N")]
        ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", "L"), 0.77)
        pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_c = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", "R"), 0.62)
        scope_changed = metrics.get("S", "U") == "C"
        pr = pr_c if scope_changed else pr_u
        pr_val = pr.get(metrics.get("PR", "N"), 0.85)
        c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("C", "N"), 0.0)
        i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("I", "N"), 0.0)
        a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics.get("A", "N"), 0.0)
    except KeyError:
        return 0.0

    isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    exploitability = 8.22 * av * ac * pr_val * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)
    return _ceil1(score)


def _ceil1(value: float) -> float:
    """Round up to one decimal place (CVSS spec roundup)."""
    import math

    return math.ceil(value * 10) / 10.0


def cvss_for_finding(finding: Any) -> Dict[str, Any]:
    """Return ``{"vector", "baseScore", "severity"}`` for a finding object/dict."""
    get = (
        (lambda name, default="": getattr(finding, name, default))
        if not isinstance(finding, dict)
        else (lambda name, default="": finding.get(name, default))
    )
    kind = str(get("kind"))
    confidence = str(get("confidence", "medium")).lower()
    oob_data = get("oob") or {}
    oob = bool(isinstance(oob_data, dict) and oob_data)
    stored = "stored" in _family(kind)
    vector = cvss_vector(kind, confidence, stored=stored, oob=oob)
    score = cvss_base_score(vector)
    severity = "critical" if score >= 9.0 else "high" if score >= 7.0 else "medium" if score >= 4.0 else "low"
    return {"vector": vector, "baseScore": score, "severity": severity}


# ---------------------------------------------------------------------------
# Compliance framework mappings
# ---------------------------------------------------------------------------

# OWASP Top 10 2021 - XSS maps to A03:2021 Injection.
OWASP_TOP10: Dict[str, Dict[str, str]] = {
    "xss": {
        "id": "A03:2021",
        "name": "Injection",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    "template": {
        "id": "A03:2021",
        "name": "Injection",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    "prototype": {
        "id": "A03:2021",
        "name": "Injection",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    "crlf": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "redirect": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    "cors": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "csp": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "secret": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    "subdomain": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
}

# PCI DSS v4.0 controls relevant to XSS.
PCI_DSS: Dict[str, Dict[str, str]] = {
    "xss": {"id": "6.2.4", "name": "Injection attacks (XSS) protection", "url": "https://www.pcisecuritystandards.org/"},
    "template": {"id": "6.2.4", "name": "Injection attacks (XSS) protection", "url": "https://www.pcisecuritystandards.org/"},
    "crlf": {"id": "6.2.4", "name": "Injection attacks protection", "url": "https://www.pcisecuritystandards.org/"},
    "cors": {"id": "6.4.3", "name": "Payment page script integrity", "url": "https://www.pcisecuritystandards.org/"},
    "csp": {"id": "11.6.1", "name": "Unauthorized change detection", "url": "https://www.pcisecuritystandards.org/"},
    "secret": {"id": "3.5.1", "name": "PAN protection - render unreadable", "url": "https://www.pcisecuritystandards.org/"},
    "redirect": {"id": "6.2.4", "name": "Injection attacks protection", "url": "https://www.pcisecuritystandards.org/"},
    "subdomain": {"id": "11.6.1", "name": "Unauthorized change detection", "url": "https://www.pcisecuritystandards.org/"},
}

# HIPAA Security Rule technical safeguards.
HIPAA: Dict[str, Dict[str, str]] = {
    "xss": {"id": "164.312(c)(1)", "name": "Integrity controls", "url": "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"},
    "template": {"id": "164.312(c)(1)", "name": "Integrity controls", "url": "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"},
    "secret": {"id": "164.312(a)(2)(iv)", "name": "Encryption and decryption", "url": "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"},
    "cors": {"id": "164.312(e)(1)", "name": "Transmission security", "url": "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"},
    "redirect": {"id": "164.312(c)(1)", "name": "Integrity controls", "url": "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"},
    "subdomain": {"id": "164.312(c)(1)", "name": "Integrity controls", "url": "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html"},
}


def _category_for_kind(kind: str) -> str:
    """Coarse finding category used to select framework controls."""
    family = _family(kind)
    for key in ("template", "xss", "dom", "reflected", "stored", "blind", "mutation", "mxss", "cookie", "header", "websocket", "service worker", "wasm", "clipboard", "web component", "dangling"):
        if key in family:
            return "xss"
    if "crlf" in family or "splitting" in family:
        return "crlf"
    if "redirect" in family:
        return "redirect"
    if "cors" in family:
        return "cors"
    if "csp" in family:
        return "csp"
    if "pollution" in family:
        return "template"
    if "secret" in family or "sensitive" in family:
        return "secret"
    if "subdomain" in family or "takeover" in family:
        return "subdomain"
    return "xss"


def compliance_for_kind(kind: str) -> Dict[str, Dict[str, str]]:
    """Return ``{"owasp": ..., "pci_dss": ..., "hipaa": ...}`` for a finding."""
    category = _category_for_kind(kind)
    return {
        "owasp": OWASP_TOP10.get(category, OWASP_TOP10["xss"]),
        "pci_dss": PCI_DSS.get(category, PCI_DSS["xss"]),
        "hipaa": HIPAA.get(category, HIPAA["xss"]),
    }


def owasp_id_for_kind(kind: str) -> str:
    return compliance_for_kind(kind)["owasp"]["id"]


def finding_dedupe_fingerprint(finding: Any) -> str:
    """Stable content fingerprint for cross-report deduplication.

    Combines finding_id (when present) with kind/url/parameter so reports
    produced by different runs of the same target still line up.
    """
    get = (
        (lambda name, default="": getattr(finding, name, default))
        if not isinstance(finding, dict)
        else (lambda name, default="": finding.get(name, default))
    )
    fid = str(get("finding_id", ""))
    if fid:
        return fid
    raw = "|".join(
        str(get(name, ""))
        for name in ("kind", "url", "parameter", "method")
    )
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()


__all__ = [
    "HIPAA",
    "OWASP_TOP10",
    "PCI_DSS",
    "compliance_for_kind",
    "cvss_base_score",
    "cvss_for_finding",
    "cvss_vector",
    "cwe_for_kind",
    "finding_dedupe_fingerprint",
    "owasp_id_for_kind",
    "secondary_cwes",
]
