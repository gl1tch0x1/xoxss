"""
Injection point representation, proof-of-concept synthesis, and parameter manipulation.
"""

from __future__ import annotations

import base64
import html
import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from xoxss.core.evidence import SENSITIVE_KEY_RE
from xoxss.core.scope import normalize_url
from xoxss.scan.vectors import render_path_payload


# JS Endpoint patterns for discovery
JS_ENDPOINT_PATTERNS = (
    re.compile(
        r"""\b(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open)\s*\(\s*["'`]([^"'`\s]{1,500})["'`]""",
        re.I,
    ),
    re.compile(
        r"""\b(?:url|endpoint|api|path|action|href|src)\s*[:=]\s*["'`]([^"'`\s]{1,500})["'`]""",
        re.I,
    ),
    re.compile(r"""["'`]((?:https?://|/|\./|\.\./)[^"'`\s<>]{1,500})["'`]""", re.I),
)

VULNERABLE_LIBS = {
    "jquery": {
        "1.0.0": ("1.0.0", "1.12.4", "CVE-2019-11358", "high"),
        "2.0.0": ("2.0.0", "2.2.4", "CVE-2019-11358", "high"),
        "3.0.0": ("3.0.0", "3.4.0", "CVE-2020-11022,CVE-2020-11023", "high"),
    },
    "angular": {
        "1.0.0": ("1.0.0", "1.7.9", "CVE-2018-8005", "medium"),
        "2.0.0": ("2.0.0", "2.4.10", "CVE-2018-8005", "medium"),
        "4.0.0": ("4.0.0", "4.5.9", "CVE-2018-8005", "medium"),
        "5.0.0": ("5.0.0", "5.2.9", "CVE-2018-8005", "medium"),
    },
    "react": {
        "0.0.0": ("0.0.0", "0.14.9", "CVE-2016-10742", "medium"),
        "15.0.0": ("15.0.0", "15.6.2", "CVE-2018-6343", "medium"),
        "16.0.0": ("16.0.0", "16.3.0", "CVE-2018-6343", "medium"),
    },
    "vue": {
        "0.0.0": ("0.0.0", "2.5.16", "CVE-2018-19687", "medium"),
    },
    "bootstrap": {
        "1.0.0": ("1.0.0", "1.4.0", "CVE-2019-8331", "medium"),
        "2.0.0": ("2.0.0", "2.3.2", "CVE-2019-8331", "medium"),
        "3.0.0": ("3.0.0", "3.4.1", "CVE-2019-8331", "medium"),
        "4.0.0": ("4.0.0", "4.3.1", "CVE-2019-8331", "medium"),
    },
    "d3": {
        "0.0.0": ("0.0.0", "3.5.16", "CVE-2018-12411", "medium"),
    },
    "handlebars": {
        "0.0.0": ("0.0.0", "4.0.11", "CVE-2019-20933", "high"),
    },
    "lodash": {
        "0.0.0": ("0.0.0", "4.17.14", "CVE-2019-10744", "high"),
    },
    "moment": {
        "0.0.0": ("0.0.0", "2.24.0", "CVE-2019-13555", "medium"),
    },
    "axios": {
        "0.0.0": ("0.0.0", "0.19.0", "CVE-2020-28168", "medium"),
    },
    "ckeditor": {
        "0.0.0": ("0.0.0", "4.11.4", "CVE-2019-8197", "high"),
    },
    "tinymce": {
        "0.0.0": ("0.0.0", "4.9.11", "CVE-2019-17571", "high"),
    },
    "prototype": {
        "0.0.0": ("0.0.0", "1.7.3", "CVE-2015-1830", "high"),
    },
    "scriptaculous": {
        "0.0.0": ("0.0.0", "1.9.0", "CVE-2015-1830", "high"),
    },
    "swfobject": {
        "0.0.0": ("0.0.0", "2.2.0", "CVE-2018-12446", "medium"),
    },
}


@dataclass
class FormField:
    name: str
    value: str = ""
    type: str = "text"
    tag: str = "input"


@dataclass
class InjectionPoint:
    url: str
    method: str
    param: str
    value: str = ""
    # query | form | json | cookie | header | path | fragment | api | websocket
    source: str = "query"
    param_source: str = "discovered"  # discovered | fuzzed
    form_index: Optional[int] = None
    fields: Dict[str, FormField] = field(default_factory=dict)
    page_url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    json_body: Dict[str, Any] = field(default_factory=dict)
    content_type: str = ""
    fragment: str = ""
    path_index: int = -1
    body_text: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        return "|".join(
            [self.source, self.method, self.url, self.param, str(self.form_index), str(self.path_index)]
        )


@dataclass
class VulnerableLib:
    name: str
    version: str
    cve: str
    severity: str
    url: str = ""


@dataclass
class WAFReport:
    names: List[str] = field(default_factory=list)
    blocking: bool = False

    def __bool__(self) -> bool:
        return bool(self.names)

    def label(self) -> str:
        return ", ".join(self.names) if self.names else "none detected"


class WAFDetector:
    """Detects WAF signatures and active blocking behaviour."""

    def __init__(self, engine: Any, console: Any, target: str) -> None:
        self.engine = engine
        self.console = console
        self.target = target

    async def detect(self) -> WAFReport:
        report = WAFReport()
        response = await self.engine.get(self.target, cache=False)
        if getattr(response, "error", None):
            return report

        try:
            from xoxss.detection.waf import (
                BLOCK_WORDS,
                fingerprint as fingerprint_waf,
                looks_blocked,
            )
            if fingerprint_waf is not None:
                report.names = fingerprint_waf(
                    response.headers, response.text, response.header("set-cookie", "")
                )

            probe_url = merge_query(self.target, {"xoxss_waf_probe": "<script>alert(1)</script>"})
            probe = await self.engine.get(probe_url, allow_redirects=False)
            if probe.error is None and looks_blocked is not None:
                if looks_blocked(probe.status, probe.text, BLOCK_WORDS):
                    report.blocking = True
                    if not report.names:
                        report.names.append("Generic/Unknown WAF")
        except Exception:
            pass

        report.names = sorted(set(report.names))
        if report.names:
            message = f"WAF detected: {', '.join(report.names)}"
            if report.blocking:
                message += " (payload probe was blocked - consider --tamper)"
            self.console.warn(message)
        else:
            self.console.info("No WAF fingerprint matched")
        return report


def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of integers for comparison."""
    try:
        cleaned = re.sub(r"[-+].*$", "", version_str).lstrip("v")
        parts = [int(x) for x in cleaned.split(".")]
        return tuple(parts)
    except (ValueError, AttributeError):
        return (0,)


def version_in_range(version: str, min_ver: str, max_ver: str) -> bool:
    """Check if a version is within the vulnerable range (inclusive)."""
    try:
        v = parse_version(version)
        min_v = parse_version(min_ver)
        max_v = parse_version(max_ver)
        return min_v <= v <= max_v
    except Exception:
        return False


def extract_lib_version_from_filename(filename: str) -> Optional[Tuple[str, str]]:
    """Extract library name and version from a script filename."""
    filename = filename.lower()
    patterns = [
        ("jquery", r"jquery(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("angular", r"angular(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("react", r"react(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("vue", r"vue(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("bootstrap", r"bootstrap(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("d3", r"d3(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("handlebars", r"handlebars(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("lodash", r"lodash(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("moment", r"moment(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("axios", r"axios(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("ckeditor", r"ckeditor(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("tinymce", r"tinymce(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("prototype", r"prototype(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("scriptaculous", r"scriptaculous(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
        ("swfobject", r"swfobject(?:[-._]v?|\.)(\d+(?:\.\d+)*)"),
    ]
    for lib_name, pattern in patterns:
        match = re.search(pattern, filename)
        if match:
            version = match.group(1)
            return lib_name, version
    return None


def extract_lib_version_from_content(content: str) -> List[Tuple[str, str]]:
    """Extract library names and versions from script content."""
    results: List[Tuple[str, str]] = []
    lowered = content.lower()
    for lib, pattern in [
        ("jquery", r"jquery\s*v?(\d+[.\d]*)"),
        ("angular", r"angular\.version\s*=\s*\{[^}]*full\s*:\s*['\"](\d+[.\d]*)"),
        ("react", r"react[\s_-]?version\s*[:=]\s*['\"](\d+[.\d]*)"),
        ("vue", r"vue[\s_-]?version\s*[:=]\s*['\"](\d+[.\d]*)"),
        ("bootstrap", r"bootstrap[\s_-]?version\s*[:=]\s*['\"](\d+[.\d]*)"),
    ]:
        match = re.search(pattern, lowered)
        if match:
            results.append((lib, match.group(1)))
    return results


def check_vulnerable_libs(script_url: str, script_content: str = "") -> List[VulnerableLib]:
    """Check if a script matches known vulnerable library versions."""
    vulnerabilities = []
    filename = urlsplit(script_url).path.split("/")[-1]
    from_filename = extract_lib_version_from_filename(filename)

    libs_to_check = []
    if from_filename:
        libs_to_check.append(from_filename)
    if script_content:
        libs_to_check.extend(extract_lib_version_from_content(script_content))

    for lib_name, version in libs_to_check:
        lib_lower = lib_name.lower()
        if lib_lower in VULNERABLE_LIBS:
            for base_ver, (min_ver, max_ver, cve, severity) in VULNERABLE_LIBS[lib_lower].items():
                if version_in_range(version, min_ver, max_ver):
                    vulnerabilities.append(
                        VulnerableLib(
                            name=lib_name,
                            version=version,
                            cve=cve,
                            severity=severity,
                            url=script_url,
                        )
                    )
                    break
    return vulnerabilities


def default_field_value(field_type: str, name: str = "") -> str:
    """Generate a realistic benign default value for an HTML form field."""
    field_type = (field_type or "text").lower()
    if field_type == "email":
        return "xoxss@example.com"
    if field_type == "number":
        return "1"
    if field_type == "tel":
        return "1234567890"
    if field_type == "url":
        return "https://example.com"
    if field_type == "password":
        return "TestPassword123!"
    if field_type == "date":
        return "2026-01-01"
    if field_type == "search":
        return "test"
    return "test"


def endpoint_accepts_query_params(url: str, response_text: str = "") -> bool:
    """Verify whether endpoint accepts query parameters."""
    if bool(urlsplit(url).query):
        return True
    if not response_text:
        return False
    return (
        "?" in response_text
        or "location.search" in response_text
        or "URLSearchParams" in response_text
    )


def replace_query_param(url: str, param: str, value: str) -> str:
    """Replace or append a query parameter in a URL."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    out: List[Tuple[str, str]] = []
    replaced = False
    for key, old in pairs:
        if key == param and not replaced:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, old))
    if not replaced:
        out.append((param, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(out, doseq=True), ""))


def merge_query(url: str, extra: Dict[str, str]) -> str:
    """Merge dictionary of query parameters into a URL."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    out: List[Tuple[str, str]] = []
    remaining = dict(extra)
    for key, old in pairs:
        if key in remaining:
            out.append((key, remaining.pop(key)))
        else:
            out.append((key, old))
    out.extend(remaining.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(out, doseq=True), ""))


def extract_endpoints_from_text(text: str, base_url: str) -> List[str]:
    """Extract API routes / page URLs from HTML or JavaScript source."""
    if not text:
        return []
    found: List[str] = []
    seen: Set[str] = set()
    for pattern in JS_ENDPOINT_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(1).strip()
            if not raw or len(raw) > 500:
                continue
            if any(marker in raw for marker in ("${", "{", "}", "<", ">", "\\", " ")):
                continue
            lowered = raw.lower()
            if lowered.startswith(("javascript:", "data:", "mailto:", "tel:", "#", "blob:")):
                continue
            if lowered.endswith(
                (
                    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3",
                )
            ):
                continue
            if raw.startswith("//"):
                raw = urlsplit(base_url).scheme + ":" + raw
            absolute = urljoin(base_url, raw)
            parts = urlsplit(absolute)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                continue
            normalized = normalize_url(absolute)
            if normalized in seen:
                continue
            seen.add(normalized)
            found.append(absolute)
    return found


def build_form_html_poc(point: InjectionPoint, payload: str) -> str:
    """Self-contained HTML form PoC (base64 data URL) for POST form points."""
    if point.method.upper() == "GET":
        return ""
    if point.source == "json":
        return ""
    fields = {name: spec.value for name, spec in point.fields.items()}
    fields[point.param] = payload
    hidden = "\n".join(
        f'<input type="hidden" name="{html.escape(name)}" '
        f'value="{html.escape(value)}">'
        for name, value in fields.items()
    )
    document = (
        "<!doctype html><meta charset=\"utf-8\">"
        "<title>XOXSS PoC</title>"
        f'<form method="post" action="{html.escape(point.url)}">'
        f"{hidden}<button type=\"submit\">Submit XOXSS PoC</button></form>"
    )
    encoded = base64.b64encode(document.encode("utf-8", "replace")).decode("ascii")
    return f"data:text/html;base64,{encoded}"


def build_poc(point: InjectionPoint, payload: str) -> Tuple[str, str]:
    """Build the reproduction proof for an injection point."""
    method = point.method.upper()
    if method == "GET":
        if point.source == "path":
            return render_path_payload(point.url, payload), ""
        if point.source == "fragment":
            base = point.url.split("#", 1)[0]
            return f"{base}#{payload}", ""
        if point.source in ("query", "form", "api"):
            try:
                if point.source == "query":
                    return replace_query_param(point.url, point.param, payload), ""
                values = {name: spec.value for name, spec in point.fields.items()}
                values[point.param] = payload
                return merge_query(point.url, values), ""
            except Exception:
                return point.url, ""
        if point.source == "header" and point.param:
            command = f"curl -sk '{point.url}' -H '{point.param}: {payload}'"
            return point.url, command
        if point.source == "cookie" and point.param:
            command = f"curl -sk '{point.url}' -H 'Cookie: {point.param}={payload}'"
            return point.url, command
        return point.url, ""
    if point.source == "json":
        body: Dict[str, Any] = dict(point.json_body or {})
        body[point.param] = payload
        for key in list(body):
            if key != point.param and SENSITIVE_KEY_RE.fullmatch(key):
                body[key] = "REDACTED"
        try:
            serialized = json.dumps(body, separators=(",", ":"))
        except Exception:
            serialized = json.dumps({point.param: payload})
        content_type = point.content_type or "application/json"
        command = (
            f"curl -sk -X POST '{point.url}' "
            f"-H 'Content-Type: {content_type}' --data-raw {shlex.quote(serialized)}"
        )
        return point.url, command
    body_data = urlencode({point.param: payload})
    command = f"curl -sk -X POST '{point.url}' --data '{body_data}'"
    return point.url, command


__all__ = [
    "FormField",
    "InjectionPoint",
    "VulnerableLib",
    "WAFReport",
    "VULNERABLE_LIBS",
    "JS_ENDPOINT_PATTERNS",
    "parse_version",
    "version_in_range",
    "extract_lib_version_from_filename",
    "extract_lib_version_from_content",
    "check_vulnerable_libs",
    "default_field_value",
    "endpoint_accepts_query_params",
    "replace_query_param",
    "merge_query",
    "extract_endpoints_from_text",
    "build_form_html_poc",
    "build_poc",
]
