"""Shared finding-evidence helpers.

Every finding must be reproducible and safe to share.  This module owns the
small pieces that would otherwise drift between the scanner, the report
writers, the OOB confirmation path and ``--replay``:

* response excerpts centred on the reflected marker,
* copy-paste ``curl`` commands derived from the request that was actually
  sent,
* redaction of session material (cookies, auth headers, CSRF tokens),
* callback-context extraction for blind/OOB hits,
* the canonical URL used for finding de-duplication.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

# Header names whose values must never be copied into a shareable report.
SENSITIVE_HEADER_RE = re.compile(
    r"^(?:cookie|cookie2|set-cookie|authorization|proxy-authorization|"
    r"x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|x-access-token|"
    r"x-session-token|api-key|apikey)$",
    re.IGNORECASE,
)

# Body keys (JSON/form) whose values are session material, not proof.
SENSITIVE_KEY_RE = re.compile(
    r"[a-z0-9_-]*(csrf|xsrf|token|session|auth|password|passwd|secret|cookie|"
    r"api[._-]?key|key)[a-z0-9_-]*",
    re.IGNORECASE,
)

SENSITIVE_HEADER_NAMES = {
    "cookie",
    "cookie2",
    "set-cookie",
    "authorization",
    "proxy-authorization",
}

# Cookie names that typically carry session material.
SENSITIVE_COOKIE_RE = re.compile(
    r"(?:sess|sid|auth|token|jwt|csrf|xsrf|login|remember|api[_-]?key)",
    re.IGNORECASE,
)


def redact_headers(
    headers: Optional[Mapping[str, Any]],
    *,
    keep: Optional[Iterable[str]] = None,
) -> Dict[str, str]:
    """Return a header mapping safe for a report.

    Values of cookies/auth headers are replaced with ``[REDACTED]``.  Callers
    that genuinely need the live value (the request itself) keep using the
    original mapping; only the evidence copy is redacted.
    """
    preserved = {str(name).lower() for name in (keep or ())}
    result: Dict[str, str] = {}
    for name, value in (headers or {}).items():
        header_name = str(name)
        text = "" if value is None else str(value)
        if SENSITIVE_HEADER_RE.match(header_name) and header_name.lower() not in preserved:
            result[header_name] = REDACTED
        else:
            result[header_name] = text
    return result


def redact_cookie_header(value: str) -> str:
    """Redact the values of a ``Cookie`` header while keeping the names."""
    parts: List[str] = []
    for chunk in str(value or "").split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            name, _sep, _val = chunk.partition("=")
            parts.append(f"{name.strip()}={REDACTED}")
        else:
            parts.append(chunk)
    return "; ".join(parts)


def _form_pairs(text: str) -> Optional[List[Tuple[str, str]]]:
    """Return decoded form pairs when ``text`` looks like a form body.

    The round-trip matters: re-encoding preserves the wire format (``%26`` in a
    value must not become a new pair separator) while still letting us swap
    session values for ``[REDACTED]``.
    """
    if "=" not in text:
        return None
    for chunk in text.split("&"):
        if "=" not in chunk:
            return None
        name = chunk.split("=", 1)[0]
        if not name or any(char.isspace() for char in name):
            return None
    pairs = parse_qsl(text, keep_blank_values=True)
    return pairs or None


def redact_body(body: str, *, injected_parameter: str = "") -> str:
    """Redact session-bound values in a JSON or form body.

    The injected parameter is always preserved so the evidence still shows the
    payload that triggered the finding.
    """
    text = str(body or "")
    if not text:
        return ""
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            payload = json.loads(text)
        except Exception:
            return text
        return json.dumps(
            _redact_json_value(payload, injected_parameter),
            separators=(",", ":"),
            ensure_ascii=False,
        )
    if stripped[:1] == '"':
        # A JSON string body, not a form; leave it untouched.
        return text
    pairs = _form_pairs(text)
    if pairs is not None:
        def _form_value(name: str, value: str) -> str:
            if injected_parameter:
                # The injected parameter is the proof; everything else in
                # the form may carry session material.
                return value if name == injected_parameter else REDACTED
            return REDACTED if SENSITIVE_KEY_RE.fullmatch(name) else value

        return urlencode([(name, _form_value(name, value)) for name, value in pairs])
    return text


def _redact_json_value(value: Any, injected_parameter: str) -> Any:
    if isinstance(value, dict):
        return {
            str(key): (
                item
                if str(key) == injected_parameter
                else (REDACTED if SENSITIVE_KEY_RE.fullmatch(str(key)) else _redact_json_value(item, injected_parameter))
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json_value(item, injected_parameter) for item in value]
    return value


def response_excerpt(body: str, marker: str, radius: int = 100) -> str:
    """Return ``±radius`` characters around the first ``marker`` occurrence."""
    text = str(body or "")
    token = str(marker or "")
    if not text or not token:
        return ""
    index = text.find(token)
    if index < 0:
        index = text.lower().find(token.lower())
    if index < 0:
        return ""
    start = max(0, index - max(0, int(radius)))
    end = min(len(text), index + len(token) + max(0, int(radius)))
    excerpt = text[start:end]
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{excerpt}{suffix}"


def build_curl(
    method: str,
    url: str,
    *,
    headers: Optional[Mapping[str, Any]] = None,
    body: str = "",
    injected_parameter: str = "",
    redact: bool = True,
) -> str:
    """Build a copy-paste ``curl`` command for a request."""
    method = (method or "GET").upper()
    parts: List[str] = ["curl", "-sk"]
    if method not in ("GET", "HEAD"):
        parts.extend(["-X", method])
    parts.append(shlex.quote(str(url or "")))
    for name, value in (headers or {}).items():
        header_name = str(name)
        header_value = str(value)
        if redact and SENSITIVE_HEADER_RE.match(header_name):
            header_value = REDACTED
        elif redact and header_name.lower() == "cookie":
            header_value = REDACTED
        parts.extend(["-H", shlex.quote(f"{header_name}: {header_value}")])
    if body:
        rendered = (
            redact_body(str(body), injected_parameter=injected_parameter)
            if redact
            else str(body)
        )
        has_content_type = any(
            str(name).lower() == "content-type" for name in (headers or {})
        )
        if not has_content_type and rendered.lstrip()[:1] in ("{", "["):
            # curl defaults to form encoding; JSON bodies need the header.
            parts.extend(["-H", shlex.quote("Content-Type: application/json")])
        parts.extend(["--data-raw", shlex.quote(rendered)])
    return " ".join(parts)


def request_to_dict(
    method: str,
    url: str,
    *,
    headers: Optional[Mapping[str, Any]] = None,
    body: str = "",
    injected_parameter: str = "",
    redact: bool = True,
) -> Dict[str, Any]:
    """Serialise the request that produced a finding."""
    header_copy = redact_headers(headers) if redact else dict(headers or {})
    body_copy = redact_body(body, injected_parameter=injected_parameter) if redact else str(body or "")
    return {
        "method": (method or "GET").upper(),
        "url": str(url or ""),
        "headers": header_copy,
        "body": body_copy,
        "redacted": bool(redact),
    }


def finding_curl(finding: Any) -> str:
    """Return the best available curl reproduction for a finding."""
    existing = str(getattr(finding, "poc_command", "") or "")
    if existing and existing.lstrip().lower().startswith("curl"):
        return existing
    request = getattr(finding, "request", None)
    if isinstance(request, dict) and request.get("url"):
        return build_curl(
            str(request.get("method") or getattr(finding, "method", "GET")),
            str(request.get("url")),
            headers=request.get("headers") or {},
            body=str(request.get("body") or ""),
            injected_parameter=str(getattr(finding, "parameter", "") or ""),
        )
    poc_url = str(getattr(finding, "poc_url", "") or "")
    if poc_url:
        return build_curl("GET", poc_url)
    url = str(getattr(finding, "url", "") or "")
    return build_curl(getattr(finding, "method", "GET"), url) if url else ""


def canonical_finding_url(url: str, source: str = "") -> str:
    """Normalise a finding URL for duplicate detection.

    The injection *parameter* is already part of the finding key, so the query
    string is redundant for query/form/JSON points.  Stripping it prevents a
    payload-bearing URL from creating a duplicate of the same injection point.
    Other sources (DOM fragments, stored pages) keep their full URL because the
    URL itself identifies the sink.
    """
    text = str(url or "")
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    query = "" if source in ("query", "form", "json", "api") else parts.query
    fragment = "" if source == "fragment" else parts.fragment
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", query, fragment))


def finding_id(key: str) -> str:
    """Short, stable identifier used by ``--replay`` and report tables."""
    return str(key or "")[:16]


_URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
_COOKIE_HEADER_RE = re.compile(r"(?im)^\s*cookie\s*:\s*(.+)$")
_USER_AGENT_RE = re.compile(r"(?im)^\s*user-agent\s*:\s*(.+)$")
_REFERER_RE = re.compile(r"(?im)^\s*referer\s*:\s*(.+)$")


def parse_oob_context(raw: str, *, redact: bool = True) -> Dict[str, Any]:
    """Extract page URL, cookies and headers from an OOB callback body."""
    text = str(raw or "")
    result: Dict[str, Any] = {
        "page_url": "",
        "cookies": [],
        "user_agent": "",
        "referer": "",
        "method": "",
        "headers": {},
    }
    match = _URL_RE.search(text)
    if match:
        result["page_url"] = match.group(0).rstrip(".,)")
    cookie_match = _COOKIE_HEADER_RE.search(text)
    if cookie_match:
        cookie_text = cookie_match.group(1).strip()
        cookies: List[str] = []
        for chunk in cookie_text.split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "=" in chunk:
                name, _sep, value = chunk.partition("=")
                if redact and SENSITIVE_COOKIE_RE.search(name):
                    cookies.append(f"{name.strip()}={REDACTED}")
                else:
                    cookies.append(f"{name.strip()}={value.strip()}")
            else:
                cookies.append(chunk)
        result["cookies"] = cookies
    ua_match = _USER_AGENT_RE.search(text)
    if ua_match:
        result["user_agent"] = ua_match.group(1).strip()[:500]
    referer_match = _REFERER_RE.search(text)
    if referer_match:
        result["referer"] = referer_match.group(1).strip()[:2000]
    request_line = re.search(r"(?m)^\s*(GET|POST|PUT|PATCH|DELETE|HEAD)\s+\S+", text)
    if request_line:
        result["method"] = request_line.group(1).upper()
    return result


def parse_curl_request(command: str) -> Optional[Dict[str, Any]]:
    """Best-effort parser for the ``curl`` PoCs this project emits.

    Used by ``--replay`` for older reports that predate structured request
    capture.  It intentionally handles only the flags XOXSS writes.
    """
    text = str(command or "").strip()
    if not text.lower().startswith("curl"):
        return None
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return None
    method = "GET"
    url = ""
    headers: Dict[str, str] = {}
    body = ""
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in ("-X", "--request") and index + 1 < len(tokens):
            method = tokens[index + 1].upper()
            index += 2
        elif token in ("-H", "--header") and index + 1 < len(tokens):
            name, _sep, value = tokens[index + 1].partition(":")
            if name.strip():
                headers[name.strip()] = value.strip()
            index += 2
        elif token in ("--data", "--data-raw", "--data-binary") and index + 1 < len(tokens):
            body = tokens[index + 1]
            index += 2
        elif token in ("-k", "-sk", "-s", "-L", "--insecure", "--silent", "--location"):
            index += 1
        elif token.startswith("-"):
            index += 1
        else:
            if not url:
                url = token
            index += 1
    if not url:
        return None
    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "redacted": False,
    }


__all__ = [
    "REDACTED",
    "SENSITIVE_HEADER_RE",
    "SENSITIVE_KEY_RE",
    "redact_headers",
    "redact_cookie_header",
    "redact_body",
    "response_excerpt",
    "build_curl",
    "request_to_dict",
    "finding_curl",
    "canonical_finding_url",
    "finding_id",
    "parse_oob_context",
    "parse_curl_request",
]
