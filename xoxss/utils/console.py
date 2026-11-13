"""
Console abstraction, ANSI styling, live progress status line, and briefing UI.
"""

from __future__ import annotations

import json
import random
import re
import shutil
import string
import sys
import textwrap
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Optional, Tuple

if TYPE_CHECKING:
    from xoxss.core.finding import Finding

try:
    from xoxss.utils import ui as _ui
except Exception:  # pragma: no cover
    _ui = None

from xoxss.utils.helpers import fmt_duration, now_iso, strip_ansi, truncate

APP_NAME = "XOX$$"
VERSION = "2.0.0"
CODENAME = "PERSISTENT"


class bcolors:
    """ANSI colour codes for terminal styling."""
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


def slugify(value: str, maxlen: int = 48) -> str:
    """Convert arbitrary string into filesystem-safe identifier."""
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-")
    return (slug or "target")[:maxlen]


def sanitize_text(text: Any, limit: int = 100000) -> str:
    """Escape control characters but keep newlines and SGR colour codes."""
    s = str(text).replace("\r", "\\r").replace("\x00", "\\0")
    s = re.sub(r"\x1b(?!\[[0-9;]*m)", lambda m: "\\x1b", s)
    s = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]", lambda m: "\\x%02x" % ord(m.group()), s)
    return s[:limit]


def unique_token(prefix: str = "z", length: int = 9) -> str:
    """Generate a random alphanumeric token for injection tracking."""
    alphabet = string.ascii_lowercase + string.digits
    return prefix + "".join(random.choice(alphabet) for _ in range(length))


def js_marker(token: str) -> str:
    """Quote-free JS snippet that records token in window.__xoxss_hits and triggers alert."""
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


def mark_ai_payload(payload: str, token: str) -> str:
    """Make an AI candidate attributable without breaking syntax."""
    codes = ",".join(str(ord(ch)) for ch in token)
    call = f"/*{token}*/String.fromCharCode({codes})"
    replaced = _DIALOG_CALL_RE.sub(lambda match: f"{match.group('fn')}({call})", payload)
    if replaced != payload:
        return replaced
    return (
        payload
        + f";/*{token}*/window.__xoxss_hits=(window.__xoxss_hits||[]);"
        + f"window.__xoxss_hits.push(String.fromCharCode({codes}));"
        + f"try{{window.alert(String.fromCharCode({codes}))}}catch(e){{}}"
    )


class Console:
    """Thread-safe console with optional live status line and file logging."""

    def __init__(
        self,
        verbose: bool = False,
        quiet: bool = False,
        log_file: Optional[str] = None,
        events_file: Optional[str] = None,
    ) -> None:
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
            return f"{bcolors.FAIL}{bcolors.BOLD}{label}{bcolors.ENDC} "
        return (
            f"{bcolors.GREY}[{bcolors.ENDC}{colour}{label[1]}{bcolors.ENDC}"
            f"{bcolors.GREY}]{bcolors.ENDC} "
        )

    def rule(self, text: str = "", *, important: bool = True) -> None:
        """Styled section header."""
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
                break_long_words=False,
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

    def finding(self, finding: Finding) -> None:
        """Display an actionable finding report in console."""
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
            lines.append(f"{bcolors.GREY}Rationale  :{bcolors.ENDC} {finding.confidence_rationale}")
        if finding.screenshot:
            lines.append(f"{bcolors.GREY}Screenshot :{bcolors.ENDC} {finding.screenshot}")
        if finding.poc_url:
            lines.append(f"{bcolors.GREY}PoC URL    :{bcolors.ENDC} {finding.poc_url}")
        if finding.poc_command:
            lines.append(f"{bcolors.GREY}PoC command:{bcolors.ENDC} {finding.poc_command}")
        if finding.finding_id:
            lines.append(f"{bcolors.GREY}Id         :{bcolors.ENDC} {finding.finding_id}")
        self._emit("ok", "\n".join(lines), important=True)


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
    """Print the stylized XOXSS header art."""
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


def briefing_rows(args: Any, target: str) -> List[Tuple[str, str]]:
    """Return compact metadata rows shown in the pre-scan operation briefing."""
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
        ("dom", "DOM"),
        ("scan_headers", "headers"),
        ("fuzz_params", "fuzz"),
        ("fuzz_paths", "paths"),
        ("path_xss", "path-xss"),
        ("fragment_xss", "fragment"),
        ("stored", "stored"),
        ("subdomains", "subdomains"),
        ("passive_urls", "passive-urls"),
        ("openapi", "openapi"),
        ("hybrid", "hybrid-zero-fp"),
        ("proto_pollution", "proto-pollution"),
        ("postmessage", "postMessage"),
        ("graphql", "graphql"),
        ("websocket", "websocket"),
    )
    for attr, label in vector_flags:
        if getattr(args, attr, False):
            vectors.append(label)
    vector_text = ", ".join(vectors[:6])
    if len(vectors) > 6:
        vector_text += f" (+{len(vectors) - 6} more)"

    evidence = "browser-verified" if not getattr(args, "no_browser", False) else "HTTP-only"
    if getattr(args, "oracle_verify", False):
        evidence += " + oracle"
    if getattr(args, "screenshot", False):
        evidence += " + screenshots"
    if getattr(args, "char_matrix", False):
        evidence += " + char-matrix"

    reports = getattr(args, "report", "all")
    artifacts = f"reports: {reports} -> {getattr(args, 'report_dir', '.xoxss/reports')}"
    if not getattr(args, "no_state", False):
        artifacts += f" | state: {getattr(args, 'state_dir', '.xoxss')}"

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


__all__ = [
    "bcolors",
    "Console",
    "APP_NAME",
    "VERSION",
    "CODENAME",
    "now_iso",
    "slugify",
    "truncate",
    "strip_ansi",
    "sanitize_text",
    "fmt_duration",
    "unique_token",
    "js_marker",
    "mark_ai_payload",
    "banner",
    "briefing_rows",
]

