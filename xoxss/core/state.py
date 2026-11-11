"""Crash-safe per-target scan checkpoints and resume state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from xoxss.reports.common import APP_NAME, VERSION, now_iso


def _slugify(value: str, maxlen: int = 48) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-")
    return (slug or "target")[:maxlen]


def _normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "http").lower()
    netloc = parts.netloc.lower()
    path = parts.path or "/"
    query = urlencode(parse_qsl(parts.query, keep_blank_values=True))
    return urlunsplit((scheme, netloc, path, query, ""))


class StateStore:
    """Crash-safe JSON checkpoints for a target (resume + finding dedupe)."""

    SCHEMA = 1

    def __init__(self, target: str, directory: str, enabled: bool = True, console: Optional[Any] = None):
        self.target = target
        self.enabled = enabled
        self.console = console
        digest = hashlib.sha256(target.encode("utf-8", "replace")).hexdigest()[:12]
        host = urlsplit(target).hostname or "target"
        self.path = Path(directory) / "state" / f"{_slugify(host)}-{digest}.json"
        self.created = now_iso()
        self.scanned: Set[str] = set()
        self.findings: List[Dict[str, Any]] = []
        self.waf: List[str] = []
        self.extra: Dict[str, Any] = {}
        # Keep lifecycle state separate from the legacy ``scanned`` set so
        # existing checkpoints remain readable and only successful URLs are
        # eligible for resume skipping.
        self.url_status: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._last_save = 0.0
        # Debounce periodic checkpoints to avoid a disk write for every URL.
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
        raw_status = self.extra.get("url_status", {})
        if isinstance(raw_status, dict):
            self.url_status = {
                str(url): value for url, value in raw_status.items()
                if isinstance(value, dict)
            }
        return True

    def save(self, force: bool = False) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and (now - self._last_save) < self.min_save_interval:
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
        payload["extra"]["url_status"] = self.url_status
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                os.replace(tmp, self.path)
            except OSError:
                pass

    def is_scanned(self, url: str) -> bool:
        return _normalize_url(url) in self.scanned

    def mark_scanned(self, url: str) -> None:
        with self._lock:
            normalized = _normalize_url(url)
            self.scanned.add(normalized)
            self.url_status[normalized] = {"status": "complete", "updated": now_iso()}

    def mark_url_status(self, url: str, status: str, error: str = "") -> None:
        normalized = _normalize_url(url)
        with self._lock:
            self.url_status[normalized] = {
                "status": status,
                "updated": now_iso(),
                **({"error": error[:1000]} if error else {}),
            }
            if status != "complete":
                self.scanned.discard(normalized)

    def add_finding(self, finding: Any) -> None:
        with self._lock:
            self.findings.append(finding.to_dict())

    def replace_finding(self, old_finding: Any, finding: Any) -> None:
        """Replace a stored finding with its stronger version.

        Used when a stronger version of an already-reported issue is found
        (e.g. a browser-confirmed runtime sink replacing a static taint-flow
        lead) so resumed scans and reports never show both.  The old entry is
        located by its stored ``finding_id`` - the new finding may legitimately
        have a different precise key.
        """
        old_payload = old_finding.to_dict() if hasattr(old_finding, "to_dict") else old_finding
        old_id = str((old_payload or {}).get("finding_id") or "")
        payload = finding.to_dict()
        with self._lock:
            for index, existing in enumerate(self.findings):
                if old_id and str(existing.get("finding_id") or "") == old_id:
                    self.findings[index] = payload
                    break
            else:
                self.findings.append(payload)

    def reset(self) -> None:
        self.scanned.clear()
        self.url_status.clear()
        self.findings.clear()
        self.waf.clear()
        self.extra.clear()
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError:
            pass


__all__ = ["StateStore"]
