"""
Out-of-band (OOB) primitives shared by blind-XSS backends.

Blind XSS is only proven when an external system observes the payload's
callback.  The scanner supports two transports:

* **interactsh** – register with a public or self-hosted interactsh server and
  poll encrypted interactions (``xoxss/oob/interactsh.py``).
* **callback** – poll any JSON/text endpoint the operator controls
  (``xoxss/oob/poller.py``), e.g. XSS Hunter, Burp Collaborator's REST proxy or
  a tiny self-hosted collector.

``OOBManager`` ties them together: it allocates a unique callback URL per
injection point, remembers the marker -> injection metadata mapping, polls in
the background, and returns correlated hits.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Set


_MARKER_RE = re.compile(r"(?:[?&](?:m|marker|id|token)=)([A-Za-z0-9_-]{5,80})", re.I)


class ConsoleLike(Protocol):  # pragma: no cover
    def info(self, message: str, important: bool = False) -> None: ...
    def warn(self, message: str, important: bool = True) -> None: ...
    def debug(self, message: str) -> None: ...


@dataclass
class OOBHit:
    """A single observed out-of-band interaction."""

    marker: str
    protocol: str = ""
    remote_address: str = ""
    raw: str = ""
    timestamp: str = ""
    full_id: str = ""
    source: str = ""

    def key(self) -> str:
        digest = hashlib.sha1(
            f"{self.marker}|{self.protocol}|{self.full_id}|{self.raw[:2000]}".encode(
                "utf-8", "replace"
            )
        ).hexdigest()
        return digest

    def to_dict(self) -> Dict[str, Any]:
        return {
            "marker": self.marker,
            "protocol": self.protocol,
            "remote_address": self.remote_address,
            "raw": self.raw[:4000],
            "timestamp": self.timestamp,
            "full_id": self.full_id,
            "source": self.source,
        }


@dataclass
class MarkerRegistration:
    """Metadata for a callback allocated to one injection point."""

    marker: str
    callback: str
    url: str
    parameter: str
    method: str = "GET"
    payload: str = ""
    created: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "marker": self.marker,
            "callback": self.callback,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "created": self.created,
        }


def extract_marker(text: str, known: Optional[Iterable[str]] = None) -> str:
    """Find a marker in a callback payload."""
    blob = text or ""
    if known:
        for marker in known:
            if marker and marker in blob:
                return marker
    match = _MARKER_RE.search(blob)
    return match.group(1) if match else ""


class OOBSource:
    """Base class for an out-of-band interaction transport."""

    name = "base"

    async def start(self) -> bool:  # pragma: no cover - interface
        return True

    async def close(self) -> None:  # pragma: no cover - interface
        return None

    async def poll(self) -> List[OOBHit]:  # pragma: no cover - interface
        return []

    def callback_for(self, marker: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class OOBManager:
    """Allocate markers, poll a transport, and correlate confirmed callbacks."""

    def __init__(
        self,
        console: ConsoleLike,
        source: OOBSource,
        *,
        poll_interval: float = 5.0,
        max_hits: int = 500,
    ):
        self.console = console
        self.source = source
        self.poll_interval = max(1.0, poll_interval)
        self.max_hits = max(1, max_hits)
        self.registrations: Dict[str, MarkerRegistration] = {}
        self.hits: List[OOBHit] = []
        self._seen: Set[str] = set()
        self._lock = asyncio.Lock()
        self._started = False

    async def start(self) -> bool:
        if self._started:
            return True
        try:
            ok = await self.source.start()
        except Exception as exc:
            self.console.warn(f"OOB transport {self.source.name} failed to start: {exc}")
            return False
        self._started = bool(ok)
        if not self._started:
            self.console.warn(f"OOB transport {self.source.name} is unavailable")
        return self._started

    async def close(self) -> None:
        try:
            await self.source.close()
        except Exception:
            pass
        self._started = False

    def allocate(
        self,
        marker: str,
        url: str,
        parameter: str,
        method: str = "GET",
        payload: str = "",
        *,
        callback: Optional[str] = None,
    ) -> MarkerRegistration:
        # Callers that already own a collector (``--blind``) can keep using it
        # for injection while a different transport handles polling.
        callback = callback or self.source.callback_for(marker)
        registration = MarkerRegistration(
            marker=marker,
            callback=callback,
            url=url,
            parameter=parameter,
            method=method.upper(),
            payload=payload,
            created=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        self.registrations[marker] = registration
        return registration

    async def poll_once(self) -> List[OOBHit]:
        async with self._lock:
            try:
                hits = await self.source.poll()
            except Exception as exc:
                self.console.debug(f"OOB poll failed: {exc}")
                return []
            known = self.registrations.keys()
            fresh: List[OOBHit] = []
            for hit in hits:
                marker = hit.marker or extract_marker(hit.raw, known)
                if not marker or marker not in self.registrations:
                    # Unknown markers are still useful evidence but cannot be
                    # correlated to a specific injection point.
                    continue
                hit.marker = marker
                key = hit.key()
                if key in self._seen:
                    continue
                self._seen.add(key)
                self.hits.append(hit)
                fresh.append(hit)
                if len(self.hits) >= self.max_hits:
                    break
            for hit in fresh:
                registration = self.registrations[hit.marker]
                self.console.ok(
                    f"OOB callback received for {hit.marker} "
                    f"({hit.protocol or 'unknown'}) -> {registration.url}"
                )
            return fresh

    async def run(self, stop: asyncio.Event) -> None:
        """Poll until ``stop`` is set.  Safe to cancel."""
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.poll_interval)
                break
            except asyncio.TimeoutError:
                await self.poll_once()

    def hits_for(self, marker: str) -> List[OOBHit]:
        return [hit for hit in self.hits if hit.marker == marker]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transport": self.source.name,
            "poll_interval": self.poll_interval,
            "registrations": [item.to_dict() for item in self.registrations.values()],
            "hits": [hit.to_dict() for hit in self.hits],
        }


def parse_generic_payload(text: str, known: Optional[Iterable[str]] = None) -> List[OOBHit]:
    """Parse a callback endpoint payload.

    Accepts a JSON list/dict (common collector formats) or newline-delimited
    text.  Every item that carries a known marker is returned.
    """
    import json

    known_list = list(known or [])
    hits: List[OOBHit] = []

    def add(raw: str, protocol: str = "", remote: str = "", full_id: str = "", timestamp: str = "") -> None:
        marker = extract_marker(raw, known_list)
        if not marker:
            return
        hits.append(
            OOBHit(
                marker=marker,
                protocol=protocol,
                remote_address=remote,
                raw=raw,
                full_id=full_id,
                timestamp=timestamp,
            )
        )

    stripped = (text or "").strip()
    if not stripped:
        return hits
    try:
        payload = json.loads(stripped)
    except Exception:
        payload = None

    if isinstance(payload, dict) and any(
        key in payload for key in ("data", "hits", "requests", "results", "interactions", "events")
    ):
        for key in ("data", "hits", "requests", "results", "interactions", "events"):
            items = payload.get(key)
            if isinstance(items, list):
                payload = items
                break
    if isinstance(payload, dict):
        payload = [payload]

    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, str):
                add(item)
            elif isinstance(item, dict):
                raw = json.dumps(item, ensure_ascii=False)
                add(
                    raw,
                    protocol=str(item.get("protocol") or item.get("type") or ""),
                    remote=str(
                        item.get("remote-address")
                        or item.get("remote_address")
                        or item.get("remote")
                        or item.get("ip")
                        or ""
                    ),
                    full_id=str(item.get("full-id") or item.get("full_id") or item.get("host") or ""),
                    timestamp=str(item.get("timestamp") or item.get("time") or ""),
                )
        return hits

    for line in stripped.splitlines():
        line = line.strip()
        if line:
            add(line)
    return hits


__all__ = [
    "OOBHit",
    "MarkerRegistration",
    "OOBSource",
    "OOBManager",
    "extract_marker",
    "parse_generic_payload",
]
