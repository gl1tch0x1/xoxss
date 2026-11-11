"""
Generic OOB pollers.

Many bug-bounty setups already have a collector (XSS Hunter, a Burp Collaborator
REST bridge, a tiny Flask app, or the JSON output of interactsh-client).  These
pollers let XOXSS consume that data without forcing a particular provider.

``CallbackPoller`` polls an HTTP(S) endpoint; ``FilePoller`` tails a JSON-lines
or plain-text file (handy for a local collector or interactsh-client's output).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from xoxss.oob.base import OOBHit, OOBSource, parse_generic_payload


class CallbackPoller(OOBSource):
    """Poll a callback endpoint that returns JSON or newline-delimited text."""

    name = "callback"

    def __init__(
        self,
        console: Any,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 15.0,
        insecure: bool = False,
        proxy: Optional[str] = None,
    ):
        self.console = console
        self.url = url or ""
        self.headers = dict(headers or {})
        self.timeout = max(3.0, timeout)
        self.insecure = insecure
        self.proxy = proxy
        self.session: Any = None

    async def start(self) -> bool:
        if not self.url:
            return False
        try:
            import aiohttp
        except Exception:  # pragma: no cover
            return False
        connector = aiohttp.TCPConnector(ssl=not self.insecure)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        )
        return True

    async def close(self) -> None:
        if self.session is not None and not self.session.closed:
            await self.session.close()
        self.session = None

    def callback_for(self, marker: str) -> str:
        separator = "&" if "?" in self.url else "?"
        return f"{self.url}{separator}m={quote(marker)}"

    async def poll(self) -> List[OOBHit]:
        if self.session is None:
            return []
        try:
            async with self.session.get(self.url, headers=self.headers or None, proxy=self.proxy) as response:
                text = await response.text()
                if response.status != 200:
                    self.console.debug(f"callback poll HTTP {response.status}: {text[:120]}")
                    return []
        except Exception as exc:
            self.console.debug(f"callback poll error: {exc}")
            return []
        return parse_generic_payload(text)


class FilePoller(OOBSource):
    """Tail a local file written by a collector."""

    name = "file"

    def __init__(self, console: Any, path: str, *, callback_base: str = ""):
        self.console = console
        self.path = path or ""
        self.callback_base = callback_base
        self._offset = 0
        self._inode: Optional[int] = None

    async def start(self) -> bool:
        return bool(self.path) and Path(self.path).parent.exists()

    async def close(self) -> None:
        return None

    def callback_for(self, marker: str) -> str:
        base = self.callback_base or "file://"
        separator = "&" if "?" in base else "?"
        return f"{base}{separator}m={quote(marker)}"

    async def poll(self) -> List[OOBHit]:
        path = Path(self.path)
        if not path.exists():
            return []
        try:
            stat = path.stat()
        except OSError:
            return []
        if self._inode is not None and self._inode != getattr(stat, "st_ino", 0):
            self._offset = 0
        self._inode = getattr(stat, "st_ino", 0)
        if stat.st_size < self._offset:
            self._offset = 0
        if stat.st_size == self._offset:
            return []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._offset)
                chunk = handle.read()
                self._offset = handle.tell()
        except OSError:
            return []
        return parse_generic_payload(chunk)


__all__ = ["CallbackPoller", "FilePoller"]
