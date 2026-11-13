"""Structural protocols shared by scanning subsystems.

Several modules accept narrow duck-typed collaborators — a console writer or an
async HTTP client — so they stay usable without importing the concrete
:class:`~xoxss.utils.console.Console` or :class:`~xoxss.core.http.HttpEngine`.
Those protocols had drifted into eight near-duplicate copies of ``ConsoleLike``
and five of ``HttpLike``; one canonical definition keeps their signatures from
skewing when a method changes.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Protocol


class ConsoleLike(Protocol):  # pragma: no cover - structural typing
    """Reporting surface used by scanners, probes and exporters."""

    def ok(self, message: str, important: bool = True) -> None: ...
    def info(self, message: str, important: bool = True) -> None: ...
    def warn(self, message: str, important: bool = True) -> None: ...
    def error(self, message: str, important: bool = True) -> None: ...
    def debug(self, message: str) -> None: ...


class HttpLike(Protocol):  # pragma: no cover - structural typing
    """Minimal async GET surface used by crawlers and harvesters."""

    async def get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        cache: bool = False,
    ) -> Any: ...


class HttpPostLike(HttpLike, Protocol):  # pragma: no cover - structural typing
    """``HttpLike`` plus the form/JSON POST used by reflection probes."""

    async def post(
        self,
        url: str,
        *,
        data: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Any: ...
