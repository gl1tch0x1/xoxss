"""Browser backends must enforce target scope on every network request."""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional

import pytest

from xoxss.core.browser import BrowserEngine, PlaywrightEngine


class StubConsole:
    def ok(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def info(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def warn(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def error(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def debug(self, *_args: Any, **_kwargs: Any) -> None:
        pass


class StubRequest:
    def __init__(self, url: str) -> None:
        self.url = url
        self.failed = False

    def fail(self) -> None:
        self.failed = True


class LegacyStubRequest:
    def __init__(self, url: str) -> None:
        self.url = url
        self.failed = False

    def fail_request(self) -> None:
        self.failed = True


class ModernNetwork:
    def __init__(self) -> None:
        self.callback: Optional[Callable[[Any], None]] = None

    def add_request_handler(self, callback: Optional[Callable[[Any], None]] = None) -> str:
        self.callback = callback
        return "handler-1"


class LegacyNetwork:
    def __init__(self) -> None:
        self.event: Optional[str] = None
        self.callback: Optional[Callable[[Any], None]] = None

    def add_request_handler(
        self, event: str, callback: Callable[[Any], None], url_patterns: Any = None
    ) -> int:
        self.event = event
        self.callback = callback
        return 1


class StubRoute:
    def __init__(self, url: str) -> None:
        self.request = type("Request", (), {"url": url})()
        self.aborted = False
        self.continued = False
        self.abort_reason = ""

    async def abort(self, reason: str) -> None:
        self.aborted = True
        self.abort_reason = reason

    async def continue_(self) -> None:
        self.continued = True


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def allow_target(url: str) -> bool:
    return url.startswith("https://target.test/")


def test_selenium_current_bidi_handler_blocks_out_of_scope_requests() -> None:
    engine = BrowserEngine(StubConsole(), url_allowed=allow_target)
    network = ModernNetwork()

    engine._install_scope_guard(type("Driver", (), {"network": network})())

    assert network.callback is not None
    allowed = StubRequest("https://target.test/app")
    blocked = StubRequest("https://other.test/")
    network.callback(allowed)
    network.callback(blocked)
    assert not allowed.failed
    assert blocked.failed
    assert engine.scope_blocked_requests == 1


def test_selenium_legacy_bidi_handler_is_supported() -> None:
    engine = BrowserEngine(StubConsole(), url_allowed=allow_target)
    network = LegacyNetwork()
    engine._install_scope_guard(type("Driver", (), {"network": network})())

    assert network.event == "before_request"
    assert network.callback is not None
    request = LegacyStubRequest("https://other.test/")
    network.callback(request)
    assert request.failed


def test_selenium_fails_closed_without_bidi_support() -> None:
    engine = BrowserEngine(StubConsole(), url_allowed=allow_target)

    with pytest.raises(RuntimeError, match="BiDi network interception"):
        engine._install_scope_guard(object())


@pytest.mark.parametrize("kind", ["chrome", "chromium", "edge"])
def test_scoped_selenium_chromium_fails_closed(kind: str) -> None:
    engine = BrowserEngine(StubConsole(), kind=kind, url_allowed=allow_target)

    with pytest.raises(RuntimeError, match="use Firefox or Playwright"):
        engine._install_scope_guard(object())


def test_playwright_route_blocks_out_of_scope_and_allows_in_scope() -> None:
    engine = PlaywrightEngine(StubConsole(), url_allowed=allow_target)
    blocked = StubRoute("https://other.test/resource.js")
    allowed = StubRoute("https://target.test/app.js")

    run(engine._guard_route(blocked))
    run(engine._guard_route(allowed))

    assert blocked.aborted
    assert blocked.abort_reason == "blockedbyclient"
    assert not blocked.continued
    assert allowed.continued
    assert not allowed.aborted
    assert engine.scope_blocked_requests == 1


def test_browser_scope_errors_fail_closed() -> None:
    def broken_scope(_url: str) -> bool:
        raise ValueError("invalid scope data")

    engine = BrowserEngine(StubConsole(), url_allowed=broken_scope)
    request = StubRequest("https://target.test/app")

    engine._on_scope_request(request)

    assert request.failed
