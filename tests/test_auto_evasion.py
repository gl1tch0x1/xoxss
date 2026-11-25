"""Scanner-level behaviour used by ``--auto`` (polyglot fall-through, evasion)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from xoxss.cli_parser import build_parser
from xoxss.scanner import (
    APP_NAME,
    DEFAULT_STATE_DIR,
    TAMPERS,
    USER_AGENT,
    VERSION,
    XSSScanner,
)
from xoxss.utils.console import Console


def _args(*extra: str):
    parser = build_parser(APP_NAME, VERSION, DEFAULT_STATE_DIR, USER_AGENT, TAMPERS.keys())
    return parser.parse_args(
        ["http://127.0.0.1:9/?q=1", "--no-browser", "--no-state", "--report", "none", *extra]
    )


def _point():
    return SimpleNamespace(
        url="http://127.0.0.1:9/?q=1",
        method="GET",
        param="q",
        value="1",
        source="query",
        param_source="discovered",
        page_url="http://127.0.0.1:9/?q=1",
        extra={},
    )


class _Response:
    error = None
    text = "<html><body>no marker here</body></html>"

    def header(self, _name: str, default: str = "") -> str:
        return "text/html"


def test_polyglot_without_confirmation_falls_through(monkeypatch) -> None:
    args = _args("--polyglot")
    scanner = XSSScanner("http://127.0.0.1:9/?q=1", args, Console(quiet=True))

    async def fake_send(_point, _payload):
        return _Response()

    monkeypatch.setattr(scanner, "send_point", fake_send)
    info = SimpleNamespace(context="html", reflected=True, executable=False, raw_specials="<>")

    handled = asyncio.run(
        scanner._try_polyglots(_point(), "token123", info, ("u", "q", "html"))
    )
    assert handled is False


def test_auto_evasion_returns_improved_candidate(monkeypatch) -> None:
    args = _args("--auto")
    args.auto_evasion_limit = 6
    scanner = XSSScanner("http://127.0.0.1:9/?q=1", args, Console(quiet=True))

    async def fake_send(_point, payload):
        response = _Response()
        response.text = f"<html>{payload}</html>"
        return response

    monkeypatch.setattr(scanner, "send_point", fake_send)
    info = SimpleNamespace(context="html", reflected=True, executable=True, raw_specials="<>")
    seed = "<script>alert('seedtoken')</script>"

    finding, best = asyncio.run(
        scanner._auto_evasion_pass(_point(), info, (seed, "seedtoken", info, "text/html", None), "loc")
    )
    assert finding is None
    assert best is not None
    assert best[0] != seed
    assert scanner.stats.payloads > 0


def test_auto_evasion_without_executable_reflection_returns_nothing(monkeypatch) -> None:
    args = _args("--auto")
    args.auto_evasion_limit = 4
    scanner = XSSScanner("http://127.0.0.1:9/?q=1", args, Console(quiet=True))

    async def fake_send(_point, _payload):
        return _Response()

    monkeypatch.setattr(scanner, "send_point", fake_send)
    info = SimpleNamespace(context="html", reflected=True, executable=True, raw_specials="<>")
    finding, best = asyncio.run(
        scanner._auto_evasion_pass(_point(), info, ("<script>x</script>", "t", info, "", None), "loc")
    )
    assert finding is None
    assert best is None
