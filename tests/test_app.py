"""Application-layer helpers behind the CLI entry point."""

from __future__ import annotations

import argparse
import io
from typing import Any

import pytest

from xoxss import app


class StubConsole:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.infos: list[str] = []
        self.warns: list[str] = []
        self.raws: list[str] = []
        self.quiet = False

    def error(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.errors.append(str(message))

    def info(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.infos.append(str(message))

    def warn(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.warns.append(str(message))

    def raw(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.raws.append(str(message))


class InteractiveStream(io.StringIO):
    def isatty(self) -> bool:
        return True


def make_args(**overrides: Any) -> argparse.Namespace:
    defaults: dict[str, Any] = {
        "profile": "balanced",
        "crawl": True,
        "deep": False,
        "no_browser": False,
        "remote_payloads": True,
        "confirm": "auto",
        "threads": 10,
        "concurrency": 16,
        "max_response_bytes": 5 * 1024 * 1024,
        "max_payloads": 20,
        "crawl_depth": 2,
        "max_urls": 200,
        "js_files": 5,
        "fuzz_param_limit": 10,
        "subdomain_brute": 0,
        "oob_interval": 5.0,
        "oob_wait": 0.0,
        "discover": False,
        "discover_paths": False,
        "fuzz_params": False,
        "path_xss": False,
        "blind": None,
        "encoder": None,
        "oob_file": None,
        "interactsh": None,
        "subdomains": False,
        "passive_urls": False,
        "openapi": False,
        "fuzz_paths": False,
        "mine_params": False,
        "external_tools": False,
        "list_payloads": False,
        "list_payload_catalog": False,
        "list_tampers": False,
        "list_encoders": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# -- profiles ---------------------------------------------------------------


def test_quick_profile_disables_crawl_browser_and_remote_payloads() -> None:
    args = make_args(profile="quick")
    app._apply_profile(args, {"--profile"}, god_mode_requested=False)
    assert args.crawl is False
    assert args.no_browser is True
    assert args.remote_payloads is False


def test_quick_profile_respects_explicit_flags() -> None:
    args = make_args(profile="quick")
    app._apply_profile(
        args,
        {"--profile", "--browser", "--remote-payloads"},
        god_mode_requested=False,
    )
    assert args.crawl is False
    assert args.no_browser is False
    assert args.remote_payloads is True


def test_quick_profile_leaves_god_mode_alone() -> None:
    args = make_args(profile="quick")
    app._apply_profile(args, {"--god"}, god_mode_requested=True)
    assert args.crawl is True
    assert args.no_browser is False
    assert args.remote_payloads is True


def test_deep_profile_sets_deep_flag() -> None:
    args = make_args(profile="deep")
    app._apply_profile(args, {"--profile"}, god_mode_requested=False)
    assert args.deep is True


def test_apply_deep_mode_expands_limits() -> None:
    args = make_args(deep=True, crawl_depth=1, max_urls=10)
    app._apply_deep_mode(args, set())
    assert args.crawl is True
    assert args.crawl_depth == 5
    assert args.max_urls == 1500
    assert args.discover is True
    assert args.discover_paths is True
    assert args.fuzz_params is True
    assert args.path_xss is True


def test_apply_deep_mode_respects_no_path_xss() -> None:
    args = make_args(deep=True)
    app._apply_deep_mode(args, {"--no-path-xss"})
    assert args.path_xss is False


def test_apply_deep_mode_is_a_noop_without_deep() -> None:
    args = make_args(deep=False)
    app._apply_deep_mode(args, set())
    assert args.crawl_depth == 2
    assert args.max_urls == 200
    assert args.path_xss is False


# -- limit normalisation ----------------------------------------------------


def test_normalize_limits_clamps_zero_and_negative_values() -> None:
    console = StubConsole()
    args = make_args(
        no_browser=True,
        threads=0,
        concurrency=0,
        max_response_bytes=10,
        max_payloads=0,
        crawl_depth=0,
        max_urls=0,
        js_files=-1,
        fuzz_param_limit=0,
        subdomain_brute=-3,
        oob_interval=0.1,
        oob_wait=-1,
    )
    app._normalize_limits(args, console)  # type: ignore[arg-type]

    assert args.confirm == "http"
    assert args.threads == 1
    assert args.concurrency == 1
    assert args.max_response_bytes == 1024
    assert args.max_payloads == 1
    assert args.crawl_depth == 1
    assert args.max_urls == 1
    assert args.js_files == 0
    assert args.fuzz_param_limit == 1
    assert args.subdomain_brute == 0
    assert args.oob_interval == 1.0
    assert args.oob_wait == 0.0
    assert console.warns


def test_normalize_limits_keeps_valid_values() -> None:
    console = StubConsole()
    args = make_args()
    app._normalize_limits(args, console)  # type: ignore[arg-type]
    assert args.threads == 10
    assert args.crawl_depth == 2
    assert console.warns == []


# -- input validation -------------------------------------------------------


def test_invalid_blind_callback_is_rejected() -> None:
    console = StubConsole()
    args = make_args(blind="javascript:alert(1)")
    assert app._check_inputs(args, console) == 1  # type: ignore[arg-type]
    assert "http(s) callback URL" in console.errors[0]


def test_valid_blind_callback_is_announced() -> None:
    console = StubConsole()
    args = make_args(blind="https://xo.example")
    assert app._check_inputs(args, console) is None  # type: ignore[arg-type]
    assert any("xo.example" in line for line in console.infos)


def test_unknown_encoder_is_rejected() -> None:
    console = StubConsole()
    args = make_args(encoder=["not-a-real-encoder"])
    assert app._check_inputs(args, console) == 1  # type: ignore[arg-type]
    assert "--list-encoders" in console.errors[0]


def test_known_encoder_is_accepted() -> None:
    console = StubConsole()
    args = make_args(encoder=["urlencode"])
    assert app._check_inputs(args, console) is None  # type: ignore[arg-type]


def test_oob_file_requires_a_callback_source() -> None:
    console = StubConsole()
    args = make_args(oob_file="/tmp/callbacks.log")
    assert app._check_inputs(args, console) == 1  # type: ignore[arg-type]
    assert "--blind" in console.errors[0]


def test_oob_file_with_interactsh_is_accepted() -> None:
    console = StubConsole()
    args = make_args(oob_file="/tmp/callbacks.log", interactsh="oast.pro")
    assert app._check_inputs(args, console) is None  # type: ignore[arg-type]


def test_recon_requested_without_modules_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    console = StubConsole()
    monkeypatch.setattr(app, "HAS_RECON", False)
    args = make_args(passive_urls=True)
    assert app._check_recon_support(args, console) == 1  # type: ignore[arg-type]
    assert "Reconnaissance modules failed to import" in console.errors[0]


def test_recon_requested_with_modules_is_fine() -> None:
    console = StubConsole()
    args = make_args(passive_urls=True)
    assert app._check_recon_support(args, console) is None  # type: ignore[arg-type]


def test_missing_optional_dependency_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    console = StubConsole()
    monkeypatch.setattr(app, "HAS_AIOHTTP", False)
    assert app._check_required_dependencies(console) == 1  # type: ignore[arg-type]
    assert "aiohttp is required" in console.errors[0]

    console = StubConsole()
    monkeypatch.setattr(app, "HAS_AIOHTTP", True)
    monkeypatch.setattr(app, "HAS_BS4", False)
    assert app._check_required_dependencies(console) == 1  # type: ignore[arg-type]
    assert "beautifulsoup4 is required" in console.errors[0]


# -- listings and entry point ------------------------------------------------


@pytest.mark.parametrize(
    "flag", ["list_payloads", "list_payload_catalog", "list_tampers", "list_encoders"]
)
def test_listing_flags_short_circuit(
    flag: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("print_payloads", "print_payload_catalog", "print_tampers", "print_encoders"):
        monkeypatch.setattr(app, name, lambda: print("listing"))
    args = make_args(**{flag: True})
    assert app._print_requested_listing(args) == 0
    assert "listing" in capsys.readouterr().out


def test_no_listing_flag_returns_none() -> None:
    assert app._print_requested_listing(make_args()) is None


def test_main_version_flag_exits_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        app.main(["--version"])
    assert excinfo.value.code == 0
    assert "XOX$$" in capsys.readouterr().out


def test_main_list_encoders_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert app.main(["--list-encoders"]) == 0
    assert "urlencode" in capsys.readouterr().out


def test_clear_screen_only_emits_control_codes_for_interactive_terminals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal = InteractiveStream()
    monkeypatch.setattr(app.sys, "stdout", terminal)
    monkeypatch.delenv("TERM", raising=False)

    app._clear_screen()

    assert terminal.getvalue() == "\033[2J\033[H\033[3J"


def test_clear_screen_skips_non_interactive_and_dumb_terminals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = io.StringIO()
    monkeypatch.setattr(app.sys, "stdout", output)
    app._clear_screen()
    assert output.getvalue() == ""

    terminal = InteractiveStream()
    monkeypatch.setattr(app.sys, "stdout", terminal)
    monkeypatch.setenv("TERM", "dumb")
    app._clear_screen()
    assert terminal.getvalue() == ""
