"""``--god`` preset: supremacy, opt-out handling, and drift protection.

God mode must always be the strongest preset the tool can run: every
capability flag on, every budget at its ceiling, and explicit user choices
(including ``--no-*`` opt-outs) preserved.  The drift test below fails when a
new capability flag is added without deciding whether god mode enables it.
"""

from __future__ import annotations

import argparse
from typing import Set

import pytest

import xoxss.scanner as scanner_mod
from xoxss.cli_parser import build_parser
from xoxss.core.config import ScanConfig
from xoxss.scanner import (
    APP_NAME,
    DEFAULT_STATE_DIR,
    TAMPERS,
    USER_AGENT,
    VERSION,
    apply_god_preset,
)
from xoxss.utils.console import Console


def parse(*argv: str) -> argparse.Namespace:
    parser = build_parser(
        APP_NAME, VERSION, DEFAULT_STATE_DIR, USER_AGENT, TAMPERS.keys()
    )
    return parser.parse_args(list(argv))


def engage(args: argparse.Namespace, flags: Set[str] | None = None) -> argparse.Namespace:
    apply_god_preset(args, Console(quiet=True, log_file=None), set(flags or ()))
    return args


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the preset deterministic: no local browser, no configured AI key."""
    monkeypatch.setattr(scanner_mod, "_god_browser_choice", lambda: None)
    monkeypatch.setattr(scanner_mod, "resolve_ai_key", lambda *_a, **_k: "")


#: Switches god mode deliberately leaves alone: operator-facing behaviour,
#: safety controls, or modes that change the CLI contract rather than the
#: amount of detection performed.
OPERATOR_FLAGS = {
    "ai_only",  # replaces the deterministic corpus instead of adding to it
    "allow_scheme_downgrade",  # would send credentials over cleartext
    "auto",  # mode selector: a curated plan, not a capability flag
    "doctor",
    "deep",  # preset marker; god mode already applies everything it sets
    "fail_on_findings",
    "god",
    "insecure",  # TLS verification stays on
    "keep_payloads",
    "list_encoders",
    "list_payload_catalog",
    "list_payloads",
    "list_tampers",
    "mass",
    "no_browser",
    "no_color",
    "no_resume",
    "no_state",
    "param_audit",
    "quiet",
    "remote_payloads",  # third-party payload downloads stay opt-in
    "show_browser",
    "show_secrets",  # secret masking stays on
    "verbose",
}

#: Enabled only when a usable browser backend is available.
BROWSER_ONLY = {
    "browser_discovery",
    "fragment_xss",
    "headless",
    "screenshot",
    "spa_crawl",
}

#: Enabled only when an API key is actually configured.
KEY_ONLY = {"ai"}

#: Enabled only when the optional recon stack is installed.
RECON_ONLY = {
    "allow_subdomains",
    "external_tools",  # additionally needs a supported binary on PATH
    "mine_params",
    "openapi",
    "passive_urls",
    "subdomains",
}


def default_false_booleans() -> Set[str]:
    parser = build_parser(
        APP_NAME, VERSION, DEFAULT_STATE_DIR, USER_AGENT, TAMPERS.keys()
    )
    return {
        action.dest
        for action in parser._actions
        if action.option_strings and action.default is False
    }


def test_every_capability_flag_is_enabled() -> None:
    args = engage(parse("https://target.test", "--no-browser"), {"--no-browser"})

    expected = (
        default_false_booleans()
        - OPERATOR_FLAGS
        - BROWSER_ONLY
        - KEY_ONLY
        - RECON_ONLY
        - {"hybrid", "oracle_verify"}
    )
    disabled = sorted(dest for dest in expected if getattr(args, dest, None) is not True)
    assert not disabled, f"god mode left capability flags off: {disabled}"

    # Optional modules degrade instead of disabling the capability contract.
    assert args.hybrid is scanner_mod.HAS_HYBRID
    assert args.oracle_verify is scanner_mod.HAS_HYBRID
    if scanner_mod.HAS_RECON:
        assert args.subdomains is True
        assert args.passive_urls is True
        assert args.openapi is True
        assert args.mine_params is True
        assert args.allow_subdomains is True


@pytest.mark.skipif(
    not (scanner_mod.HAS_RECON and scanner_mod.ExternalToolkit is not None),
    reason="recon stack unavailable",
)
def test_external_tools_follow_installed_binaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scanner_mod, "available_tools", lambda: {"dalfox": "dalfox"})
    args = engage(parse("https://target.test", "--no-browser"), {"--no-browser"})
    assert args.external_tools is True

    monkeypatch.setattr(scanner_mod, "available_tools", lambda: {})
    args = engage(parse("https://target.test", "--no-browser"), {"--no-browser"})
    assert args.external_tools is False

    monkeypatch.setattr(scanner_mod, "available_tools", lambda: {"dalfox": "dalfox"})
    args = engage(
        parse("https://target.test", "--no-browser", "--no-external-tools"),
        {"--no-browser", "--no-external-tools"},
    )
    assert args.external_tools is False


def test_budgets_are_at_the_ceiling() -> None:
    args = engage(parse("https://target.test", "--no-browser"), {"--no-browser"})

    assert args.crawl_depth >= 8
    assert args.max_urls >= 5000
    assert args.js_files >= 100
    assert args.max_payloads >= 24
    assert args.header_injection_limit >= 25
    assert args.header_injection_budget >= 1000
    assert args.fuzz_budget >= 1500
    assert args.fuzz_targets >= 24
    assert args.fuzz_words >= 300
    assert args.threads >= 32
    assert args.concurrency >= 48
    assert args.retries >= 3
    assert args.timeout >= 45.0


def test_explicit_flags_win_including_opt_outs() -> None:
    flags = {
        "--no-browser",
        "--no-dom",
        "--no-dangling-markup",
        "--no-external-tools",
        "--no-header-injection",
        "--no-fuzz",
        "--no-mine-params",
        "--no-openapi",
        "--no-passive-urls",
        "--no-service-worker",
        "--no-subdomains",
        "--max-urls",
        "--threads",
    }
    args = engage(
        parse(
            "https://target.test",
            "--no-browser",
            "--no-dom",
            "--no-dangling-markup",
            "--no-external-tools",
            "--no-header-injection",
            "--no-fuzz",
            "--no-mine-params",
            "--no-openapi",
            "--no-passive-urls",
            "--no-service-worker",
            "--no-subdomains",
            "--max-urls",
            "50",
            "--threads",
            "4",
        ),
        flags,
    )

    assert args.max_urls == 50
    assert args.threads == 4
    assert args.dom is False
    assert args.dangling_markup is False
    assert args.header_injection is False
    assert args.fuzz is False
    assert args.service_worker is False
    assert args.subdomains is False
    assert args.passive_urls is False
    assert args.openapi is False
    assert args.mine_params is False
    assert args.external_tools is False
    assert args.no_browser is True
    assert args.confirm == "http"


def test_browser_extras_require_a_working_browser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scanner_mod, "_god_browser_choice", lambda: ("chrome", None))
    args = engage(parse("https://target.test"))

    assert args.browser == "chrome"
    assert args.no_browser is False
    assert args.headless is True
    assert args.screenshot is True
    assert args.fragment_xss is True
    assert args.browser_discovery is True
    assert args.spa_crawl is True
    assert args.browser_workers >= 3
    assert args.browser_discovery_pages >= 25


def test_confirm_http_disables_browser_only_stages() -> None:
    args = engage(
        parse("https://target.test", "--confirm", "http"), {"--confirm"}
    )

    assert args.confirm == "http"
    assert args.fragment_xss is False
    assert args.spa_crawl is False


@pytest.mark.skipif(not scanner_mod.HAS_AI, reason="AI module unavailable")
def test_ai_fallback_only_with_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    args = engage(parse("https://target.test", "--no-browser"), {"--no-browser"})
    assert args.ai is False

    monkeypatch.setattr(scanner_mod, "resolve_ai_key", lambda *_a, **_k: "sk-test")
    args = engage(parse("https://target.test", "--no-browser"), {"--no-browser"})
    assert args.ai is True
    assert args.ai_timeout >= 90.0

    # ``--no-ai`` is a hard opt-out even with a key configured.
    args = engage(
        parse("https://target.test", "--no-browser", "--no-ai"),
        {"--no-browser", "--no-ai"},
    )
    assert args.ai is False


def test_config_round_trip_preserves_new_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scanner_mod, "_god_browser_choice", lambda: ("chrome", None))
    args = engage(parse("https://target.test"))
    config = ScanConfig.from_namespace(args)

    for name in (
        "csp_bypass",
        "enhanced_sinks",
        "storage_xss",
        "service_worker",
        "framework_bypass",
        "graphql_xss",
        "browser_discovery",
        "spa_crawl",
        "dangling_markup",
        "header_injection",
    ):
        assert getattr(config, name) is True, name


def test_cli_path_honours_assignment_tokens() -> None:
    """``--max-urls=50`` must claim the flag the same way ``--max-urls 50`` does."""
    from xoxss.app import _apply_god_mode

    argv = ["https://target.test", "--max-urls=50", "--no-browser"]
    args = parse(*argv)
    _apply_god_mode(args, argv, Console(quiet=True, log_file=None))

    assert args.max_urls == 50
    assert args.no_browser is True
    assert args.confirm == "http"
