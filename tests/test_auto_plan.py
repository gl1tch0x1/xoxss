"""The ``--auto`` preset: enable the pipeline without trampling the operator."""

from __future__ import annotations

import argparse

from xoxss.auto.plan import AUTO_PHASES, apply_auto_preset, build_plan
from xoxss.cli_parser import build_parser
from xoxss.scanner import APP_NAME, DEFAULT_STATE_DIR, TAMPERS, USER_AGENT, VERSION
from xoxss.utils.console import Console


def parse(*argv: str) -> argparse.Namespace:
    parser = build_parser(APP_NAME, VERSION, DEFAULT_STATE_DIR, USER_AGENT, TAMPERS.keys())
    return parser.parse_args(list(argv))


def apply(args: argparse.Namespace, flags: set[str]) -> argparse.Namespace:
    apply_auto_preset(args, Console(quiet=True, log_file=None), set(flags))
    return args


def test_auto_enables_the_pipeline() -> None:
    args = apply(parse("example.com", "--auto"), {"--auto"})
    for dest in (
        "crawl",
        "discover",
        "discover_paths",
        "fuzz",
        "fuzz_params",
        "mine_params",
        "passive_urls",
        "openapi",
        "dom",
        "stored",
        "char_matrix",
        "mutation_probes",
        "adaptive_payloads",
        "polyglot",
        "path_xss",
        "fragment_xss",
        "scan_headers",
        "csp_bypass",
        "mxss",
        "proto_pollution",
        "graphql_xss",
        "websocket",
        "enhanced_sinks",
        "storage_xss",
        "dangling_markup",
        "extended_analysis",
        "screenshot",
    ):
        assert getattr(args, dest) is True, dest


def test_auto_sets_sane_budgets() -> None:
    args = apply(parse("example.com", "--auto"), {"--auto"})
    assert args.auto is True
    assert args.crawl_depth >= 4
    assert args.max_urls >= 1200
    assert args.js_files >= 80
    assert args.threads >= 20
    assert args.concurrency >= 32
    assert args.max_payloads >= 24
    assert args.stored_pages >= 25


def test_auto_preserves_explicit_flags() -> None:
    args = apply(
        parse("example.com", "--auto", "--max-urls", "10", "--threads", "2", "--report", "json"),
        {"--auto", "--max-urls", "--threads", "--report"},
    )
    assert args.max_urls == 10
    assert args.threads == 2
    assert args.report == "json"


def test_auto_does_not_enable_third_party_downloads() -> None:
    args = apply(parse("example.com", "--auto"), {"--auto"})
    assert args.remote_payloads is False


def test_auto_respects_no_browser() -> None:
    args = apply(parse("example.com", "--auto", "--no-browser"), {"--auto", "--no-browser"})
    assert args.no_browser is True
    assert args.confirm == "auto"


def test_auto_defaults_to_browser_confirmation() -> None:
    args = apply(parse("example.com", "--auto"), {"--auto"})
    assert args.confirm == "browser"
    assert args.report == "all"


def test_auto_keeps_scope_narrow_by_default() -> None:
    args = apply(parse("example.com", "--auto"), {"--auto"})
    assert args.subdomains is False
    assert args.allow_subdomains is False
    assert args.external_tools is False


def test_plan_has_every_phase() -> None:
    args = apply(parse("example.com", "--auto"), {"--auto"})
    plan = build_plan("https://example.com", args)
    keys = [phase.key for phase in plan.phases]
    assert keys == [phase.key for phase in AUTO_PHASES]
    assert "recon" in keys and "chain" in keys
    assert plan.budgets["max_urls"] >= 1200
    assert "mutation/evasion" in " ".join(plan.enabled_techniques)


def test_plan_summary_is_readable() -> None:
    plan = build_plan("https://example.com", parse("example.com"))
    summary = plan.summary()
    assert "auto plan for https://example.com" in summary
    assert "recon" in summary
