"""Tests for the ``--god`` / ``--yolo`` full-automatic preset."""

import pytest

from xoxss import scanner


def _console():
    return scanner.Console(verbose=False, quiet=True)


def _parse(extra=None):
    parser = scanner.build_parser()
    return parser.parse_args(["https://example.com", *(extra or [])])


def test_god_flag_and_aliases():
    parser = scanner.build_parser()
    assert parser.parse_args(["https://example.com", "--god"]).god is True
    assert parser.parse_args(["https://example.com", "--yolo"]).god is True
    assert parser.parse_args(["https://example.com"]).god is False


def test_god_preset_enables_full_stack():
    args = _parse(["--god"])
    scanner.apply_god_preset(args, _console(), {"--god"})

    # discovery
    assert args.crawl is True
    assert args.crawl_depth >= 6
    assert args.max_urls >= 3000
    assert args.js_files >= 60
    assert args.discover is True
    assert args.discover_paths is True
    assert args.fuzz_paths is True
    assert args.fuzz_params is True
    assert args.fuzz_param_limit >= 25

    # injection
    assert args.max_payloads >= 16
    assert args.payload_limit >= 1500
    assert args.scan_headers is True
    assert args.stored is True
    assert args.stored_pages >= 20
    assert args.report_reflections is True
    assert args.mutation_probes is True
    assert args.adaptive_payloads is True

    #advanced analysis
    assert args.polyglot is True
    assert args.jsonp is True
    assert args.csp_analyze is True
    assert args.cors_analyze is True
    assert args.smart_rate is True

    # network
    assert args.threads >= 20
    assert args.concurrency >= 32
    assert args.timeout >= 30.0

    # browser: headless workers + screenshots unless unavailable
    if args.no_browser:
        assert args.confirm == "http"
    else:
        assert args.browser in ("firefox", "chrome", "chromium", "edge", "playwright")
        assert args.headless is True
        assert args.browser_workers >= 2
        assert args.screenshot is True

    # automatic blind-XSS callbacks when interactsh is usable
    if scanner.HAS_RECON and scanner.InteractshClient is not None:
        assert args.interactsh == "oast.pro"
        assert args.oob_wait >= 30.0

    # recon-driven discovery requires the recon modules
    if scanner.HAS_RECON:
        assert args.subdomains is True
        assert args.passive_urls is True
        assert args.openapi is True
        assert args.mine_params is True
        assert args.allow_subdomains is True


def test_god_preset_respects_explicit_flags():
    args = _parse(["--god", "--crawl-depth", "2", "--max-payloads", "3", "--no-fuzz-params"])
    flags = {"--god", "--crawl-depth", "--max-payloads", "--no-fuzz-params"}
    scanner.apply_god_preset(args, _console(), flags)

    assert args.crawl_depth == 2
    assert args.max_payloads == 3
    assert args.fuzz_params is False
    # untouched defaults still get bumped
    assert args.max_urls >= 3000
    assert args.stored is True


@pytest.mark.parametrize(
    "argv",
    [
        ["--god", "--mass", "https://example.com"],
        ["--god", "--param-audit", "https://example.com"],
        ["--yolo", "--mass", "https://example.com"],
    ],
)
def test_god_rejected_with_standalone_modes(argv):
    assert scanner.main(argv) == 1
