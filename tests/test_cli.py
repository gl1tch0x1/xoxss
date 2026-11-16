"""CLI parser surface: defaults, choices and the version flag."""

from __future__ import annotations

import os

import pytest

from xoxss.cli import build_parser
from xoxss.detection.encoders import encoder_names

VERSION = "9.9.9-test"


def make_parser():
    return build_parser("XOX$$", VERSION, ".xoxss", "XOXSS-Test/1.0", encoder_names())


def test_targets_are_positional_and_multiple() -> None:
    args = make_parser().parse_args(["example.com", "https://example.org/app"])
    assert args.target == ["example.com", "https://example.org/app"]


def test_profile_defaults_to_balanced() -> None:
    args = make_parser().parse_args(["example.com"])
    assert args.profile == "balanced"


def test_profile_choices_are_enforced() -> None:
    parser = make_parser()
    assert parser.parse_args(["--profile", "deep", "example.com"]).profile == "deep"
    with pytest.raises(SystemExit):
        parser.parse_args(["--profile", "nonsense", "example.com"])


def test_tamper_choices_include_every_encoder() -> None:
    args = make_parser().parse_args(["--tamper", "urlencode", "example.com"])
    assert args.tamper == "urlencode"
    with pytest.raises(SystemExit):
        make_parser().parse_args(["--tamper", "not-an-encoder", "example.com"])


def test_state_and_report_directories_are_linked() -> None:
    args = make_parser().parse_args(["--state-dir", "/tmp/state", "example.com"])
    assert args.state_dir == "/tmp/state"
    default = make_parser().parse_args(["example.com"])
    assert default.report_dir == os.path.join(".xoxss", "reports")


def test_version_flag_exits_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        make_parser().parse_args(["--version"])
    assert excinfo.value.code == 0
    assert VERSION in capsys.readouterr().out


def test_ast_analysis_is_on_by_default() -> None:
    # Regression: the flag was accepted and advertised but never read by the
    # scanner, so the analysis ran unconditionally and could not be disabled.
    assert make_parser().parse_args(["example.com"]).ast_analysis is True


def test_no_ast_analysis_disables_it() -> None:
    assert make_parser().parse_args(["--no-ast-analysis", "example.com"]).ast_analysis is False


def test_unknown_flag_is_rejected() -> None:
    with pytest.raises(SystemExit) as excinfo:
        make_parser().parse_args(["--definitely-not-a-flag"])
    assert excinfo.value.code == 2
