"""Display helpers shared by the console and every report renderer."""

from __future__ import annotations

from datetime import datetime

from xoxss.utils.helpers import fmt_duration, now_iso, strip_ansi, truncate


def test_truncate_leaves_short_text_untouched() -> None:
    assert truncate("hello", 10) == "hello"


def test_truncate_adds_ellipsis_and_respects_limit() -> None:
    assert truncate("abcdefghij", 7) == "abcd..."
    assert len(truncate("abcdefghij", 7)) == 7


def test_truncate_edge_limits() -> None:
    assert truncate("abcdef", 0) == ""
    assert truncate("abcdef", 3) == "abc"


def test_truncate_coerces_non_strings() -> None:
    assert truncate(12345, 10) == "12345"  # type: ignore[arg-type]


def test_fmt_duration_scales() -> None:
    assert fmt_duration(0) == "0.00s"
    assert fmt_duration(12.5) == "12.50s"
    assert fmt_duration(61) == "1m 1s"
    assert fmt_duration(3661) == "1h 1m 1s"


def test_fmt_duration_clamps_negative_values() -> None:
    assert fmt_duration(-5) == "0.00s"


def test_strip_ansi_removes_sgr_sequences() -> None:
    assert strip_ansi("\033[91mred\033[0m") == "red"
    assert strip_ansi("plain") == "plain"


def test_now_iso_is_parseable_utc() -> None:
    value = now_iso()
    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None
    offset = parsed.utcoffset()
    assert offset is not None
    assert offset.total_seconds() == 0
