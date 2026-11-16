"""Reflection analysis: executability and evidence scoring."""

from __future__ import annotations

from xoxss.detection.reflection import score_reflection
from xoxss.scan.reflection import ReflectionInfo, analyze_reflection

MARKER = "XOXMARK42"
PAYLOAD = f"<img src=x onerror=alert(1)>{MARKER}"


def test_verbatim_markup_reflection_is_executable() -> None:
    body = f"<div>{PAYLOAD}</div>"
    info = analyze_reflection(body, MARKER, PAYLOAD)
    assert info.reflected is True
    assert info.context == "html"
    assert info.executable is True
    assert "<" in info.raw_specials


def test_entity_encoded_reflection_is_not_executable() -> None:
    body = "<div>&lt;img src=x onerror=alert(1)&gt;" + MARKER + "</div>"
    info = analyze_reflection(body, MARKER, PAYLOAD)
    assert info.reflected is True
    assert info.executable is False


def test_missing_marker_is_not_a_reflection() -> None:
    info = analyze_reflection("<div>nothing here</div>", MARKER, PAYLOAD)
    assert info == ReflectionInfo() or info.reflected is False


def test_comment_reflection_is_inert_without_breakout() -> None:
    info = analyze_reflection(f"<!-- {MARKER} -->", MARKER, MARKER)
    assert info.context == "comment"
    assert info.executable is False


def test_textarea_reflection_is_inert_without_breakout() -> None:
    info = analyze_reflection(f"<textarea>{MARKER}</textarea>", MARKER, MARKER)
    assert info.context == "textarea"
    assert info.executable is False


def test_comment_breakout_payload_is_executable() -> None:
    payload = f"--><img src=x onerror=alert(1)>{MARKER}"
    body = f"<!-- {payload} -->"
    info = analyze_reflection(body, MARKER, payload)
    assert info.context == "html"
    assert info.executable is True


def test_score_reflection_rewards_exact_survival() -> None:
    payload = "<script>alert(1)</script>"
    body = f"<html><body>{payload}</body></html>"
    efficiency, distortion = score_reflection(payload, body)
    assert efficiency > 50.0
    assert distortion < 50.0


def test_score_reflection_penalises_absence() -> None:
    assert score_reflection("<script>alert(1)</script>", "<html></html>") == (0.0, 100.0)


def test_score_reflection_handles_empty_input() -> None:
    assert score_reflection("", "body") == (0.0, 100.0)
    assert score_reflection("payload", "") == (0.0, 100.0)
