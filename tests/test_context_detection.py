"""Context detection: the parser must classify real injection points."""

from __future__ import annotations

import pytest

from xoxss.detection.context import ContextDetector, ContextType

MARKER = "MARK"


def detect(body: str, marker: str = MARKER):
    index = body.index(marker)
    return ContextDetector().detect_context(body, index, marker)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("<div>MARK</div>", ContextType.HTML_BODY),
        ("<p>hello MARK world</p>", ContextType.HTML_BODY),
        ('<input value="MARK">', ContextType.ATTR_DOUBLE_QUOTED),
        ("<input value='MARK'>", ContextType.ATTR_SINGLE_QUOTED),
        ("<input value=MARK>", ContextType.ATTR_UNQUOTED),
        ("<img src=x MARK>", ContextType.HTML_TAG),
        ("<script>var a='MARK';</script>", ContextType.JAVASCRIPT_STRING_SINGLE),
        ('<script>var a="MARK";</script>', ContextType.JAVASCRIPT_STRING_DOUBLE),
        ("<script>/* MARK */</script>", ContextType.JAVASCRIPT_COMMENT),
        ("<style>a{color:MARK}</style>", ContextType.CSS_PROPERTY),
        ("<!-- MARK -->", ContextType.HTML_COMMENT),
        ("<textarea>MARK</textarea>", ContextType.TEXTAREA),
        ('{"a":"MARK"}', ContextType.JSON_STRING),
        ('{"a":MARK}', ContextType.JSON_VALUE),
    ],
)
def test_detects_expected_context(body: str, expected: ContextType) -> None:
    assert detect(body).context_type is expected


def test_analysis_carries_confidence_and_payloads() -> None:
    analysis = detect("<div>MARK</div>")
    assert 0.0 <= analysis.confidence <= 1.0
    assert analysis.suggested_payloads
    assert all(isinstance(item, str) for item in analysis.suggested_payloads)


def test_entity_encoded_output_is_flagged() -> None:
    analysis = detect("<div>&lt;script&gt;MARK&lt;/script&gt;</div>")
    assert analysis.entity_encoded is True


def test_inert_zone_is_reported_for_comments() -> None:
    analysis = detect("<!-- MARK -->")
    assert analysis.inert_reason


def test_enum_has_no_url_only_members() -> None:
    # The URL_*/DATA_URI members were never produced by the parser and their
    # payload branches were unreachable dead code.
    names = {member.name for member in ContextType}
    assert not {name for name in names if name.startswith("URL_")}
    assert "DATA_URI" not in names
