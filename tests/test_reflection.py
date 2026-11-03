"""
Tests for the reflection analysis module.
"""

import pytest

from xoxss.detection.reflection import (
    ReflectionAnalyzer,
    ReflectionInfo,
    XSSContext,
    levenshtein_distance,
    score_reflection,
)


def test_levenshtein_distance():
    """Test Levenshtein distance calculation."""
    assert levenshtein_distance("test", "test") == 0
    assert levenshtein_distance("test", "test2") == 1
    assert levenshtein_distance("kitten", "sitting") == 3
    assert levenshtein_distance("", "abc") == 3


def test_analyze_reflection():
    """Test basic reflection analysis."""
    analyzer = ReflectionAnalyzer()
    response = '<div><script>alert(1)</script></div>'
    payload = '<script>alert(1)</script>'
    marker = 'alert(1)'

    info = analyzer.analyze_reflection(response, payload, marker, "text/html")

    assert info.reflected is True
    assert info.context == XSSContext.HTML
    assert info.efficiency_score > 0


def test_not_reflected():
    """A payload that never reaches the response is reported as such."""
    analyzer = ReflectionAnalyzer()
    info = analyzer.analyze_reflection("<div>nothing here</div>", "payloadXYZ", "payloadXYZ")
    assert info.reflected is False
    assert info.position == -1


def test_context_detection():
    """Test XSS context detection."""
    analyzer = ReflectionAnalyzer()

    html_response = '<div>payload</div>'
    info = analyzer.analyze_reflection(html_response, 'payload', 'payload', "text/html")
    assert info.context == XSSContext.HTML

    attr_response = '<input value="payload">'
    info = analyzer.analyze_reflection(attr_response, 'payload', 'payload', "text/html")
    assert info.context in (XSSContext.ATTR_DOUBLE, XSSContext.HTML)


def test_efficiency_scoring():
    """Efficiency drops when the backend mutates the payload."""
    analyzer = ReflectionAnalyzer()
    marker = "xssM1"
    payload = f"<svg/onload=alert('{marker}')>"

    # Perfect match: echoed byte-for-byte.
    response = f"<div>{payload}</div>"
    info = analyzer.analyze_reflection(response, payload, marker, "text/html")
    assert info.efficiency_score == 100.0
    assert info.distortion_percentage == 0.0

    # Quotes stripped: the payload is still there but two characters were lost.
    distorted = f"<div><svg/onload=alert({marker})></div>"
    info = analyzer.analyze_reflection(distorted, payload, marker, "text/html")
    assert info.efficiency_score < 100.0
    assert info.distortion_percentage > 0.0

    # Entity encoding is a transformation, not a faithful reflection.
    encoded = f"<div>&lt;svg/onload=alert('{marker}')&gt;</div>"
    info = analyzer.analyze_reflection(encoded, payload, marker, "text/html")
    assert 50.0 < info.efficiency_score < 100.0
    assert info.escaped is True


def test_score_reflection_helper():
    """The shared helper used by the scanner reports the same numbers."""
    marker = "xssM2"
    payload = f'<img src=x onerror=alert("{marker}")>'
    response = f"<p>{payload}</p>"

    efficiency, distortion = score_reflection(payload, response, marker)
    assert efficiency == pytest.approx(100.0)
    assert distortion == pytest.approx(0.0)

    truncated = f"<p><img src=x onerror=alert(\"{marker}\"</p>"
    efficiency, distortion = score_reflection(payload, truncated, marker)
    assert 0.0 < efficiency < 100.0
    assert distortion == pytest.approx(100.0 - efficiency)


def test_reflection_info_is_serialisable():
    """Reports call asdict() on these dataclasses."""
    from dataclasses import asdict

    info = ReflectionInfo(
        reflected=True,
        context=XSSContext.HTML,
        executable=True,
        detail="context: html",
        position=0,
        escaped=False,
        encoded=False,
        tags_before=[],
        tags_after=[],
        attributes={},
        efficiency_score=99.5,
        distortion_percentage=0.5,
    )
    data = asdict(info)
    assert data["efficiency_score"] == 99.5
    assert data["context"] is XSSContext.HTML


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
