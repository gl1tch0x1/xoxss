"""
Tests for the context detection module.
"""

import pytest

from xoxss.detection.context import ContextDetector, ContextType, ContextAnalysis


def _detect(response: str, marker: str = "test_marker") -> ContextAnalysis:
    detector = ContextDetector()
    return detector.detect_context(response, response.find(marker), marker)


def test_context_detection():
    """Test XSS context detection."""
    analysis = _detect('<div>test_marker</div>')
    assert analysis.context_type == ContextType.HTML_BODY

    analysis = _detect('<input value="test_marker">')
    assert analysis.context_type == ContextType.ATTR_DOUBLE_QUOTED

    analysis = _detect("<input value='test_marker'>")
    assert analysis.context_type == ContextType.ATTR_SINGLE_QUOTED

    analysis = _detect("<input value=test_marker>")
    assert analysis.context_type == ContextType.ATTR_UNQUOTED


def test_script_contexts():
    """A marker inside a script tag must not be reported as HTML body."""
    analysis = _detect('<script>var payload = "test_marker";</script>')
    assert analysis.context_type == ContextType.JAVASCRIPT_STRING_DOUBLE

    analysis = _detect("<script>var payload = 'test_marker';</script>")
    assert analysis.context_type == ContextType.JAVASCRIPT_STRING_SINGLE

    analysis = _detect("<script>doSink(test_marker)</script>")
    assert analysis.context_type == ContextType.JAVASCRIPT_CODE

    analysis = _detect("<script>// test_marker</script>")
    assert analysis.context_type == ContextType.JAVASCRIPT_COMMENT


def test_comment_context():
    analysis = _detect("<!-- test_marker -->")
    assert analysis.context_type == ContextType.HTML_COMMENT


def test_json_context():
    analysis = _detect('{"echo": "test_marker"}')
    assert analysis.context_type in (ContextType.JSON_STRING, ContextType.JSON_VALUE)


def test_payload_generation():
    """Test context-specific payload generation."""
    for response in (
        "<div>test</div>",
        '<input value="test">',
        "<script>var x = 'test';</script>",
    ):
        analysis = _detect(response, "test")
        assert analysis.suggested_payloads, response
        assert analysis.confidence > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
