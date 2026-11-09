"""Position-aware reflection analysis: inert zones and entity encoding."""

from xoxss.detection.context import (
    ContextDetector,
    ContextType,
    analyze_char_survival,
    inert_zone,
    strip_inert_regions,
)
from xoxss.scan.reflection import analyze_reflection, browser_prequalified


def test_textarea_reflection_is_inert_without_breakout():
    body = "<textarea>hello TOKEN</textarea>"
    info = analyze_reflection(body, "TOKEN", "TOKEN<script>alert(1)</script>", "text/html")

    assert info.reflected
    assert info.context == "textarea"
    assert not info.executable
    assert "textarea" in info.inert_reason


def test_textarea_breakout_payload_is_executable():
    payload = "</textarea><script>TOKEN</script>"
    body = f"<textarea>{payload}</textarea>"
    info = analyze_reflection(body, "TOKEN", payload, "text/html")

    assert info.reflected
    assert info.executable
    assert not info.inert_reason


def test_html_comment_reflection_is_inert_without_breakout():
    body = "<!-- hello TOKEN -->"
    info = analyze_reflection(body, "TOKEN", "TOKEN<script>alert(1)</script>", "text/html")

    assert info.reflected
    assert info.context == "comment"
    assert not info.executable


def test_html_comment_breakout_is_executable():
    payload = "--><script>TOKEN</script>"
    body = f"<!-- {payload} -->"
    info = analyze_reflection(body, "TOKEN", payload, "text/html")

    assert info.reflected
    assert info.executable


def test_entity_encoded_output_is_not_executable():
    body = "<p>&lt;script&gt;TOKEN&lt;/script&gt;</p>"
    info = analyze_reflection(body, "TOKEN", "<script>TOKEN</script>", "text/html")

    assert info.reflected
    assert not info.executable
    assert "entity" in info.inert_reason or "encoded" in info.inert_reason


def test_unrelated_markup_does_not_count_as_payload_survival():
    # The document has "<" and ">" elsewhere, but the reflected payload tails
    # are entity-encoded.  A naive "character appears anywhere" check would
    # wrongly mark this executable.
    body = "<div>&lt;script&gt;TOKEN&lt;/script&gt;</div>"
    info = analyze_reflection(body, "TOKEN", "<script>TOKEN</script>", "text/html")

    assert not info.executable


def test_analyze_char_survival_only_looks_after_the_marker():
    body = "<div class=x>TOKEN plain text</div>"
    raw, encoded = analyze_char_survival(
        body, body.find("TOKEN"), "TOKEN", "TOKEN<script>"
    )

    # "<" and ">" exist *before* the marker but the payload tail does not
    # survive after it, so no delimiter counts as survived.
    assert "<" not in raw
    assert ">" not in raw
    assert not encoded


def test_analyze_char_survival_counts_payload_prefix_delimiters():
    payload = '"><img src=x onerror=alert(1)>TOKEN'
    body = f"<div>{payload}</div>"
    raw, encoded = analyze_char_survival(body, body.find("TOKEN"), "TOKEN", payload)

    assert {'"', "<", ">"}.issubset(raw)
    assert not encoded


def test_analyze_char_survival_marks_encoded_prefix_delimiters():
    payload = "<script>TOKEN</script>"
    body = "&lt;script&gt;TOKEN&lt;/script&gt;"
    raw, encoded = analyze_char_survival(body, body.find("TOKEN"), "TOKEN", payload)

    assert "<" in encoded
    assert "<" not in raw


def test_analyze_char_survival_detects_a_genuine_tail():
    body = "<div>TOKEN<script>alert(1)</script></div>"
    raw, encoded = analyze_char_survival(
        body, body.find("TOKEN"), "TOKEN", "TOKEN<script>alert(1)</script>"
    )

    assert {"<", ">"}.issubset(raw)
    assert not encoded


def test_inert_zone_reports_breakout():
    body = "<textarea>TOKEN</textarea>"
    reason, breakout = inert_zone(body, body.find("TOKEN"), "TOKEN")
    assert reason == "textarea"
    assert breakout

    reason, breakout = inert_zone("<textarea>TOKEN", 10, "TOKEN")
    assert reason == "textarea"
    assert not breakout


def test_strip_inert_regions_removes_comments_and_entities():
    snippet = "<!-- <b>inside</b> --><p>&lt;tag&gt;</p><textarea><i>x</i></textarea>"
    stripped = strip_inert_regions(snippet)

    # Comments and textarea bodies disappear entirely; entity references are
    # dropped so their ``<``/``>`` cannot be mistaken for live delimiters.
    assert "inside" not in stripped
    assert "&lt;" not in stripped
    assert "&gt;" not in stripped
    assert "<i>" not in stripped
    assert "x" not in stripped
    # Only the surrounding markup's own delimiters survive.
    assert stripped == "<p>tag</p>"


def test_context_detector_marks_textarea_content():
    body = "<textarea>test_marker</textarea>"
    analysis = ContextDetector().detect_context(body, body.find("test_marker"), "test_marker")

    assert analysis.context_type == ContextType.TEXTAREA


def test_browser_prequalified_rejects_textarea_and_comment():
    textarea = analyze_reflection(
        "<textarea>TOKEN</textarea>", "TOKEN", "TOKEN<script>", "text/html"
    )
    comment = analyze_reflection("<!-- TOKEN -->", "TOKEN", "TOKEN<script>", "text/html")

    assert not browser_prequalified(textarea, "text/html")
    assert not browser_prequalified(comment, "text/html")
