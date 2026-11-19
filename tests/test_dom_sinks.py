"""Modern DOM sink/source coverage shared by the scanner and DOM analyzer."""

from __future__ import annotations

from xoxss.detection.dom import DOMAnalyzer, DOMSink
from xoxss.scanner import DomScript, has_dom_sink, static_dom_candidates


def test_has_dom_sink_recognizes_modern_apis() -> None:
    for code in (
        "el.setHTMLUnsafe(location.hash)",
        "el.setHTML(location.hash)",
        "document.parseHTMLUnsafe(location.hash)",
        "range.createContextualFragment(location.search)",
        "$('#out').html(location.hash)",
        "$.parseHTML(location.hash)",
        "document.execCommand('insertHTML', false, location.hash)",
        "importScripts(location.hash)",
        "new Worker(location.hash)",
        "window.open(location.hash)",
        "el.setAttribute('srcdoc', location.hash)",
    ):
        assert has_dom_sink(code), code
    assert not has_dom_sink("const value = 1 + 2;")


def test_static_candidates_require_a_source_near_the_sink() -> None:
    tainted = [DomScript(url="https://t/app.js", content="el.setHTMLUnsafe(location.hash)")]
    candidates = static_dom_candidates(tainted)
    assert candidates
    assert candidates[0]["sink"] == "setHTMLUnsafe"
    assert candidates[0]["source"] == "location.hash"

    static = [
        DomScript(url="https://t/app.js", content="el.setHTMLUnsafe('<b>static</b>')")
    ]
    assert static_dom_candidates(static) == []


def test_dom_analyzer_models_urlsearchparams_to_sethtmlunsafe() -> None:
    code = (
        "const value = new URLSearchParams(location.search).get('q');\n"
        "output.setHTMLUnsafe(value);\n"
    )
    analyzer = DOMAnalyzer()
    flows = analyzer.analyze_javascript(code)

    assert any(flow.sink.sink_type == DOMSink.SET_HTML_UNSAFE for flow in flows)
    html_flow = next(
        flow for flow in flows if flow.sink.sink_type == DOMSink.SET_HTML_UNSAFE
    )
    payload = analyzer.generate_dom_payload(html_flow, "marker")
    assert "window.__xoxss_dom_hits.push('marker')" in payload
    assert payload.startswith("<img")


def test_dom_analyzer_models_window_opener_to_eval() -> None:
    code = "const v = window.opener.name;\neval(v);\n"
    flows = DOMAnalyzer().analyze_javascript(code)

    assert any(flow.sink.sink_type == DOMSink.EVAL for flow in flows)
