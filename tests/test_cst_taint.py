"""Tests for the optional tree-sitter (CST) taint backend."""

import pytest

from xoxss.analysis import ast_taint
from xoxss.analysis.ast_taint import analyze_javascript, analyze_javascript_regex
from xoxss.analysis.cst_taint import AVAILABLE, analyze_javascript_cst


pytestmark = pytest.mark.skipif(not AVAILABLE, reason="tree-sitter is not installed")


def test_cst_direct_flow_matches_regex_shape():
    code = "document.getElementById('out').innerHTML = location.hash;"
    flows = analyze_javascript_cst(code, "https://app.test/bundle.js")
    assert flows
    flow = flows[0]
    assert flow.source == "location.hash"
    assert flow.sink == "innerHTML"
    assert flow.context == "html"
    assert flow.url == "https://app.test/bundle.js"
    assert flow.confidence >= 0.85


def test_cst_shadowing_does_not_report_inner_clean_variable():
    code = (
        "function outer() {\n"
        "  var data = location.hash;\n"
        "  function inner() { var data = 'safe'; el.innerHTML = data; }\n"
        "}\n"
    )
    assert analyze_javascript_cst(code) == []


def test_cst_closure_capture_is_followed():
    code = (
        "function outer() {\n"
        "  const payload = location.search;\n"
        "  const handler = () => { document.body.innerHTML = payload; };\n"
        "}\n"
    )
    flows = analyze_javascript_cst(code)
    assert flows
    assert flows[0].source == "location.search"
    assert flows[0].sink == "innerHTML"
    assert "payload" in (flows[0].path or [])


def test_cst_minified_single_letter_reuse():
    code = (
        "!function(e){var t=location.hash;function o(a){var t=a;el.innerHTML=t}o(t)}();"
    )
    flows = analyze_javascript_cst(code)
    assert flows
    assert flows[0].source == "location.hash"
    assert flows[0].sink == "innerHTML"


def test_cst_interprocedural_return_flow():
    code = (
        "function read() { return location.hash; }\n"
        "function render(v) { document.querySelector('#x').innerHTML = v; }\n"
        "render(read());\n"
    )
    flows = analyze_javascript_cst(code)
    assert flows
    assert flows[0].source == "location.hash"


def test_cst_sanitizer_is_attributed():
    code = (
        "var h = location.hash;\n"
        "var safe = DOMPurify.sanitize(h);\n"
        "el.innerHTML = safe;\n"
    )
    flows = analyze_javascript_cst(code)
    assert flows
    assert flows[0].sanitized is True
    assert flows[0].sanitizer == "DOMPurify"
    assert flows[0].confidence < 0.5


def test_cst_literal_timer_is_not_a_flow():
    assert analyze_javascript_cst("setTimeout('alert(1)', 10)") == []


def test_dispatcher_honours_regex_override(monkeypatch):
    monkeypatch.setenv("XOXSS_AST_BACKEND", "regex")

    calls = []
    real = ast_taint.analyze_javascript_regex

    def spy(code, url=""):
        calls.append(code)
        return real(code, url)

    monkeypatch.setattr(ast_taint, "analyze_javascript_regex", spy)
    flows = analyze_javascript("el.innerHTML = location.hash;")
    assert calls
    assert flows and flows[0].sink == "innerHTML"


def test_dispatcher_falls_back_when_cst_unavailable(monkeypatch):
    from xoxss.analysis import cst_taint

    monkeypatch.setattr(cst_taint, "AVAILABLE", False)
    flows = analyze_javascript("el.innerHTML = location.hash;")
    assert flows and flows[0].sink == "innerHTML"


def test_regex_backend_is_still_exported():
    flows = analyze_javascript_regex("el.innerHTML = location.hash;")
    assert flows and flows[0].sink == "innerHTML"
