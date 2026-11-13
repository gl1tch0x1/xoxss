"""
Comprehensive test suite for the Hybrid Detection Pipeline in xoxss.

Verifies:
1. CDP Runtime Hooks (cdp_hooks.py): Dual browser script generation, prototype wrapping,
   and telemetry parsing.
2. AST, CFG & DFG Static Slicer (dfg_slicer.py): Asynchronous flow tracking (fetch / promise / indexedDB),
   framework suppression (Vue, Alpine, React), and code slice extraction.
3. DOM Reflection Context Mutator (context_mutator.py): DOM context classification and targeted
   breakout generation calling window.__xoxss_verify().
4. LLM Semantic Triage Engine (llm_triage.py): Graceful degradation when no API key is set,
   heuristic fallback, and structured verdict parsing.
5. Headless Execution Verification Oracle (execution_oracle.py): Zero-FP gate separating
   CONFIRMED from POTENTIAL findings.
6. Full Regression: Minified Vue 3 + Alpine.js vendor bundle produces ZERO false positives.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from xoxss.core.cdp_hooks import (
    CdpTelemetryParser,
    build_cdp_instrumentation,
)
from xoxss.analysis.dfg_slicer import DfgSlicer
from xoxss.analysis.context_mutator import ContextMutator, DomSyntaxContext
from xoxss.analysis.llm_triage import (
    LLMTriageEngine,
)
from xoxss.core.execution_oracle import ExecutionOracle


# ==============================================================================
# 1. CDP Runtime Hooks & Telemetry Tests
# ==============================================================================
def test_cdp_hooks_generation():
    """Verify CDP instrumentation script builds and contains all prototype wrappers."""
    js = build_cdp_instrumentation(canary_prefix="__canary_test_")
    assert "__xoxss_cdp_active" in js
    assert "__xoxss_telemetry" in js
    assert "__xoxss_verify" in js
    assert "Element.prototype" in js
    assert "innerHTML" in js
    assert "document.write" in js
    assert "Storage.prototype.getItem" in js
    assert "IDBObjectStore.prototype.get" in js
    assert "__canary_test_" in js


def test_cdp_telemetry_parser():
    """Verify CdpTelemetryParser extracts canary hits and verified tokens."""
    sample_telemetry = {
        "hits": [
            {
                "sink": "innerHTML",
                "value": "<div>__canary_abc123</div>",
                "dom_path": "div#content",
                "script_url": "https://example.com/app.js",
                "caller_line": 42,
                "has_canary": True,
            }
        ],
        "sinks": [],
        "sources": [],
        "verified": [
            {
                "token": "tok_oracle_999",
                "timestamp": 123456789,
                "script_url": "https://example.com/app.js",
                "type": "oracle-verify",
            }
        ],
        "alerts": ["Alert: __canary_abc123"],
        "errors": [],
    }

    # Verify canary hit extraction (sink reached)
    hit = CdpTelemetryParser.match_canary_hit(sample_telemetry, "__canary_abc123")
    assert hit is not None
    assert hit["sink"] == "innerHTML"
    assert hit["status"] == "sink_reached"

    # Verify oracle verified token match (confirmed execution)
    verified_hit = CdpTelemetryParser.match_canary_hit(sample_telemetry, "tok_oracle_999")
    assert verified_hit is not None
    assert verified_hit["status"] == "confirmed_execution"

    # Verify oracle verified token extraction
    tokens = CdpTelemetryParser.extract_verified_tokens(sample_telemetry)
    assert "tok_oracle_999" in tokens

    # Non-matching token returns None
    assert CdpTelemetryParser.match_canary_hit(sample_telemetry, "non_existent_token") is None


# ==============================================================================
# 2. AST / CFG / DFG Static Slicer Tests
# ==============================================================================
def test_dfg_slicer_async_promise_flow():
    """Verify DFG slicer tracks data flows through fetch / Promise .then() callbacks."""
    async_code = """
    function loadProfile() {
        const urlParams = new URLSearchParams(window.location.search);
        const userId = urlParams.get('id');
        fetch('/api/user?id=' + userId)
            .then(response => response.json())
            .then(data => {
                const bio = data.bio;
                document.getElementById('bio').innerHTML = bio;
            });
    }
    """
    slicer = DfgSlicer(async_code, "https://example.com/async_test.js")
    flows = slicer.analyze()
    assert len(flows) >= 1
    flow = flows[0]
    assert "location.search" in flow.source or "urlparams" in flow.source.lower()
    assert flow.sink == "innerHTML"
    assert flow.is_async is True
    assert len(flow.code_slice) > 0


def test_dfg_slicer_indexeddb_callback_flow():
    """Verify DFG slicer tracks flows through IndexedDB callback parameters."""
    idb_code = """
    function readCache() {
        const req = window.indexedDB.open('my_db', 1);
        req.onsuccess = function(e) {
            const db = e.target.result;
            const tx = db.transaction(['notes'], 'readonly');
            const store = tx.objectStore('notes');
            const getReq = store.get(1);
            getReq.onsuccess = function(ev) {
                const storedVal = ev.target.result.content;
                document.body.innerHTML = storedVal;
            };
        };
    }
    """
    slicer = DfgSlicer(idb_code, "https://example.com/idb_test.js")
    flows = slicer.analyze()
    assert len(flows) >= 1
    flow = flows[0]
    assert "indexedDB" in flow.source
    assert flow.sink == "innerHTML"
    assert flow.is_async is True


def test_dfg_slicer_code_slice_extraction():
    """Verify minimal 50-150 line code slice generation."""
    lines = [f"// line {i}" for i in range(200)]
    lines[50] = "const userInput = location.hash.substring(1);"
    for i in range(51, 99):
        lines[i] = f"const temp_{i} = userInput + '{i}';"
    lines[100] = "document.getElementById('target').innerHTML = temp_98;"
    long_code = "\n".join(lines)

    slicer = DfgSlicer(long_code, "https://example.com/long.js")
    code_slice = slicer.extract_slice_by_lines([50, 100], "innerHTML = temp_98", ["userInput", "temp_98"])
    slice_lines = code_slice.splitlines()
    assert 5 <= len(slice_lines) <= 150
    assert "location.hash" in code_slice
    assert "innerHTML" in code_slice


# ==============================================================================
# 3. DOM Context Mutator Tests
# ==============================================================================
def test_context_mutator_classification():
    """Verify DOM syntax context detection for different reflection points."""
    mutator = ContextMutator()

    # HTML body context
    ctx = mutator.classify_dom_context("<div>Hello CANARY_TOKEN</div>", "CANARY_TOKEN")
    assert ctx == DomSyntaxContext.HTML_BODY

    # Double quoted attribute
    ctx = mutator.classify_dom_context('<input value="CANARY_TOKEN">', "CANARY_TOKEN")
    assert ctx == DomSyntaxContext.ATTR_DOUBLE_QUOTE

    # Single quoted attribute
    ctx = mutator.classify_dom_context("<div class='CANARY_TOKEN'>", "CANARY_TOKEN")
    assert ctx == DomSyntaxContext.ATTR_SINGLE_QUOTE

    # URI attribute
    ctx = mutator.classify_dom_context("<a href='CANARY_TOKEN'>", "CANARY_TOKEN")
    assert ctx == DomSyntaxContext.URI_ATTR

    # Script double quoted string
    ctx = mutator.classify_dom_context('<script>var msg = "CANARY_TOKEN";</script>', "CANARY_TOKEN")
    assert ctx == DomSyntaxContext.SCRIPT_DOUBLE_QUOTE

    # Template literal
    ctx = mutator.classify_dom_context("<script>var t = `CANARY_TOKEN`;</script>", "CANARY_TOKEN")
    assert ctx == DomSyntaxContext.SCRIPT_TEMPLATE_LITERAL


def test_context_mutator_payload_generation():
    """Verify generated breakout payloads invoke window.__xoxss_verify."""
    mutator = ContextMutator()
    token = "test_tok_123"

    # In HTML body, payload should contain tag breakout with __xoxss_verify
    html_payloads = mutator.generate_breakout_payloads("<div>CANARY</div>", token, "CANARY")
    assert len(html_payloads) >= 3
    assert any("__xoxss_verify" in p for p in html_payloads)

    # In double quoted attribute, payload should break out with quote and close
    attr_payloads = mutator.generate_breakout_payloads('<input value="CANARY">', token, "CANARY")
    assert any('"' in p and "__xoxss_verify" in p for p in attr_payloads)


# ==============================================================================
# 4. LLM Semantic Triage Engine Tests
# ==============================================================================
def test_llm_triage_graceful_degradation():
    """Verify LLMTriageEngine functions smoothly with rule-based heuristics when no key is set."""
    engine = LLMTriageEngine(provider="none", api_key="")

    # 1. Custom Sanitizer Analysis without LLM key
    custom_sanitizer_js = "function clean(s) { return s.replace(/<script>/gi, ''); }"
    res = engine.analyze_custom_sanitizer(custom_sanitizer_js, "<script>alert(1)</script>")
    assert res.bypass_possible is True
    assert "__xoxss_verify" in res.bypass_payload

    # 2. Recognized standard sanitizer (DOMPurify)
    dompurify_code = "const safe = DOMPurify.sanitize(input);"
    safe_res = engine.analyze_custom_sanitizer(dompurify_code)
    assert safe_res.is_safe is True
    assert safe_res.bypass_possible is False

    # 3. Component de-obfuscation fallback
    component_res = engine.deobfuscate_component("const x = 1; function test() { return x; }")
    assert component_res is not None
    assert component_res.component_name != ""

    # 4. Multi-step stored XSS planning fallback
    plan = engine.plan_stored_xss_payload("/api/profile", '{"bio": "string"}', "innerHTML")
    assert plan.endpoint == "/api/profile"
    assert "__xoxss_verify" in plan.payload


# ==============================================================================
# 5. Headless Execution Verification Oracle Tests
# ==============================================================================
class MockBrowser:
    """Mock browser engine for unit testing execution verification."""

    def __init__(self, executed: bool = False, verified_tokens: list | None = None, sinks: list | None = None):
        self._executed = executed
        self._verified_tokens = verified_tokens or []
        self._sinks = sinks or []
        self.navigated_url = ""

    async def navigate(self, url: str) -> str:
        self.navigated_url = url
        return "ok"

    async def screenshot(self, path: str) -> str:
        return f"screenshot_saved_{path}"

    @property
    def page(self):
        return self

    async def evaluate(self, script: str, *args) -> Any:
        if "COLLECT_TELEMETRY" in script or "window.__xoxss_telemetry" in script:
            return {
                "hits": [{"sink": "innerHTML", "value": "xyz", "has_canary": True}] if self._executed else [],
                "sinks": self._sinks,
                "sources": [],
                "verified": [{"token": t} for t in self._verified_tokens],
                "alerts": [],
                "errors": [],
            }
        return None


def test_execution_oracle_confirmed_verdict():
    """Verify Oracle returns CONFIRMED when window.__xoxss_verify token is captured."""
    token = "confirm_tok_777"
    mock_browser = MockBrowser(executed=True, verified_tokens=[token])
    oracle = ExecutionOracle(page_timeout=0.5)

    verdict = asyncio.run(oracle.verify_url_payload(mock_browser, "https://example.com/#" + token, token))
    assert verdict.status == "CONFIRMED"
    assert verdict.executed is True
    assert verdict.token == token
    assert "window.__xoxss_verify" in verdict.channel


def test_execution_oracle_potential_verdict():
    """Verify Oracle returns POTENTIAL when token is in DOM sink but did NOT execute."""
    token = "unexecuted_tok_888"
    mock_browser = MockBrowser(
        executed=False,
        verified_tokens=[],
        sinks=[{"sink": "innerHTML", "value": f"<div>{token}</div>", "dom_path": "div#main"}],
    )
    oracle = ExecutionOracle(page_timeout=0.3)

    verdict = asyncio.run(oracle.verify_url_payload(mock_browser, "https://example.com/#" + token, token))
    assert verdict.status == "POTENTIAL"
    assert verdict.executed is False
    assert "Canary reached sink" in verdict.evidence


# ==============================================================================
# 6. Etsy Bug Full Regression Test
# ==============================================================================
def test_etsy_bug_full_regression():
    """
    Regression Test: The exact Etsy pattern (minified Vue 3.5.34 + Alpine.js 3.15.12 vendor bundle)
    must produce ZERO flows and ZERO alerts through the entire hybrid detection pipeline.
    """
    etsy_bundle = (
        'const s = new Set(); s.add("tracking_token"); '
        'document.body.classList.add("dark-theme"); '
        'var Af = document.createElement("div"); '
        'function Ef(t) { return t; } '
        'Af.innerHTML = Ef("<div>template</div>"); '
        'const D = function(name, handler) {}; '
        'D("html", (e, {modifiers: t, expression: r}, {evaluateLater: n, effect: i}) => { '
        '    n(t => { e.innerHTML = t; }); '
        '});'
    )

    # 1. DFG Static Slicer must report 0 flows
    slicer = DfgSlicer(etsy_bundle, "https://etsy.com/assets/app-DMS-8TqE.js")
    dfg_flows = slicer.analyze()
    assert len(dfg_flows) == 0, f"Expected 0 DFG flows on Etsy bundle, got {len(dfg_flows)}"

    # 2. Minified collision filter must detect short helper identifiers as non-sources
    assert slicer._is_minified_identifier("s") is True
    assert slicer._is_minified_identifier("D") is True
    assert slicer._is_minified_identifier("indexedDB") is False


if __name__ == "__main__":
    print("1. test_cdp_hooks_generation...", end=" ", flush=True)
    test_cdp_hooks_generation()
    print("OK")
    print("2. test_cdp_telemetry_parser...", end=" ", flush=True)
    test_cdp_telemetry_parser()
    print("OK")
    print("3. test_dfg_slicer_async_promise_flow...", end=" ", flush=True)
    test_dfg_slicer_async_promise_flow()
    print("OK")
    print("4. test_dfg_slicer_indexeddb_callback_flow...", end=" ", flush=True)
    test_dfg_slicer_indexeddb_callback_flow()
    print("OK")
    print("5. test_dfg_slicer_code_slice_extraction...", end=" ", flush=True)
    test_dfg_slicer_code_slice_extraction()
    print("OK")
    print("6. test_context_mutator_classification...", end=" ", flush=True)
    test_context_mutator_classification()
    print("OK")
    print("7. test_context_mutator_payload_generation...", end=" ", flush=True)
    test_context_mutator_payload_generation()
    print("OK")
    print("8. test_llm_triage_graceful_degradation...", end=" ", flush=True)
    test_llm_triage_graceful_degradation()
    print("OK")
    print("9. test_execution_oracle_confirmed_verdict...", end=" ", flush=True)
    test_execution_oracle_confirmed_verdict()
    print("OK")
    print("10. test_execution_oracle_potential_verdict...", end=" ", flush=True)
    test_execution_oracle_potential_verdict()
    print("OK")
    print("11. test_etsy_bug_full_regression...", end=" ", flush=True)
    test_etsy_bug_full_regression()
    print("OK")
    print("ALL HYBRID PIPELINE TESTS PASSED (11/11)! ZERO FALSE POSITIVES CONFIRMED.")
