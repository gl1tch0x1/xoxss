"""
Regression test suite for DOM XSS false-positive elimination guards.

Verifies:
1. Minified Vue 3 + Alpine.js vendor bundle (the Etsy bug) produces ZERO alerts.
2. Feature-detection probes and static templates produce ZERO alerts.
3. Sanitized flows (IndexedDB -> DOMPurify -> innerHTML) are flagged as sanitized (no high-confidence alert).
4. True positive flows (location.search -> IndexedDB -> innerHTML) alert with exact source/sink evidence.
5. Third-party analytics scripts (GTM, Segment) are isolated and filtered from application findings.
6. Safe DOM sinks (textContent, innerText, data-* attributes) produce ZERO HTML alerts.
7. Minified variable name collisions across unrelated closures do not contaminate taint.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from xoxss.analysis.framework_sinks import (
    is_third_party_analytics,
)
from xoxss.analysis.storage_xss import StorageType, StorageXSSAnalyzer
from xoxss.analysis.enhanced_sinks import EnhancedSinkTracker
from xoxss.analysis.ast_taint import analyze_javascript
from xoxss.scanner import DomScript, static_dom_candidates


def test_vue_alpine_bundle_etsy_bug():
    """Pattern 1 & 3: Minified Vue 3.5 + Alpine 3.15 bundle with Set.add/classList.add must NOT alert."""
    bundle = (
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

    # Storage analyzer must NOT mistake Set.add / classList.add for IndexedDB
    storage_analyzer = StorageXSSAnalyzer()
    vectors = storage_analyzer.analyze(bundle)
    assert len(vectors) == 0, f"Expected 0 storage vectors, got {len(vectors)}: {[v.description for v in vectors]}"

    # Enhanced sinks tracker must NOT flag bare add() as indexeddb_execute
    tracker = EnhancedSinkTracker()
    enhanced_matches = tracker.analyze(bundle)
    for match in enhanced_matches:
        assert match.sink.value != "indexeddb_execute", f"Unexpected indexeddb_execute match: {match.code}"

    # AST taint analysis must NOT flag framework runtime internals
    flows = analyze_javascript(bundle, url="https://etsy.com/assets/app-DMS-8TqE.js")
    executable_flows = [f for f in flows if not f.sanitized and f.confidence > 0.5]
    assert len(executable_flows) == 0, f"Expected 0 executable flows, got: {[f.snippet for f in executable_flows]}"

    # Static DOM candidate generator must NOT match
    dom_scripts = [DomScript(url="https://etsy.com/assets/app-DMS-8TqE.js", content=bundle, inline=False)]
    candidates = static_dom_candidates(dom_scripts)
    assert len(candidates) == 0, f"Expected 0 candidates, got: {candidates}"
    print("[PASS] test_vue_alpine_bundle_etsy_bug")


def test_feature_detection_and_static_literals():
    """Pattern 4: Feature-detection probes and static HTML literals must NOT alert."""
    code = (
        'var div = document.createElement("div"); '
        'div.innerHTML = "<svg></svg>"; '
        'var a = document.createElement("a"); '
        'a.innerHTML = "  <link/><table></table><a href=\'/a\'>a</a><input type=\'checkbox\'/>"; '
        'var tmpl = document.createElement("template"); '
        'tmpl.innerHTML = "<span>static text</span>"; '
        'var target = document.getElementById("main"); '
        'target.innerHTML = ""; '
        'target.innerHTML = null;'
    )

    storage_analyzer = StorageXSSAnalyzer()
    assert len(storage_analyzer.analyze(code)) == 0

    flows = analyze_javascript(code, url="https://example.com/app.js")
    executable_flows = [f for f in flows if not f.sanitized]
    assert len(executable_flows) == 0, f"Expected 0 flows, got: {[f.snippet for f in executable_flows]}"

    dom_scripts = [DomScript(url="https://example.com/app.js", content=code, inline=True)]
    candidates = static_dom_candidates(dom_scripts)
    assert len(candidates) == 0, f"Expected 0 candidates, got: {candidates}"
    print("[PASS] test_feature_detection_and_static_literals")


def test_sanitized_flow():
    """Pattern 7: Flows passing through DOMPurify or HTML escaping must NOT produce high-confidence alerts."""
    code = (
        'const req = indexedDB.open("app_db", 1); '
        'req.onsuccess = (e) => { '
        '    const db = e.target.result; '
        '    const store = db.transaction(["notes"], "readonly").objectStore("notes"); '
        '    store.get(42).onsuccess = (ev) => { '
        '        const raw = ev.target.result; '
        '        const clean = DOMPurify.sanitize(raw); '
        '        document.getElementById("output").innerHTML = clean; '
        '    }; '
        '};'
    )

    storage_analyzer = StorageXSSAnalyzer()
    vectors = storage_analyzer.analyze(code)
    # Any detected vector must be marked sanitized with low confidence
    for v in vectors:
        assert v.sanitized is True, f"Expected sanitized=True for: {v.description}"
        assert v.sanitizer == "DOMPurify"
        assert v.confidence <= 0.35, f"Expected low confidence, got {v.confidence}"

    high_conf = storage_analyzer.get_high_confidence_vectors(0.7)
    assert len(high_conf) == 0, f"Expected 0 high-confidence vectors, got: {high_conf}"

    flows = analyze_javascript(code, url="https://example.com/notes.js")
    for f in flows:
        assert f.sanitized is True or f.confidence <= 0.35
    print("[PASS] test_sanitized_flow")


def test_true_positive_indexeddb_flow():
    """Verification: True positive attacker-controlled flow into IndexedDB and innerHTML MUST alert with exact evidence."""
    code = (
        'const params = new URLSearchParams(location.search); '
        'const userPayload = params.get("payload"); '
        'const req = indexedDB.open("vulnerable_db", 1); '
        'req.onsuccess = (e) => { '
        '    const db = e.target.result; '
        '    const tx = db.transaction(["data"], "readwrite"); '
        '    tx.objectStore("data").put({id: 1, val: userPayload}); '
        '    tx.objectStore("data").get(1).onsuccess = (ev) => { '
        '        const stored = ev.target.result.val; '
        '        document.getElementById("display").innerHTML = stored; '
        '    }; '
        '};'
    )

    storage_analyzer = StorageXSSAnalyzer()
    vectors = storage_analyzer.analyze(code)
    assert len(vectors) > 0, "Expected true positive IndexedDB vector to be found"

    v = vectors[0]
    assert v.storage_type == StorageType.INDEXEDDB
    assert v.attacker_reachable is True, "Expected attacker_reachable=True due to location.search"
    assert v.confidence >= 0.7, f"Expected confidence >= 0.7, got {v.confidence}"
    assert v.sink_api == "innerHTML"
    assert "indexedDB" in v.source_api or "data" in v.key
    assert "innerHTML" in v.sink_snippet
    print(f"[PASS] test_true_positive_indexeddb_flow: {v.description} (confidence={v.confidence})")


def test_third_party_analytics_isolation():
    """Pattern 5: Third-party analytics scripts (GTM, Segment, Intercom) must be tagged and suppressed."""
    gtm_url = "https://www.googletagmanager.com/gtm.js?id=GTM-TEST1234"
    gtm_code = (
        'window.dataLayer = window.dataLayer || []; '
        'var d = document.createElement("div"); '
        'd.innerHTML = "<iframe src=\'https://stats.example.com\'></iframe>";'
    )

    assert is_third_party_analytics(gtm_url, gtm_code) is True

    # Must be ignored by static_dom_candidates
    candidates = static_dom_candidates([DomScript(url=gtm_url, content=gtm_code, inline=False)])
    assert len(candidates) == 0, f"Expected 0 candidates for third-party script, got: {candidates}"

    # In AST taint, must be tagged as third-party-analytics with low confidence
    flows = analyze_javascript(gtm_code, url=gtm_url)
    for flow in flows:
        assert flow.context == "third-party-analytics"
        assert flow.confidence <= 0.25
    print("[PASS] test_third_party_analytics_isolation")


def test_safe_dom_sinks():
    """Pattern 9: textContent, innerText, value, and safe attributes must NOT be flagged as HTML injection."""
    code = (
        'var user = location.hash; '
        'document.getElementById("username").textContent = user; '
        'document.getElementById("status").innerText = user; '
        'document.getElementById("card").setAttribute("data-user", user); '
        'document.getElementById("input").value = user;'
    )

    flows = analyze_javascript(code, url="https://example.com/safe.js")
    # None of these safe sinks are in SINK_PATTERNS
    html_flows = [f for f in flows if f.sink in ("innerHTML", "outerHTML", "document.write")]
    assert len(html_flows) == 0, f"Expected 0 HTML flows, got: {html_flows}"

    candidates = static_dom_candidates([DomScript(url="https://example.com/safe.js", content=code, inline=True)])
    assert len(candidates) == 0, f"Expected 0 candidates, got: {candidates}"
    print("[PASS] test_safe_dom_sinks")


def test_minified_name_collision():
    """Pattern 2: Short minified variable collisions across independent functions must NOT connect."""
    code = (
        'function logUser() { var id = location.search; console.log(id); } '
        '/* thousands of characters of other code */ '
        'function showBanner() { var id = "banner-header"; Af.innerHTML = "<h1>" + id + "</h1>"; }'
    )

    flows = analyze_javascript(code, url="https://example.com/bundle.js")
    # Must NOT connect location.search in logUser() to Af.innerHTML in showBanner()
    bad_flows = [f for f in flows if f.source == "location.search" and "innerHTML" in f.sink and not f.sanitized]
    assert len(bad_flows) == 0, f"Expected 0 collision flows, got: {[f.snippet for f in bad_flows]}"
    print("[PASS] test_minified_name_collision")


def run_all_tests():
    print("=" * 60)
    print("Running DOM XSS False Positive Elimination Regression Suite")
    print("=" * 60)

    test_vue_alpine_bundle_etsy_bug()
    test_feature_detection_and_static_literals()
    test_sanitized_flow()
    test_true_positive_indexeddb_flow()
    test_third_party_analytics_isolation()
    test_safe_dom_sinks()
    test_minified_name_collision()

    print("=" * 60)
    print("ALL 7 REGRESSION TESTS PASSED CLEANLY!")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
