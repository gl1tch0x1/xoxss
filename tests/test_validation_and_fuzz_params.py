"""Unit tests for execution-based validation pipeline (Task 1) and gated parameter discovery (Task 2)."""

import asyncio
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from xoxss.scanner import (
    CONFIRMED_EXECUTION,
    FALSE_POSITIVE,
    FUZZ_PARAM_NAMES,
    NEEDS_MANUAL_TEST,
    REJECTED,
    UNVERIFIED,
    Console,
    Finding,
    InjectionPoint,
    PayloadEngine,
    ScanStats,
    ValidationResult,
    XSSScanner,
    endpoint_accepts_query_params,
    js_marker,
)


# --------------------------------------------------------------------------------------
# Task 2: FUZZ_PARAM_NAMES and Gated Parameter Discovery Tests
# --------------------------------------------------------------------------------------

def test_fuzz_param_names_categories_coverage():
    """Verify that FUZZ_PARAM_NAMES is a tuple containing all required category parameters."""
    assert isinstance(FUZZ_PARAM_NAMES, tuple)

    # Redirect / URL sinks
    redirect_sinks = [
        "redirect_url", "redirect_uri", "redirectTo", "returnTo", "return_url",
        "return_uri", "ruri", "next_url", "continueUrl", "goto", "dest",
        "destination", "forward", "link", "path", "uri", "u", "to", "rurl",
    ]
    for param in redirect_sinks:
        assert param in FUZZ_PARAM_NAMES, f"Missing redirect sink: {param}"

    # Template / rendering sinks
    template_sinks = [
        "template", "tpl", "view", "section", "lang", "locale",
        "format", "mode", "sort", "order", "action", "type",
    ]
    for param in template_sinks:
        assert param in FUZZ_PARAM_NAMES, f"Missing template sink: {param}"

    # Content / UI sinks
    content_sinks = [
        "comment", "msg", "body", "description", "summary", "filter", "term",
        "error", "code", "reason",
    ]
    for param in content_sinks:
        assert param in FUZZ_PARAM_NAMES, f"Missing content sink: {param}"

    # Search & User input
    for param in ["q", "s", "search", "query", "keyword", "keywords", "name", "id"]:
        assert param in FUZZ_PARAM_NAMES, f"Missing search sink: {param}"


def test_endpoint_accepts_query_params_gate():
    """Verify that the gate only allows fuzzing when evidence of query params exists."""
    # 1. URL already has a query string
    assert endpoint_accepts_query_params("https://example.com/search?q=1") is True
    assert endpoint_accepts_query_params("https://example.com/api?debug") is True

    # 2. Page has no query string and no indicators in HTML/JS
    assert endpoint_accepts_query_params("https://example.com/about", "<h1>About Us</h1>") is False
    assert endpoint_accepts_query_params("https://example.com/terms", "<p>Terms of service</p>") is False

    # 3. Page references '?' in links or scripts
    assert endpoint_accepts_query_params("https://example.com/page", '<a href="/results?page=2">Next</a>') is True
    assert endpoint_accepts_query_params("https://example.com/page", 'fetch("/api/user?id=" + uid)') is True

    # 4. Page references 'location.search'
    assert endpoint_accepts_query_params("https://example.com/app", "const query = location.search;") is True

    # 5. Page references 'URLSearchParams'
    assert endpoint_accepts_query_params("https://example.com/app", "const p = new URLSearchParams(window.location.search);") is True


def test_parameter_discovery_order_and_sources():
    """Verify that discovered parameters take precedence and sources are tagged correctly."""
    console = Console(quiet=True)
    args = SimpleNamespace(
        state_dir="/tmp/xoxss-test",
        no_state=True,
        payload_file=None,
        headers=None,
        cookies=None,
        cookie_file=None,
        timeout=10.0,
        retries=1,
        rate_limit=0,
        concurrency=1,
        proxy=None,
        insecure=True,
        fuzz_params=True,
        fuzz_param_limit=5,
        param_wordlist=None,
        path_xss=False,
        crawl=True,
    )
    scanner = XSSScanner("https://example.com/", args=args, console=console)

    html_with_evidence = """
    <html>
      <form action="/login" method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
      <script>
        const params = new URLSearchParams(location.search);
      </script>
    </html>
    """
    scanner.http.get = AsyncMock(return_value=SimpleNamespace(error=None, text=html_with_evidence, header=lambda *_: "text/html"))

    points = asyncio.run(scanner.discover_points("https://example.com/login"))

    discovered = [p for p in points if getattr(p, "param_source", "") == "discovered"]
    fuzzed = [p for p in points if getattr(p, "param_source", "") == "fuzzed"]

    # Form parameters discovered first
    discovered_names = {p.param for p in discovered}
    assert "username" in discovered_names
    assert "password" in discovered_names

    # Fallback fuzzed parameters added only for non-discovered names
    assert len(fuzzed) > 0
    for fp in fuzzed:
        assert fp.param not in discovered_names
        assert fp.param in FUZZ_PARAM_NAMES


def test_parameter_discovery_gate_rejects_clean_endpoints():
    """Clean endpoints without query param evidence should NOT have invented params fuzzed."""
    console = Console(quiet=True)
    args = SimpleNamespace(
        state_dir="/tmp/xoxss-test",
        no_state=True,
        payload_file=None,
        headers=None,
        cookies=None,
        cookie_file=None,
        timeout=10.0,
        retries=1,
        rate_limit=0,
        concurrency=1,
        proxy=None,
        insecure=True,
        fuzz_params=True,
        fuzz_param_limit=10,
        param_wordlist=None,
        path_xss=False,
        crawl=True,
    )
    scanner = XSSScanner("https://example.com/static-page", args=args, console=console)

    clean_html = "<html><body><h1>Hello World</h1><p>Static article text.</p></body></html>"
    scanner.http.get = AsyncMock(return_value=SimpleNamespace(error=None, text=clean_html, header=lambda *_: "text/html"))

    points = asyncio.run(scanner.discover_points("https://example.com/static-page"))
    fuzzed = [p for p in points if getattr(p, "param_source", "") == "fuzzed"]
    assert len(fuzzed) == 0, "Clean endpoint must not be fuzzed without evidence"


# --------------------------------------------------------------------------------------
# Task 1: Execution-Based Validation Pipeline Tests
# --------------------------------------------------------------------------------------

class _MockEngine:
    def __init__(self, data: Dict[str, Any], nav_err: str = ""):
        self._data = data
        self._nav_err = nav_err

    async def navigate(self, url: str) -> str:
        if self._nav_err:
            raise RuntimeError(self._nav_err)
        return ""

    async def collect(self) -> Dict[str, Any]:
        return self._data

    async def screenshot(self, path: str) -> str:
        return path


class _MockPool:
    def __init__(self, engine: _MockEngine):
        self.engines = [engine]
        self._engine = engine

    def borrow(self):
        engine = self._engine
        class _Ctx:
            async def __aenter__(self):
                return engine
            async def __aexit__(self, *args):
                pass
        return _Ctx()


def test_js_marker_substitutes_alert():
    """Verify that js_marker includes quote-free alert and comment token."""
    token = "zxq9t1a7"
    marker = js_marker(token)
    assert f"/*{token}*/" in marker
    assert "window.__xoxss_hits" in marker
    assert "window.alert" in marker
    # Quote-free: no single or double quotes
    assert "'" not in marker
    assert '"' not in marker


def test_payload_render_replaces_alert_one():
    """Verify that templates using alert(1) replace it with unique marker string."""
    console = Console(quiet=True)
    engine = PayloadEngine(console, None)
    rendered = engine.render("<script>alert(1)</script>", "zxq9t1a7", "html")
    assert "alert(1)" not in rendered
    assert "String.fromCharCode(" in rendered


def test_validate_execution_confirmed():
    """Both reflection and execution with marker observed -> CONFIRMED_EXECUTION."""
    console = Console(quiet=True)
    args = SimpleNamespace(
        state_dir="/tmp/xoxss-test",
        no_state=True,
        payload_file=None,
        headers=None,
        cookies=None,
        cookie_file=None,
        timeout=10.0,
        retries=1,
        rate_limit=0,
        concurrency=1,
        proxy=None,
        insecure=True,
        confirm="browser",
    )
    scanner = XSSScanner("https://example.com/", args=args, console=console)
    token = "zxq9t1a7"

    mock_engine = _MockEngine({
        "dialogs": [f"alert triggered: {token}"],
        "alerts": [],
        "hits": [token],
        "sinks": [],
        "errors": [],
        "html": f"<html><body>hello {token}</body></html>",
    })
    scanner.pool = _MockPool(mock_engine)

    point = InjectionPoint(url="https://example.com/search", method="GET", param="q", value="")
    val = asyncio.run(scanner.validate_execution(point, f"<script>alert('{token}')</script>", token, response_text=f"hello {token}"))

    assert val.status == CONFIRMED_EXECUTION
    assert val.classification is None
    assert val.dialog_text is not None
    assert token in val.dialog_text


def test_validate_execution_rejected_not_reflected():
    """Marker neither in response nor DOM -> REJECTED (FALSE_POSITIVE)."""
    console = Console(quiet=True)
    args = SimpleNamespace(
        state_dir="/tmp/xoxss-test",
        no_state=True,
        payload_file=None,
        headers=None,
        cookies=None,
        cookie_file=None,
        timeout=10.0,
        retries=1,
        rate_limit=0,
        concurrency=1,
        proxy=None,
        insecure=True,
    )
    scanner = XSSScanner("https://example.com/", args=args, console=console)
    token = "zxq9t1a7"

    mock_engine = _MockEngine({
        "dialogs": [],
        "alerts": [],
        "hits": [],
        "sinks": [],
        "errors": [],
        "html": "<html><body>sanitized response</body></html>",
    })
    scanner.pool = _MockPool(mock_engine)

    point = InjectionPoint(url="https://example.com/search", method="GET", param="q", value="")
    val = asyncio.run(scanner.validate_execution(point, f"payload-{token}", token, response_text="sanitized response"))

    assert val.status == REJECTED
    assert val.classification == FALSE_POSITIVE
    assert "marker string not present" in val.reason


def test_validate_execution_rejected_coincidental_foreign_dialog():
    """Pre-existing dialog on page not containing our marker -> REJECTED (FALSE_POSITIVE)."""
    console = Console(quiet=True)
    args = SimpleNamespace(
        state_dir="/tmp/xoxss-test",
        no_state=True,
        payload_file=None,
        headers=None,
        cookies=None,
        cookie_file=None,
        timeout=10.0,
        retries=1,
        rate_limit=0,
        concurrency=1,
        proxy=None,
        insecure=True,
    )
    scanner = XSSScanner("https://example.com/", args=args, console=console)
    token = "zxq9t1a7"

    mock_engine = _MockEngine({
        # Foreign dialog fired by the site, e.g. cookie consent or session warning
        "dialogs": ["Please accept our cookies to continue"],
        "alerts": [],
        "hits": [],
        "sinks": [],
        "errors": [],
        "html": f"<html><body>{token} reflected but no XSS</body></html>",
    })
    scanner.pool = _MockPool(mock_engine)

    point = InjectionPoint(url="https://example.com/search", method="GET", param="q", value="")
    val = asyncio.run(scanner.validate_execution(point, f"payload-{token}", token, response_text=f"{token}"))

    assert val.status == REJECTED
    assert val.classification == FALSE_POSITIVE
    assert "coincidental page dialog" in val.reason


def test_validate_execution_unverified_navigation_error():
    """Navigation failure -> UNVERIFIED (NEEDS_MANUAL_TEST)."""
    console = Console(quiet=True)
    args = SimpleNamespace(
        state_dir="/tmp/xoxss-test",
        no_state=True,
        payload_file=None,
        headers=None,
        cookies=None,
        cookie_file=None,
        timeout=10.0,
        retries=1,
        rate_limit=0,
        concurrency=1,
        proxy=None,
        insecure=True,
    )
    scanner = XSSScanner("https://example.com/", args=args, console=console)
    token = "zxq9t1a7"

    mock_engine = _MockEngine({}, nav_err="net::ERR_CONNECTION_REFUSED")
    scanner.pool = _MockPool(mock_engine)

    point = InjectionPoint(url="https://example.com/search", method="GET", param="q", value="")
    val = asyncio.run(scanner.validate_execution(point, f"payload-{token}", token, response_text=f"{token}"))

    assert val.status == UNVERIFIED
    assert val.classification == NEEDS_MANUAL_TEST
    assert "navigation error" in val.reason


def test_rejection_stats_recording():
    """Validation rejections update scanner stats false_positives and needs_manual_test."""
    console = Console(quiet=True)
    args = SimpleNamespace(
        state_dir="/tmp/xoxss-test",
        no_state=True,
        payload_file=None,
        headers=None,
        cookies=None,
        cookie_file=None,
        timeout=10.0,
        retries=1,
        rate_limit=0,
        concurrency=1,
        proxy=None,
        insecure=True,
    )
    scanner = XSSScanner("https://example.com/", args=args, console=console)

    fp_val = ValidationResult(status=REJECTED, classification=FALSE_POSITIVE, reason="no execution")
    nmt_val = ValidationResult(status=UNVERIFIED, classification=NEEDS_MANUAL_TEST, reason="nav error")

    scanner._record_validation_rejection(fp_val)
    scanner._record_validation_rejection(nmt_val)

    assert scanner.stats.false_positives == 1
    assert scanner.stats.needs_manual_test == 1
    assert scanner.stats.rejections["no execution"] == 1
    assert scanner.stats.rejections["nav error"] == 1


def test_context_deduplication():
    """Deduplication ensures each (endpoint, param, context) reports at most once."""
    console = Console(quiet=True)
    args = SimpleNamespace(
        state_dir="/tmp/xoxss-test",
        no_state=True,
        payload_file=None,
        headers=None,
        cookies=None,
        cookie_file=None,
        timeout=10.0,
        retries=1,
        rate_limit=0,
        concurrency=1,
        proxy=None,
        insecure=True,
    )
    scanner = XSSScanner("https://example.com/", args=args, console=console)
    scanner.screenshot_dir.mkdir(parents=True, exist_ok=True)

    dedup_key = ("https://example.com/search", "q", "html")
    assert dedup_key not in scanner._confirmed_contexts

    scanner._confirmed_contexts.add(dedup_key)
    assert dedup_key in scanner._confirmed_contexts


# --------------------------------------------------------------------------------------
# False Positive Reduction & Confidence Policy Tests
# --------------------------------------------------------------------------------------

def _make_test_scanner(**kwargs):
    console = Console(quiet=True)
    base_args = dict(
        state_dir="/tmp/xoxss-test",
        no_state=True,
        payload_file=None,
        headers=None,
        cookies=None,
        cookie_file=None,
        timeout=10.0,
        retries=1,
        rate_limit=0,
        concurrency=1,
        proxy=None,
        insecure=True,
    )
    base_args.update(kwargs)
    args = SimpleNamespace(**base_args)
    return XSSScanner("https://example.com/", args=args, console=console)


def test_taint_flow_low_confidence():
    """Static AST taint flows must remain low confidence leads (never elevated to high/medium)."""
    scanner = _make_test_scanner(report_reflections=True)

    flow = SimpleNamespace(
        source="location.search",
        sink="element.innerHTML",
        line=42,
        snippet="element.innerHTML = location.search",
        sanitized=False,
        confidence=0.95,
        path=["q", "target"],
        context="dom",
        sanitizer="",
    )

    scanner._record_taint_flow("https://example.com/app.js", flow)
    assert len(scanner.findings) == 1
    finding = scanner.findings[0]
    assert finding.kind == "DOM XSS (taint flow)"
    assert finding.confidence == "low"
    assert "static analysis lead" in finding.confidence_rationale


def test_enforce_finding_policy_caps_unverified_leads():
    """enforce_finding_policy caps unverified static/header/cookie/websocket leads to low."""
    from xoxss.scanner import enforce_finding_policy

    finding = Finding(
        kind="Header XSS (reflection)",
        url="https://example.com/",
        parameter="User-Agent",
        method="GET",
        payload="<script>alert(1)</script>",
        evidence="reflected",
        confidence="high",
        source="header",
    )
    assert enforce_finding_policy(finding) is True
    assert finding.confidence == "low"


def test_check_stored_rejects_non_html_and_error_pages():
    """check_stored rejects 4xx/5xx errors, non-HTML responses, and entity-encoded inert reflections."""
    from xoxss.scanner import HttpResponse

    scanner = _make_test_scanner(stored=True, stored_pages=5)

    point = InjectionPoint(url="https://example.com/submit", method="POST", param="body", page_url="https://example.com/view")
    token = "zxq9t1a7"

    # 1. Error status (404) -> rejected
    http_mock = MagicMock()
    http_mock.get = AsyncMock(return_value=HttpResponse(
        "https://example.com/view", status=404, headers={"content-type": "text/html"}, text=f"Page not found: {token}"
    ))
    scanner.http = http_mock
    res = asyncio.run(scanner.check_stored(point, token, f"<script>{token}</script>"))
    assert res is None

    # 2. Non-HTML content type (application/json) -> rejected
    http_mock.get = AsyncMock(return_value=HttpResponse(
        "https://example.com/view", status=200, headers={"content-type": "application/json"}, text=f'{{"status": "ok", "msg": "<script>{token}</script>"}}'
    ))
    scanner.http = http_mock
    res = asyncio.run(scanner.check_stored(point, token, f"<script>{token}</script>"))
    assert res is None

    # 3. Entity-encoded HTML reflection (&lt;script&gt;) -> rejected
    http_mock.get = AsyncMock(return_value=HttpResponse(
        "https://example.com/view", status=200, headers={"content-type": "text/html"}, text=f'<div>&lt;script&gt;{token}&lt;/script&gt;</div>'
    ))
    scanner.http = http_mock
    res = asyncio.run(scanner.check_stored(point, token, f"<script>{token}</script>"))
    assert res is None

    # 4. Executable unescaped reflection in valid HTML 200 OK -> accepted
    http_mock.get = AsyncMock(return_value=HttpResponse(
        "https://example.com/view", status=200, headers={"content-type": "text/html"}, text=f'<div><script>{token}</script></div>'
    ))
    scanner.http = http_mock
    res = asyncio.run(scanner.check_stored(point, token, f"<script>{token}</script>"))
    assert res == "https://example.com/view"


