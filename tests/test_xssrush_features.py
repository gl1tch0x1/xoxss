"""XSSRush-alignment features: matrix, path/fragment vectors, cookies, AI, JS mining."""

import asyncio
import json
import threading
from types import SimpleNamespace
from urllib.parse import unquote

from xoxss.analysis.ai import (
    AIAnalyzer,
    build_system_prompt,
    build_user_prompt,
    parse_ai_response,
    resolve_ai_key,
    sanitize_payloads,
)
from xoxss.detection.matrix import (
    PROBE_CHARS,
    analyze_character_matrix,
    build_matrix_probe,
    format_matrix_summary,
    matrix_delta,
)
from xoxss.recon.jsintel import extract_parameters
from xoxss.scan.vectors import (
    PATH_MARKER,
    build_path_vectors,
    path_vector_label,
    render_path_payload,
)
from xoxss.scanner import (
    Console,
    Finding,
    InjectionPoint,
    XSSScanner,
    build_form_html_poc,
    build_poc,
    mark_ai_payload,
)


# --------------------------------------------------------------------------------------
# character matrix
# --------------------------------------------------------------------------------------


def test_matrix_probe_brackets_every_delimiter_with_the_token():
    probe = build_matrix_probe("tk")
    assert probe.startswith("tk0'")
    assert "tk11`" in probe
    assert len(PROBE_CHARS) == 12


def test_matrix_reports_allowed_escaped_filtered_replaced_and_absent():
    token = "tk"
    probe = build_matrix_probe(token)
    allowed = analyze_character_matrix(probe, token)
    assert set(allowed.values()) == {"allowed"}

    escaped_body = "tk2&lt;tk tk1&quot;tk"
    escaped = analyze_character_matrix(escaped_body, token)
    assert escaped["<"] == "escaped"
    assert escaped['"'] == "escaped"

    filtered = analyze_character_matrix("tk0tk", token)
    assert filtered["'"] == "filtered"

    replaced = analyze_character_matrix("tk0Xtk", token)
    assert replaced["'"] == "replaced"

    assert analyze_character_matrix("", token)["<"] == "absent"


def test_matrix_summary_and_delta_group_statuses():
    matrix = {"<": "allowed", ">": "filtered", '"': "allowed"}
    summary = format_matrix_summary(matrix)
    assert set(summary["allowed"]) == {"<", '"'}
    assert summary["filtered"] == [">"]
    assert "allowed->filtered" in matrix_delta({"<": "allowed"}, {"<": "filtered"})


# --------------------------------------------------------------------------------------
# path / fragment vectors and PoCs
# --------------------------------------------------------------------------------------


def test_path_vectors_cover_append_and_each_segment():
    vectors = build_path_vectors("https://example.test/a/b?x=1")
    urls = [url for url, _ in vectors]
    assert urls[0] == f"https://example.test/a/b/{PATH_MARKER}"
    assert f"https://example.test/a/{PATH_MARKER}" in urls
    assert f"https://example.test/{PATH_MARKER}/b" in urls
    assert path_vector_label(-1) == "PATH(appended)"


def test_path_and_fragment_pocs_are_ready_to_open():
    payload = "<svg onload=alert(1)>"
    path_point = InjectionPoint(
        url=f"https://example.test/a/{PATH_MARKER}", method="GET", param="PATH", source="path", path_index=1
    )
    poc_url, command = build_poc(path_point, payload)
    assert command == ""
    assert "%3Csvg" in poc_url and unquote(poc_url).endswith(payload)

    fragment_point = InjectionPoint(
        url="https://example.test/page", method="GET", param="#hash", source="fragment"
    )
    fragment_url, _ = build_poc(fragment_point, payload)
    assert fragment_url == f"https://example.test/page#{payload}"
    rendered = render_path_payload(f"https://example.test/{PATH_MARKER}", payload)
    assert "<" not in rendered


def test_form_poc_is_a_base64_data_url_for_post_points():
    point = InjectionPoint(
        url="https://example.test/submit",
        method="POST",
        param="q",
        source="form",
        fields={"q": SimpleNamespace(value="old")},
    )
    data_url = build_form_html_poc(point, "<img src=x onerror=alert(1)>")
    assert data_url.startswith("data:text/html;base64,")


# --------------------------------------------------------------------------------------
# cookie parsing
# --------------------------------------------------------------------------------------


def test_cookie_parser_accepts_inline_headers_and_files(tmp_path):
    assert XSSScanner._parse_cookies(["a=1; b=2"]) == {"a": "1", "b": "2"}
    assert XSSScanner._parse_cookies(["Cookie: s=abc; t=def"]) == {"s": "abc", "t": "def"}

    json_file = tmp_path / "cookies.json"
    json_file.write_text(json.dumps({"cookies": [{"name": "sid", "value": "xyz"}]}), encoding="utf-8")
    assert XSSScanner._parse_cookies([str(json_file)]) == {"sid": "xyz"}

    netscape = tmp_path / "cookies.txt"
    netscape.write_text(
        "# Netscape HTTP Cookie File\n"
        ".example.test\tTRUE\t/\tFALSE\t0\tsession\tvalue\n",
        encoding="utf-8",
    )
    assert XSSScanner._parse_cookies([], [str(netscape)]).get("session") == "value"

    lines = tmp_path / "plain.txt"
    lines.write_text("alpha=one\nbeta=two\n", encoding="utf-8")
    assert XSSScanner._parse_cookies([str(lines)]) == {"alpha": "one", "beta": "two"}


# --------------------------------------------------------------------------------------
# JavaScript global mining
# --------------------------------------------------------------------------------------


def test_js_parameter_mining_includes_window_globals_and_filters_browser_state():
    js = """
    window.tracker = { enabled: true };
    window['checkoutToken'] = 'secret';
    window.location = '/next';
    if (Object.keys(window).length) { run(); }
    """
    names = extract_parameters(js)
    assert "tracker" in names
    assert "checkoutToken" in names
    assert "location" not in names
    assert "__window_keys__" in names


# --------------------------------------------------------------------------------------
# AI fallback
# --------------------------------------------------------------------------------------


def test_ai_key_resolution_priority(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "env-key")
    assert resolve_ai_key("cli-key") == "cli-key"
    assert resolve_ai_key("") == "env-key"


def test_ai_response_parsing_is_tolerant():
    assert parse_ai_response('```json\n{"analysis": "x", "payloads": ["a", "b"]}\n```') == {
        "analysis": "x",
        "payloads": ["a", "b"],
    }
    assert parse_ai_response('["a", "b"]')["payloads"] == ["a", "b"]
    assert parse_ai_response("not json") == {"analysis": "", "payloads": []}
    assert sanitize_payloads(["a", "a", "b", "c"], limit=2) == ["a", "b"]


def test_ai_prompts_carry_context_and_matrix():
    prompt = build_user_prompt(
        endpoint="https://example.test/?q=1",
        param_name="q",
        location="GET",
        context="script",
        char_matrix={"<": "filtered", "'": "allowed"},
    )
    assert "https://example.test/?q=1" in prompt
    assert "filtered" in prompt
    assert "char_matrix" in build_system_prompt().lower() or "character matrix" in build_system_prompt().lower()


def test_ai_analyzer_caches_and_only_returns_payload_candidates():
    calls = []

    async def transport(system_prompt, user_prompt):
        calls.append(user_prompt)
        return json.dumps({"analysis": "break out", "payloads": ["';alert(1)//", "x"]})

    analyzer = AIAnalyzer("key", transport=transport)
    first = asyncio.run(
        analyzer.generate_payloads(
            endpoint="https://example.test/",
            param_name="q",
            context="script",
            char_matrix={"'": "allowed"},
        )
    )
    second = asyncio.run(
        analyzer.generate_payloads(
            endpoint="https://example.test/",
            param_name="q",
            context="script",
            char_matrix={"'": "allowed"},
        )
    )
    assert first == ["';alert(1)//", "x"]
    assert second == first
    assert len(calls) == 1


def test_mark_ai_payload_embeds_attributable_dialog_argument():
    marked = mark_ai_payload("<img src=x onerror=alert(1)>", "tok123")
    assert "/*tok123*/" in marked
    assert "String.fromCharCode(" in marked
    assert "alert(1)" not in marked

    appended = mark_ai_payload("console.log(1)", "tok123")
    assert "__xoxss_hits" in appended


def test_finding_coerces_missing_matrix_to_dict():
    finding = Finding(
        kind="Reflected XSS",
        url="https://example.test/",
        parameter="q",
        method="GET",
        payload="x",
        char_matrix=None,
    )
    assert finding.char_matrix == {}


# --------------------------------------------------------------------------------------
# header exclusion + cookie header injection
# --------------------------------------------------------------------------------------


class _Payloads:
    def render(self, template, token, context=""):
        marker = token
        if "{m}" in template:
            return template.replace("{m}", marker)
        return template


class _HeaderHttp:
    def __init__(self, reflect=""):
        self.reflect = reflect
        self.calls = []

    async def get(self, url, **kwargs):
        headers = dict(kwargs.get("headers") or {})
        self.calls.append(headers)
        value = headers.get(self.reflect, "")
        body = f"<html><body>{value}</body></html>"
        return SimpleNamespace(
            status=200,
            text=body,
            error=None,
            headers={"content-type": "text/html"},
            header=lambda name, default="": {"content-type": "text/html"}.get(name, default),
        )


def _bare_scanner(http, *, headers, exclude=None, cookies=None):
    scanner = object.__new__(XSSScanner)
    scanner.args = SimpleNamespace(
        header_list=headers,
        exclude_header=exclude or [],
        tamper=None,
        encoder=None,
    )
    scanner.http = http
    scanner.console = Console(quiet=True)
    scanner._stop = threading.Event()
    scanner.payloads = _Payloads()
    scanner.findings = []
    if cookies is not None:
        scanner._cookies = cookies

    def add_finding(finding):
        scanner.findings.append(finding)
        return True

    scanner.add_finding = add_finding
    return scanner


def test_exclude_header_skips_named_candidates():
    http = _HeaderHttp(reflect="Referer")
    scanner = _bare_scanner(http, headers=["Referer", "Origin"], exclude=["referer"])
    asyncio.run(scanner.test_headers("https://example.test/"))
    assert all("Referer" not in call for call in http.calls)


def test_cookie_header_injection_preserves_session_and_reports_executable_reflection():
    http = _HeaderHttp(reflect="Cookie")
    scanner = _bare_scanner(
        http, headers=["X-Forwarded-For"], cookies={"session": "abc", "other": "def"}
    )
    asyncio.run(scanner.test_headers("https://example.test/"))
    assert any("session=" in call.get("Cookie", "") for call in http.calls)
    cookie_findings = [f for f in scanner.findings if f.source == "cookie"]
    assert cookie_findings
    assert cookie_findings[0].parameter in {"session", "other"}
    assert cookie_findings[0].poc_command.startswith("curl -sk")


# --------------------------------------------------------------------------------------
# fragment phase
# --------------------------------------------------------------------------------------


class _FragmentBrowser:
    def __init__(self):
        self.urls = []

    async def navigate(self, url):
        self.urls.append(url)
        return url

    async def check_token(self, token, timeout=2.5):
        return {"executed": "yes", "evidence": "js-executed: marker", "sink": "innerHTML"}

    async def screenshot(self, path):
        return path


class _FragmentPool:
    def __init__(self, browser):
        self.engines = [object()]
        self.browser = browser

    def borrow(self):
        browser = self.browser

        class _Ctx:
            async def __aenter__(self):
                return browser

            async def __aexit__(self, *exc):
                return False

        return _Ctx()


class _FragmentPayloads:
    def payloads_for(self, context, limit):
        return ["<img src=x onerror={m}>"][:limit]

    def render(self, template, token, context=""):
        return template.replace("{m}", token)


def test_fragment_phase_requires_browser_execution_and_emits_fragment_finding(tmp_path):
    browser = _FragmentBrowser()
    scanner = object.__new__(XSSScanner)
    scanner.args = SimpleNamespace(fragment_xss=True, max_payloads=4)
    scanner.console = Console(quiet=True)
    scanner._stop = threading.Event()
    scanner.payloads = _FragmentPayloads()
    scanner.pool = _FragmentPool(browser)
    scanner.screenshot_dir = tmp_path
    scanner.stats = SimpleNamespace(browser_checks=0)
    scanner.findings = []

    def add_finding(finding):
        scanner.findings.append(finding)
        return True

    scanner.add_finding = add_finding
    asyncio.run(scanner.test_fragment("https://example.test/page"))

    assert browser.urls and "#" in browser.urls[0]
    assert scanner.findings
    assert scanner.findings[0].source == "fragment"
    assert scanner.findings[0].confidence == "confirmed"
    assert scanner.findings[0].poc_url.startswith("https://example.test/page#")
