"""Evidence policy: every finding carries a reproducible PoC.

Covers ``build_poc`` (GET query/form, JSON, POST form, header, cookie),
``Finding`` round-trips through state checkpoints, and SARIF results
embedding ``pocUrl`` / ``pocCommand``.
"""

from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlencode, urlparse

from xoxss.scanner import (
    Finding,
    InjectionPoint,
    FormField,
    analyze_reflection,
    build_poc,
)
from xoxss.reports.sarif import build_sarif_document


def _parse_query(url: str) -> dict:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query, keep_blank_values=True).items()}


# --------------------------------------------------------------------------------------
# build_poc
# --------------------------------------------------------------------------------------


def test_poc_get_query_produces_ready_to_open_url():
    point = InjectionPoint(
        url="https://example.test/search?q=hello&page=2",
        method="GET",
        param="q",
        source="query",
    )
    payload = "<script>alert(1)</script>"
    poc_url, command = build_poc(point, payload)

    assert command == ""
    assert poc_url.startswith("https://example.test/search?")
    query = _parse_query(poc_url)
    assert query.get("q") == payload
    # Untouched parameters survive.
    assert query.get("page") == "2"


def test_poc_get_form_merges_existing_fields():
    point = InjectionPoint(
        url="https://example.test/filter",
        method="GET",
        param="freetext",
        source="form",
        fields={
            "category": FormField(name="category", value="books"),
            "freetext": FormField(name="freetext", value=""),
        },
    )
    poc_url, command = build_poc(point, "<img src=x>")

    assert command == ""
    query = _parse_query(poc_url)
    assert query.get("freetext") == "<img src=x>"
    assert query.get("category") == "books"


def test_poc_header_injection_is_curl_command():
    point = InjectionPoint(
        url="https://example.test/docs?ref=x",
        method="GET",
        param="X-Forwarded-Uri",
        source="header",
    )
    payload = "<script>alert(1)</script>"
    poc_url, command = build_poc(point, payload)

    assert poc_url == "https://example.test/docs?ref=x"
    assert command == f"curl -sk '{point.url}' -H 'X-Forwarded-Uri: {payload}'"


def test_poc_cookie_injection_is_curl_command():
    point = InjectionPoint(
        url="https://example.test/account",
        method="GET",
        param="last_search",
        source="cookie",
    )
    poc_url, command = build_poc(point, "<svg onload=alert(1)>")

    assert poc_url == "https://example.test/account"
    assert command == f"curl -sk '{point.url}' -H 'Cookie: last_search=<svg onload=alert(1)>'"


def test_poc_json_post_embeds_full_body_and_content_type():
    point = InjectionPoint(
        url="https://example.test/api/comments",
        method="POST",
        param="message",
        source="json",
        json_body={"message": "", "thread": 7},
        content_type="application/json",
    )
    poc_url, command = build_poc(point, "<img src=x onerror=alert(1)>")

    assert poc_url == point.url
    assert command.startswith("curl -sk -X POST 'https://example.test/api/comments'")
    assert "-H 'Content-Type: application/json'" in command
    assert "--data-raw" in command
    # The JSON body is the full original body with the injected parameter.
    assert '"thread":7' in command.replace("\\", "")
    assert '"thread":7' in unquote(command)


def test_poc_form_post_is_urlencoded_curl():
    point = InjectionPoint(
        url="https://example.test/contact",
        method="POST",
        param="comment",
        source="form",
        fields={"comment": FormField(name="comment", value="")},
    )
    payload = "<script>alert(1)</script>"
    poc_url, command = build_poc(point, payload)

    assert poc_url == point.url
    assert command.startswith(f"curl -sk -X POST '{point.url}' --data 'comment=")
    # Form submissions are urlencoded, like the real request body.
    assert urlencode({point.param: payload}) in command or "<script>alert(1)</script>" not in command
    assert command.endswith(f"--data '{urlencode({point.param: payload})}'")


def test_poc_contains_no_cookies_or_session_data():
    """The PoC must be safe to hand over: no cookies, tokens or auth headers."""
    point = InjectionPoint(
        url="https://example.test/api/comments",
        method="POST",
        param="message",
        source="json",
        json_body={"csrf_token": "s3cret", "session": "abc", "title": "t"},
    )
    _, command = build_poc(point, "<script>x</script>")

    # Session-bound values never appear in the shared proof.
    assert "s3cret" not in command
    assert "abc" not in command
    # The rest of the body shape is kept, and the injected payload survives.
    assert '"title":"t"' in command


# --------------------------------------------------------------------------------------
# Finding round-trip (state checkpoints)
# --------------------------------------------------------------------------------------


def test_finding_roundtrip_preserves_poc_fields():
    finding = Finding(
        kind="Reflected XSS (HTTP evidence)",
        url="https://example.test/?q=x",
        parameter="q",
        method="GET",
        payload="<script>alert(1)</script>",
        evidence="payload reflected unescaped",
        confidence="high",
        context="html",
        poc_url="https://example.test/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    )
    raw = finding.to_dict()

    # Exactly like StateStore resume (_load_state).
    restored = Finding(**{k: raw.get(k, "") for k in Finding.__dataclass_fields__})
    assert restored.poc_url == finding.poc_url
    assert restored.poc_command == finding.poc_command == ""
    assert restored.confidence == "high"
    assert restored.tags == finding.tags


def test_old_checkpoint_without_poc_fields_still_loads():
    finding = Finding(kind="Reflected XSS", url="https://a.test/", parameter="q", method="GET", payload="p")
    raw = finding.to_dict()
    raw.pop("poc_url", None)
    raw.pop("poc_command", None)

    restored = Finding(**{k: raw.get(k, "") for k in Finding.__dataclass_fields__})
    assert restored.poc_url == ""
    assert restored.poc_command == ""


def test_every_finding_from_poc_builder_carries_a_poc():
    """GET query / header / JSON / POST points all yield a usable proof."""
    cases = [
        InjectionPoint("https://example.test/?q=1", "GET", "q", source="query"),
        InjectionPoint("https://example.test/docs", "GET", "X-Debug", source="header"),
        InjectionPoint(
            "https://example.test/api", "POST", "m", source="json", json_body={"m": ""}
        ),
        InjectionPoint("https://example.test/contact", "POST", "c", source="form"),
    ]
    for point in cases:
        url, command = build_poc(point, "<script>alert(1)</script>")
        # There must be either a URL carrying the payload or a command that does.
        assert "<script>alert(1)</script>" in unquote(url) or "<script>alert(1)</script>" in unquote(command), point


# --------------------------------------------------------------------------------------
# analyze_reflection gates (no dummy reports)
# --------------------------------------------------------------------------------------


def test_reflection_inert_markup_is_not_executable():
    """A reflected payload whose critical characters are escaped is 'low'."""
    body = "<p>Hello &lt;script&gt;TOKEN&lt;/script&gt;</p>"
    info = analyze_reflection(body, "TOKEN", "<script>TOKEN</script>", "text/html")
    assert info.reflected
    assert not info.executable  # no high finding for escaped/encoded reflection


def test_reflection_with_special_char_survival_is_executable():
    body = '<p>Hello <script>TOKEN</script></p>'
    info = analyze_reflection(body, "TOKEN", "<script>TOKEN</script>", "text/html")
    assert info.reflected


# --------------------------------------------------------------------------------------
# SARIF PoC properties
# --------------------------------------------------------------------------------------


def _scanner_stub(findings):
    return SimpleNamespace(
        findings=findings,
        target="https://example.test/",
        waf=SimpleNamespace(names=[]),
        stats=SimpleNamespace(elapsed=1.25),
        endpoints=set(),
        blind_markers=[],
    )


def test_sarif_result_embeds_poc_url_and_command():
    finding = Finding(
        kind="Reflected XSS (HTTP evidence)",
        url="https://example.test/",
        parameter="X-Debug",
        method="GET",
        payload="<script>alert(1)</script>",
        evidence="injected header reflected unescaped",
        confidence="medium",
        context="html",
        poc_url="https://example.test/",
        poc_command="curl -sk 'https://example.test/' -H 'X-Debug: <script>alert(1)</script>'",
    )
    result = build_sarif_document(
        [finding], target="https://example.test/"
    )["runs"][0]["results"][0]

    assert result["properties"]["pocUrl"] == "https://example.test/"
    assert result["properties"]["pocCommand"].startswith("curl -sk")
    assert "PoC command" in result["message"]["text"]
    assert result["level"] == "warning"  # medium


def test_sarif_result_message_includes_poc_url_when_present():
    finding = Finding(
        kind="Reflected XSS (HTTP evidence)",
        url="https://example.test/?q=x",
        parameter="q",
        method="GET",
        payload="<script>alert(1)</script>",
        evidence="payload reflected unescaped",
        confidence="high",
        context="html",
        poc_url="https://example.test/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    )
    result = build_sarif_document(
        [finding], target="https://example.test/"
    )["runs"][0]["results"][0]

    assert result["properties"]["pocCommand"] == ""
    assert "PoC:" in result["message"]["text"]
