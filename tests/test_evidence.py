"""Finding evidence: excerpts, redaction, curl PoCs and stable identities."""

import json
from urllib.parse import unquote

from xoxss.core.evidence import (
    REDACTED,
    build_curl,
    canonical_finding_url,
    finding_curl,
    redact_body,
    parse_curl_request,
    request_to_dict,
    response_excerpt,
)
from xoxss.core.http import HttpEngine, HttpResponse
from xoxss.scanner import Finding


def test_response_excerpt_is_centred_on_the_marker():
    body = "A" * 500 + "<script>TOKEN</script>" + "B" * 500
    excerpt = response_excerpt(body, "TOKEN", radius=100)

    assert "TOKEN" in excerpt
    # ±100 characters around the marker plus the marker itself.
    core = excerpt.strip(".")
    assert len(core) <= len("<script>TOKEN</script>") + 200
    assert len(core) >= len("<script>TOKEN</script>") + 150


def test_response_excerpt_missing_marker_is_empty():
    assert response_excerpt("nothing here", "TOKEN") == ""
    assert response_excerpt("", "TOKEN") == ""
    assert response_excerpt("TOKEN", "") == ""


def test_build_curl_redacts_session_headers_but_keeps_the_payload():
    command = build_curl(
        "POST",
        "https://example.test/search?q=%3Cscript%3E",
        headers={
            "Cookie": "session=secret",
            "Authorization": "Bearer secret",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body="q=%3Cscript%3E&csrf=abc",
    )

    assert command.startswith("curl -sk")
    assert "session=secret" not in command
    assert "Bearer secret" not in command
    # The form is re-encoded, so the payload keeps its wire representation and
    # the CSRF value is replaced without changing the body structure.
    assert "q=%3Cscript%3E&csrf=%5BREDACTED%5D" in command
    assert "csrf=abc" not in command


def test_redact_body_preserves_encoded_separators_in_form_values():
    body = redact_body("q=a%26b&csrf=abc", injected_parameter="q")

    assert body == "q=a%26b&csrf=%5BREDACTED%5D"


def test_redact_body_leaves_json_string_bodies_untouched():
    assert redact_body('"a=b"') == '"a=b"'


def test_build_curl_adds_json_content_type_when_the_request_omits_it():
    command = build_curl(
        "POST", "https://example.test/api", body='{"q":"<script>"}'
    )

    assert "Content-Type: application/json" in command


def test_sent_request_records_the_json_content_type():
    engine = object.__new__(HttpEngine)
    engine.base_headers = {}
    engine.cookies = {}

    headers, body = engine._sent_request(None, None, {"q": "<script>"})

    assert headers["Content-Type"] == "application/json"
    assert body == '{"q":"<script>"}'


def test_request_to_dict_redacts_sensitive_json_values():
    evidence = request_to_dict(
        "POST",
        "https://example.test/api",
        headers={"Cookie": "session=secret", "X-Test": "1"},
        body=json.dumps(
            {"q": "<script>alert(1)</script>", "csrf": "abc", "password": "p"}
        ),
        injected_parameter="q",
    )

    assert evidence["method"] == "POST"
    assert evidence["headers"]["Cookie"] == REDACTED
    assert evidence["headers"]["X-Test"] == "1"
    payload = json.loads(evidence["body"])
    assert payload["q"] == "<script>alert(1)</script>"
    assert payload["csrf"] == REDACTED
    assert payload["password"] == REDACTED


def test_request_to_dict_redacts_form_values_except_the_injected_parameter():
    evidence = request_to_dict(
        "POST",
        "https://example.test/form",
        body="q=payload&token=secret&other=value",
        injected_parameter="q",
    )

    assert "q=payload" in evidence["body"]
    assert "token=secret" not in evidence["body"]
    assert "other=value" not in evidence["body"]


def test_canonical_finding_url_strips_query_only_for_query_points():
    url = "https://Example.test/search?q=payload&page=2#frag"

    assert (
        canonical_finding_url(url, "query")
        == "https://example.test/search#frag"
    )
    assert (
        canonical_finding_url(url, "form")
        == "https://example.test/search#frag"
    )
    assert (
        canonical_finding_url(url, "dom")
        == "https://example.test/search?q=payload&page=2#frag"
    )
    # Fragments identify DOM sinks; they are stripped for fragment findings.
    assert (
        canonical_finding_url("https://example.test/page#payload", "fragment")
        == "https://example.test/page"
    )


def test_parse_curl_request_round_trips_emitted_commands():
    command = build_curl(
        "POST",
        "https://example.test/api?x=1",
        headers={"Content-Type": "application/json", "X-Test": "yes"},
        body='{"q":"<script>"}',
    )
    parsed = parse_curl_request(command)

    assert parsed is not None
    assert parsed["method"] == "POST"
    assert parsed["url"] == "https://example.test/api?x=1"
    assert parsed["headers"]["X-Test"] == "yes"
    assert parsed["body"] == '{"q":"<script>"}'


def test_parse_curl_request_rejects_non_curl():
    assert parse_curl_request("wget https://example.test/") is None
    assert parse_curl_request("") is None


def test_http_response_request_dict_redacts_cookie_headers():
    response = HttpResponse(
        url="https://example.test/",
        status=200,
        request_method="GET",
        request_url="https://example.test/?q=1",
        request_headers={"Cookie": "session=secret", "Accept": "*/*"},
    )
    evidence = response.request_dict("q")

    assert evidence["method"] == "GET"
    assert evidence["url"] == "https://example.test/?q=1"
    assert evidence["headers"]["Cookie"] == REDACTED
    assert evidence["headers"]["Accept"] == "*/*"


def test_finding_identity_includes_source_and_survives_serialisation():
    query = Finding(
        kind="Reflected XSS (HTTP evidence)",
        url="https://example.test/search?q=payload",
        parameter="q",
        method="GET",
        payload="<script>alert(1)</script>",
        source="query",
    )
    header = Finding(
        kind="Reflected XSS (HTTP evidence)",
        url="https://example.test/search?q=payload",
        parameter="q",
        method="GET",
        payload="<script>alert(1)</script>",
        source="header",
    )

    assert query.key() != header.key()
    assert query.finding_id
    assert query.finding_id == query.finding_id

    data = query.to_dict()
    assert data["finding_id"] == query.finding_id
    assert data["source"] == "query"
    assert data["request"] == {}
    assert data["oob"] == {}
    assert data["poc_curl"].startswith("curl")


def test_finding_key_does_not_include_the_payload():
    first = Finding(
        kind="Reflected XSS",
        url="https://example.test/?q=one",
        parameter="q",
        method="GET",
        payload="<script>alert(1)</script>",
        source="query",
    )
    second = Finding(
        kind="Reflected XSS",
        url="https://example.test/?q=two",
        parameter="q",
        method="GET",
        payload="<img src=x onerror=alert(2)>",
        source="query",
    )

    assert first.key() == second.key()


def test_finding_curl_prefers_structured_request_over_poc_command():
    finding = Finding(
        kind="Reflected XSS",
        url="https://example.test/",
        parameter="q",
        method="POST",
        payload="<script>",
        source="form",
        request={
            "method": "POST",
            "url": "https://example.test/search",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "q=<script>",
        },
    )

    command = finding_curl(finding)
    assert "https://example.test/search" in command
    assert "--data-raw" in unquote(command)
