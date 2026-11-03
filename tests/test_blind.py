"""Tests for blind XSS / out-of-band payload generation."""

import pytest

from xoxss.detection.payload import build_blind_payloads


def test_blind_payloads_carry_callback_and_marker():
    items = build_blind_payloads("https://cb.example/collect", "MARK123", "html")

    assert items, "at least one blind payload is generated"
    template = items[0].template
    assert "https://cb.example/collect?m=MARK123" in template
    assert "document.cookie" in template
    assert "location.href" in template
    assert all(item.marker == "MARK123" for item in items)
    assert all(item.tamper_resistant for item in items)


def test_blind_callback_with_existing_query():
    items = build_blind_payloads("https://cb.example/x?id=7", "ABC", "attr_double")

    assert items
    assert "?id=7&m=ABC" in items[0].template


def test_blind_payload_escapes_quotes():
    items = build_blind_payloads("https://cb.example/x'quote", "ABC", "script")

    assert items
    assert "'quote" not in items[0].template
    assert "%27quote" in items[0].template


@pytest.mark.parametrize(
    "context",
    ["html", "attr_double", "attr_single", "attr_unquoted", "script", "script_string", "comment", "url"],
)
def test_blind_payload_contexts(context):
    items = build_blind_payloads("https://cb.example/x", "TOKEN", context)
    assert items
    assert all("TOKEN" in item.template for item in items)


def test_blind_payload_without_callback():
    assert build_blind_payloads("", "TOKEN", "html") == []
