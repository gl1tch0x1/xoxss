"""WAF fingerprinting and block-page heuristics."""

from __future__ import annotations

from xoxss.detection.waf import BODY_SIGNATURES, HEADER_SIGNATURES, fingerprint, looks_blocked


def test_header_signature_identifies_cloudflare() -> None:
    assert "Cloudflare" in fingerprint({"cf-ray": "8a1b2c3d"}, "")


def test_body_signature_identifies_cloudflare() -> None:
    assert "Cloudflare" in fingerprint({}, "Attention Required! | Cloudflare")


def test_cookie_signature_identifies_waf() -> None:
    assert "Imperva/Incapsula" in fingerprint({}, "", cookies="incap_ses_123=abc")


def test_clean_response_matches_nothing() -> None:
    assert fingerprint({"server": "nginx"}, "<html><body>ok</body></html>") == []


def test_fingerprint_is_sorted_and_unique() -> None:
    names = fingerprint({"cf-ray": "x", "x-sucuri-id": "y"}, "")
    assert names == sorted(set(names))


def test_signature_tables_are_populated() -> None:
    assert len(HEADER_SIGNATURES) >= 30
    assert len(BODY_SIGNATURES) >= 10
    assert all(signatures for signatures in HEADER_SIGNATURES.values())


def test_block_status_codes_are_rejected() -> None:
    for status in (403, 406, 429, 501, 503):
        assert looks_blocked(status, "") is True


def test_block_words_are_detected() -> None:
    assert looks_blocked(200, "Request blocked by security policy") is True


def test_benign_response_is_not_blocked() -> None:
    assert looks_blocked(200, "<html>welcome</html>") is False


def test_custom_block_words_override_defaults() -> None:
    assert looks_blocked(200, "nope", words=("nope",)) is True
    assert looks_blocked(200, "access denied", words=("nope",)) is False
