"""Finding identity, deduplication and serialisation."""

from __future__ import annotations

import shlex
from typing import Any, Dict
from urllib.parse import urlsplit

from xoxss.core.finding import Finding


def make(**overrides: Any) -> Finding:
    data: Dict[str, Any] = {
        "kind": "Reflected XSS",
        "url": "https://example.com/search?q=1",
        "parameter": "q",
        "method": "GET",
        "payload": "<script>alert(1)</script>",
    }
    data.update(overrides)
    return Finding(**data)


def test_finding_gets_stable_identity() -> None:
    first, second = make(), make()
    assert first.key() == second.key()
    assert first.finding_id == second.finding_id


def test_identity_separates_parameters() -> None:
    assert make(parameter="q").key() != make(parameter="next").key()


def test_dom_dedupe_key_ignores_query_string() -> None:
    one = make(kind="DOM XSS", url="https://example.com/page?x=1")
    two = make(kind="DOM XSS", url="https://example.com/page?x=2")
    assert one.dedupe_key() == two.dedupe_key()
    # Reflected findings stay distinct per URL.
    assert make().dedupe_key() != make(url="https://example.com/other?q=1").dedupe_key()


def test_to_dict_round_trips_fields() -> None:
    finding = make()
    payload = finding.to_dict()
    assert payload["kind"] == finding.kind
    assert payload["url"] == finding.url
    assert payload["parameter"] == finding.parameter
    assert payload["finding_id"] == finding.finding_id


def test_nested_containers_are_coerced_to_dicts() -> None:
    finding = make(request="not-a-dict", oob=[], char_matrix=None)  # type: ignore[arg-type]
    assert finding.request == {}
    assert finding.oob == {}
    assert finding.char_matrix == {}


def test_curl_poc_is_populated() -> None:
    finding = make()
    command = shlex.split(finding.poc_curl)
    assert command[:2] == ["curl", "-sk"]
    # Parse the URL instead of substring-matching the host, so the assertion
    # cannot pass on a URL that merely embeds "example.com" somewhere
    # (py/incomplete-url-substring-sanitization).
    url = next(token for token in command if token.startswith(("http://", "https://")))
    parsed = urlsplit(url)
    assert parsed.scheme == "https"
    assert parsed.hostname == "example.com"
    assert parsed.path == "/search"
