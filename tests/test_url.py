"""URL normalisation used for scope checks and deduplication."""

from __future__ import annotations

import pytest

from xoxss.utils.url import normalize_url, safe_urljoin


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "http://example.com"),
        ("example.com/path?q=1", "http://example.com/path?q=1"),
        ("http://example.com", "http://example.com"),
        ("HTTPS://Example.COM/a", "HTTPS://Example.COM/a"),
    ],
)
def test_normalize_url_adds_scheme_only_when_missing(value: str, expected: str) -> None:
    assert normalize_url(value) == expected


@pytest.mark.parametrize(
    ("base", "relative", "expected"),
    [
        ("https://example.com/a/b", "c", "https://example.com/a/c"),
        ("https://example.com/a/b", "/root", "https://example.com/root"),
        ("https://example.com/a/b", "//cdn.example.com/x", "https://cdn.example.com/x"),
    ],
)
def test_safe_urljoin(base: str, relative: str, expected: str) -> None:
    assert safe_urljoin(base, relative) == expected
