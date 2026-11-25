"""Target normalisation for the domain-first workflow."""

from __future__ import annotations

import pytest

from xoxss.auto.target import (
    TargetError,
    normalize_target,
    sibling_targets,
    target_host,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com"),
        ("example.com/", "https://example.com"),
        ("example.com/app?q=1", "https://example.com/app?q=1"),
        ("https://example.com/", "https://example.com"),
        ("http://example.com/", "http://example.com"),
        ("localhost:8080", "http://localhost:8080"),
        ("127.0.0.1:8080/app", "http://127.0.0.1:8080/app"),
        ("[::1]:9000", "http://[::1]:9000"),
        ("sub.example.com", "https://sub.example.com"),
    ],
)
def test_normalize_target(raw: str, expected: str) -> None:
    assert normalize_target(raw) == expected


def test_normalize_rejects_empty() -> None:
    with pytest.raises(TargetError):
        normalize_target("   ")


def test_normalize_rejects_unsupported_scheme() -> None:
    with pytest.raises(TargetError):
        normalize_target("ftp://example.com")


def test_normalize_rejects_credentials() -> None:
    with pytest.raises(TargetError):
        normalize_target("https://user:pass@example.com")


def test_normalize_rejects_bad_host() -> None:
    with pytest.raises(TargetError):
        normalize_target("exa mple.com")


def test_target_host_lowercases() -> None:
    assert target_host("https://Example.COM/app") == "example.com"


def test_sibling_targets_include_www_and_schemes() -> None:
    variants = sibling_targets("https://example.com/app")
    assert "https://example.com/app" in variants
    assert "https://www.example.com/app" in variants
    assert "http://example.com/app" in variants


def test_sibling_targets_strip_www() -> None:
    variants = sibling_targets("https://www.example.com/")
    assert "https://example.com/" in variants
