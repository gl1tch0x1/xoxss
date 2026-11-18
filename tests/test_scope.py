"""Target-scope boundaries used by HTTP and browser request guards."""

from __future__ import annotations

from xoxss.core.scope import Scope


def test_scope_matches_host_port_and_path_filters() -> None:
    scope = Scope(
        "https://example.test:8443",
        allow_subdomains=True,
        include=[r"/app(?:/|$)"],
        exclude=[r"/app/logout"],
    )

    assert scope.in_scope("https://example.test:8443/app")
    assert scope.in_scope("https://api.example.test:8443/app/search")
    assert not scope.in_scope("https://example.test:8444/app")
    assert not scope.in_scope("https://notexample.test:8443/app")
    assert not scope.in_scope("https://example.test:8443/app/logout")
    assert not scope.in_scope("https://example.test:8443/admin")


def test_scope_rejects_credentials_and_invalid_urls() -> None:
    scope = Scope("https://example.test")

    assert not scope.in_scope("https://user:password@example.test/")
    assert not scope.in_scope("https://example.test:invalid/")
    assert not scope.in_scope("javascript:alert(1)")


def test_scope_blocks_https_to_http_downgrade() -> None:
    scope = Scope("https://example.test")

    assert scope.in_scope("https://example.test/app")
    assert not scope.in_scope("http://example.test/app")
    assert not scope.in_scope("http://example.test:443/app")


def test_scope_allows_downgrade_only_when_explicitly_enabled() -> None:
    scope = Scope("https://example.test", allow_scheme_downgrade=True)

    assert scope.in_scope("http://example.test/app")


def test_scope_allows_http_to_https_upgrade() -> None:
    scope = Scope("http://example.test")

    assert scope.in_scope("https://example.test/app")


def test_scope_origin_ignores_default_ports() -> None:
    assert Scope("https://example.test").origin == "https://example.test"
    assert Scope("https://example.test:443").origin == "https://example.test"
    assert Scope("https://example.test:8443").origin == "https://example.test:8443"
    assert Scope("http://example.test").origin == "http://example.test"
