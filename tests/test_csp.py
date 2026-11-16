"""CSP source-expression parsing and bypass gating.

Regression coverage for py/incomplete-url-substring-sanitization: hosts must
be compared as parsed hostnames (with CSP wildcard rules), never as substrings
of the raw directive value.
"""

from __future__ import annotations

from xoxss.analysis.csp import (
    CSPAnalyzer,
    CSPBypassAutomator,
    _is_scheme_source,
    _source_allows_host,
)


def bypasses_for(header: str) -> set[str]:
    automator = CSPBypassAutomator()
    policy = automator.parse_csp(header)
    return {bypass.technique for bypass in automator.get_applicable_bypasses(policy)}


# -- source-expression helpers ------------------------------------------------


def test_source_allows_exact_host_only() -> None:
    assert _source_allows_host("https://ajax.googleapis.com", "ajax.googleapis.com")
    assert _source_allows_host("https://AJAX.GOOGLEAPIS.COM", "ajax.googleapis.com")
    assert _source_allows_host("ajax.googleapis.com", "ajax.googleapis.com")
    assert _source_allows_host("https://ajax.googleapis.com:8443", "ajax.googleapis.com")
    assert not _source_allows_host(
        "https://evil.example/ajax.googleapis.com", "ajax.googleapis.com"
    )
    assert not _source_allows_host(
        "https://evil.example/?next=https://ajax.googleapis.com", "ajax.googleapis.com"
    )
    assert not _source_allows_host("https://ajax.googleapis.com.evil.example", "ajax.googleapis.com")
    assert not _source_allows_host("'self'", "ajax.googleapis.com")
    assert not _source_allows_host("data:", "ajax.googleapis.com")


def test_source_wildcard_follows_csp_subdomain_rules() -> None:
    assert _source_allows_host("*.googleapis.com", "ajax.googleapis.com")
    assert _source_allows_host("https://*.googleapis.com", "ajax.googleapis.com")
    assert _source_allows_host("*.googleapis.com", "googleapis.com")
    # A lookalike whose label merely ends with the suffix must not match.
    assert not _source_allows_host("*.googleapis.com", "notgoogleapis.com")
    assert not _source_allows_host("*.example.com", "notexample.com")


def test_scheme_source_requires_exact_token() -> None:
    assert _is_scheme_source("data:", "data")
    assert _is_scheme_source("  DATA:  ", "data")
    assert not _is_scheme_source("https://example.com/data:", "data")
    assert not _is_scheme_source("https://example.com/?next=data:", "data")
    assert not _is_scheme_source("'data:'", "data")


# -- bypass automation --------------------------------------------------------


def test_angular_cdn_bypass_accepts_allowed_hosts() -> None:
    for header in (
        "script-src https://ajax.googleapis.com",
        "script-src https://ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.min.js",
        "script-src https://*.googleapis.com",
        "script-src ajax.googleapis.com",
    ):
        assert "angular_cdn" in bypasses_for(header), header


def test_angular_cdn_bypass_ignores_embedded_hosts() -> None:
    for header in (
        "script-src https://evil.example/ajax.googleapis.com",
        "script-src https://evil.example/?next=https://ajax.googleapis.com",
        "script-src https://ajax.googleapis.com.evil.example",
        "script-src https://evilajax.googleapis.com",
    ):
        assert "angular_cdn" not in bypasses_for(header), header


def test_data_uri_bypass_requires_a_scheme_source() -> None:
    assert "data_uri" in bypasses_for("script-src data:")
    assert "data_uri" not in bypasses_for("script-src https://example.com/data:")
    assert "data_uri" not in bypasses_for("script-src https://example.com/?next=data:")


def test_iframe_sandbox_bypass_ignores_lookalike_hosts() -> None:
    assert "iframe_sandbox" not in bypasses_for("frame-src https://sandbox.example.com")
    assert "iframe_sandbox" in bypasses_for("frame-src sandbox")


# -- weakness analysis --------------------------------------------------------


def test_jsonp_gadget_detection_parses_hostnames() -> None:
    analyzer = CSPAnalyzer()

    risky = analyzer.analyze_csp("script-src https://ajax.googleapis.com")
    assert any(issue.issue_type == "jsonp_gadget_domain" for issue in risky.issues)

    wildcard = analyzer.analyze_csp("script-src https://*.googleapis.com")
    assert any(issue.issue_type == "jsonp_gadget_domain" for issue in wildcard.issues)

    embedded = analyzer.analyze_csp("script-src https://evil.example/ajax.googleapis.com")
    assert not any(issue.issue_type == "jsonp_gadget_domain" for issue in embedded.issues)

    query = analyzer.analyze_csp(
        "script-src https://evil.example/?next=https://ajax.googleapis.com"
    )
    assert not any(issue.issue_type == "jsonp_gadget_domain" for issue in query.issues)
