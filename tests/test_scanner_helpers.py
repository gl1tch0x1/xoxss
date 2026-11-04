"""Tests for scanner-level helpers: WAF fingerprints and SARIF export."""

import asyncio
import json
import socket
from types import SimpleNamespace

from xoxss.scanner import (
    Console,
    Finding,
    HttpEngine,
    Scope,
    ScanStats,
    WAFDetector,
    build_sarif,
    install_uvloop,
    sarif_rule_id,
)
from xoxss.detection.waf import fingerprint, looks_blocked
from xoxss.core.browser import BrowserEngine


def test_http_engine_returns_actionable_dns_error():
    class FailedRequest:
        async def __aenter__(self):
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")

        async def __aexit__(self, *_args):
            return False

    class FailedSession:
        closed = False

        async def request(self, *_args, **_kwargs):
            return await FailedRequest().__aenter__()

    async def run():
        engine = HttpEngine(Console(quiet=True), ScanStats(), retries=0)
        engine.session = FailedSession()
        result = await engine.get("https://unresolvable.example/")
        return result, engine.stats

    response, stats = asyncio.run(run())
    assert "DNS resolution failed for unresolvable.example" in response.error
    assert "Temporary failure in name resolution" in response.error
    assert stats.errors == 1


def test_uvloop_is_disabled_on_python_314(monkeypatch):
    import xoxss.scanner as scanner

    called = []
    monkeypatch.setattr(scanner.sys, "platform", "linux")
    monkeypatch.setattr(scanner.sys, "version_info", (3, 14, 0))
    monkeypatch.setitem(__import__("sys").modules, "uvloop", SimpleNamespace(install=lambda: called.append(True)))
    install_uvloop()
    assert called == []


def test_scope_validates_host_port_and_url_credentials():
    scope = Scope("https://example.test")
    assert scope.in_scope("http://example.test/search?q=x")
    assert scope.in_scope("https://example.test/search?q=x")
    assert not scope.in_scope("https://example.test:8443/")
    assert not scope.in_scope("https://user@example.test/")
    assert not scope.in_scope("https://example.test.attacker.invalid/")

    custom_port = Scope("http://example.test:8080")
    assert custom_port.in_scope("https://example.test:8080/")
    assert not custom_port.in_scope("http://example.test/")


def test_http_engine_rejects_out_of_scope_before_opening_session():
    async def run():
        scope = Scope("https://example.test")
        engine = HttpEngine(Console(quiet=True), ScanStats(), redirect_scope=scope.in_scope)
        response = await engine.get("https://other.test/")
        return response, engine

    response, engine = asyncio.run(run())
    assert "outside the configured scan scope" in response.error
    assert engine.session is None
    assert engine.stats.requests == 0


def test_browser_engine_rejects_out_of_scope_navigation():
    engine = BrowserEngine(
        Console(quiet=True), url_allowed=lambda url: url.startswith("https://in-scope.test/")
    )
    error = asyncio.run(engine.navigate("https://outside.test/"))
    assert "outside the configured scan scope" in error
    assert engine.navigation_count == 0


def test_console_writes_versioned_jsonl_events(tmp_path):
    path = tmp_path / "run" / "events.jsonl"
    console = Console(quiet=True, events_file=str(path))
    console.event("target_started", target="https://example.test", index=1)
    event = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert event["schema_version"] == 1
    assert event["event"] == "target_started"
    assert event["target"] == "https://example.test"
    assert event["index"] == 1


def test_waf_signature_coverage():
    """Parity target: 30+ distinct WAF fingerprints (XSStrike has ~30)."""
    names = set(WAFDetector.HEADER_SIGNATURES) | set(WAFDetector.BODY_SIGNATURES)
    assert len(names) >= 30, f"only {len(names)} fingerprints"

    for expected in (
        "Cloudflare",
        "Imperva/Incapsula",
        "AWS WAF",
        "ModSecurity",
        "Wallarm",
        "Radware",
        "Reblaze",
        "Cloudbric",
        "Comodo cWatch",
        "West263",
        "SafeDog",
        "Chaitin SafeLine",
        "DataDome",
        "Kasada",
        "NSFOCUS",
        "Alibaba Cloud WAF",
        "Tencent Cloud WAF",
        "Baidu Yunjiasu",
        "Huawei Cloud WAF",
    ):
        assert expected in names, expected


def test_waf_fingerprint_matcher():
    """The extracted matcher recognises header and body signatures."""
    headers = {"CF-RAY": "8abc", "Server": "cloudflare"}
    names = fingerprint(headers, "<html>Attention Required! | Cloudflare</html>")
    assert "Cloudflare" in names

    # Body-only appliance (no headers).
    names = fingerprint({"Content-Type": "text/html"}, "Your request was blocked by Wallarm")
    assert "Wallarm" in names

    # No false positive on a clean response.
    assert fingerprint({"Content-Type": "text/html"}, "<html>hello</html>") == []


def test_looks_blocked():
    assert looks_blocked(403, "")
    assert looks_blocked(200, "Access denied by security policy")
    assert not looks_blocked(200, "<html>welcome</html>")


def _scanner_stub(findings):
    return SimpleNamespace(
        findings=findings,
        target="https://example.test/",
        waf=SimpleNamespace(names=["Cloudflare"]),
        stats=SimpleNamespace(elapsed=1.25),
        endpoints={"https://example.test/?q=1"},
        blind_markers=[],
    )


def test_sarif_rule_ids_are_stable():
    assert sarif_rule_id("Reflected XSS (HTTP evidence)") == "xoxss/reflected-xss"
    assert sarif_rule_id("Reflected XSS") == "xoxss/reflected-xss"
    assert sarif_rule_id("Stored XSS (payload persisted)") == "xoxss/stored-xss"
    assert sarif_rule_id("Blind XSS (callback injected)") == "xoxss/blind-xss"


def test_build_sarif_document():
    finding = Finding(
        kind="Reflected XSS (HTTP evidence)",
        url="https://example.test/?q=%3Cscript%3E",
        parameter="q",
        method="GET",
        payload="<script>alert(1)</script>",
        evidence="payload reflected unescaped (context=html)",
        confidence="high",
        context="html",
    )
    document = build_sarif(_scanner_stub([finding]))

    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")

    run = document["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"]
    assert driver["version"]
    assert len(driver["rules"]) == 1
    assert driver["rules"][0]["id"] == "xoxss/reflected-xss"
    assert driver["rules"][0]["defaultConfiguration"]["level"] == "error"

    result = run["results"][0]
    assert result["ruleId"] == "xoxss/reflected-xss"
    assert result["ruleIndex"] == 0
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
        "https://example.test/"
    )
    assert result["properties"]["parameter"] == "q"
    assert result["partialFingerprints"]["xoxssFinding/v1"] == finding.key()
    assert run["invocations"][0]["executionSuccessful"] is True


def test_sarif_severity_mapping():
    findings = [
        Finding("Reflected XSS", "https://a.test/", "q", "GET", "p", confidence="confirmed"),
        Finding("Reflected XSS", "https://a.test/", "q", "GET", "p", confidence="medium"),
        Finding("Blind XSS (callback injected)", "https://a.test/", "q", "GET", "p", confidence="low"),
    ]
    results = build_sarif(_scanner_stub(findings))["runs"][0]["results"]
    assert [item["level"] for item in results] == ["error", "warning", "note"]


def test_sarif_empty_scan():
    document = build_sarif(_scanner_stub([]))
    run = document["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
