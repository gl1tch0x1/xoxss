"""Tests for scanner-level helpers: WAF fingerprints and SARIF export."""

from types import SimpleNamespace

from xoxss.scanner import Finding, WAFDetector, build_sarif, sarif_rule_id
from xoxss.detection.waf import fingerprint, looks_blocked


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
