"""Chain derivation: only compose primitives that actually exist."""

from __future__ import annotations

from xoxss.auto.chains import build_chains
from xoxss.core.finding import Finding


def finding(
    kind: str,
    *,
    confidence: str = "high",
    url: str = "https://t.test/search?q=1",
    parameter: str = "q",
    tags: list[str] | None = None,
    evidence: str = "marker reflected",
) -> Finding:
    return Finding(
        kind=kind,
        url=url,
        parameter=parameter,
        method="GET",
        payload="<svg onload=alert(1)>",
        evidence=evidence,
        confidence=confidence,
        tags=list(tags or []),
        source="auto",
    )


def kinds(findings: list[Finding]) -> list[str]:
    return [chain.finding.kind for chain in build_chains(findings)]


def test_no_findings_no_chains() -> None:
    assert build_chains([]) == []


def test_single_xss_is_not_a_chain() -> None:
    assert kinds([finding("Reflected XSS")]) == []


def test_open_redirect_plus_xss_chains() -> None:
    chains = build_chains(
        [
            finding("Open redirect", tags=["open-redirect"]),
            finding("Reflected XSS", confidence="confirmed"),
        ]
    )
    assert len(chains) == 1
    assert chains[0].finding.kind == "XSS chain (open redirect -> XSS)"
    assert "open-redirect" in chains[0].finding.tags
    assert chains[0].primitives


def test_chain_confidence_uses_the_weaker_primitive() -> None:
    chains = build_chains(
        [
            finding("Open redirect", confidence="medium", tags=["open-redirect"]),
            finding("Reflected XSS", confidence="confirmed"),
        ]
    )
    assert chains[0].finding.confidence == "medium"


def test_static_dom_is_not_execution_evidence() -> None:
    assert kinds([finding("DOM XSS (static candidate)", confidence="low")]) == []


def test_cors_and_xss_chain() -> None:
    chains = build_chains(
        [
            finding("CORS misconfiguration", tags=["cors"]),
            finding("Stored XSS", confidence="high"),
        ]
    )
    assert "XSS chain (CORS + XSS data theft)" in [chain.finding.kind for chain in chains]


def test_postmessage_and_dom_flow_chain() -> None:
    chains = build_chains(
        [
            finding(
                "postMessage to DOM sink (origin unchecked)",
                confidence="medium",
                tags=["postmessage", "dom"],
            ),
            finding("DOM XSS (static source-to-sink)", confidence="low"),
        ]
    )
    assert [chain.finding.kind for chain in chains] == [
        "XSS chain (postMessage -> DOM sink)"
    ]
    assert chains[0].finding.confidence == "medium"


def test_source_map_and_secret_chain() -> None:
    chains = build_chains(
        [
            finding("Source map exposed", confidence="low", tags=["source-map"]),
            finding("Secret in JavaScript (AWS access key)", confidence="high", tags=["secret"]),
        ]
    )
    assert [chain.finding.kind for chain in chains] == [
        "Secret disclosure chain (source map + credential)"
    ]


def test_chain_findings_are_evidence_backed() -> None:
    chains = build_chains(
        [
            finding("Host header injection", tags=["host-header"]),
            finding("Reflected XSS", confidence="confirmed"),
        ]
    )
    assert chains
    assert chains[0].finding.evidence
    assert "host-header" in chains[0].finding.tags
