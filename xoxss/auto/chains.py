"""Chain analysis for the autonomous engine.

A single primitive is often a ``low`` lead; two primitives that compose are a
real finding.  This module takes the merged finding set (scanner findings plus
post-scan probe leads) and derives higher-impact chains without inventing any
new evidence: every chain quotes the findings it was built from.

Rules:

* a chain is only emitted when *all* of its primitives exist;
* the chain never claims browser execution unless the XSS primitive itself was
  confirmed;
* the chain inherits the weakest required confidence, capped at ``high``;
* chains are ordinary :class:`~xoxss.core.finding.Finding` objects, so they
  flow through the existing dedupe, reporting and SARIF paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from xoxss.core.finding import Finding

_XSS_CONFIDENCE = ("confirmed", "high")


@dataclass
class Chain:
    """One derived finding plus the primitives it came from."""

    name: str
    finding: Finding
    primitives: List[str] = field(default_factory=list)


def _kind(finding: Finding) -> str:
    return str(finding.kind or "")


def _tags(finding: Finding) -> set[str]:
    return {str(tag).lower() for tag in (finding.tags or [])}


def _is_xss(finding: Finding) -> bool:
    kind = _kind(finding).lower()
    if "xss" not in kind:
        return False
    # Static/taint leads are not execution evidence.
    if kind.startswith(("dom xss (static", "dom xss (taint")):
        return False
    return finding.confidence in _XSS_CONFIDENCE


def _first(
    findings: Sequence[Finding],
    predicate: Callable[[Finding], bool],
) -> Optional[Finding]:
    for finding in findings:
        if predicate(finding):
            return finding
    return None


def _label(finding: Finding) -> str:
    return (
        f"{finding.kind} on {finding.url}"
        + (f" ({finding.parameter})" if finding.parameter else "")
        + f" [{finding.confidence}]"
    )


def _chain_finding(
    *,
    name: str,
    subkey: str,
    base: Finding,
    primitives: Sequence[Finding],
    confidence: str,
    detail: str,
    tags: Sequence[str],
) -> Finding:
    evidence = " | ".join(_label(item) for item in primitives)
    return Finding(
        kind=name,
        url=base.url,
        parameter=base.parameter,
        method=base.method,
        payload=base.payload,
        evidence=evidence,
        confidence=confidence,
        confidence_rationale=detail,
        context=base.context,
        detail=detail,
        source="auto",
        subkey=subkey,
        tags=list(dict.fromkeys(["chain", *tags])),
        request=dict(base.request),
        response_status=base.response_status,
        response_excerpt=base.response_excerpt or evidence[:400],
    )


def _weaker(first: str, second: str) -> str:
    order = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}
    return first if order.get(first, 0) <= order.get(second, 0) else second


def build_chains(findings: Sequence[Finding]) -> List[Chain]:
    """Return every chain that can be derived from ``findings``."""
    if not findings:
        return []

    chains: List[Chain] = []
    xss_findings = [finding for finding in findings if _is_xss(finding)]
    strongest_xss = xss_findings[0] if xss_findings else None

    open_redirect = _first(
        findings,
        lambda item: _kind(item).startswith("Open redirect")
        or "open-redirect" in _tags(item),
    )
    cors = _first(
        findings,
        lambda item: _kind(item).startswith("CORS")
        or "cors" in _tags(item),
    )
    cache = _first(
        findings,
        lambda item: _kind(item).startswith("Cache poisoning")
        or "cache-poisoning" in _tags(item),
    )
    host_header = _first(
        findings,
        lambda item: _kind(item).startswith("Host header")
        or "host-header" in _tags(item),
    )
    crlf = _first(
        findings,
        lambda item: _kind(item).startswith("CRLF")
        or "crlf" in _tags(item),
    )
    postmessage = _first(
        findings,
        lambda item: _kind(item).startswith("postMessage")
        or "postmessage" in _tags(item),
    )
    jsonp = _first(
        findings,
        lambda item: _kind(item).startswith("JSONP")
        or "jsonp" in _tags(item),
    )
    source_map = _first(
        findings,
        lambda item: _kind(item).startswith("Source map")
        or "source-map" in _tags(item),
    )
    secret = _first(
        findings,
        lambda item: _kind(item).startswith("Secret in JavaScript")
        or "secret" in _tags(item),
    )

    # -- redirect / header primitives + XSS ---------------------------------
    if open_redirect and strongest_xss:
        chains.append(
            Chain(
                name="XSS chain (open redirect -> XSS)",
                finding=_chain_finding(
                    name="XSS chain (open redirect -> XSS)",
                    subkey="chain-open-redirect-xss",
                    base=strongest_xss,
                    primitives=(open_redirect, strongest_xss),
                    confidence=_weaker(open_redirect.confidence, strongest_xss.confidence),
                    detail=(
                        "A caller-controlled redirect target and an executable XSS "
                        "share this host. The redirect can deliver victims to the "
                        "payload URL (or a javascript:/data: target where the "
                        "browser permits it), which raises the impact from "
                        "self-XSS to a distributable attack."
                    ),
                    tags=("open-redirect", "xss"),
                ),
                primitives=[open_redirect.finding_id, strongest_xss.finding_id],
            )
        )

    if crlf and strongest_xss:
        chains.append(
            Chain(
                name="XSS chain (CRLF injection -> response splitting)",
                finding=_chain_finding(
                    name="XSS chain (CRLF injection -> response splitting)",
                    subkey="chain-crlf-xss",
                    base=strongest_xss,
                    primitives=(crlf, strongest_xss),
                    confidence=_weaker(crlf.confidence, strongest_xss.confidence),
                    detail=(
                        "CRLF injection lets the attacker add response headers or "
                        "a second response body. Combined with an executable "
                        "reflection this becomes a reliable reflected XSS even "
                        "when the body filter is strict."
                    ),
                    tags=("crlf", "response-splitting", "xss"),
                ),
                primitives=[crlf.finding_id, strongest_xss.finding_id],
            )
        )

    if host_header and strongest_xss:
        chains.append(
            Chain(
                name="XSS chain (host header -> reflected XSS)",
                finding=_chain_finding(
                    name="XSS chain (host header -> reflected XSS)",
                    subkey="chain-host-header-xss",
                    base=strongest_xss,
                    primitives=(host_header, strongest_xss),
                    confidence=_weaker(host_header.confidence, strongest_xss.confidence),
                    detail=(
                        "The application renders a client-supplied host header and "
                        "also reflects executable markup. An attacker can force "
                        "absolute URLs to an attacker host, enabling password-reset "
                        "poisoning and script delivery."
                    ),
                    tags=("host-header", "xss"),
                ),
                primitives=[host_header.finding_id, strongest_xss.finding_id],
            )
        )

    if cache and strongest_xss:
        chains.append(
            Chain(
                name="XSS chain (cache poisoning -> stored XSS)",
                finding=_chain_finding(
                    name="XSS chain (cache poisoning -> stored XSS)",
                    subkey="chain-cache-xss",
                    base=strongest_xss,
                    primitives=(cache, strongest_xss),
                    confidence=_weaker(cache.confidence, strongest_xss.confidence),
                    detail=(
                        "A header-driven response is cached and contains executable "
                        "markup. The payload can be persisted for other users "
                        "without touching the origin database."
                    ),
                    tags=("cache-poisoning", "xss"),
                ),
                primitives=[cache.finding_id, strongest_xss.finding_id],
            )
        )

    if cors and strongest_xss:
        chains.append(
            Chain(
                name="XSS chain (CORS + XSS data theft)",
                finding=_chain_finding(
                    name="XSS chain (CORS + XSS data theft)",
                    subkey="chain-cors-xss",
                    base=strongest_xss,
                    primitives=(cors, strongest_xss),
                    confidence=_weaker(cors.confidence, strongest_xss.confidence),
                    detail=(
                        "A permissive CORS policy lets an attacker origin read "
                        "authenticated responses. Combined with script execution on "
                        "the target, session data and API responses can be exfiltrated "
                        "without a proxy."
                    ),
                    tags=("cors", "xss"),
                ),
                primitives=[cors.finding_id, strongest_xss.finding_id],
            )
        )

    # -- DOM primitives ------------------------------------------------------
    dom_flow = _first(
        findings,
        lambda item: _kind(item).startswith("DOM XSS (static")
        or _kind(item).startswith("DOM XSS (taint"),
    )
    if postmessage and (dom_flow or strongest_xss):
        base = dom_flow or strongest_xss
        chains.append(
            Chain(
                name="XSS chain (postMessage -> DOM sink)",
                finding=_chain_finding(
                    name="XSS chain (postMessage -> DOM sink)",
                    subkey="chain-postmessage-dom",
                    base=base,
                    primitives=(postmessage, base),
                    confidence="medium",
                    detail=(
                        "A message listener reaches a dangerous DOM sink without a "
                        "strict origin check. A malicious page can post a payload "
                        "into the target window and drive the sink without a URL "
                        "parameter."
                    ),
                    tags=("postmessage", "dom"),
                ),
                primitives=[postmessage.finding_id, base.finding_id],
            )
        )

    # -- JSONP ---------------------------------------------------------------
    if jsonp and (strongest_xss or secret):
        base = strongest_xss or secret
        chains.append(
            Chain(
                name="XSS chain (JSONP callback -> script inclusion)",
                finding=_chain_finding(
                    name="XSS chain (JSONP callback -> script inclusion)",
                    subkey="chain-jsonp",
                    base=base,
                    primitives=(jsonp, base),
                    confidence="medium",
                    detail=(
                        "The endpoint wraps data in a caller-controlled callback and "
                        "is served as JavaScript. Any page that includes it can read "
                        "the response, and a javascript: callback executes in the "
                        "including origin where the browser allows it."
                    ),
                    tags=("jsonp", "script-inclusion"),
                ),
                primitives=[jsonp.finding_id, base.finding_id],
            )
        )

    # -- disclosure ----------------------------------------------------------
    if source_map and secret:
        chains.append(
            Chain(
                name="Secret disclosure chain (source map + credential)",
                finding=_chain_finding(
                    name="Secret disclosure chain (source map + credential)",
                    subkey="chain-sourcemap-secret",
                    base=secret,
                    primitives=(source_map, secret),
                    confidence="high",
                    detail=(
                        "A publicly readable source map exposes original source that "
                        "contains a credential-shaped value. Rotate the credential and "
                        "review the exposed endpoints."
                    ),
                    tags=("source-map", "secret", "disclosure"),
                ),
                primitives=[source_map.finding_id, secret.finding_id],
            )
        )

    return chains


__all__ = ["Chain", "build_chains"]
