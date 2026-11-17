"""JS intelligence exposure collection and compatibility aliases."""

from __future__ import annotations

from xoxss.core.finding import ScanStats
from xoxss.recon.jsintel import JSIntel, extract_secrets


def test_extract_secrets_still_detects_common_tokens() -> None:
    js = 'const config = {"api_key": "abcd1234efgh5678ijkl"};'
    hits = extract_secrets(js, "https://target.test/app.js")
    assert hits
    assert hits[0].kind
    assert hits[0].masked() != hits[0].value
    assert "abcd1234efgh5678ijkl" not in hits[0].masked()


def test_jsintel_exposures_alias_reads_and_writes() -> None:
    js = 'const api_key = "abcd1234efgh5678ijkl";'
    hits = extract_secrets(js)
    intel = JSIntel(exposures=hits)
    assert intel.secrets == hits
    intel.secrets = []
    assert intel.exposures == []
    assert intel.to_dict()["secrets"] == []


def test_scan_stats_secrets_alias_maps_to_js_exposures() -> None:
    stats = ScanStats()
    stats.secrets = 3
    assert stats.js_exposures == 3
    assert stats.secrets == 3
