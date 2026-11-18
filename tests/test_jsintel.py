"""JS intelligence exposure collection and compatibility aliases."""

from __future__ import annotations

from xoxss.core.finding import ScanStats
from xoxss.recon.jsintel import JSIntel, extract_inline_scripts, extract_secrets


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


def test_report_serialisation_masks_secrets_by_default() -> None:
    secret = 'const api_key = "abcd1234efgh5678ijkl";'
    intel = JSIntel(exposures=extract_secrets(secret))

    masked = intel.to_dict()
    revealed = intel.to_dict(reveal=True)

    assert masked["secrets"][0]["value"] != "abcd1234efgh5678ijkl"
    assert masked["secrets"][0]["redacted"] is True
    assert revealed["secrets"][0]["value"] == "abcd1234efgh5678ijkl"
    assert revealed["secrets"][0]["redacted"] is False


def test_scan_stats_secrets_alias_maps_to_js_exposures() -> None:
    stats = ScanStats()
    stats.secrets = 3
    assert stats.js_exposures == 3
    assert stats.secrets == 3


def test_inline_scripts_are_extracted_with_forgiving_closing_tags() -> None:
    html = (
        "<script>var a = 1;</script>"
        "<script type='module'>var b = 2;</script >"
        "<script>var c = 3;</script foo='bar'>"
        "<script src='/app.js'></script>"
    )
    scripts = extract_inline_scripts(html)
    assert scripts == ["var a = 1;", "var b = 2;", "var c = 3;"]
