"""JS intelligence exposure collection and compatibility aliases."""

from __future__ import annotations

from xoxss.core.finding import ScanStats
from xoxss.recon.jsintel import (
    JSIntel,
    extract_attr_urls,
    extract_endpoints,
    extract_inline_scripts,
    extract_secrets,
)


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


def test_extract_endpoints_covers_modern_client_surfaces() -> None:
    js = """
    const es = new EventSource('/events/stream');
    navigator.sendBeacon('/collect', data);
    import('/chunks/lazy.js');
    location.assign('/next/page');
    const w = new Worker('/workers/compute.js');
    navigator.serviceWorker.register('/sw.js');
    const s = document.createElement('script');
    s.src = '/dynamic/script.js';
    document.write('<script src="/legacy.js"></script>');
    """
    endpoints = extract_endpoints(js, "https://app.example.com")
    joined = " ".join(endpoints)
    for expected in (
        "/events/stream",
        "/collect",
        "/chunks/lazy.js",
        "/next/page",
        "/workers/compute.js",
        "/sw.js",
        "/dynamic/script.js",
        "/legacy.js",
    ):
        assert expected in joined, f"missing {expected} in {endpoints}"


def test_extract_attr_urls_covers_html_resource_surfaces() -> None:
    html = """
    <link rel="manifest" href="/manifest.json">
    <link rel="prefetch" href="/next-page">
    <iframe src="/embed/widget"></iframe>
    <object data="/plugin.swf"></object>
    <embed src="/media/clip.mp4">
    <form action="/submit"></form>
    <button formaction="/alt-submit">go</button>
    <meta http-equiv="refresh" content="0;url=/bounce">
    <base href="/base/">
    <script src="/app.js?callback=cb"></script>
    """
    urls = extract_attr_urls(html, "https://app.example.com")
    joined = " ".join(urls)
    for expected in (
        "/manifest.json",
        "/next-page",
        "/embed/widget",
        "/plugin.swf",
        "/media/clip.mp4",
        "/submit",
        "/alt-submit",
        "/bounce",
        "/base/",
        "/app.js",
    ):
        assert expected in joined, f"missing {expected} in {urls}"


def test_extract_secrets_detects_new_credential_families() -> None:
    # Tokens are assembled at runtime so no real-looking credential literal
    # appears in the source tree (push protection / secret scanning safe).
    gh = "github_pat_" + "A1" * 19
    gl = "glpat-" + "b2" * 18
    openai_key = "sk-" + "proj-" + "c3" * 20
    discord_tok = ".".join(
        ["MT" + "x" * 22, "e" * 6, "f" * 27]
    )
    tg = "123456789:" + "g4" * 17 + "h"
    aws = "ASIA" + "IOSFODNN7EXAMPLE"
    shopify_tok = "shpat_" + "0123456789abcdef" * 2
    js = f"""
    const gh = "{gh}";
    const gl = "{gl}";
    const openai = "{openai_key}";
    const discord = "{discord_tok}";
    const tg = "{tg}";
    const aws = "{aws}";
    const shopify = "{shopify_tok}";
    """
    kinds = {hit.kind for hit in extract_secrets(js)}
    for expected in (
        "github_pat",
        "gitlab_pat",
        "openai_key",
        "discord_token",
        "telegram_bot",
        "aws_session",
        "shopify_token",
    ):
        assert expected in kinds, f"missing {expected} in {kinds}"
