"""Tests for the recon / encoder / OOB integration modules.

Everything here is offline: parsers are fed recorded payloads and the OOB
transport is a fake source, so the suite never touches the network.
"""

import asyncio
import json

import pytest

from xoxss.analysis.ast_taint import (
    analyze_javascript,
    find_sources,
    strip_comments,
    summarize_flows,
)
from xoxss.detection.encoders import (
    Encoder,
    apply_chain,
    apply_encoder,
    describe_encoders,
    encoder_names,
    get_encoder,
    list_encoders,
    register_encoder,
)
from xoxss.oob.base import OOBHit, OOBManager, OOBSource, extract_marker, parse_generic_payload
from xoxss.recon.jsintel import (
    analyze_javascript_intel,
    extract_attr_urls,
    extract_endpoints,
    extract_html_parameters,
    extract_parameters,
    extract_secrets,
    sources_from_sourcemap,
)
from xoxss.recon.openapi import parse_openapi, parse_spec_text
from xoxss.recon.passive import (
    extract_query_parameters,
    filter_scope,
    normalize_url,
    parse_commoncrawl,
    parse_line_urls,
    parse_otx_urls,
    parse_urlscan_urls,
    parse_wayback,
)
from xoxss.recon.subdomains import (
    normalize_host,
    parse_certspotter,
    parse_crtsh,
    parse_hackertarget,
    parse_otx,
    parse_rapiddns,
    parse_urlscan,
    root_domain,
)
from xoxss.tools.external import (
    ExternalToolkit,
    parse_dalfox,
    parse_arjun_json,
    parse_ffuf,
    parse_katana,
    parse_nuclei,
    parse_subfinder,
    parse_x8_json,
)
from xoxss.scan.fuzzer import expand_paths, load_wordlist


# --------------------------------------------------------------------------------------
# AST taint
# --------------------------------------------------------------------------------------


def test_ast_taint_direct_source_to_sink():
    flows = analyze_javascript(
        "document.getElementById('out').innerHTML = location.hash;",
        "https://app.test/bundle.js",
    )
    assert flows
    flow = flows[0]
    assert flow.source == "location.hash"
    assert flow.sink == "innerHTML"
    assert flow.context == "html"
    assert flow.confidence >= 0.85
    assert not flow.sanitized


def test_ast_taint_alias_and_sanitizer():
    code = (
        "var h = location.search;\n"
        "el.innerHTML = h;\n"
        "var safe = DOMPurify.sanitize(location.hash);\n"
        "el2.innerHTML = safe;\n"
    )
    flows = analyze_javascript(code, "https://app.test/app.js")
    assert any("h" == (flow.path or [""])[0] for flow in flows)
    sanitized = [flow for flow in flows if flow.sanitized]
    assert sanitized
    assert sanitized[0].sanitizer == "DOMPurify"
    assert sanitized[0].confidence < 0.5


def test_ast_taint_skips_literal_timers_and_comments():
    assert analyze_javascript("setTimeout('alert(1)', 10)") == []
    cleaned = strip_comments("// el.innerHTML = location.hash;\nvar x = 1;")
    assert "innerHTML" not in cleaned
    assert analyze_javascript("// el.innerHTML = location.hash;\nvar x = 1;") == []


def test_ast_taint_helpers():
    code = "var x = document.referrer;\nfoo.innerHTML = x;"
    sources = find_sources(code)
    assert any(name == "document.referrer" for name, _line, _snippet in sources)
    summary = summarize_flows(analyze_javascript(code))
    assert summary["total"] >= 1
    assert summary["executable"] >= 1


# --------------------------------------------------------------------------------------
# Encoder registry
# --------------------------------------------------------------------------------------


def test_encoder_chain_and_lookup():
    assert apply_encoder("a b", "urlencode") == "a%20b"
    assert apply_chain("a b", ["urlencode", "uppercase"]) == "A%20B"
    assert get_encoder("UPPERCASE").encode("a") == "A"
    assert "urlencode" in encoder_names()
    assert any(item.name == "js_unicode" for item in list_encoders("script"))
    assert "urlencode" in describe_encoders()


def test_encoder_registry_duplicate_and_replace():
    encoder = Encoder("test_encoder", lambda value: value[::-1], "reverse")
    register_encoder(encoder)
    with pytest.raises(ValueError):
        register_encoder(encoder)
    replaced = register_encoder(encoder, replace=True)
    assert replaced.name == "test_encoder"
    assert apply_encoder("abc", "test_encoder") == "cba"
    with pytest.raises(KeyError):
        get_encoder("does-not-exist")


# --------------------------------------------------------------------------------------
# Passive subdomains
# --------------------------------------------------------------------------------------


def test_root_domain_handles_multi_part_suffixes():
    assert root_domain("a.b.example.co.uk") == "example.co.uk"
    assert root_domain("api.example.com") == "example.com"
    assert root_domain("https://deep.sub.example.com:8443/x") == "example.com"
    assert normalize_host("*.API.Example.com:443/path") == "api.example.com"


def test_subdomain_source_parsers():
    crt = json.dumps(
        [
            {"name_value": "a.example.com\n*.b.example.com"},
            {"name_value": "outside.test"},
        ]
    )
    assert set(parse_crtsh(crt, "example.com")) == {"a.example.com", "b.example.com"}

    certspotter = json.dumps([{"dns_names": ["api.example.com", "x.test"]}])
    assert parse_certspotter(certspotter, "example.com") == ["api.example.com"]

    assert parse_hackertarget("www.example.com,1.2.3.4\n", "example.com") == [
        "www.example.com"
    ]

    otx = json.dumps({"passive_dns": [{"hostname": "mail.example.com"}]})
    assert parse_otx(otx, "example.com") == ["mail.example.com"]

    urlscan = json.dumps({"results": [{"page": {"domain": "cdn.example.com"}}]})
    assert parse_urlscan(urlscan, "example.com") == ["cdn.example.com"]

    assert parse_rapiddns("shop.example.com", "example.com") == ["shop.example.com"]


# --------------------------------------------------------------------------------------
# Passive URLs
# --------------------------------------------------------------------------------------


def test_url_normalisation_and_scope():
    assert normalize_url("//Example.COM:443/a?b=1#x") == "https://example.com/a?b=1#x"
    assert normalize_url("javascript:alert(1)") == ""
    assert normalize_url("/relative", base="https://example.com/dir/") == (
        "https://example.com/relative"
    )
    urls = [
        "https://example.com/a?q=1",
        "https://example.com/a?q=1#frag",
        "https://evil.test/a?q=1",
        "https://sub.example.com/b",
    ]
    assert filter_scope(urls, "example.com") == [
        "https://example.com/a?q=1",
        "https://sub.example.com/b",
    ]


def test_passive_url_parsers():
    wayback = json.dumps(
        [["https://example.com/a?x=1"], ["https://example.com/b?y=2"]]
    )
    assert parse_wayback(wayback, "example.com") == [
        "https://example.com/a?x=1",
        "https://example.com/b?y=2",
    ]

    commoncrawl = "\n".join(
        json.dumps({"url": "https://example.com/c?z=3"}) for _ in range(2)
    )
    assert parse_commoncrawl(commoncrawl, "example.com") == [
        "https://example.com/c?z=3"
    ]

    urlscan = json.dumps(
        {"results": [{"page": {"url": "https://example.com/d?p=4"}}]}
    )
    assert parse_urlscan_urls(urlscan, "example.com") == [
        "https://example.com/d?p=4"
    ]

    otx = json.dumps({"url_list": [{"url": "https://example.com/e?p=5"}]})
    assert parse_otx_urls(otx, "example.com") == ["https://example.com/e?p=5"]

    assert parse_line_urls("https://example.com/f\nnonsense\n", "example.com") == [
        "https://example.com/f"
    ]
    assert extract_query_parameters(
        ["https://example.com/?a=1&b=2", "https://example.com/?a=3"]
    ) == ["a", "b"]


# --------------------------------------------------------------------------------------
# JavaScript intelligence
# --------------------------------------------------------------------------------------


def test_js_endpoints_parameters_and_html_extraction():
    js = (
        "fetch('/api/users?id=1');\n"
        "var admin = '/v2/admin';\n"
        "searchParams.get('q');\n"
        "params: {page: 1, sort: 'asc'}\n"
    )
    endpoints = extract_endpoints(js, "https://app.test/static/app.js")
    assert "https://app.test/api/users?id=1" in endpoints
    assert "https://app.test/v2/admin" in endpoints
    parameters = extract_parameters(js)
    assert {"id", "q", "page", "sort"}.issubset(set(parameters))

    html = '<input name="email"><a href="/next?tab=1">next</a>'
    assert "email" in extract_html_parameters(html)
    assert "tab" in extract_html_parameters(html)
    assert "https://app.test/next?tab=1" in extract_attr_urls(html, "https://app.test/")


def test_js_secret_detection_and_sourcemaps():
    js = (
        "var aws = 'AKIA1234567890ABCDEF';\n"
        "var stripe = 'sk_live_1234567890abcdef';\n"
        "//# sourceMappingURL=app.js.map\n"
    )
    hits = extract_secrets(js, "https://app.test/app.js")
    kinds = {hit.kind for hit in hits}
    assert "aws_access_key" in kinds
    assert "stripe_secret" in kinds
    assert all(hit.value for hit in hits)
    assert hits[0].masked() != hits[0].value

    sourcemap = json.dumps(
        {
            "sources": ["../src/app.ts"],
            "sourcesContent": ["const url = location.hash;"],
        }
    )
    sources, contents = sources_from_sourcemap(sourcemap, "https://app.test/js/app.js.map")
    assert sources == ["https://app.test/src/app.ts"]
    assert contents == ["const url = location.hash;"]


def test_js_intel_aggregates_findings():
    js = "fetch('/graphql');\nel.innerHTML = location.hash;\nvar key='AKIA1234567890ABCDEF';"
    intel = analyze_javascript_intel(js, "https://app.test/app.js", source="https://app.test/app.js")
    assert intel.url == "https://app.test/app.js"
    assert any(endpoint.endswith("/graphql") for endpoint in intel.endpoints)
    assert any(flow.sink == "innerHTML" for flow in intel.dom_flows)
    assert intel.secrets
    payload = intel.to_dict()
    assert payload["dom_flows"]


# --------------------------------------------------------------------------------------
# OpenAPI
# --------------------------------------------------------------------------------------


def test_parse_swagger_2_operations():
    document = {
        "swagger": "2.0",
        "host": "api.example.com",
        "basePath": "/v1",
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "type": "string", "default": "7"},
                        {"name": "q", "in": "query", "type": "string"},
                    ]
                }
            }
        },
    }
    operations = parse_openapi(document, "https://api.example.com/swagger.json")
    assert len(operations) == 1
    operation = operations[0]
    assert operation.method == "GET"
    assert "/users/7" in operation.url
    assert "q=xoxss" in operation.url
    assert operation.query_names() == ["q"]


def test_parse_swagger_2_body_schema_and_host():
    document = {
        "swagger": "2.0",
        "host": "api.example.com",
        "basePath": "/v1",
        "consumes": ["application/json"],
        "paths": {
            "/login": {
                "post": {
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "required": True,
                            "schema": {
                                "type": "object",
                                "required": ["user"],
                                "properties": {
                                    "user": {"type": "string"},
                                    "remember": {"type": "boolean"},
                                },
                            },
                        }
                    ]
                }
            }
        },
    }
    operations = parse_openapi(document, "https://specs.example.com/swagger.json")
    assert len(operations) == 1
    operation = operations[0]
    assert operation.url == "https://api.example.com/v1/login"
    assert operation.content_type == "application/json"
    assert {param.name for param in operation.parameters} == {"user", "remember"}
    assert operation.sample_body == {"user": "xoxss", "remember": "true"}


def test_parse_openapi_3_json_body():
    document = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/login": {
                "post": {
                    "operationId": "login",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["user"],
                                    "properties": {
                                        "user": {"type": "string"},
                                        "remember": {"type": "boolean"},
                                    },
                                }
                            }
                        }
                    },
                }
            }
        },
    }
    operations = parse_openapi(document, "https://api.example.com/openapi.json")
    assert len(operations) == 1
    operation = operations[0]
    assert operation.method == "POST"
    assert operation.content_type == "application/json"
    assert operation.sample_body == {"user": "xoxss", "remember": "true"}
    assert {param.name for param in operation.parameters if param.location == "body"} == {
        "user",
        "remember",
    }


def test_parse_spec_text_rejects_non_specs():
    assert parse_spec_text("<html>not a spec</html>", "https://x.test/openapi.json") == []
    assert parse_spec_text("", "https://x.test/openapi.json") == []


# --------------------------------------------------------------------------------------
# Out-of-band
# --------------------------------------------------------------------------------------


class FakeConsole:
    def info(self, *args, **kwargs):
        return None

    def warn(self, *args, **kwargs):
        return None

    def debug(self, *args, **kwargs):
        return None

    def ok(self, *args, **kwargs):
        return None


class FakeSource(OOBSource):
    name = "fake"

    def __init__(self):
        self.started = False
        self.hits = []

    async def start(self):
        self.started = True
        return True

    async def close(self):
        return None

    def callback_for(self, marker):
        return f"https://cb.test/{marker}"

    async def poll(self):
        hits, self.hits = self.hits, []
        return hits


def test_oob_marker_and_generic_payload_parsing():
    assert extract_marker("GET /?m=abc123 HTTP/1.1") == "abc123"
    payload = json.dumps(
        {
            "hits": [
                {"raw": "GET /?m=marker9 HTTP/1.1", "protocol": "http", "remote-address": "1.2.3.4"},
                {"raw": "no marker here"},
            ]
        }
    )
    hits = parse_generic_payload(payload)
    assert len(hits) == 1
    assert hits[0].marker == "marker9"
    assert hits[0].remote_address == "1.2.3.4"


def test_oob_manager_allocates_and_dedupes():
    async def scenario():
        source = FakeSource()
        manager = OOBManager(FakeConsole(), source, poll_interval=1.0, max_hits=10)
        assert await manager.start()
        registration = manager.allocate(
            "mark1",
            "https://target.test/?q=1",
            "q",
            callback="https://blind.test/?m=mark1",
        )
        assert registration.callback == "https://blind.test/?m=mark1"
        source.hits = [
            OOBHit(marker="mark1", raw="GET /?m=mark1", protocol="http"),
            OOBHit(marker="unknown", raw="GET /?m=unknown"),
        ]
        first = await manager.poll_once()
        assert [hit.marker for hit in first] == ["mark1"]
        source.hits = [OOBHit(marker="mark1", raw="GET /?m=mark1", protocol="http")]
        assert await manager.poll_once() == []
        assert manager.hits_for("mark1")
        assert manager.to_dict()["transport"] == "fake"
        await manager.close()

    asyncio.run(scenario())


# --------------------------------------------------------------------------------------
# External tool parsers
# --------------------------------------------------------------------------------------


def test_external_tool_parsers():
    assert parse_subfinder("a.example.com\noutside.test\n", "example.com") == [
        "a.example.com"
    ]

    katana = "\n".join(
        [
            json.dumps({"request": {"endpoint": "https://example.com/a"}, "form": {"action": "/login"}}),
            json.dumps({"request": {"endpoint": "https://example.com/b"}}),
        ]
    )
    crawl = parse_katana(katana)
    assert crawl.urls == ["https://example.com/a", "https://example.com/b"]
    assert crawl.forms == [{"action": "/login"}]

    dalfox = json.dumps(
        {"url": "https://example.com/?q=1", "param": "q", "payload": "<script>", "severity": "high"}
    )
    findings = parse_dalfox(dalfox)
    assert findings and findings[0].parameter == "q" and findings[0].severity == "high"

    nuclei = json.dumps(
        {
            "template-id": "reflected-xss",
            "matched-at": "https://example.com/?q=1",
            "info": {"name": "Reflected XSS", "severity": "medium"},
        }
    )
    assert parse_nuclei(nuclei)
    assert parse_nuclei(json.dumps({"template-id": "tech-detect", "matched-at": "https://x.test"})) == []

    ffuf = json.dumps({"results": [{"url": "https://example.com/admin", "status": 200}]})
    assert parse_ffuf(ffuf)[0]["url"] == "https://example.com/admin"

    arjun = json.dumps({"https://example.com/search": {"GET": ["q", "page"]}})
    assert parse_arjun_json(arjun) == {
        "https://example.com/search": ["page", "q"]
    }
    row_output = json.dumps({"url": "https://example.com/api", "parameters": [{"name": "debug"}]})
    assert parse_arjun_json(row_output) == {"https://example.com/api": ["debug"]}
    assert parse_x8_json(json.dumps({"parameters": ["admin", "token"]}), "https://example.com/") == {
        "https://example.com/": ["admin", "token"]
    }


def test_external_parameter_tools_merge_json_results(monkeypatch):
    import xoxss.tools.external as external
    from types import SimpleNamespace
    from pathlib import Path

    monkeypatch.setattr(external, "available_tools", lambda: {"arjun": "arjun", "x8": "x8"})

    class _NullConsole:
        def info(self, *args, **kwargs): pass
        def warn(self, *args, **kwargs): pass
        def debug(self, *args, **kwargs): pass

    toolkit = ExternalToolkit(_NullConsole(), tools=["arjun", "x8"])

    class Runner:
        async def run(self, tool, args, *, timeout=None):
            output_path = Path(args[-1])
            url = args[args.index("-u") + 1]
            if tool == "arjun":
                output_path.write_text(json.dumps({url: {"GET": ["arjunParam"]}}), encoding="utf-8")
                assert "-m" in args and args[args.index("-m") + 1] == "GET"
            else:
                output_path.write_text(json.dumps({url: {"parameters": ["x8Param"]}}), encoding="utf-8")
                assert args[args.index("-O") + 1] == "json"
            return SimpleNamespace(stdout="", returncode=0)

    toolkit.runner = Runner()
    result = asyncio.run(toolkit.parameters(["https://example.com/search"]))
    assert result == {"https://example.com/search": ["arjunParam", "x8Param"]}


# --------------------------------------------------------------------------------------
# Internal fuzzing helpers and CLI wiring
# --------------------------------------------------------------------------------------


def test_fuzzer_wordlist_helpers(tmp_path):
    assert expand_paths(["admin"], ("", ".php")) == ["admin", "admin.php"]
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("# comment\napi\n\nlogin\n", encoding="utf-8")
    assert load_wordlist(str(wordlist), ["admin"]) == ["api", "login", "admin"]


def test_interactsh_crypto_roundtrip():
    pytest.importorskip("cryptography")
    from xoxss.oob.interactsh import (
        correlation_id,
        decrypt_message,
        encrypt_message,
        generate_keypair,
        zbase32,
    )

    private_key, public_b64 = generate_keypair()
    assert public_b64
    aes_key, ciphertext = encrypt_message(private_key.public_key(), b'{"ok":true}')
    assert decrypt_message(private_key, aes_key, ciphertext) == b'{"ok":true}'
    assert len(correlation_id()) == 20
    assert zbase32(b"") == ""


def test_scanner_encoder_and_openapi_points():
    from types import SimpleNamespace

    from xoxss.recon.openapi import APIOperation, APIParameter
    from xoxss.scanner import XSSScanner

    scanner = object.__new__(XSSScanner)
    scanner.args = SimpleNamespace(tamper=None, encoder=["urlencode"])
    scanner.console = SimpleNamespace(debug=lambda *args, **kwargs: None)
    assert scanner.transform_payload("a b") == "a%20b"

    scanner.api_operations = [
        APIOperation(
            url="https://api.test/login",
            method="POST",
            parameters=[APIParameter("user", "body", required=True)],
            content_type="application/json",
            sample_body={"user": "xoxss", "remember": "true"},
        )
    ]
    points = scanner._api_points("https://api.test/login")
    assert len(points) == 1
    assert points[0].source == "json"
    assert points[0].param == "user"
    assert points[0].json_body["remember"] == "true"


def test_cli_exposes_recon_and_oob_flags(capsys):
    from xoxss.scanner import build_parser, main

    args = build_parser().parse_args(
        [
            "https://example.com",
            "--no-browser",
            "--subdomains",
            "--passive-urls",
            "--openapi",
            "--fuzz-paths",
            "--mine-params",
            "--external-tools",
            "--encoder",
            "urlencode",
            "--interactsh",
            "--oob-interval",
            "2",
            "--oob-wait",
            "5",
        ]
    )
    assert args.subdomains and args.passive_urls and args.openapi
    assert args.fuzz_paths and args.mine_params and args.external_tools
    assert args.encoder == ["urlencode"]
    assert args.interactsh == "oast.pro"
    assert args.oob_interval == 2.0 and args.oob_wait == 5.0

    assert main(["--list-encoders"]) == 0
    assert "Available encoders" in capsys.readouterr().out
