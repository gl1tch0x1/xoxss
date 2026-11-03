"""Tests for the LazyXss payload pack and collector/Gxss parameter audit."""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from xoxss.scan.parameters import (
    ParameterHarvester,
    ReflectionProbe,
    parameter_risk,
)
from xoxss.scanner import (
    Console,
    HttpEngine,
    PayloadEngine,
    ScanStats,
    build_parser,
    run_param_audit,
)


class _EchoHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _render(self, params):
        parts = []
        for key, values in params.items():
            if key == "q" or key == "user":
                parts.append(values[0])
            else:
                parts.append(f"<escaped>{key}</escaped>")
        body = ("<html><body><div>" + "|".join(parts) + "</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        self._render(parse_qs(parts.query, keep_blank_values=True))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        self._render(parse_qs(body, keep_blank_values=True))


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()


def test_lazy_payload_pack_loads_and_is_sampled():
    engine = PayloadEngine(Console(quiet=True))
    assert len(engine.lazy_payloads) > 6000
    assert len(engine.lazy_payloads) == len(set(engine.lazy_payloads))

    sampled = engine.payloads_for("html", limit=30)
    assert len(sampled) == len(set(sampled))
    assert any(payload in engine.lazy_payloads for payload in sampled)

    disabled = PayloadEngine(Console(quiet=True), lazy_payloads=False)
    assert disabled.lazy_payloads == []
    assert not any(
        payload in engine.lazy_payloads
        for payload in disabled.payloads_for("html", limit=30)
    )


def test_lazy_payload_cli_defaults_and_opt_out():
    parser = build_parser()
    assert parser.parse_args(["example.com"]).lazy_payloads is True
    assert parser.parse_args(["example.com", "--no-lazy-payloads"]).lazy_payloads is False


def test_parameter_harvester_counts_and_ranks():
    harvester = ParameterHarvester(http=object(), console=Console(quiet=True), limit=100)
    urls = [
        "https://app.test/?q=one&id=1",
        "https://app.test/search?q=two&utm_source=mail",
        "https://app.test/page?q=three&redirect=https%3A%2F%2Fevil.test",
    ]
    report = harvester.harvest(urls, source="test")
    assert len(report.urls) == 3
    by_name = {candidate.name: candidate for candidate in report.candidates}
    assert by_name["q"].count == 3
    assert by_name["q"].risk == "high"
    assert by_name["redirect"].risk == "high"
    assert by_name["utm_source"].risk == "low"
    assert report.sources["test"] == 3


def test_wayback_list_parser_keeps_scope_and_parameters():
    text = "\n".join(
        [
            "https://app.test/page?q=1",
            "https://app.test/page?q=1",
            "https://cdn.other.test/app.test/logo.png",
            "https://sub.app.test/search?term=x",
        ]
    )
    urls = ParameterHarvester.parse_wayback(text, "app.test")
    assert urls == [
        "https://app.test/page?q=1",
        "https://sub.app.test/search?term=x",
    ]


def _probe_report(server):
    async def run():
        stats = ScanStats()
        http = HttpEngine(
            Console(quiet=True), stats, timeout=5, retries=0, concurrency=2
        )
        await http.start()
        try:
            report = ParameterHarvester(
                http, Console(quiet=True), limit=50
            ).harvest([f"{server}/reflect?q=hello&safe=world"], source="test")
            probe = ReflectionProbe(
                http, Console(quiet=True), marker="Audit", concurrency=2, urls_per_param=1
            )
            await probe.probe_candidates(report.candidates)
            return report
        finally:
            await http.close()

    return asyncio.run(run())


def test_gxss_style_probe_marks_only_reflecting_parameter(server):
    report = _probe_report(server)
    by_name = {candidate.name: candidate for candidate in report.candidates}
    assert by_name["q"].reflected is True
    assert by_name["q"].context
    # A plain marker proves reflection, never execution.
    assert by_name["q"].executable is False
    assert by_name["safe"].reflected is False


def test_post_parameter_probe(server):
    async def run():
        stats = ScanStats()
        http = HttpEngine(
            Console(quiet=True), stats, timeout=5, retries=0, concurrency=2
        )
        await http.start()
        try:
            report = ParameterHarvester(http, Console(quiet=True), limit=50).from_pairs(
                f"{server}/post", [("user", "test"), ("pass", "test")], source="post"
            )
            probe = ReflectionProbe(http, Console(quiet=True), marker="PostAudit", concurrency=2)
            await probe.probe_candidates(report.candidates, data="user=test&pass=test")
            return report
        finally:
            await http.close()

    report = asyncio.run(run())
    by_name = {candidate.name: candidate for candidate in report.candidates}
    assert by_name["user"].reflected is True
    assert by_name["user"].method == "POST"
    assert by_name["pass"].reflected is False


def test_param_audit_end_to_end_writes_json_and_jsonl(server, tmp_path):
    seed_file = tmp_path / "seeds.txt"
    seed_file.write_text(f"{server}/reflect?q=hello&safe=world\n", encoding="utf-8")
    output = tmp_path / "audit.json"
    jsonl = tmp_path / "audit.jsonl"
    args = build_parser().parse_args(
        [
            server,
            "--param-audit",
            "--param-input",
            str(seed_file),
            "--param-source",
            "none",
            "--param-output",
            str(output),
            "--jsonl",
            str(jsonl),
            "--quiet",
            "--timeout",
            "5",
            "--concurrency",
            "2",
            "--param-max-checks",
            "10",
        ]
    )
    code, reflected = asyncio.run(run_param_audit(args, Console(quiet=True)))
    assert code == 0
    assert reflected == 1

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["mode"] == "param-audit"
    assert payload["stats"]["discovered_params"] >= 2
    candidates = {item["name"]: item for item in payload["candidates"]}
    assert candidates["q"]["reflected"] is True
    assert candidates["safe"]["reflected"] is False

    rows = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines()]
    assert {row["name"] for row in rows} >= {"q", "safe"}
    assert all("executable" in row for row in rows)


def test_param_audit_post_body_mode(server, tmp_path):
    output = tmp_path / "post-audit.json"
    args = build_parser().parse_args(
        [
            f"{server}/post",
            "--param-audit",
            "--param-data",
            "user=test&pass=test",
            "--param-output",
            str(output),
            "--quiet",
            "--timeout",
            "5",
            "--concurrency",
            "2",
        ]
    )
    code, reflected = asyncio.run(run_param_audit(args, Console(quiet=True)))
    assert code == 0
    assert reflected == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    candidates = {item["name"]: item for item in payload["candidates"]}
    assert candidates["user"]["reflected"] is True
    assert candidates["user"]["method"] == "POST"
    assert candidates["pass"]["reflected"] is False


def test_parameter_risk_classification():
    assert parameter_risk("q") == "high"
    assert parameter_risk("redirect_uri") == "high"
    assert parameter_risk("utm_campaign") == "low"
    assert parameter_risk("pageid") == "normal"
