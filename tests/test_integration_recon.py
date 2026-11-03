"""End-to-end check for the recon + OOB integration.

A local HTTP server serves a page with a JavaScript bundle (secret + DOM taint),
an OpenAPI document, and a collector that returns observed markers.  The scan
must discover the API operation, record the JS intel/findings, inject the blind
payload and upgrade it to a confirmed finding from the OOB poll.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HITS: list = []
HITS_LOCK = threading.Lock()
ROOT = Path(__file__).resolve().parents[1]

JS_BUNDLE = (
    "var key = 'AKIA1234567890ABCDEF';\n"
    "document.body.innerHTML = location.hash;\n"
    "fetch('/api/data');\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status: int, body: str, content_type: str = "text/html") -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        if path == "/collect":
            self.send_response(204)
            self.end_headers()
            return
        if path == "/hits":
            with HITS_LOCK:
                payload = json.dumps({"hits": list(HITS)})
            self._send(200, payload, "application/json")
            return
        if path == "/openapi.json":
            self._send(
                200,
                json.dumps(
                    {
                        "openapi": "3.0.0",
                        "paths": {
                            "/search": {
                                "get": {
                                    "parameters": [
                                        {"name": "q", "in": "query", "schema": {"type": "string"}}
                                    ]
                                }
                            }
                        },
                    }
                ),
                "application/json",
            )
            return
        if path == "/app.js":
            self._send(200, JS_BUNDLE, "application/javascript")
            return
        if path == "/api/data":
            self._send(200, '{"ok":true}', "application/json")
            return

        query = parse_qs(parts.query).get("q", [""])[0]
        # Simulate the stored/admin page executing the blind beacon: the marker
        # appears in the payload that reached this server.
        match = re.search(r"[?&]m=([a-z0-9]{6,})", query)
        if match:
            with HITS_LOCK:
                if not any(hit.get("raw", "").endswith(match.group(1)) for hit in HITS):
                    HITS.append(
                        {
                            "raw": f"GET /?m={match.group(1)}",
                            "protocol": "http",
                            "remote-address": "127.0.0.1",
                        }
                    )
        body = (
            "<html><body>"
            f"<div>{query}</div>"
            "<script src='/app.js'></script>"
            "</body></html>"
        )
        self._send(200, body)


def test_recon_js_and_oob_confirmation(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"

    try:
        cmd = [
            sys.executable,
            str(ROOT / "xoxss.py"),
            f"{base}/?q=hello",
            "--crawl",
            "--crawl-depth",
            "1",
            "--max-urls",
            "8",
            "--js-files",
            "5",
            "--openapi",
            "--blind",
            f"{base}/collect",
            "--oob-poll",
            f"{base}/hits",
            "--oob-interval",
            "1",
            "--oob-wait",
            "4",
            "--no-browser",
            "--no-state",
            "--no-remote-payloads",
            "--max-payloads",
            "1",
            "--timeout",
            "5",
            "--report",
            "json",
            "--report-dir",
            str(tmp_path),
            "--quiet",
        ]
        completed = subprocess.run(
            cmd, capture_output=True, text=True, timeout=240, cwd=str(ROOT)
        )
        assert completed.returncode == 0, completed.stdout[-4000:] + completed.stderr[-4000:]

        reports = [path for path in tmp_path.glob("*.json") if not path.name.endswith("latest.json")]
        assert reports, "no JSON report written"
        data = json.loads(reports[0].read_text(encoding="utf-8"))

        assert data["recon"]["openapi_operations"], "OpenAPI operation was not discovered"
        assert data["recon"]["js_intel"], "JS bundle was not analysed"
        assert any(intel["secrets"] for intel in data["recon"]["js_intel"])
        assert data["oob"]["transport"] == "callback"
        assert data["oob"]["hits"], "OOB poller did not observe a hit"
        assert data["stats"]["oob_hits"] >= 1

        kinds = {finding["kind"] for finding in data["findings"]}
        assert "Blind XSS (callback confirmed)" in kinds
        assert "JavaScript secret exposure" in kinds
        assert "DOM XSS (taint flow)" in kinds
    finally:
        server.shutdown()
        server.server_close()
