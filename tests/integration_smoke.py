import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HITS = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        HITS.append(self.path)
        parts = urlsplit(self.path)
        if parts.path == "/collect":
            self.send_response(204)
            self.end_headers()
            return
        q = parse_qs(parts.query).get("q", [""])[0]
        body = f"<html><body><div>{q}</div></body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    out = tempfile.mkdtemp(prefix="xoxss-smoke-")
    url = f"http://127.0.0.1:{port}/?q=hello"
    cmd = [
        sys.executable,
        "xoxss.py",
        url,
        "--no-browser",
        "--no-state",
        "--no-remote-payloads",
        "--max-payloads", "1",
        "--timeout", "5",
        "--blind", f"http://127.0.0.1:{port}/collect",
        "--report", "json,sarif,md,html",
        "--report-dir", out,
        "--quiet",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    print("exit:", proc.returncode)
    print("stdout tail:", proc.stdout[-2000:])
    print("stderr tail:", proc.stderr[-2000:])

    reports = os.listdir(out)
    print("reports:", reports)
    json_files = [p for p in reports if p.endswith(".json")]
    sarif_files = [p for p in reports if p.endswith(".sarif")]
    assert json_files, "missing JSON report"
    assert sarif_files, "missing SARIF report"

    with open(os.path.join(out, json_files[0]), encoding="utf-8") as fh:
        data = json.load(fh)
    print("findings:", [(f["kind"], f["confidence"]) for f in data["findings"]])
    print("blind markers:", data.get("blind_markers"))
    assert data.get("blind_markers"), "blind markers were not recorded"
    kinds = {f["kind"] for f in data["findings"]}
    assert any(k.startswith("Blind XSS") for k in kinds)
    assert any(k.startswith("Reflected XSS") for k in kinds)

    with open(os.path.join(out, sarif_files[0]), encoding="utf-8") as fh:
        sarif = json.load(fh)
    assert sarif["version"] == "2.1.0"
    print("sarif results:", len(sarif["runs"][0]["results"]))
    assert sarif["runs"][0]["results"]

    from urllib.parse import unquote

    injected = [h for h in HITS if "/collect" in unquote(h)]
    print("requests carrying the blind callback:", len(injected))
    assert injected, "blind payload never reached the target"
    server.shutdown()
    print("SMOKE OK")


if __name__ == "__main__":
    main()
