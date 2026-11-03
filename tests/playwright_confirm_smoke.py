"""Browser-confirmation smoke test (Playwright backend, local server)."""

import json
import os
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

    out = tempfile.mkdtemp(prefix="xoxss-pw-")
    url = f"http://127.0.0.1:{port}/?q=hello"
    cmd = [
        sys.executable,
        "xoxss.py",
        url,
        "--browser", "playwright",
        "--headless",
        "--confirm", "browser",
        "--no-state",
        "--no-remote-payloads",
        "--max-payloads", "1",
        "--timeout", "15",
        "--screenshot",
        "--report", "json",
        "--report-dir", out,
        "--quiet",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    print("exit:", proc.returncode)
    print(proc.stdout[-2500:])
    print(proc.stderr[-1500:])

    reports = [p for p in os.listdir(out) if p.endswith(".json")]
    assert reports, "missing JSON report"
    with open(os.path.join(out, reports[0]), encoding="utf-8") as handle:
        data = json.load(handle)
    print("findings:", [(f["kind"], f["confidence"]) for f in data["findings"]])
    confirmed = [f for f in data["findings"] if f["confidence"] == "confirmed"]
    assert confirmed, "Playwright did not confirm the reflected payload"
    assert confirmed[0]["screenshot"], "screenshot was not captured"
    server.shutdown()
    print("PLAYWRIGHT CONFIRM OK")


if __name__ == "__main__":
    main()
