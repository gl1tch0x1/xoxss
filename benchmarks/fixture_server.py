#!/usr/bin/env python3
"""Loopback-only vulnerable web application for scanner coverage experiments."""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


STORED: list[str] = []


class Handler(BaseHTTPRequestHandler):
    server_version = "XoxssBenchmark/1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def respond(self, body: str, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        payload = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        value = parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0]
        if parsed.path == "/":
            self.respond("""<h1>XOXSS local benchmark</h1><nav>
              <a href='/reflected?q=hello'>reflected</a>
              <a href='/attribute?q=hello'>attribute</a>
              <a href='/script?q=hello'>script</a>
              <a href='/dom-query'>DOM query</a><a href='/dom-hash'>DOM hash</a>
              <a href='/dom-storage'>DOM storage</a><a href='/dom-session-storage'>session storage</a>
              <a href='/dom-window-name'>window.name</a><a href='/dom-message'>postMessage</a>
              <a href='/stored'>stored</a><a href='/escaped?q=hello'>escaped control</a>
              <a href='/auth'>authenticated route</a></nav>""")
        elif parsed.path == "/reflected":
            self.respond(f"<main>Search result: {value}</main>")
        elif parsed.path == "/attribute":
            self.respond(f'<input name="q" value="{value}">')
        elif parsed.path == "/script":
            self.respond(f"<script>window.benchmarkQuery = '{value}';</script>")
        elif parsed.path == "/escaped":
            self.respond(f"<main>Safe output: {html.escape(value)}</main>")
        elif parsed.path == "/static":
            self.respond("<main>Static text: BENCHMARK_STATIC_TOKEN</main>")
        elif parsed.path == "/dom-query":
            self.respond("""<main id='out'></main><script>
              const value = new URLSearchParams(location.search).get('q');
              if (value) document.querySelector('#out').innerHTML = value;
            </script>""")
        elif parsed.path == "/dom-hash":
            self.respond("""<main id='out'></main><script>
              document.querySelector('#out').insertAdjacentHTML('beforeend', location.hash.slice(1));
            </script>""")
        elif parsed.path == "/dom-storage":
            self.respond("""<main id='out'></main><script>
              const value = localStorage.getItem('xss');
              if (value) document.querySelector('#out').innerHTML = value;
            </script>""")
        elif parsed.path == "/dom-session-storage":
            self.respond("""<main id='out'></main><script>
              const value = sessionStorage.getItem('xss');
              if (value) document.querySelector('#out').outerHTML = value;
            </script>""")
        elif parsed.path == "/dom-window-name":
            self.respond("""<main id='out'></main><script>
              if (window.name) document.querySelector('#out').innerHTML = window.name;
            </script>""")
        elif parsed.path == "/dom-message":
            self.respond("""<main id='out'></main><script>
              addEventListener('message', event => {
                document.querySelector('#out').innerHTML = event.data;
              });
            </script>""")
        elif parsed.path == "/stored":
            rendered = "".join(f"<li>{item}</li>" for item in STORED)
            self.respond(f"<form method='post'><input name='comment'><button>Save</button></form><ul>{rendered}</ul>")
        elif parsed.path == "/auth":
            if "benchmark_session=authorized" not in self.headers.get("Cookie", ""):
                self.respond("<h1>Login required</h1>", 401)
            else:
                self.respond("<h1>Authenticated route</h1><a href='/auth/search?q=hello'>search</a>")
        elif parsed.path == "/auth/search":
            if "benchmark_session=authorized" not in self.headers.get("Cookie", ""):
                self.respond("<h1>Login required</h1>", 401)
            else:
                self.respond(f"<main>{value}</main>")
        elif parsed.path == "/api/search":
            self.respond(json.dumps({"q": value}), content_type="application/json")
        else:
            self.respond("Not found", 404)

    def do_POST(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/stored":
            self.respond("Not found", 404)
            return
        try:
            length = min(16_384, max(0, int(self.headers.get("Content-Length", "0"))))
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            comment = form.get("comment", [""])[0]
            if comment:
                STORED.append(comment[:2000])
        except (ValueError, OSError):
            self.respond("Bad request", 400)
            return
        self.send_response(303)
        self.send_header("Location", "/stored")
        self.send_header("Content-Length", "0")
        self.end_headers()


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("Local XSS benchmark at http://127.0.0.1:8765/ (Ctrl+C to stop)")
    print("Auth fixture cookie: benchmark_session=authorized")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
