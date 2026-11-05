"""Multi-header reflection probing: one batched marker request, targeted follow-up.

Regression tests for ``XSSScanner.test_headers``: all candidate headers are
probed in a single request with unique markers, and only headers whose marker
is reflected receive the expensive executable-payload validation request.
"""

import asyncio
import threading
from types import SimpleNamespace

from xoxss.scanner import Console, XSSScanner


class _Payloads:
    """Minimal stand-in for PayloadEngine.render."""

    def render(self, template: str, token: str, context: str = "") -> str:
        marker = token
        if "{m}" in template:
            return template.replace("{m}", marker)
        if "{t}" in template:
            return template.replace("{t}", token)
        return template


class HeaderHttp:
    """Fake HTTP engine: the batched probe reflects only the chosen header."""

    def __init__(self, reflect: str = "", status: int = 200):
        self.reflect = reflect
        self.status = status
        self.calls: list = []

    async def get(self, url, **kwargs):
        headers = dict(kwargs.get("headers") or {})
        self.calls.append(headers)
        # A validation request carries the executable payload; a batched
        # probe carries plain markers.
        payloads = [value for value in headers.values() if value.startswith("<script>")]
        if payloads:
            body = "<html><body>" + payloads[0] + "</body></html>"
        else:
            body = "<html><body>" + headers.get(self.reflect, "") + "</body></html>"
        return SimpleNamespace(
            status=self.status,
            text=body,
            error=None,
            headers={"content-type": "text/html"},
            header=lambda name, default="": {"content-type": "text/html"}.get(name, default),
        )


def _scanner(http: HeaderHttp, headers) -> XSSScanner:
    scanner = object.__new__(XSSScanner)
    scanner.args = SimpleNamespace(header_list=headers, tamper=None, encoder=None)
    scanner.http = http
    scanner.console = Console(quiet=True)
    scanner._stop = threading.Event()
    scanner.payloads = _Payloads()
    scanner.findings = []

    def add_finding(finding):
        scanner.findings.append(finding)
        return True

    scanner.add_finding = add_finding
    return scanner


def test_header_probe_batches_all_candidates_into_one_request():
    http = HeaderHttp(reflect="Referer")
    scanner = _scanner(http, ["X-Forwarded-For", "Referer"])

    asyncio.run(scanner.test_headers("https://example.test/"))

    # One batched marker probe + one targeted validation for Referer only.
    assert len(http.calls) == 2
    assert set(http.calls[0]) == {"X-Forwarded-For", "Referer"}
    assert set(http.calls[1]) == {"Referer"}
    assert len(scanner.findings) == 1
    assert scanner.findings[0].parameter == "Referer"
    assert scanner.findings[0].method == "GET"
    assert scanner.findings[0].poc_command.startswith("curl -sk")


def test_header_probe_uses_url_shaped_values_for_url_headers():
    http = HeaderHttp(reflect="")
    scanner = _scanner(http, ["Origin", "Referer", "X-Forwarded-Host"])

    asyncio.run(scanner.test_headers("https://example.test/"))

    probe = http.calls[0]
    assert probe["Origin"].startswith("https://")
    assert probe["Origin"].endswith(".xoxss.invalid")
    assert probe["Referer"].startswith("https://xoxss.invalid/")
    assert probe["X-Forwarded-Host"].endswith(".xoxss.invalid")
    assert len(http.calls) == 1  # nothing reflected -> no validation requests
    assert scanner.findings == []


def test_header_probe_is_chunked_for_long_header_lists():
    headers = [f"X-Probe-{index}" for index in range(12)]
    http = HeaderHttp(reflect="")
    scanner = _scanner(http, headers)

    asyncio.run(scanner.test_headers("https://example.test/"))

    # 12 candidates in chunks of 10 -> two batched requests, no follow-ups.
    assert len(http.calls) == 2
    assert len(http.calls[0]) == 10
    assert len(http.calls[1]) == 2


def test_header_probe_deduplicates_candidates():
    http = HeaderHttp(reflect="")
    scanner = _scanner(http, ["Referer", "Referer", "Origin"])

    asyncio.run(scanner.test_headers("https://example.test/"))

    assert list(http.calls[0]) == ["Referer", "Origin"]
