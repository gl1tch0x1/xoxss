"""CRLF / HTTP response-splitting probes and scanner wiring."""

from __future__ import annotations

import asyncio
import re
import threading
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit

from xoxss.core.finding import ScanStats
from xoxss.detection.header_injection import (
    build_split_values,
    find_injected_header,
    header_value_risks,
    rank_header_candidates,
)
from xoxss.scanner import XSSScanner


def test_rank_header_candidates_prefers_redirect_parameters() -> None:
    ranked = rank_header_candidates(["q", "lang", "next", "redirect_url"])
    assert ranked[:2] == ["next", "redirect_url"]
    assert ranked[-1] == "q"


def test_split_values_contain_crlf_and_unique_token() -> None:
    values = build_split_values("abc123")
    assert values[0][0] == "crlf"
    assert values[0][1].startswith("\r\nX-XOXSS-abc123:")
    assert any(label == "obs-fold" for label, _ in values)


def test_find_injected_header_requires_parsed_header() -> None:
    headers = {"content-type": "text/html", "x-xoxss-abc123": "1"}
    assert find_injected_header(headers, "abc123") == "x-xoxss-abc123"
    assert find_injected_header({"location": "https://x/?a=X-XOXSS-abc123"}, "abc123") is None
    assert find_injected_header({}, "abc123") is None


def test_header_value_risks_only_inspects_sensitive_headers() -> None:
    risks = header_value_risks(
        {
            "location": "/next?x=<script>alert(1)</script>",
            "x-random": "<img src=x>",
            "content-type": "text/html",
        }
    )
    assert len(risks) == 1
    assert risks[0]["header"] == "location"


class _FakeResponse:
    def __init__(
        self,
        headers: Optional[Dict[str, str]] = None,
        error: Optional[str] = None,
    ) -> None:
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.error = error
        self.status = 302
        self.text = ""

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class _FakeHttp:
    def __init__(self) -> None:
        self.calls: List[str] = []
        self.inject = True

    async def get(self, url: str, **_kwargs: Any) -> _FakeResponse:
        self.calls.append(url)
        if not self.inject:
            return _FakeResponse({"content-type": "text/html"})
        query = dict(parse_qsl(urlsplit(url).query))
        value = query.get("next") or query.get("q") or ""
        match = re.search(r"X-XOXSS-([A-Za-z0-9]+)", value)
        if not match:
            return _FakeResponse({"content-type": "text/html"})
        return _FakeResponse({"x-xoxss-" + match.group(1): "1"})


class _FakeConsole:
    def __init__(self) -> None:
        self.lines: List[str] = []

    def debug(self, message: str, *_a: Any, **_k: Any) -> None:
        self.lines.append(str(message))

    def warn(self, message: str, *_a: Any, **_k: Any) -> None:
        self.lines.append(str(message))

    def info(self, message: str, *_a: Any, **_k: Any) -> None:
        self.lines.append(str(message))


class _SplitScanner:
    def __init__(self, inject: bool = True) -> None:
        self.args = SimpleNamespace(header_injection=True, header_injection_limit=4)
        self._stop = threading.Event()
        self.stats = ScanStats()
        self.console = _FakeConsole()
        self.findings: List[Any] = []
        self.http = _FakeHttp()
        self.http.inject = inject

    def add_finding(self, finding: Any) -> bool:
        self.findings.append(finding)
        return True

    @staticmethod
    def evidence_from_response(*_a: Any, **_k: Any) -> Dict[str, Any]:
        return {}


def test_response_splitting_emits_finding_when_header_is_parsed() -> None:
    scanner = _SplitScanner()
    asyncio.run(
        XSSScanner.test_response_splitting(
            scanner, "https://target.test/next?next=/home&q=1"  # type: ignore[arg-type]
        )
    )

    assert scanner.findings
    finding = scanner.findings[0]
    assert finding.kind == "HTTP Response Splitting (CRLF injection)"
    assert finding.parameter == "next"
    assert scanner.stats.response_splitting_hits == 1
    assert scanner.stats.header_injection_probes >= 1


def test_response_splitting_no_finding_without_injected_header() -> None:
    scanner = _SplitScanner(inject=False)
    asyncio.run(
        XSSScanner.test_response_splitting(
            scanner, "https://target.test/next?next=/home"  # type: ignore[arg-type]
        )
    )

    assert not scanner.findings
    assert scanner.stats.response_splitting_hits == 0
    assert scanner.stats.header_injection_probes >= 1


def test_response_splitting_skips_urls_without_parameters() -> None:
    scanner = _SplitScanner()
    asyncio.run(
        XSSScanner.test_response_splitting(
            scanner, "https://target.test/"  # type: ignore[arg-type]
        )
    )
    assert scanner.http.calls == []


def test_response_splitting_respects_request_budget() -> None:
    scanner = _SplitScanner(inject=False)
    scanner.args.header_injection_budget = 2
    asyncio.run(
        XSSScanner.test_response_splitting(
            scanner, "https://target.test/next?next=/home&q=1"  # type: ignore[arg-type]
        )
    )
    assert len(scanner.http.calls) == 2
    assert scanner.stats.header_injection_probes == 2


def test_response_splitting_can_be_disabled() -> None:
    scanner = _SplitScanner()
    scanner.args.header_injection = False
    asyncio.run(
        XSSScanner.test_response_splitting(
            scanner, "https://target.test/next?next=/home"  # type: ignore[arg-type]
        )
    )
    assert scanner.http.calls == []
