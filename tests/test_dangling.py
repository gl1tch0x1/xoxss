"""Dangling markup injection: tokenizer behaviour and scanner wiring."""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from xoxss.analysis.dangling import (
    build_dangling_payloads,
    detect_dangling,
)
from xoxss.core.finding import ScanStats
from xoxss.scan.injection import InjectionPoint
from xoxss.scan.reflection import ReflectionInfo
from xoxss.scanner import XSSScanner


def test_detects_capture_in_html_context() -> None:
    token = "dang1"
    payload = f"<img src='#{token}"
    body = (
        "<html><body><div>hello "
        + payload
        + "</div><p>csrf_token=SECRETVALUE1234567890</p></body></html>"
    )

    capture = detect_dangling(body, payload, token)

    assert capture.detected
    assert capture.tag == "img"
    assert capture.attribute == "src"
    assert capture.quote == "'"
    assert capture.captured_length >= 12
    assert "<redacted>" in capture.captured_preview or "csrf" in capture.captured_preview


def test_closed_tag_is_not_dangling() -> None:
    token = "closed1"
    payload = f"<img src='#{token}'>"
    body = f"<div>hello {payload} after</div>"

    capture = detect_dangling(body, payload, token)

    assert not capture.detected
    assert "character(s) captured" in capture.reason


def test_entity_encoded_payload_is_not_dangling() -> None:
    token = "enc1"
    payload = f"<img src='#{token}"
    body = "<div>&lt;img src=&#39;#enc1 &lt;/div&gt;</div>"

    assert not detect_dangling(body, payload, token).detected


def test_payload_inside_existing_attribute_is_not_dangling() -> None:
    """A literal ``<`` inside an outer quoted value must not be parsed as a tag."""
    token = "attr1"
    payload = f"<img src='#{token}"
    body = (
        f'<input value="{payload}">'
        "<p>csrf_token=SECRETVALUE1234567890</p></body></html>"
    )

    capture = detect_dangling(body, payload, token)

    assert not capture.detected
    assert "existing attribute" in capture.reason


def test_context_prefixes_break_out_of_attributes_and_raw_text() -> None:
    assert build_dangling_payloads("html", "t")[0][0] == "<img src='#t"
    assert build_dangling_payloads("attr_double", "t")[0][0].startswith('"><img')
    assert build_dangling_payloads("attr_single", "t")[0][0].startswith("'><img")
    assert build_dangling_payloads("script", "t")[0][0].startswith("</script>")
    assert build_dangling_payloads("comment", "t")[0][0].startswith("-->")
    assert build_dangling_payloads("json", "t") == []


def test_attribute_context_payload_breaks_out_and_captures() -> None:
    token = "attr2"
    payload = f"'><img src='#{token}"
    body = (
        "<input value='"
        + payload
        + "</div><p>secret=TOKENVALUE1234567890</p>"
    )

    capture = detect_dangling(body, payload, token)

    assert capture.detected
    assert capture.tag == "img"


class _FakeResponse:
    def __init__(
        self,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
        error: Optional[str] = None,
    ) -> None:
        self.text = text
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.error = error
        self.status = 200

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class _FakeConsole:
    def __init__(self) -> None:
        self.lines: List[str] = []

    def debug(self, message: str, *_a: Any, **_k: Any) -> None:
        self.lines.append(str(message))

    def warn(self, message: str, *_a: Any, **_k: Any) -> None:
        self.lines.append(str(message))

    def info(self, message: str, *_a: Any, **_k: Any) -> None:
        self.lines.append(str(message))


class _DanglingScanner:
    def __init__(self) -> None:
        self.args = SimpleNamespace(dangling_markup=True)
        self._stop = threading.Event()
        self.stats = ScanStats()
        self.console = _FakeConsole()
        self.findings: List[Any] = []

    async def send_point(self, _point: InjectionPoint, payload: str) -> _FakeResponse:
        return _FakeResponse(
            f"<html><body><div>{payload}</div>"
            "<p>csrf_token=SECRETVALUE1234567890</p></body></html>"
        )

    def poc_for_point(self, _point: InjectionPoint, _payload: str) -> tuple[str, str]:
        return "https://target.test/?q=x", "curl x"

    def add_finding(self, finding: Any) -> bool:
        self.findings.append(finding)
        return True

    @staticmethod
    def evidence_from_response(*_a: Any, **_k: Any) -> Dict[str, Any]:
        return {}


def test_probe_dangling_emits_finding() -> None:
    scanner = _DanglingScanner()
    point = InjectionPoint(
        url="https://target.test/?q=1", method="GET", param="q", source="query"
    )
    info = ReflectionInfo(
        reflected=True,
        context="html",
        executable=True,
        raw_specials=["<", "'"],
    )

    handled = asyncio.run(
        XSSScanner._probe_dangling(
            scanner,  # type: ignore[arg-type]
            point,
            info,
            _FakeResponse("<html></html>"),  # type: ignore[arg-type]
            "GET q",
        )
    )

    assert handled is True
    assert scanner.stats.dangling_hits == 1
    assert scanner.findings[0].kind == "Dangling Markup Injection"
    assert scanner.findings[0].confidence == "high"


def test_probe_dangling_disabled_and_ineligible_contexts() -> None:
    scanner = _DanglingScanner()
    scanner.args.dangling_markup = False
    point = InjectionPoint(
        url="https://target.test/?q=1", method="GET", param="q", source="query"
    )
    info = ReflectionInfo(reflected=True, context="html", executable=True, raw_specials=["<"])

    assert not asyncio.run(
        XSSScanner._probe_dangling(
            scanner, point, info, _FakeResponse("<html></html>"), "GET q"  # type: ignore[arg-type]
        )
    )

    scanner.args.dangling_markup = True
    info.context = "json"
    assert not asyncio.run(
        XSSScanner._probe_dangling(
            scanner, point, info, _FakeResponse("<html></html>"), "GET q"  # type: ignore[arg-type]
        )
    )
