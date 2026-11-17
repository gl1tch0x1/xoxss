"""End-to-end coverage for the 401/403 access-bypass engine.

The fixture hides two routes behind an authorisation check:

* ``/forbidden`` and ``/forbidden/search`` serve content when a proxy header
  (``X-Forwarded-For``, ``X-Real-IP``, ...), a URL-rewrite header or a
  non-canonical path is supplied;
* ``/auth`` only accepts a session cookie, so every bypass attempt must fail
  (negative control: a forged header must never be reported as a bypass).

The suite verifies the engine itself and then proves that the scanner still
finds the reflected XSS behind the protected route.
"""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.fixture_server import Handler  # noqa: E402
from xoxss.core.finding import ScanStats  # noqa: E402
from xoxss.core.http import HttpEngine  # noqa: E402
from xoxss.recon.access import AccessBypassEngine, BypassResult  # noqa: E402

STRONG = {"medium", "high", "confirmed"}


class NullConsole:
    def debug(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def info(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def ok(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def warn(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def error(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def raw(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def event(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def base_url() -> Iterator[str]:
    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 5
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.05)
    try:
        yield url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _run_engine(url: str, path: str, **kwargs: Any) -> Optional[BypassResult]:
    async def scenario() -> Optional[BypassResult]:
        http = HttpEngine(NullConsole(), ScanStats(), timeout=5.0, retries=0, concurrency=4)
        await http.start()
        try:
            baseline = await http.get(url + path)
            engine = AccessBypassEngine(http, NullConsole(), timeout=5.0, **kwargs)
            return await engine.probe(url + path, baseline)
        finally:
            await http.close()

    return asyncio.run(scenario())


def test_header_bypass_is_verified(base_url: str) -> None:
    result = _run_engine(base_url, "/forbidden")
    assert result is not None
    assert result.status == 200
    assert result.baseline_status == 403
    assert result.category == "header"
    assert result.confidence in STRONG
    assert "Administrative console" in result.excerpt


def test_path_bypass_is_verified_when_headers_are_disabled(base_url: str) -> None:
    result = _run_engine(base_url, "/forbidden", techniques=["path"])
    assert result is not None
    assert result.category == "path"
    assert result.variant
    assert result.status == 200


def test_protected_route_without_a_way_in_is_not_reported(base_url: str) -> None:
    # /auth only accepts a session cookie; no forged header may pass.
    assert _run_engine(base_url, "/auth") is None


def _latest_report(directory: Path) -> Optional[Path]:
    reports = sorted(directory.glob("*.json"), key=lambda item: item.stat().st_mtime)
    return reports[-1] if reports else None


@pytest.mark.parametrize("technique", [None, "path"])
def test_scanner_finds_xss_behind_a_403(base_url: str, technique: Optional[str]) -> None:
    report_dir = Path(tempfile.mkdtemp(prefix="xoxss-bypass-"))
    command = [
        sys.executable,
        "-m",
        "xoxss",
        f"{base_url}/forbidden/search?q=hello",
        "--no-state",
        "--no-color",
        "--quiet",
        "--no-browser",
        "--confirm",
        "http",
        "--max-payloads",
        "8",
        "--report",
        "json",
        "--report-dir",
        str(report_dir),
    ]
    if technique:
        command += ["--bypass-techniques", technique]
    completed = subprocess.run(
        command,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    try:
        report = _latest_report(report_dir)
        assert report is not None, completed.stderr[-2000:]
        payload: Dict[str, Any] = json.loads(report.read_text(encoding="utf-8"))
        findings: List[Dict[str, Any]] = list(payload.get("findings") or [])
        stats: Dict[str, Any] = dict(payload.get("stats") or {})
    finally:
        for item in report_dir.glob("*"):
            item.unlink(missing_ok=True)
        report_dir.rmdir()

    assert completed.returncode == 0, completed.stderr[-2000:]
    assert int(stats.get("access_bypasses") or 0) >= 1
    assert int(stats.get("bypass_attempts") or 0) >= 1
    kinds = {str(item.get("kind") or "") for item in findings}
    assert any("Access control bypass" in kind for kind in kinds)
    strong = [
        item
        for item in findings
        if str(item.get("confidence") or "").lower() in STRONG
        and "Access control bypass" not in str(item.get("kind") or "")
    ]
    assert strong, f"no XSS finding behind the 403: {kinds}"
