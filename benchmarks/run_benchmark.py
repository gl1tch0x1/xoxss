#!/usr/bin/env python3
"""Run the local XSS benchmark corpus against the fixture.

The corpus in ``cases.json`` describes expected detection per case.  This
runner turns each case into a real scanner invocation, reads the JSON report,
and compares the *evidence grade* with the expectation:

* ``finding``: at least one medium/high/confirmed finding.
* ``none``: no medium/high/confirmed finding (low informational leads allowed).

The fixture server is started automatically on loopback unless ``--base-url``
points at an already-running instance.  Only use this against the bundled
fixture or an application you are authorized to test.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
CASES_FILE = Path(__file__).resolve().parent / "cases.json"
FIXTURE = Path(__file__).resolve().parent / "fixture_server.py"
STRONG = {"confirmed", "high", "medium"}


def load_cases() -> Dict[str, Any]:
    with CASES_FILE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def wait_for_server(base_url: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base_url, timeout=1.0):
                return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"fixture server did not become ready at {base_url}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def latest_report(directory: Path) -> Optional[Path]:
    reports = sorted(directory.glob("*.json"), key=lambda path: path.stat().st_mtime)
    return reports[-1] if reports else None


def strongest(findings: List[Dict[str, Any]]) -> str:
    rank = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}
    return max((str(item.get("confidence") or "low") for item in findings), key=lambda c: rank.get(c, 0), default="none")


def run_case(
    case: Dict[str, Any],
    base_url: str,
    *,
    browser: str,
    timeout: int,
) -> Dict[str, Any]:
    report_dir = Path(tempfile.mkdtemp(prefix=f"xoxss-bench-{case['id']}-"))
    command = [
        sys.executable,
        "-m",
        "xoxss",
        base_url.rstrip("/") + str(case.get("url") or "/"),
        "--no-state",
        "--no-color",
        "--quiet",
        "--report",
        "json",
        "--report-dir",
        str(report_dir),
        "--max-payloads",
        "8",
    ]
    if browser != "none" and case.get("browser"):
        command += ["--browser", browser, "--headless"]
        if case.get("dom_source_probes"):
            command += ["--dom", "--dom-source-probes"]
        elif case.get("stored"):
            command += ["--stored", "--crawl", "--max-urls", "4"]
        else:
            command += ["--dom"]
    else:
        command += ["--confirm", "http", "--no-browser"]
    if case.get("stored") and browser == "none":
        command += ["--stored"]
    if case.get("cookie"):
        command += ["--cookies", str(case["cookie"])]
    try:
        completed = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(report_dir, ignore_errors=True)
        return {"case": case["id"], "status": "timeout", "expected": case.get("expect")}
    report = latest_report(report_dir)
    findings: List[Dict[str, Any]] = []
    if report is not None:
        try:
            payload = json.loads(report.read_text(encoding="utf-8"))
            findings = list(payload.get("findings") or [])
        except (OSError, ValueError):
            findings = []
    confidence = strongest(findings)
    expected = str(case.get("expect") or "finding")
    ok = (confidence in STRONG) if expected == "finding" else (confidence not in STRONG)
    result = {
        "case": case["id"],
        "status": "pass" if ok else "fail",
        "expected": expected,
        "confidence": confidence,
        "findings": len(findings),
        "kinds": sorted({str(item.get("kind") or "") for item in findings}),
        "exit": completed.returncode,
        "stderr": completed.stderr[-1200:] if not ok else "",
    }
    shutil.rmtree(report_dir, ignore_errors=True)
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", help="use an already-running fixture instead of starting one")
    parser.add_argument("--browser", choices=("playwright", "none"), default="playwright")
    parser.add_argument("--quick", action="store_true", help="run only HTTP-level cases")
    parser.add_argument("--only", action="append", default=[], help="run specific case id(s)")
    parser.add_argument("--timeout", type=int, default=180, help="per-case timeout in seconds")
    parser.add_argument("--json-out", help="write machine-readable results to this path")
    args = parser.parse_args(argv)

    corpus = load_cases()
    cases: List[Dict[str, Any]] = list(corpus.get("cases") or [])
    if args.quick:
        cases = [case for case in cases if not case.get("browser")]
    if args.only:
        wanted = set(args.only)
        cases = [case for case in cases if case["id"] in wanted]
    if not cases:
        print("No benchmark cases selected.", file=sys.stderr)
        return 2

    process: Optional[subprocess.Popen[str]] = None
    base_url = args.base_url or str(corpus.get("base_url") or "http://127.0.0.1:8765")
    if not args.base_url:
        port = free_port()
        base_url = f"http://127.0.0.1:{port}"
        # The fixture binds 8765; a disposable copy keeps the runner from
        # fighting an operator's existing instance.
        env = dict(os.environ)
        env["XOXSS_BENCH_PORT"] = str(port)
        process = subprocess.Popen(
            [sys.executable, str(FIXTURE)],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    try:
        wait_for_server(base_url)
        results = [
            run_case(case, base_url, browser=args.browser, timeout=args.timeout)
            for case in cases
        ]
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    failed = [result for result in results if result["status"] != "pass"]
    for result in results:
        marker = "PASS" if result["status"] == "pass" else "FAIL"
        print(
            f"[{marker}] {result['case']:<28} expected={result['expected']:<7} "
            f"confidence={result.get('confidence', 'n/a'):<9} "
            f"findings={result.get('findings', 0)}"
        )
    print(f"\n{len(results) - len(failed)}/{len(results)} case(s) passed")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
