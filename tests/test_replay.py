"""Replay helpers: report selection, finding matching and token extraction."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from xoxss.replay import (
    _replay_report_path,
    _replay_request_args,
    _replay_token,
    load_replay_finding,
)


def _args(**values: Any) -> argparse.Namespace:
    base = {
        "replay": "",
        "replay_report": None,
        "report_dir": None,
    }
    base.update(values)
    return argparse.Namespace(**base)


def _write_report(path: Path, findings: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"findings": findings}), encoding="utf-8")


def test_replay_token_prefers_js_marker_charcode() -> None:
    # "marker12" as String.fromCharCode(109,97,114,107,101,114,49,50)
    payload = "<script>/*marker12*/String.fromCharCode(109,97,114,107,101,114,49,50)</script>"
    assert _replay_token(payload) == "marker12"


def test_replay_token_prefers_comment_then_longest_candidate() -> None:
    assert _replay_token("<svg onload=/*abcdefgh*/>") == "abcdefgh"
    assert _replay_token("alert('javascript'); payloadtoken99") == "payloadtoken99"


def test_replay_token_falls_back_to_the_payload() -> None:
    assert _replay_token("<b>x</b>") == "<b>x</b>"
    assert _replay_token("") == ""


def test_replay_token_ignores_short_charcode_gadgets() -> None:
    # "alert" is a payload gadget, not the run marker.
    assert _replay_token("String.fromCharCode(97,108,101,114,116)") != "alert"


def test_replay_request_args_prefers_structured_request() -> None:
    item = {
        "method": "POST",
        "url": "https://target.test/fallback",
        "request": {
            "method": "post",
            "url": "https://target.test/search",
            "headers": {"Content-Type": "application/json", "X-Test": "[REDACTED]"},
            "body": '{"q":"1"}',
        },
    }
    method, url, headers, body = _replay_request_args(item)
    assert (method, url, body) == ("POST", "https://target.test/search", '{"q":"1"}')
    assert headers == {"Content-Type": "application/json"}


def test_replay_request_args_parses_curl_when_request_missing() -> None:
    item = {
        "poc_curl": (
            "curl 'https://target.test/find?q=1' -H 'Cookie: sid=1' "
            "-X POST --data 'q=2'"
        )
    }
    method, url, headers, body = _replay_request_args(item)
    assert method == "POST"
    assert url == "https://target.test/find?q=1"
    assert headers.get("Cookie") == "sid=1"
    assert body == "q=2"


def test_replay_request_args_falls_back_to_poc_url() -> None:
    method, url, headers, body = _replay_request_args(
        {"poc_url": "https://target.test/x?q=payload"}
    )
    assert (method, url, headers, body) == (
        "GET",
        "https://target.test/x?q=payload",
        {},
        "",
    )


def test_replay_report_path_prefers_explicit_then_newest(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit.json"
    assert _replay_report_path(_args(replay_report=str(explicit))) == explicit

    report_dir = tmp_path / "reports"
    older = report_dir / "older.json"
    newer = report_dir / "newer.json"
    _write_report(older, [])
    _write_report(newer, [])
    now = time.time()
    older.touch()
    newer.touch()
    import os

    os.utime(older, (now - 100, now - 100))
    os.utime(newer, (now, now))

    assert _replay_report_path(_args(report_dir=str(report_dir))) == newer
    assert _replay_report_path(_args(report_dir=str(tmp_path / "missing"))) is None


def test_load_replay_finding_matches_by_prefix(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    _write_report(report, [{"finding_id": "abcdef123456", "kind": "reflected"}])

    item, path, error = load_replay_finding(
        _args(replay="abcdef", replay_report=str(report))
    )
    assert error == ""
    assert path == report
    assert item is not None and item["kind"] == "reflected"


def test_load_replay_finding_derives_identity_for_legacy_reports(
    tmp_path: Path,
) -> None:
    report = tmp_path / "legacy.json"
    _write_report(
        report,
        [
            {
                "kind": "reflected XSS",
                "url": "https://target.test/?q=1",
                "method": "GET",
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
                "confidence": "high",
            }
        ],
    )

    from xoxss.core.finding import Finding

    derived = Finding(
        kind="reflected XSS",
        url="https://target.test/?q=1",
        method="GET",
        parameter="q",
        payload="<script>alert(1)</script>",
        confidence="high",
    )
    item, _path, error = load_replay_finding(
        _args(replay=derived.finding_id[:8], replay_report=str(report))
    )
    assert error == ""
    assert item is not None


def test_load_replay_finding_reports_actionable_errors(tmp_path: Path) -> None:
    _item, _path, missing = load_replay_finding(
        _args(replay="x", report_dir=str(tmp_path / "no-reports"))
    )
    assert "no JSON report found" in missing

    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    _item, _path, invalid = load_replay_finding(
        _args(replay="x", replay_report=str(broken))
    )
    assert "not valid JSON" in invalid

    empty = tmp_path / "empty.json"
    _write_report(empty, [])
    _item, _path, no_findings = load_replay_finding(
        _args(replay="x", replay_report=str(empty))
    )
    assert "contains no findings" in no_findings

    populated = tmp_path / "populated.json"
    _write_report(populated, [{"finding_id": "abc123"}])
    _item, _path, no_match = load_replay_finding(
        _args(replay="nope", replay_report=str(populated))
    )
    assert "no finding matches" in no_match
