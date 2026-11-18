"""Replay of a single reported finding.

``xoxss --replay <finding-id>`` re-issues exactly one request from a previous
JSON report and, unless browser verification is disabled, opens the PoC in a
real browser to confirm execution.  This module owns that workflow; the scanner
re-exports :func:`run_replay` for the CLI entry point.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from xoxss.core.browser import BrowserEngine, PlaywrightEngine
from xoxss.core.evidence import parse_curl_request
from xoxss.core.finding import Finding, ScanStats
from xoxss.core.http import HttpEngine, HttpResponse
from xoxss.scan.reflection import analyze_reflection
from xoxss.utils.console import Console
from xoxss.utils.helpers import truncate

DEFAULT_STATE_DIR = ".xoxss"

_REPLAY_TOKEN_RE = re.compile(r"[a-z][a-z0-9]{8,}")
_REPLAY_COMMENT_TOKEN_RE = re.compile(r"/\*\s*([a-z][a-z0-9]{6,})\s*\*/")
_REPLAY_CHARCODE_RE = re.compile(r"String\.fromCharCode\(\s*([0-9][0-9,\s]*)\)")


def _replay_report_path(args: argparse.Namespace) -> Optional[Path]:
    explicit = getattr(args, "replay_report", None)
    if explicit:
        return Path(explicit)
    report_dir = Path(
        getattr(args, "report_dir", None)
        or os.path.join(DEFAULT_STATE_DIR, "reports")
    )
    if not report_dir.is_dir():
        return None

    def _mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    candidates = sorted(report_dir.glob("*.json"), key=_mtime, reverse=True)
    return candidates[0] if candidates else None


def load_replay_finding(
    args: argparse.Namespace,
) -> Tuple[Optional[Dict[str, Any]], Optional[Path], str]:
    """Return ``(finding, report_path, error)`` for ``--replay``."""
    path = _replay_report_path(args)
    if path is None:
        return None, None, (
            "no JSON report found; pass --replay-report PATH or write a report with --report json"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return None, path, f"cannot read {path}: {exc}"
    except json.JSONDecodeError as exc:
        return None, path, f"{path} is not valid JSON: {exc}"
    findings = data.get("findings")
    if not isinstance(findings, list) or not findings:
        return None, path, f"{path} contains no findings"
    wanted = str(getattr(args, "replay", "") or "").strip().lower()
    if not wanted:
        return None, path, "--replay requires a finding id (see the report's finding_id column)"
    fields = set(Finding.__dataclass_fields__)
    for item in findings:
        if not isinstance(item, dict):
            continue
        identity = str(item.get("finding_id") or "").strip().lower()
        if not identity:
            # Reports written before finding IDs were introduced still carry
            # every field needed to derive the same stable identity.
            try:
                derived = Finding(
                    **{key: value for key, value in item.items() if key in fields}
                )
            except Exception:
                identity = ""
            else:
                identity = derived.finding_id.lower()
        if identity and (identity == wanted or identity.startswith(wanted)):
            return item, path, ""
    return None, path, f"no finding matches '{wanted}' in {path.name}"


def _replay_request_args(
    item: Dict[str, Any],
) -> Tuple[str, str, Dict[str, str], str]:
    """Recover ``(method, url, headers, body)`` from a report finding."""
    request_raw = item.get("request")
    request: Dict[str, Any] = request_raw if isinstance(request_raw, dict) else {}
    url = str(request.get("url") or "")
    method = str(request.get("method") or item.get("method") or "GET").upper()
    headers = {
        str(name): str(value)
        for name, value in (request.get("headers") or {}).items()
    }
    body = str(request.get("body") or "")
    if not url:
        parsed = parse_curl_request(
            str(item.get("poc_curl") or item.get("poc_command") or "")
        )
        if parsed:
            url = str(parsed.get("url") or "")
            method = str(parsed.get("method") or method).upper()
            headers = dict(parsed.get("headers") or {})
            body = str(parsed.get("body") or "")
    if not url:
        url = str(item.get("poc_url") or item.get("url") or "")
    # Redacted values are placeholders, not credentials: drop them so the
    # request is not replayed with the literal string "[REDACTED]".
    headers = {
        name: value
        for name, value in headers.items()
        if value and value != "[REDACTED]"
    }
    return method, url, headers, body


def _replay_token(payload: str) -> str:
    """Pick the strongest marker embedded in a payload for browser matching.

    ``js_marker`` writes the marker both as a ``/*token*/`` comment and as a
    ``String.fromCharCode`` call.  Preferring those forms avoids mistaking an
    ordinary long word (``javascript``) for the run's unique marker.
    """
    text = payload or ""
    charcode = _REPLAY_CHARCODE_RE.search(text)
    if charcode:
        try:
            decoded = "".join(
                chr(int(part))
                for part in charcode.group(1).replace(" ", "").split(",")
                if part
            )
        except (TypeError, ValueError):
            decoded = ""
        # ``js_marker`` pushes a unique token; requiring a digit and some
        # length avoids mistaking a payload gadget (``String.fromCharCode``
        # for "alert") for the marker.
        if (
            len(decoded) >= 8
            and re.fullmatch(r"[a-z][a-z0-9]+", decoded)
            and any(char.isdigit() for char in decoded)
        ):
            return decoded
    comment = _REPLAY_COMMENT_TOKEN_RE.search(text)
    if comment:
        return comment.group(1)
    candidates = _REPLAY_TOKEN_RE.findall(text)
    if candidates:
        return max(candidates, key=len)
    return text


def _make_replay_browser(args: argparse.Namespace, console: Console) -> Any:
    use_playwright = (getattr(args, "browser", "") or "").lower() == "playwright" or bool(
        getattr(args, "auth_state", None)
    )
    engine_class = PlaywrightEngine if use_playwright else BrowserEngine
    return engine_class(
        console,
        kind="playwright" if use_playwright else getattr(args, "browser", "firefox"),
        headless=getattr(args, "headless", True),
        page_timeout=max(10.0, getattr(args, "timeout", 20.0)),
        user_agent=getattr(args, "user_agent", None),
        proxy=getattr(args, "proxy", None),
        binary=getattr(args, "binary", None),
        insecure=getattr(args, "insecure", False),
        auth_state=getattr(args, "auth_state", None),
    )


async def run_replay(args: argparse.Namespace, console: Console) -> int:
    """Re-run exactly one reported finding: one request + one browser check."""
    # Imported lazily: ``xoxss.scanner`` imports this module to re-export
    # ``run_replay``, so a module-level import would be circular.
    from xoxss.scanner import XSSScanner

    item, report_path, error = load_replay_finding(args)
    if item is None:
        console.error(error)
        return 1
    method, url, headers, body = _replay_request_args(item)
    if not url:
        console.error("The selected finding has no reproducible URL or curl PoC")
        return 1

    payload = str(item.get("payload") or "")
    token = _replay_token(payload)
    user_headers = XSSScanner._parse_headers(getattr(args, "headers", None))
    user_cookies = XSSScanner._parse_cookies(
        getattr(args, "cookies", None),
        getattr(args, "cookie_file", None),
    )
    headers.update(user_headers)

    console.rule("replay")
    console.info(f"Report: {report_path}")
    console.info(f"Finding: {item.get('finding_id', '?')}  {item.get('kind', '')}")
    console.info(f"Request: {method} {truncate(url, 160)}")
    if body:
        console.info(f"Body: {truncate(body, 200)}", important=False)

    stats = ScanStats(urls_total=1)
    http = HttpEngine(
        console,
        stats,
        headers=user_headers,
        cookies=user_cookies,
        timeout=getattr(args, "timeout", 20.0),
        retries=0,
        rate=0.0,
        concurrency=1,
        proxy=getattr(args, "proxy", None),
        insecure=getattr(args, "insecure", False),
        max_response_bytes=getattr(args, "max_response_bytes", 5 * 1024 * 1024),
        http2=getattr(args, "http2", False),
        impersonate=getattr(args, "impersonate", None),
    )

    response: Optional[HttpResponse] = None
    try:
        await http.start()
        data: Any = None
        json_body: Optional[Dict[str, Any]] = None
        if method not in ("GET", "HEAD") and body:
            stripped = body.lstrip()
            if stripped[:1] in ("{", "["):
                try:
                    json_body = json.loads(body)
                except json.JSONDecodeError:
                    data = body
            elif "=" in stripped:
                data = body
            else:
                data = body
        response = await http.request(
            method,
            url,
            headers=headers or None,
            data=data,
            json_body=json_body,
            allow_redirects=True,
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        console.error(f"Replay request failed: {exc}")
        return 1
    finally:
        await http.close()

    if response is None:
        console.error("Replay produced no response")
        return 1
    if response.error:
        console.error(f"Replay request error: {response.error}")
        return 1

    reflected = bool(payload) and payload in (response.text or "")
    info = None
    if reflected:
        info = analyze_reflection(
            response.text, payload, payload, response.header("content-type", "")
        )
    executable = bool(info and info.executable)

    browser_executed = False
    browser_evidence = ""
    browser_attempted = False
    if not getattr(args, "no_browser", False) and getattr(args, "confirm", "auto") != "http":
        browser_attempted = True
        engine = _make_replay_browser(args, console)
        try:
            if await engine.start():
                try:
                    if method in ("GET", "HEAD"):
                        await engine.navigate(url)
                    else:
                        await engine.navigate(str(item.get("url") or url))
                        await engine.submit_form(
                            0, str(item.get("parameter") or ""), payload
                        )
                    hit = await engine.check_token(token, timeout=3.0)
                    if hit:
                        browser_executed = hit.get("executed") == "yes"
                        browser_evidence = str(hit.get("evidence") or "")
                        if hit.get("sink"):
                            browser_evidence = (
                                f"sink={hit.get('sink')}"
                                + (
                                    f" at {hit.get('dom_path')}"
                                    if hit.get("dom_path")
                                    else ""
                                )
                                + (f"; {browser_evidence}" if browser_evidence else "")
                            )
                finally:
                    await engine.stop()
        except Exception as exc:
            console.debug(f"Replay browser check failed: {exc}")
    else:
        console.warn(
            "Browser check skipped (--no-browser/--confirm http); HTTP evidence only"
        )

    confirmed = browser_executed or executable
    status = {
        "finding_id": item.get("finding_id", ""),
        "kind": item.get("kind", ""),
        "report": str(report_path),
        "request": {"method": method, "url": url},
        "response_status": response.status or 0,
        "reflected": reflected,
        "executable": executable,
        "browser_attempted": browser_attempted,
        "browser_executed": browser_executed,
        "browser_evidence": browser_evidence,
        "context": info.context if info else "",
        "reproduced": confirmed,
        "confidence": "confirmed" if browser_executed else ("high" if executable else "low"),
    }
    console.event("replay_result", **status)
    console.raw("")
    console.raw(json.dumps(status, indent=2, ensure_ascii=False))
    console.raw("")
    if browser_executed:
        console.ok("Replay confirmed: the payload executed in the browser")
        return 0
    if executable:
        console.ok("Replay reproduced HTTP-level execution evidence (browser not confirmed)")
        return 0
    if reflected:
        console.warn("Replay reflected the payload, but it is not executable in this context")
        return 1
    console.error("Replay did not reproduce the finding")
    return 1


__all__ = ["load_replay_finding", "run_replay"]
