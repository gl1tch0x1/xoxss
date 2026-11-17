"""401/403 bypass planning and verification.

The engine must find a genuine bypass, but it is equally important that CDN
block pages, the same login screen and soft-200 error pages are rejected.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Tuple

import pytest

from xoxss.recon.access import (
    AccessBypassEngine,
    BypassResult,
    mutate_path,
    path_variants,
    plan_attempts,
)


class FakeResponse:
    def __init__(
        self,
        status: int = 200,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
        url: str = "https://target.test/forbidden",
        error: Optional[str] = None,
    ) -> None:
        self.status = status
        self.text = text
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}
        self.url = url
        self.error = error

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class FakeHttp:
    """Minimal HttpEngine double that records every outgoing request."""

    def __init__(self, handler: Any) -> None:
        self.handler = handler
        self.calls: List[Tuple[str, str, Dict[str, str]]] = []

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        cache: bool = False,
        data: Any = None,
        json_body: Any = None,
    ) -> FakeResponse:
        self.calls.append((method, url, dict(headers or {})))
        return self.handler(method, url, dict(headers or {}))

    async def get(self, url: str, **kwargs: Any) -> FakeResponse:
        return await self.request("GET", url, **kwargs)


BLOCKED = FakeResponse(
    status=403,
    text="<h1>Access denied</h1><p>Administrators only.</p>",
    headers={"content-type": "text/html"},
)
ADMIN = FakeResponse(
    status=200,
    text=(
        "<h1>Administrative console</h1>"
        "<form method='get' action='/search'><input name='q'></form>"
        "<table><tr><td>user</td></tr></table>"
        "<script>var dashboard = true;</script>"
    ),
    headers={"content-type": "text/html"},
    url="https://target.test/forbidden",
)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# -- planning -------------------------------------------------------------------


def test_plan_puts_forwarded_for_first() -> None:
    plan = plan_attempts("https://target.test/admin")
    assert plan
    assert plan[0].name == "header:X-Forwarded-For"
    assert plan[0].category == "header"


def test_plan_is_deterministic_and_deduplicated() -> None:
    first = plan_attempts("https://target.test/admin?q=1", limit=64)
    second = plan_attempts("https://target.test/admin?q=1", limit=64)
    keys = [(item.name, item.url, item.headers) for item in first]
    assert keys == [(item.name, item.url, item.headers) for item in second]
    assert len(keys) == len(set(keys))


def test_plan_respects_category_filter() -> None:
    plan = plan_attempts("https://target.test/admin", techniques=["path"])
    assert plan
    assert all(item.category == "path" for item in plan)


def test_plan_respects_named_technique_filter() -> None:
    plan = plan_attempts("https://target.test/admin", techniques=["trailing-slash"])
    assert len(plan) == 1
    assert plan[0].variant == "trailing-slash"


def test_plan_limit_is_honoured() -> None:
    assert len(plan_attempts("https://target.test/admin", limit=3)) == 3
    assert plan_attempts("https://target.test/admin", limit=0) == []


def test_plan_aggressive_adds_method_probes() -> None:
    safe = plan_attempts("https://target.test/admin", techniques=["method"], limit=64)
    aggressive = plan_attempts(
        "https://target.test/admin", techniques=["method"], aggressive=True, limit=64
    )
    assert {item.method for item in safe} == {"HEAD", "OPTIONS", "TRACE"}
    assert {"POST", "PUT", "PATCH"} <= {item.method for item in aggressive}


def test_path_variants_are_unique_and_keep_the_query() -> None:
    url = "https://target.test/a/b?x=1"
    plan = plan_attempts(url, techniques=["path"], limit=64)
    urls = [item.url for item in plan]
    assert len(urls) == len(set(urls))
    assert all("x=1" in item for item in urls)


def test_mutate_path_shapes() -> None:
    assert mutate_path("/admin", "trailing-slash") == "/admin/"
    assert mutate_path("/admin", "double-slash") == "//admin"
    assert mutate_path("/admin", "dot-slash") == "/./admin"
    assert mutate_path("/admin", "encoded-dot") == "/%2e/admin"
    assert mutate_path("/admin", "semicolon-slash") == "/admin/..;/"
    assert mutate_path("/admin", "slash-encoded") == "%2fadmin"
    assert mutate_path("/Admin", "case-toggle") == "/aDMIN"
    assert mutate_path("/admin", "unknown-variant") == "/admin"


def test_path_variants_do_not_escape_the_origin() -> None:
    for _variant, mutated in path_variants("/a/b"):
        assert mutated.startswith(("/", "%2f", "%252f", "\\", "//"))


# -- verification ---------------------------------------------------------------


def test_classify_accepts_a_real_content_page() -> None:
    engine = AccessBypassEngine(FakeHttp(lambda *_: ADMIN), None)
    accepted, reason, confidence = engine._classify(BLOCKED, ADMIN)
    assert accepted
    assert "403->200" in reason
    assert confidence in ("medium", "high")


def test_classify_accepts_a_compact_fragment_page() -> None:
    compact = FakeResponse(
        status=200,
        text="<main>Search result: hello</main>",
        headers={"content-type": "text/html"},
    )
    engine = AccessBypassEngine(FakeHttp(lambda *_: compact), None)
    accepted, _, _ = engine._classify(BLOCKED, compact)
    assert accepted


def test_classify_rejects_an_empty_or_tiny_body() -> None:
    engine = AccessBypassEngine(FakeHttp(lambda *_: ADMIN), None)
    tiny = FakeResponse(status=200, text="", headers={"content-type": "text/html"})
    assert not engine._classify(BLOCKED, tiny)[0]


def test_classify_rejects_the_same_body_with_a_new_status() -> None:
    engine = AccessBypassEngine(FakeHttp(lambda *_: ADMIN), None)
    soft_200 = FakeResponse(
        status=200,
        text=BLOCKED.text,
        headers={"content-type": "text/html"},
    )
    accepted, _, _ = engine._classify(BLOCKED, soft_200)
    assert not accepted


def test_classify_rejects_cloudflare_challenge() -> None:
    challenge = FakeResponse(
        status=200,
        text=(
            "<html><title>Attention Required! | Cloudflare</title>"
            "<a href='/cdn-cgi/l/email-protection'>support</a></html>"
        ),
        headers={"content-type": "text/html"},
    )
    engine = AccessBypassEngine(FakeHttp(lambda *_: ADMIN), None)
    assert not engine._classify(BLOCKED, challenge)[0]


def test_classify_rejects_a_soft_200_block_page() -> None:
    blocked_200 = FakeResponse(
        status=200,
        text=(
            "<html><title>Access denied</title><h1>Forbidden</h1>"
            "<a href='https://support.example'>contact support</a></html>"
        ),
        headers={"content-type": "text/html"},
    )
    engine = AccessBypassEngine(FakeHttp(lambda *_: ADMIN), None)
    assert not engine._classify(BLOCKED, blocked_200)[0]


def test_classify_rejects_a_login_page() -> None:
    login = FakeResponse(
        status=200,
        text=(
            "<html><title>Sign in</title><form method='post'>"
            "<input name='user'><input type='password' name='pass'></form></html>"
        ),
        headers={"content-type": "text/html"},
        url="https://target.test/login",
    )
    engine = AccessBypassEngine(FakeHttp(lambda *_: ADMIN), None)
    assert not engine._classify(BLOCKED, login)[0]


def test_classify_rejects_binary_and_error_responses() -> None:
    engine = AccessBypassEngine(FakeHttp(lambda *_: ADMIN), None)
    binary = FakeResponse(
        status=200,
        text="\x00\x01\x02" * 64,
        headers={"content-type": "application/octet-stream"},
    )
    assert not engine._classify(BLOCKED, binary)[0]
    error = FakeResponse(status=200, text="", error="timeout")
    assert not engine._classify(BLOCKED, error)[0]


def test_classify_rejects_unchanged_forbidden_status() -> None:
    engine = AccessBypassEngine(FakeHttp(lambda *_: ADMIN), None)
    assert not engine._classify(BLOCKED, BLOCKED)[0]


# -- engine ---------------------------------------------------------------------


def test_engine_probe_returns_the_working_technique() -> None:
    def handler(method: str, url: str, headers: Dict[str, str]) -> FakeResponse:
        if headers.get("X-Forwarded-For"):
            return ADMIN
        return BLOCKED

    http = FakeHttp(handler)
    engine = AccessBypassEngine(http, None)
    result = run(engine.probe("https://target.test/forbidden", BLOCKED))
    assert isinstance(result, BypassResult)
    assert result.technique == "header:X-Forwarded-For"
    assert result.status == 200
    assert result.baseline_status == 403
    assert result.category == "header"
    assert http.calls[0][2].get("X-Forwarded-For") == "127.0.0.1"


def test_engine_probe_is_cached() -> None:
    calls: List[str] = []

    def handler(method: str, url: str, headers: Dict[str, str]) -> FakeResponse:
        calls.append(url)
        return ADMIN if headers.get("X-Forwarded-For") else BLOCKED

    engine = AccessBypassEngine(FakeHttp(handler), None)
    first = run(engine.probe("https://target.test/forbidden", BLOCKED))
    sent = len(calls)
    second = run(engine.probe("https://target.test/forbidden", BLOCKED))
    assert first is second
    assert len(calls) == sent


def test_host_winner_is_tried_first_on_a_sibling_route() -> None:
    def handler(method: str, url: str, headers: Dict[str, str]) -> FakeResponse:
        return ADMIN if headers.get("X-Forwarded-For") else BLOCKED

    http = FakeHttp(handler)
    engine = AccessBypassEngine(http, None)
    run(engine.probe("https://target.test/forbidden", BLOCKED))
    sent = len(http.calls)
    result = run(engine.probe("https://target.test/admin", BLOCKED))
    assert result is not None
    first = http.calls[sent]
    assert first[1] == "https://target.test/admin"
    assert first[2].get("X-Forwarded-For") == "127.0.0.1"


def test_engine_probe_skips_non_forbidden_baselines() -> None:
    http = FakeHttp(lambda *_: ADMIN)
    engine = AccessBypassEngine(http, None)
    ok_page = FakeResponse(status=200, text="<main>public</main>")
    assert run(engine.probe("https://target.test/public", ok_page)) is None
    assert http.calls == []


def test_engine_path_only_bypass() -> None:
    def handler(method: str, url: str, headers: Dict[str, str]) -> FakeResponse:
        return ADMIN if url.rstrip("/") != "https://target.test/forbidden" else BLOCKED

    engine = AccessBypassEngine(FakeHttp(handler), None, techniques=["path"])
    result = run(engine.probe("https://target.test/forbidden", BLOCKED))
    assert result is not None
    assert result.category == "path"
    assert result.variant
    assert result.applied_url("https://target.test/forbidden?q=1").endswith("?q=1")


def test_engine_reports_no_bypass_when_everything_stays_blocked() -> None:
    http = FakeHttp(lambda *_: BLOCKED)
    engine = AccessBypassEngine(http, None, max_attempts=8)
    assert run(engine.probe("https://target.test/forbidden", BLOCKED)) is None
    assert len(http.calls) == 8


def test_engine_loads_and_exports_results() -> None:
    result = BypassResult(
        url="https://target.test/forbidden",
        technique="header:X-Forwarded-For",
        category="header",
        status=200,
        baseline_status=403,
        headers={"X-Forwarded-For": "127.0.0.1"},
        reason="status 403->200",
    )
    engine = AccessBypassEngine(FakeHttp(lambda *_: ADMIN), None)
    assert engine.load_results([result.to_dict()]) == 1
    assert engine.cached("https://target.test/forbidden") is not None
    exported = engine.export_results()
    assert exported[0]["technique"] == "header:X-Forwarded-For"


def test_engine_method_override_header_is_replayable() -> None:
    def handler(method: str, url: str, headers: Dict[str, str]) -> FakeResponse:
        return ADMIN if headers.get("X-HTTP-Method-Override") == "GET" else BLOCKED

    http = FakeHttp(handler)
    engine = AccessBypassEngine(http, None, techniques=["X-HTTP-Method-Override"])
    result = run(engine.probe("https://target.test/forbidden", BLOCKED))
    assert result is not None
    assert result.replay_headers() == {"X-HTTP-Method-Override": "GET"}


def test_engine_rejects_login_and_keeps_probing() -> None:
    login = FakeResponse(
        status=200,
        text="<title>Sign in</title><input type='password'>",
        headers={"content-type": "text/html"},
        url="https://target.test/login",
    )

    def handler(method: str, url: str, headers: Dict[str, str]) -> FakeResponse:
        if headers.get("X-Forwarded-For"):
            return login
        if headers.get("X-Real-IP"):
            return ADMIN
        return BLOCKED

    engine = AccessBypassEngine(FakeHttp(handler), None, max_attempts=4)
    result = run(engine.probe("https://target.test/forbidden", BLOCKED))
    assert result is not None
    assert result.technique == "header:X-Real-IP"


@pytest.mark.parametrize("variant", ["trailing-slash", "double-slash", "null-suffix"])
def test_result_applies_mutation_to_query_urls(variant: str) -> None:
    result = BypassResult(
        url="https://target.test/forbidden",
        technique=f"path:{variant}",
        category="path",
        status=200,
        baseline_status=403,
        variant=variant,
    )
    applied = result.applied_url("https://target.test/forbidden/search?q=1")
    assert "q=1" in applied
    assert applied != "https://target.test/forbidden/search?q=1"
