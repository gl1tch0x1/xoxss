"""Surface inventory harvesting for the autonomous engine."""

from __future__ import annotations

from types import SimpleNamespace

from xoxss.auto.surface import COMMON_PARAMS, SurfaceInventory, query_params


class _Point:
    def __init__(self, param: str, method: str = "GET") -> None:
        self.param = param
        self.method = method
        self.form_index = 0
        self.source = "browser"


def _scanner() -> SimpleNamespace:
    return SimpleNamespace(
        target="https://t.test/",
        endpoints={
            "https://t.test/",
            "https://t.test/search?q=1",
            "https://t.test/app.js",
        },
        state=SimpleNamespace(scanned=["https://t.test/about"]),
        _browser_points={
            "https://t.test/login": [_Point("username", "POST"), _Point("password", "POST")]
        },
        _mined_params={"https://t.test/api": ["id", "name"]},
        _js_seen={"https://t.test/app.js"},
        args=SimpleNamespace(header_list=["X-Test: 1"], cookies="sid=abc; theme=dark"),
        waf=SimpleNamespace(names=["cloudflare"]),
        endpoint_sources={"https://t.test/api": {"js", "crawl"}},
    )


def test_query_params_preserves_order() -> None:
    assert query_params("https://t.test/?b=2&a=1") == ["b", "a"]


def test_inventory_harvests_every_source() -> None:
    inventory = SurfaceInventory.from_scanner(_scanner())
    assert "https://t.test/search?q=1" in inventory.urls
    assert "https://t.test/about" in inventory.urls
    assert "https://t.test/login" in inventory.urls
    assert inventory.parameters["https://t.test/search?q=1"] == ["q"]
    assert inventory.parameters["https://t.test/login"] == ["username", "password"]
    assert inventory.parameters["https://t.test/api"] == ["id", "name"]
    assert inventory.js_urls == ["https://t.test/app.js"]
    assert inventory.headers == ["X-Test"]
    assert inventory.cookies == ["sid", "theme"]
    assert inventory.waf == ["cloudflare"]
    assert inventory.endpoint_sources["https://t.test/api"] == ["crawl", "js"]


def test_ranked_urls_prioritises_parameters() -> None:
    inventory = SurfaceInventory.from_scanner(_scanner())
    ranked = inventory.ranked_urls(10)
    assert ranked[0] in {
        "https://t.test/search?q=1",
        "https://t.test/api",
        "https://t.test/login",
    }
    assert ranked[-1] == "https://t.test/app.js"


def test_params_for_adds_common_names() -> None:
    inventory = SurfaceInventory.from_scanner(_scanner())
    params = inventory.params_for("https://t.test/")
    assert "q" in params
    assert all(name in params for name in COMMON_PARAMS)


def test_params_for_can_skip_common_names() -> None:
    inventory = SurfaceInventory.from_scanner(_scanner())
    assert inventory.params_for("https://t.test/", include_common=False) == []


def test_summary_counts() -> None:
    inventory = SurfaceInventory.from_scanner(_scanner())
    summary = inventory.summary()
    assert summary["urls"] >= 4
    assert summary["forms"] == 2
    assert summary["js_urls"] == 1
