"""Surface inventory for the autonomous engine.

The scanner already discovers URLs, parameters, forms and JavaScript files.
This module turns that internal state into a stable, read-only inventory that
the post-scan probes and chain engine can consume without reaching into
private scanner fields from every call site.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlsplit

#: Parameters worth probing even when a page has no query string.
COMMON_PARAMS: tuple[str, ...] = (
    "q",
    "s",
    "search",
    "query",
    "id",
    "page",
    "url",
    "next",
    "redirect",
    "return",
    "continue",
    "dest",
    "target",
    "callback",
    "jsonp",
    "lang",
    "view",
    "name",
    "title",
    "message",
    "comment",
    "ref",
    "from",
    "to",
    "file",
    "path",
    "template",
    "theme",
)


def query_params(url: str) -> List[str]:
    """Return query parameter names from ``url`` (order preserved)."""
    try:
        return [name for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    except ValueError:
        return []


@dataclass
class SurfaceInventory:
    """Everything the scanner learned about the target's attack surface."""

    target: str
    urls: List[str] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    js_urls: List[str] = field(default_factory=list)
    headers: List[str] = field(default_factory=list)
    cookies: List[str] = field(default_factory=list)
    waf: List[str] = field(default_factory=list)
    endpoint_sources: Dict[str, List[str]] = field(default_factory=dict)

    @classmethod
    def from_scanner(cls, scanner: Any) -> "SurfaceInventory":
        urls: List[str] = []
        parameters: Dict[str, List[str]] = {}

        def add_url(url: Any) -> None:
            value = str(url or "").strip()
            if not value.startswith(("http://", "https://")):
                return
            if value not in urls:
                urls.append(value)
            params = query_params(value)
            if params:
                parameters[value] = list(dict.fromkeys(params))

        for url in getattr(scanner, "endpoints", set()) or ():
            add_url(url)
        for url in getattr(scanner, "state", None).scanned if getattr(scanner, "state", None) else ():
            add_url(url)
        extra = getattr(getattr(scanner, "state", None), "extra", {}) or {}
        for url in extra.get("discovered", []) or ():
            add_url(url)

        forms: List[Dict[str, Any]] = []
        browser_points = getattr(scanner, "_browser_points", {}) or {}
        for page_url, points in browser_points.items():
            add_url(page_url)
            for point in points or ():
                param = str(getattr(point, "param", "") or "")
                if not param:
                    continue
                parameters.setdefault(str(page_url), [])
                if param not in parameters[str(page_url)]:
                    parameters[str(page_url)].append(param)
                forms.append(
                    {
                        "page_url": str(page_url),
                        "param": param,
                        "method": str(getattr(point, "method", "GET") or "GET"),
                        "form_index": getattr(point, "form_index", None),
                        "source": str(getattr(point, "source", "browser") or "browser"),
                    }
                )

        mined = getattr(scanner, "_mined_params", {}) or {}
        for page_url, names in mined.items():
            add_url(page_url)
            parameters.setdefault(str(page_url), [])
            for name in names or ():
                if name and name not in parameters[str(page_url)]:
                    parameters[str(page_url)].append(str(name))

        js_urls = sorted(
            str(url)
            for url in (getattr(scanner, "_js_seen", set()) or set())
            if str(url).startswith(("http://", "https://"))
        )

        headers = []
        for raw in getattr(getattr(scanner, "args", None), "header_list", None) or ():
            name = str(raw).split(":", 1)[0].strip()
            if name:
                headers.append(name)
        if not headers:
            headers = [
                "Referer",
                "User-Agent",
                "X-Forwarded-Host",
                "X-Forwarded-For",
                "X-Original-URL",
                "X-Rewrite-URL",
            ]

        cookies = []
        cookie_arg = getattr(getattr(scanner, "args", None), "cookies", None)
        if cookie_arg:
            for part in str(cookie_arg).split(";"):
                name = part.split("=", 1)[0].strip()
                if name:
                    cookies.append(name)

        waf_report = getattr(scanner, "waf", None)
        waf_names = list(getattr(waf_report, "names", []) or [])

        sources: Dict[str, List[str]] = {}
        for endpoint, source_set in (getattr(scanner, "endpoint_sources", {}) or {}).items():
            sources[str(endpoint)] = sorted(str(item) for item in source_set or ())

        return cls(
            target=str(getattr(scanner, "target", "") or ""),
            urls=urls,
            parameters=parameters,
            forms=forms,
            js_urls=js_urls,
            headers=list(dict.fromkeys(headers)),
            cookies=list(dict.fromkeys(cookies)),
            waf=waf_names,
            endpoint_sources=sources,
        )

    def ranked_urls(self, limit: int = 200) -> List[str]:
        """Return the most interesting URLs first.

        Pages with parameters, forms, API-looking paths and JavaScript are
        prioritised; static assets are pushed to the back.
        """
        def score(url: str) -> tuple:
            lower = url.lower()
            value = 0
            if self.parameters.get(url):
                value += 40
            if any(form["page_url"] == url for form in self.forms):
                value += 30
            if any(token in lower for token in ("/api", "/graphql", "/search", "/login", "/admin", "/upload")):
                value += 20
            if lower.endswith((".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ico")):
                value -= 30
            if "?" in url:
                value += 10
            return (-value, len(url), url)

        return sorted(self.urls, key=score)[: max(1, limit)]

    def params_for(self, url: str, *, include_common: bool = True) -> List[str]:
        params = list(self.parameters.get(url, []))
        if include_common:
            params.extend(name for name in COMMON_PARAMS if name not in params)
        return list(dict.fromkeys(params))

    def summary(self) -> Dict[str, int]:
        return {
            "urls": len(self.urls),
            "parameters": sum(len(value) for value in self.parameters.values()),
            "forms": len(self.forms),
            "js_urls": len(self.js_urls),
            "headers": len(self.headers),
            "cookies": len(self.cookies),
        }


__all__ = ["COMMON_PARAMS", "SurfaceInventory", "query_params"]
