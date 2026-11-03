"""
Application fuzzing: content discovery and parameter mining.

This is an internal, dependency-free complement to the optional external tools
(ffuf/feroxbuster are used when installed).  It is conservative by default:
a baseline request fingerprints the soft-404 response so endless catch-all
pages do not explode the crawl queue.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import re
import string
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

try:  # pragma: no cover
    from typing import Protocol
except Exception:  # pragma: no cover
    Protocol = object  # type: ignore


class HttpLike(Protocol):  # pragma: no cover
    async def get(self, url: str, **kwargs: Any) -> Any: ...


class ConsoleLike(Protocol):  # pragma: no cover
    def info(self, message: str, important: bool = True) -> None: ...
    def debug(self, message: str) -> None: ...
    def warn(self, message: str, important: bool = True) -> None: ...


DIR_WORDS: Tuple[str, ...] = (
    "admin", "administrator", "adminpanel", "admin-console", "api", "api/v1",
    "api/v2", "api/v3", "apis", "app", "apps", "assets", "auth", "authorize",
    "backend", "backup", "backups", "beta", "bin", "build", "cache", "cgi-bin",
    "cgi", "config", "configs", "console", "content", "cpanel", "crm", "css",
    "dashboard", "data", "database", "db", "debug", "dev", "developer", "docs",
    "download", "downloads", "dump", "email", "env", "files", "file", "fonts",
    "forms", "graphql", "health", "healthcheck", "help", "home", "html", "img",
    "images", "includes", "index", "internal", "js", "json", "lang", "log",
    "login", "logout", "logs", "mail", "manage", "management", "media", "metrics",
    "mobile", "monitor", "monitoring", "news", "oauth", "old", "panel", "pay",
    "payment", "payments", "portal", "private", "prod", "public", "register",
    "reset", "rest", "rpc", "scripts", "search", "secure", "server", "service",
    "services", "settings", "setup", "signin", "signup", "sitemap", "sql", "src",
    "staging", "static", "status", "storage", "support", "system", "temp",
    "test", "tests", "tmp", "token", "upload", "uploads", "user", "users",
    "v1", "v2", "v3", "vendor", "web", "webhook", "webhooks", "welcome", "ws",
    "xmlrpc", "actuator", "actuator/env", "actuator/health", "swagger",
    "swagger-ui", "swagger-ui.html", "openapi.json", "api-docs", "graphiql",
    "phpinfo.php", "info.php", "test.php", "shell.php", "admin.php", "login.php",
    "wp-admin", "wp-login.php", "wp-json", "wp-content", "server-status",
    "robots.txt", "sitemap.xml", "security.txt", ".well-known", ".git/config",
    ".env", ".ds_store", "README.md", "package.json", "composer.json",
)

FUZZ_EXTENSIONS: Tuple[str, ...] = (
    "", ".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action", ".json",
    ".xml", ".html", ".htm", ".txt", ".bak", ".old", ".zip", ".tar.gz", ".sql",
    ".log", ".js", ".map", ".yaml", ".yml",
)

PARAM_WORDS: Tuple[str, ...] = (
    "q", "query", "search", "keyword", "keywords", "s", "term", "text",
    "id", "ids", "uid", "user", "userid", "user_id", "account", "accountid",
    "email", "username", "name", "firstname", "lastname", "fullname", "title",
    "url", "uri", "link", "redirect", "redirect_uri", "return", "returnurl",
    "next", "continue", "target", "dest", "destination", "callback", "ref",
    "referer", "referrer", "from", "to", "page", "p", "pageid", "page_id",
    "path", "file", "filename", "filepath", "dir", "folder", "template",
    "view", "display", "mode", "action", "cmd", "command", "op", "operation",
    "type", "kind", "category", "cat", "tag", "tags", "lang", "language",
    "locale", "country", "region", "city", "address", "zip", "postal",
    "phone", "mobile", "message", "msg", "comment", "content", "body", "desc",
    "description", "note", "notes", "subject", "status", "state", "code",
    "token", "auth", "key", "apikey", "api_key", "secret", "password", "pass",
    "session", "sessionid", "sid", "csrf", "nonce", "signature", "sig", "hash",
    "format", "output", "jsonp", "callback", "cb", "method", "api", "version",
    "v", "debug", "test", "preview", "draft", "print", "embed", "iframe",
    "widget", "share", "source", "src", "href", "img", "image", "icon", "logo",
    "color", "theme", "style", "css", "js", "script", "html", "raw", "download",
    "export", "import", "upload", "attachment", "invoice", "order", "orderid",
    "product", "productid", "item", "itemid", "cart", "coupon", "price",
    "amount", "currency", "date", "start", "end", "startdate", "enddate",
    "from_date", "to_date", "limit", "offset", "per_page", "pagesize", "sort",
    "order_by", "filter", "where", "select", "table", "db", "host", "domain",
    "subdomain", "port", "ip", "remote", "proxy", "feed", "rss", "sitemap",
    "report", "chart", "graph", "metric", "event", "log", "level", "ipn",
    "webhook", "notification", "notify", "alert", "email_to", "recipient",
)


@dataclass
class FuzzResult:
    url: str
    status: int = 0
    size: int = 0
    content_type: str = ""
    redirect: str = ""
    words: int = 0
    source: str = "dir"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "size": self.size,
            "content_type": self.content_type,
            "redirect": self.redirect,
            "words": self.words,
            "source": self.source,
        }


@dataclass
class DiscoveredParameter:
    url: str
    name: str
    method: str = "GET"
    evidence: str = ""
    reflected: bool = False
    status: int = 0
    baseline_status: int = 0
    size_delta: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "name": self.name,
            "method": self.method,
            "evidence": self.evidence,
            "reflected": self.reflected,
            "status": self.status,
            "baseline_status": self.baseline_status,
            "size_delta": self.size_delta,
        }

    def key(self) -> str:
        return f"{self.method}|{self.url}|{self.name}"


def load_wordlist(path: Optional[str], fallback: Sequence[str], limit: int = 5000) -> List[str]:
    words: List[str] = []
    seen: Set[str] = set()
    if path:
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
                for line in handle:
                    word = line.strip()
                    if not word or word.startswith("#"):
                        continue
                    if word not in seen:
                        seen.add(word)
                        words.append(word)
                    if len(words) >= limit:
                        break
        except OSError:
            pass
    for word in fallback:
        if word and word not in seen:
            seen.add(word)
            words.append(word)
        if len(words) >= limit:
            break
    return words


def expand_paths(words: Iterable[str], extensions: Sequence[str] = FUZZ_EXTENSIONS) -> List[str]:
    paths: List[str] = []
    seen: Set[str] = set()
    for word in words:
        word = word.strip().lstrip("/")
        if not word:
            continue
        candidates = [word]
        if not word.endswith(tuple(ext for ext in extensions if ext)):
            for ext in extensions:
                candidates.append(word + ext)
        for candidate in candidates:
            if candidate and candidate not in seen:
                seen.add(candidate)
                paths.append(candidate)
    return paths


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _soft_404_signature(status: int, body: str) -> Tuple[int, int, str]:
    normalized = re.sub(r"\s+", " ", (body or "")[:4000]).strip().lower()
    return status, len(body or ""), hashlib.sha1(normalized.encode("utf-8", "replace")).hexdigest()


class DirFuzzer:
    """Small, safe content-discovery engine."""

    def __init__(
        self,
        http: HttpLike,
        console: ConsoleLike,
        *,
        wordlist: Optional[str] = None,
        extensions: Sequence[str] = FUZZ_EXTENSIONS,
        concurrency: int = 10,
        limit: int = 2000,
        timeout: float = 10.0,
    ):
        self.http = http
        self.console = console
        self.words = expand_paths(load_wordlist(wordlist, DIR_WORDS, limit), extensions)[:limit]
        self.concurrency = max(1, concurrency)
        self.timeout = max(3.0, timeout)
        self._baselines: Dict[str, Tuple[int, int, str]] = {}

    async def _baseline(self, origin: str) -> Tuple[int, int, str]:
        if origin not in self._baselines:
            token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            try:
                response = await asyncio.wait_for(
                    self.http.get(f"{origin}/{token}", allow_redirects=False, cache=False),
                    timeout=self.timeout,
                )
                self._baselines[origin] = _soft_404_signature(
                    getattr(response, "status", 0), getattr(response, "text", "")
                )
            except Exception:
                self._baselines[origin] = (404, 0, "")
        return self._baselines[origin]

    async def _probe(self, url: str, origin: str, baseline: Tuple[int, int, str]) -> Optional[FuzzResult]:
        try:
            response = await asyncio.wait_for(
                self.http.get(url, allow_redirects=False, cache=False), timeout=self.timeout
            )
        except Exception:
            return None
        if getattr(response, "error", None):
            return None
        status = int(getattr(response, "status", 0) or 0)
        if status not in (200, 201, 204, 206, 301, 302, 303, 307, 308, 401, 403, 405):
            return None
        body = getattr(response, "text", "") or ""
        signature = _soft_404_signature(status, body)
        if status in (200, 201, 204, 206) and signature[0] == baseline[0] and signature[1] == baseline[1] and signature[2] == baseline[2]:
            return None
        headers = getattr(response, "headers", {}) or {}
        return FuzzResult(
            url=str(getattr(response, "url", "") or url),
            status=status,
            size=len(body),
            content_type=str(headers.get("content-type", "")),
            redirect=str(headers.get("location", "")),
            words=len(body.split()),
            source="dir",
        )

    async def discover(self, target: str, *, recursive: bool = False, max_depth: int = 1) -> List[FuzzResult]:
        origin = _origin(target)
        baseline = await self._baseline(origin)
        queue: List[Tuple[str, int]] = [(origin + "/", 0)]
        seen: Set[str] = set()
        results: List[FuzzResult] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        while queue:
            base, depth = queue.pop(0)
            if base in seen:
                continue
            seen.add(base)

            async def probe(path: str) -> Optional[FuzzResult]:
                async with semaphore:
                    return await self._probe(urljoin(base, path), origin, baseline)

            group = await asyncio.gather(*(probe(path) for path in self.words), return_exceptions=True)
            for item in group:
                if not isinstance(item, FuzzResult):
                    continue
                results.append(item)
                if recursive and depth < max_depth and item.url.endswith("/"):
                    queue.append((item.url, depth + 1))
            self.console.debug(
                f"Directory fuzzing {base}: {len(results)} hit(s) so far"
            )
        return results


class ParameterMiner:
    """Find hidden query parameters by observing response deltas."""

    def __init__(
        self,
        http: HttpLike,
        console: ConsoleLike,
        *,
        marker: str = "xoxss",
        concurrency: int = 8,
        timeout: float = 10.0,
    ):
        self.http = http
        self.console = console
        self.marker = marker
        self.concurrency = max(1, concurrency)
        self.timeout = max(3.0, timeout)

    @staticmethod
    def _with_param(url: str, name: str, value: str) -> str:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        query = [(key, val) for key, val in query if key != name]
        query.append((name, value))
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), parts.fragment)
        )

    async def _baseline(self, url: str) -> Any:
        try:
            return await asyncio.wait_for(
                self.http.get(url, allow_redirects=True, cache=True), timeout=self.timeout
            )
        except Exception:
            return None

    async def mine(
        self,
        urls: Sequence[str],
        param_names: Sequence[str],
        *,
        limit_per_url: int = 40,
    ) -> List[DiscoveredParameter]:
        discovered: List[DiscoveredParameter] = []
        seen: Set[str] = set()
        semaphore = asyncio.Semaphore(self.concurrency)
        names = list(dict.fromkeys(param_names))[:limit_per_url]

        async def check(url: str, name: str, baseline: Any) -> Optional[DiscoveredParameter]:
            async with semaphore:
                candidate = self._with_param(url, name, self.marker)
                try:
                    response = await asyncio.wait_for(
                        self.http.get(candidate, allow_redirects=True, cache=False),
                        timeout=self.timeout,
                    )
                except Exception:
                    return None
                if getattr(response, "error", None):
                    return None
                body = getattr(response, "text", "") or ""
                base_body = getattr(baseline, "text", "") if baseline is not None else ""
                status = int(getattr(response, "status", 0) or 0)
                base_status = int(getattr(baseline, "status", 0) or 0) if baseline is not None else 0
                reflected = self.marker in body
                delta = len(body) - len(base_body)
                changed = status != base_status or abs(delta) > 24
                if not reflected and not changed:
                    return None
                evidence = (
                    "marker reflected"
                    if reflected
                    else f"status {base_status}->{status}, size {delta:+d}"
                )
                return DiscoveredParameter(
                    url=url,
                    name=name,
                    evidence=evidence,
                    reflected=reflected,
                    status=status,
                    baseline_status=base_status,
                    size_delta=delta,
                )

        for url in urls:
            baseline = await self._baseline(url)
            group = await asyncio.gather(
                *(check(url, name, baseline) for name in names), return_exceptions=True
            )
            for item in group:
                if isinstance(item, DiscoveredParameter) and item.key() not in seen:
                    seen.add(item.key())
                    discovered.append(item)
            if len(discovered) >= 500:
                break
        if discovered:
            self.console.info(
                f"Parameter mining: {len(discovered)} hidden parameter(s) discovered",
                important=False,
            )
        return discovered


__all__ = [
    "FuzzResult",
    "DiscoveredParameter",
    "DirFuzzer",
    "ParameterMiner",
    "DIR_WORDS",
    "PARAM_WORDS",
    "FUZZ_EXTENSIONS",
    "load_wordlist",
    "expand_paths",
]
