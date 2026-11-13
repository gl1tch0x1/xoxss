"""Shared asynchronous HTTP transport and response models."""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import socket
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlsplit

try:
    import aiohttp
except Exception:  # pragma: no cover - caller reports the missing dependency
    aiohttp = None

try:  # optional HTTP/2 + TLS-fingerprint transport (--http2 / --impersonate)
    from curl_cffi import CurlHttpVersion  # type: ignore
    from curl_cffi.requests import AsyncSession as CurlAsyncSession  # type: ignore
    from curl_cffi.requests.exceptions import ImpersonateError as CurlImpersonateError  # type: ignore

    CURL_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    CurlHttpVersion = None  # type: ignore
    CurlAsyncSession = None  # type: ignore
    CurlImpersonateError = type("_CurlImpersonateUnavailable", (Exception,), {})  # type: ignore
    CURL_AVAILABLE = False

if TYPE_CHECKING:  # pragma: no cover - optional runtime dependency
    from aiohttp import ClientResponse, ClientSession

from xoxss.utils.helpers import truncate

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

@dataclass
class HttpResponse:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    elapsed: float = 0.0
    error: Optional[str] = None
    from_cache: bool = False
    truncated: bool = False
    raw: bytes = field(default=b"", repr=False)
    # The request that produced this response.  Kept alongside the body so a
    # finding can carry a complete, reproducible request instead of only the
    # parameter that was mutated.
    request_method: str = "GET"
    request_url: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def request_dict(self, injected_parameter: str = "") -> Dict[str, object]:
        """Redacted request evidence for reports and ``--replay``."""
        from xoxss.core.evidence import request_to_dict

        return request_to_dict(
            self.request_method,
            self.request_url or self.url,
            headers=self.request_headers,
            body=self.request_body,
            injected_parameter=injected_parameter,
        )


class RateLimiter:
    def __init__(self, rate_per_second: float = 0.0):
        self.interval = (1.0 / rate_per_second) if rate_per_second and rate_per_second > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_at = 0.0

    async def acquire(self) -> None:
        if self.interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_at - now)
            self._next_at = max(now, self._next_at) + self.interval
        if wait:
            await asyncio.sleep(wait)


# --------------------------------------------------------------------------------------
# HTTP engine
# --------------------------------------------------------------------------------------


class HttpEngine:
    """aiohttp wrapper with retries, backoff, rate limiting and a small TTL cache."""

    RETRY_STATUS = {429, 500, 502, 503, 504}

    def __init__(
        self,
        console: Any,
        stats: Any,
        *,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: float = 20.0,
        retries: int = 2,
        rate: float = 0.0,
        concurrency: int = 16,
        per_host_concurrency: int = 4,
        proxy: Optional[str] = None,
        insecure: bool = False,
        cache_ttl: float = 60.0,
        cache_size: int = 512,
        max_response_bytes: int = 5 * 1024 * 1024,
        redirect_scope: Optional[Any] = None,
        auth_state: Optional[str] = None,
        http2: bool = False,
        impersonate: Optional[str] = None,
    ):
        self.console = console
        self.stats = stats
        self.base_headers = dict(headers or {})
        self.http2 = bool(http2)
        self.impersonate = (impersonate or "").strip() or None
        self.transport = "aiohttp"
        if self.http2 or self.impersonate:
            if CURL_AVAILABLE:
                self.transport = "curl"
            else:
                # Degrade gracefully instead of failing the whole scan.
                self.http2 = False
                self.impersonate = None
                try:
                    console.debug(
                        "HTTP/2 or impersonation requested but curl_cffi is not "
                        "installed; falling back to the aiohttp HTTP/1.1 transport"
                    )
                except Exception:
                    pass
        if not self.impersonate:
            # Impersonation profiles already provide a coherent browser header
            # set; overriding them would weaken the TLS/HTTP fingerprint.
            self.base_headers.setdefault("User-Agent", USER_AGENT)
            self.base_headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            self.base_headers.setdefault("Accept-Language", "en-US,en;q=0.9")
        self.cookies = dict(cookies or {})
        self.timeout = timeout
        self.retries = max(0, retries)
        self.proxy = proxy
        self.insecure = insecure
        self.cache_ttl = cache_ttl
        self.cache_size = cache_size
        self.max_response_bytes = max(1024, int(max_response_bytes))
        self.redirect_scope = redirect_scope
        self.auth_state = auth_state
        self.rate = rate
        self.limiter = RateLimiter(rate)
        self.semaphore = asyncio.Semaphore(max(1, concurrency))
        self.per_host_concurrency = max(1, int(per_host_concurrency))
        self._host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self.session: Optional["ClientSession"] = None
        self._cache: Dict[str, Tuple[float, HttpResponse]] = {}
        self._host_failures: Counter = Counter()
        self._smart_limiter = None
        self._use_smart_rate = False

    async def start(self) -> None:
        if self.transport == "curl":
            if self.session is not None:
                return
            assert CurlAsyncSession is not None, "curl_cffi is not installed"
            options: Dict[str, Any] = {
                "headers": self.base_headers,
                "timeout": self.timeout,
                "verify": not self.insecure,
            }
            if self.cookies:
                options["cookies"] = self.cookies
            if self.proxy:
                options["proxy"] = self.proxy
            if self.impersonate:
                options["impersonate"] = self.impersonate
            if self.http2 and CurlHttpVersion is not None:
                # CURL_HTTP_VERSION_2_0 negotiates h2 over ALPN and falls back
                # to HTTP/1.1 when the origin cannot speak HTTP/2.
                options["http_version"] = CurlHttpVersion.V2_0
            try:
                self.session = CurlAsyncSession(**options)  # type: ignore[assignment]
            except Exception as exc:
                # A misspelled impersonation profile (or a curl build without
                # HTTP/2) must not abort the scan; degrade to aiohttp.
                self.console.warn(
                    f"Could not start the curl transport ({exc}); "
                    "falling back to the aiohttp HTTP/1.1 transport",
                    important=False,
                )
                self.transport = "aiohttp"
                self.http2 = False
                self.impersonate = None
                await self.start()
                return
            if self.auth_state:
                self._load_auth_state_cookies_curl()
            return
        if self.session is not None and not self.session.closed:
            return
        assert aiohttp is not None, "aiohttp is not installed"
        resolver = aiohttp.ThreadedResolver()
        # The c-ares resolver is fast on Unix event loops. Windows defaults to
        # ProactorEventLoop, which is not compatible with aiodns 3.x callbacks.
        if sys.platform != "win32":
            try:
                resolver = aiohttp.AsyncResolver()
            except Exception:
                pass
        connector = aiohttp.TCPConnector(
            resolver=resolver,
            limit=100,
            ttl_dns_cache=300,
            ssl=not self.insecure,
            enable_cleanup_closed=True,
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=min(self.timeout, 10.0))
        # Playwright storage-state cookies can legitimately target loopback/IP
        # hosts in the local benchmark and private test environments. Keep the
        # default strict behavior unless the operator supplied auth state.
        cookie_jar = aiohttp.CookieJar(unsafe=bool(self.auth_state))
        self.session = aiohttp.ClientSession(
            headers=self.base_headers,
            cookies=self.cookies,
            timeout=timeout,
            connector=connector,
            cookie_jar=cookie_jar,
        )
        if self.auth_state:
            self._load_auth_state_cookies()

    def _load_auth_state_cookies(self) -> None:
        """Load Playwright cookies into aiohttp with their original host/path scope."""
        if self.session is None or not self.auth_state:
            return
        try:
            from http.cookies import SimpleCookie
            from email.utils import formatdate
            from yarl import URL

            path = Path(self.auth_state).expanduser()
            if not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
                raise ValueError("file is missing or exceeds 10 MiB")
            data = json.loads(path.read_text(encoding="utf-8"))
            cookies = data.get("cookies", []) if isinstance(data, dict) else []
            if not isinstance(cookies, list):
                raise ValueError("storage state has no valid cookies array")
            loaded = 0
            for item in cookies[:5000]:
                if not isinstance(item, dict):
                    continue
                name, value = item.get("name"), item.get("value")
                domain = str(item.get("domain") or "").lstrip(".")
                cookie_path = str(item.get("path") or "/")
                expires = item.get("expires")
                if expires not in (None, -1, -1.0, 0, 0.0):
                    try:
                        expiry_time = float(expires)
                        if expiry_time <= time.time():
                            continue
                    except (TypeError, ValueError):
                        expiry_time = 0.0
                else:
                    expiry_time = 0.0
                if not name or not domain or any(ch in domain for ch in "/:@"):
                    continue
                cookie = SimpleCookie()
                cookie[str(name)] = str(value or "")
                if item.get("domain"):
                    cookie[str(name)]["domain"] = str(item["domain"])
                cookie[str(name)]["path"] = cookie_path
                if item.get("secure"):
                    cookie[str(name)]["secure"] = True
                if expiry_time > 0:
                    cookie[str(name)]["expires"] = formatdate(expiry_time, usegmt=True)
                scheme = "https" if item.get("secure") else "http"
                self.session.cookie_jar.update_cookies(
                    cookie, response_url=URL(f"{scheme}://{domain}{cookie_path}")
                )
                loaded += 1
            self.console.info(f"Loaded {loaded} domain-scoped auth cookie(s) from Playwright storage state", important=False)
        except Exception as exc:
            self.console.warn(f"Could not load HTTP auth cookies from --auth-state: {exc}")

    def _load_auth_state_cookies_curl(self) -> None:
        """Load Playwright storage-state cookies into the curl session."""
        if self.session is None or not self.auth_state:
            return
        try:
            path = Path(self.auth_state).expanduser()
            if not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
                raise ValueError("file is missing or exceeds 10 MiB")
            data = json.loads(path.read_text(encoding="utf-8"))
            cookies = data.get("cookies", []) if isinstance(data, dict) else []
            if not isinstance(cookies, list):
                raise ValueError("storage state has no valid cookies array")
            loaded = 0
            for item in cookies[:5000]:
                if not isinstance(item, dict):
                    continue
                name, value = item.get("name"), item.get("value")
                domain = str(item.get("domain") or "").lstrip(".")
                cookie_path = str(item.get("path") or "/")
                expires = item.get("expires")
                if expires not in (None, -1, -1.0, 0, 0.0):
                    try:
                        if float(expires) <= time.time():
                            continue
                    except (TypeError, ValueError):
                        pass
                if not name or not domain or any(ch in domain for ch in "/:@"):
                    continue
                cookie_jar = getattr(self.session, "cookies", None)
                if cookie_jar is None:
                    continue
                try:
                    cookie_jar.set(
                        str(name), str(value or ""), domain=domain,
                        path=cookie_path, secure=bool(item.get("secure")),
                    )
                except Exception:
                    continue
                loaded += 1
            self.console.info(
                f"Loaded {loaded} domain-scoped auth cookie(s) from Playwright storage state",
                important=False,
            )
        except Exception as exc:
            self.console.warn(f"Could not load HTTP auth cookies from --auth-state: {exc}")

    async def close(self) -> None:
        if self.session is not None:
            try:
                await self.session.close()
            except Exception:
                pass
        self.session = None

    def enable_smart_rate(self, initial_rate: float) -> None:
        """Enable adaptive smart rate limiting."""
        try:
            from xoxss.analysis.rate_limit import SmartRateLimiter
        except Exception:
            return
        self._smart_limiter = SmartRateLimiter(initial_rate)
        self._use_smart_rate = True

    async def _apply_rate_limit(self, host: str) -> None:
        """Apply rate limiting (smart or standard)."""
        if self._use_smart_rate and self._smart_limiter:
            await self._smart_limiter.acquire()
        else:
            await self.limiter.acquire()

    # -- public API -------------------------------------------------------------------
    async def get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        cache: bool = False,
    ) -> HttpResponse:
        return await self.request("GET", url, headers=headers, allow_redirects=allow_redirects, cache=cache)

    async def post(
        self,
        url: str,
        *,
        data: Optional[Any] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        return await self.request(
            "POST",
            url,
            data=data,
            json_body=json_body,
            headers=headers,
            allow_redirects=allow_redirects,
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_body: Optional[Dict[str, Any]] = None,
        allow_redirects: bool = True,
        cache: bool = False,
    ) -> HttpResponse:
        if self.redirect_scope is not None and not self.redirect_scope(url):
            self.stats.errors += 1
            return HttpResponse(url=url, error="request target is outside the configured scan scope")
        if self.session is None:
            await self.start()

        cache_key = ""
        if cache:
            cache_key = self._cache_key(method, url, headers, data, json_body)
            if cache_key in self._cache:
                expiry, cached = self._cache[cache_key]
                if expiry > time.monotonic():
                    hit = HttpResponse(**{**cached.__dict__, "from_cache": True})
                    return hit

        if self.transport == "curl":
            return await self._request_curl(
                method,
                url,
                headers=headers,
                data=data,
                json_body=json_body,
                allow_redirects=allow_redirects,
                cache=cache,
                cache_key=cache_key,
            )

        delay = 0.0
        last_error = "request failed after retries"
        for attempt in range(self.retries + 1):
            if delay:
                await asyncio.sleep(delay)
            try:
                host = (urlsplit(url).hostname or "").lower()
                host_semaphore = self._host_semaphores.get(host)
                if host_semaphore is None:
                    host_semaphore = asyncio.Semaphore(self.per_host_concurrency)
                    self._host_semaphores[host] = host_semaphore
                async with host_semaphore, self.semaphore:
                    assert self.session is not None
                    current_url, current_method = url, method
                    current_data, current_json = data, json_body
                    response: Optional[ClientResponse] = None
                    started = time.monotonic()
                    sent_headers: Dict[str, str] = {}
                    sent_body = ""
                    for redirect_count in range(11):
                        await self._apply_rate_limit(urlsplit(current_url).hostname or "")
                        sent_headers, sent_body = self._sent_request(
                            headers, current_data, current_json
                        )
                        response = await self.session.request(
                            current_method,
                            current_url,
                            headers=headers,
                            data=current_data,
                            json=current_json,
                            allow_redirects=False,
                            proxy=self.proxy,
                            ssl=not self.insecure,
                        )
                        self.stats.requests += 1
                        location = response.headers.get("Location")
                        is_redirect = response.status in (301, 302, 303, 307, 308) and location
                        if not (allow_redirects and is_redirect):
                            break
                        next_url = urljoin(str(response.url), location)
                        current_parts = urlsplit(str(response.url))
                        next_parts = urlsplit(next_url)
                        same_origin = (
                            current_parts.scheme.lower(), current_parts.hostname, current_parts.port
                        ) == (
                            next_parts.scheme.lower(), next_parts.hostname, next_parts.port
                        )
                        if not same_origin or (
                            self.redirect_scope is not None and not self.redirect_scope(next_url)
                        ):
                            result = HttpResponse(
                                url=str(response.url), status=response.status,
                                headers={k.lower(): v for k, v in response.headers.items()},
                                error="redirect target is outside the request origin or scan scope",
                            )
                            response.release()
                            return result
                        response.release()
                        if redirect_count == 10:
                            return HttpResponse(url=current_url, error="too many redirects")
                        if response.status == 303 or (response.status in (301, 302) and current_method.upper() == "POST"):
                            current_method, current_data, current_json = "GET", None, None
                        current_url = next_url
                    assert response is not None
                    try:
                        raw = bytearray()
                        while len(raw) <= self.max_response_bytes:
                            chunk = await response.content.read(min(65536, self.max_response_bytes + 1 - len(raw)))
                            if not chunk:
                                break
                            raw.extend(chunk)
                        truncated = len(raw) > self.max_response_bytes
                        if truncated:
                            del raw[self.max_response_bytes:]
                        try:
                            text = bytes(raw).decode(response.get_encoding() or "utf-8", "replace")
                        except (LookupError, RuntimeError):
                            text = bytes(raw).decode("utf-8", "replace")
                        elapsed = time.monotonic() - started
                        result = HttpResponse(
                            url=str(response.url),
                            status=response.status,
                            headers={k.lower(): v for k, v in response.headers.items()},
                            text=text,
                            raw=bytes(raw),
                            elapsed=elapsed,
                            truncated=truncated,
                            request_method=current_method,
                            request_url=current_url,
                            request_headers=sent_headers,
                            request_body=sent_body,
                        )
                        if truncated:
                            self.stats.truncated_responses += 1
                            self.console.debug(
                                f"Response from {truncate(str(response.url), 120)} exceeded "
                                f"{self.max_response_bytes} bytes; analysis used a truncated body"
                            )
                        # Track for smart rate limiter
                        if self._use_smart_rate and self._smart_limiter:
                            self._smart_limiter.record_request(
                                success=response.status < 400,
                                elapsed=elapsed,
                                is_retry=False
                            )

                        if response.status in self.RETRY_STATUS and attempt < self.retries:
                            delay = self._retry_delay(response, attempt)
                            self.stats.blocked += 1
                            self.console.debug(
                                f"{method} {truncate(url, 120)} -> HTTP {response.status}, retrying in {delay:.1f}s"
                            )
                            continue
                        self.console.debug(
                            f"{method} {truncate(url, 120)} -> {response.status} ({elapsed * 1000:.0f} ms)"
                        )
                        if cache:
                            self._store_cache(cache_key, result)
                        return result
                    finally:
                        response.release()
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                delay = min(8.0, 0.6 * (2 ** attempt))
                self.console.debug(f"{method} {truncate(url, 120)} -> timeout, retry {attempt + 1}/{self.retries}")
                if self._use_smart_rate and self._smart_limiter:
                    self._smart_limiter.record_request(success=False, elapsed=delay, is_retry=True)
            except socket.gaierror as exc:
                host = urlsplit(url).hostname or "unknown host"
                last_error = f"DNS resolution failed for {host}: {exc}"
                if exc.errno != socket.EAI_AGAIN:
                    self.console.debug(last_error)
                    break
                delay = min(8.0, 0.6 * (2 ** attempt))
                self.console.debug(
                    f"{last_error}; retry {attempt + 1}/{self.retries} in {delay:.1f}s"
                )
                if host != "unknown host":
                    self._host_failures[host] += 1
            except Exception as exc:  # aiohttp errors, DNS, TLS, connection resets
                dns_exc = exc if isinstance(exc, socket.gaierror) else getattr(exc, "os_error", None)
                if isinstance(dns_exc, socket.gaierror):
                    host = urlsplit(url).hostname or "unknown host"
                    last_error = f"DNS resolution failed for {host}: {dns_exc}"
                    if dns_exc.errno != socket.EAI_AGAIN:
                        self.console.debug(last_error)
                        break
                    delay = min(8.0, 0.6 * (2 ** attempt))
                    self.console.debug(
                        f"{last_error}; retry {attempt + 1}/{self.retries} in {delay:.1f}s"
                    )
                    if host != "unknown host":
                        self._host_failures[host] += 1
                    continue
                delay = min(8.0, 0.6 * (2 ** attempt))
                last_error = f"{type(exc).__name__}: {exc}"
                self.console.debug(f"{method} {truncate(url, 120)} -> {last_error}")
                host = urlsplit(url).hostname or ""
                if host:
                    self._host_failures[host] += 1
                if self._use_smart_rate and self._smart_limiter:
                    self._smart_limiter.record_request(success=False, elapsed=delay, is_retry=True)

        self.stats.errors += 1
        return HttpResponse(url=url, error=last_error)

    # -- internals --------------------------------------------------------------------
    def _sent_request(
        self,
        headers: Optional[Dict[str, str]],
        data: Optional[Any],
        json_body: Optional[Dict[str, Any]],
    ) -> Tuple[Dict[str, str], str]:
        """Materialise the headers/body actually sent for evidence capture."""
        merged: Dict[str, str] = dict(self.base_headers)
        if headers:
            merged.update({str(key): str(value) for key, value in headers.items()})
        if self.cookies and not any(name.lower() == "cookie" for name in merged):
            merged["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
        body = ""
        if data:
            body = urlencode(data, doseq=True) if isinstance(data, dict) else str(data)
        elif json_body is not None:
            body = json.dumps(json_body, separators=(",", ":"), ensure_ascii=False)
            if not any(name.lower() == "content-type" for name in merged):
                # aiohttp/curl_cffi add this themselves; capture it so the
                # evidence (and its curl PoC) reproduces the request.
                merged["Content-Type"] = "application/json"
        return merged, body

    async def _request_curl(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_body: Optional[Dict[str, Any]] = None,
        allow_redirects: bool = True,
        cache: bool = False,
        cache_key: str = "",
    ) -> HttpResponse:
        """curl_cffi transport with the same retry/cache/redirect semantics.

        Multiplexes concurrent requests over a persistent HTTP/2 connection and,
        when ``impersonate`` is set, presents a real browser TLS fingerprint.
        """
        delay = 0.0
        last_error = "request failed after retries"
        for attempt in range(self.retries + 1):
            if delay:
                await asyncio.sleep(delay)
            try:
                host = (urlsplit(url).hostname or "").lower()
                host_semaphore = self._host_semaphores.get(host)
                if host_semaphore is None:
                    host_semaphore = asyncio.Semaphore(self.per_host_concurrency)
                    self._host_semaphores[host] = host_semaphore
                async with host_semaphore, self.semaphore:
                    assert self.session is not None
                    current_url, current_method = url, method
                    current_data, current_json = data, json_body
                    response: Any = None
                    response_headers: Dict[str, str] = {}
                    started = time.monotonic()
                    sent_headers: Dict[str, str] = {}
                    sent_body = ""
                    for redirect_count in range(11):
                        await self._apply_rate_limit(urlsplit(current_url).hostname or "")
                        request_headers, sent_body = self._sent_request(
                            headers, current_data, current_json
                        )
                        sent_headers = request_headers
                        options: Dict[str, Any] = {
                            "headers": request_headers,
                            "data": current_data,
                            "json": current_json,
                            "allow_redirects": False,
                            "timeout": self.timeout,
                            "verify": not self.insecure,
                        }
                        if self.proxy:
                            options["proxy"] = self.proxy
                        if self.impersonate:
                            options["impersonate"] = self.impersonate
                        if self.http2 and CurlHttpVersion is not None:
                            options["http_version"] = CurlHttpVersion.V2_0
                        response = await self.session.request(
                            current_method, current_url, **options
                        )
                        self.stats.requests += 1
                        response_headers = {
                            str(k).lower(): str(v) for k, v in response.headers.items()
                        }
                        location = (
                            response_headers.get("location")
                            or response.headers.get("Location")
                            or ""
                        )
                        is_redirect = int(response.status_code) in (301, 302, 303, 307, 308) and location
                        if not (allow_redirects and is_redirect):
                            break
                        response_url = str(getattr(response, "url", current_url) or current_url)
                        next_url = urljoin(response_url, location)
                        current_parts = urlsplit(response_url)
                        next_parts = urlsplit(next_url)
                        same_origin = (
                            current_parts.scheme.lower(), current_parts.hostname, current_parts.port
                        ) == (
                            next_parts.scheme.lower(), next_parts.hostname, next_parts.port
                        )
                        if not same_origin or (
                            self.redirect_scope is not None and not self.redirect_scope(next_url)
                        ):
                            self._close_curl_response(response)
                            return HttpResponse(
                                url=response_url,
                                status=int(response.status_code),
                                headers=response_headers,
                                error="redirect target is outside the request origin or scan scope",
                            )
                        self._close_curl_response(response)
                        if redirect_count == 10:
                            return HttpResponse(url=current_url, error="too many redirects")
                        if response.status_code == 303 or (
                            response.status_code in (301, 302) and current_method.upper() == "POST"
                        ):
                            current_method, current_data, current_json = "GET", None, None
                        current_url = next_url
                    assert response is not None
                    try:
                        raw = bytes(getattr(response, "content", b"") or b"")
                        truncated = len(raw) > self.max_response_bytes
                        if truncated:
                            raw = raw[: self.max_response_bytes]
                        encoding = getattr(response, "encoding", None) or "utf-8"
                        try:
                            text = raw.decode(encoding, "replace")
                        except (LookupError, RuntimeError):
                            text = raw.decode("utf-8", "replace")
                        elapsed = time.monotonic() - started
                        status = int(response.status_code)
                        result = HttpResponse(
                            url=str(getattr(response, "url", current_url) or current_url),
                            status=status,
                            headers=response_headers,
                            text=text,
                            raw=raw,
                            elapsed=elapsed,
                            truncated=truncated,
                            request_method=current_method,
                            request_url=current_url,
                            request_headers=sent_headers,
                            request_body=sent_body,
                        )
                        if truncated:
                            self.stats.truncated_responses += 1
                            self.console.debug(
                                f"Response from {truncate(result.url, 120)} exceeded "
                                f"{self.max_response_bytes} bytes; analysis used a truncated body"
                            )
                        if self._use_smart_rate and self._smart_limiter:
                            self._smart_limiter.record_request(
                                success=status < 400, elapsed=elapsed, is_retry=False
                            )
                        if status in self.RETRY_STATUS and attempt < self.retries:
                            delay = self._retry_delay(response, attempt)
                            self.stats.blocked += 1
                            self.console.debug(
                                f"{method} {truncate(url, 120)} -> HTTP {status}, retrying in {delay:.1f}s"
                            )
                            continue
                        self.console.debug(
                            f"{method} {truncate(url, 120)} -> {status} ({elapsed * 1000:.0f} ms)"
                        )
                        if cache and cache_key:
                            self._store_cache(cache_key, result)
                        return result
                    finally:
                        self._close_curl_response(response)
            except asyncio.CancelledError:
                raise
            except CurlImpersonateError as exc:
                # An unknown --impersonate profile is a configuration error, not
                # a target failure: drop the fingerprint and continue on aiohttp.
                self.console.warn(
                    f"Unsupported --impersonate profile ({exc}); "
                    "falling back to the aiohttp HTTP/1.1 transport",
                    important=False,
                )
                self.transport = "aiohttp"
                self.http2 = False
                self.impersonate = None
                await self.close()
                return await self.request(
                    method,
                    url,
                    headers=headers,
                    data=data,
                    json_body=json_body,
                    allow_redirects=allow_redirects,
                    cache=cache,
                )
            except asyncio.TimeoutError:
                delay = min(8.0, 0.6 * (2 ** attempt))
                self.console.debug(f"{method} {truncate(url, 120)} -> timeout, retry {attempt + 1}/{self.retries}")
                if self._use_smart_rate and self._smart_limiter:
                    self._smart_limiter.record_request(success=False, elapsed=delay, is_retry=True)
            except Exception as exc:
                dns_exc = exc if isinstance(exc, socket.gaierror) else getattr(exc, "os_error", None)
                delay = min(8.0, 0.6 * (2 ** attempt))
                if isinstance(dns_exc, socket.gaierror):
                    host = urlsplit(url).hostname or "unknown host"
                    last_error = f"DNS resolution failed for {host}: {dns_exc}"
                    if dns_exc.errno != socket.EAI_AGAIN:
                        self.console.debug(last_error)
                        break
                else:
                    last_error = f"{type(exc).__name__}: {exc}"
                self.console.debug(f"{method} {truncate(url, 120)} -> {last_error}")
                host = urlsplit(url).hostname or ""
                if host:
                    self._host_failures[host] += 1
                if self._use_smart_rate and self._smart_limiter:
                    self._smart_limiter.record_request(success=False, elapsed=delay, is_retry=True)
        self.stats.errors += 1
        return HttpResponse(url=url, error=last_error)

    @staticmethod
    def _close_curl_response(response: Any) -> None:
        try:
            response.close()
        except Exception:
            pass

    @staticmethod
    def _cache_key(
        method: str,
        url: str,
        headers: Optional[Dict[str, str]],
        data: Optional[Any],
        json_body: Optional[Dict[str, Any]] = None,
    ) -> str:
        raw = json.dumps(
            [method.upper(), url, headers or {}, data or {}, json_body or {}],
            sort_keys=True,
            default=str,
        )
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()

    def _store_cache(self, key: str, response: HttpResponse) -> None:
        if len(self._cache) >= self.cache_size:
            # drop the oldest entry (dicts keep insertion order)
            self._cache.pop(next(iter(self._cache)), None)
        self._cache[key] = (time.monotonic() + self.cache_ttl, response)

    def peek(self, url: str) -> Optional[HttpResponse]:
        """Cached GET response for ``url`` without any network activity."""
        cache_key = self._cache_key("GET", url, None, None, None)
        entry = self._cache.get(cache_key)
        if entry is None:
            return None
        expiry, cached = entry
        if expiry <= time.monotonic():
            return None
        return HttpResponse(**{**cached.__dict__, "from_cache": True})

    @staticmethod
    def _retry_delay(response: ClientResponse, attempt: int) -> float:
        try:
            retry_after = response.headers.get("Retry-After", "") or response.headers.get("retry-after", "")
        except Exception:
            retry_after = ""
        if retry_after.isdigit():
            return min(30.0, float(retry_after))
        return min(8.0, 0.7 * (2 ** attempt)) + random.uniform(0, 0.4)
