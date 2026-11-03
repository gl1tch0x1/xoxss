"""
Passive subdomain enumeration and DNS resolution.

The scanner accepts a bare domain as a target.  In that mode we first expand
the registrable domain into its known subdomains using public certificate
transparency / passive-DNS sources, then let the crawler scan every live host.

No brute-force is performed unless a wordlist is supplied or the caller asks
for the built-in list.  All network calls are isolated so one failing source
never aborts a scan.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import socket
import string
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote

try:  # pragma: no cover - typing only
    from typing import Protocol
except Exception:  # pragma: no cover
    Protocol = object  # type: ignore


class HttpLike(Protocol):  # pragma: no cover - structural typing
    async def get(self, url: str, **kwargs: Any) -> Any: ...


class ConsoleLike(Protocol):  # pragma: no cover
    def info(self, message: str, important: bool = True) -> None: ...
    def warn(self, message: str, important: bool = True) -> None: ...
    def debug(self, message: str) -> None: ...


# A pragmatic subset of the Public Suffix List.  Anything not listed is treated
# as a single-label suffix (example.com -> example.com), which is correct for
# the vast majority of targets.
_MULTI_PART_SUFFIXES: Set[str] = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
    "co.za", "org.za", "net.za", "gov.za", "ac.za",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.mx", "org.mx", "net.mx", "gob.mx", "edu.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    "com.co", "net.co", "org.co", "gov.co", "edu.co",
    "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe",
    "com.ve", "net.ve", "org.ve", "gob.ve",
    "com.ec", "com.bo", "com.py", "com.uy", "com.do",
    "com.gt", "com.hn", "com.ni", "com.pa", "com.sv",
    "co.id", "or.id", "ac.id", "go.id", "web.id",
    "co.th", "or.th", "ac.th", "go.th", "in.th",
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    "co.ir", "org.ir", "net.ir", "ac.ir", "gov.ir",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    "co.ke", "or.ke", "ac.ke", "go.ke", "ne.ke",
    "co.ug", "or.ug", "ac.ug", "go.ug", "ne.ug",
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
    "co.tz", "or.tz", "ac.tz", "go.tz", "ne.tz",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd",
    "com.np", "net.np", "org.np", "gov.np", "edu.np",
    "com.lk", "net.lk", "org.lk", "gov.lk", "edu.lk",
    "co.ve", "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua",
    "com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru",
    "co.at", "or.at", "ac.at", "gv.at",
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
    "com.pt", "org.pt", "gov.pt", "edu.pt",
    "com.gr", "net.gr", "org.gr", "gov.gr", "edu.gr",
    "com.ro", "org.ro", "gov.ro", "edu.ro",
    "com.hr", "com.si", "com.sk", "com.cz", "com.hu", "com.bg",
    "com.ee", "com.lv", "com.lt", "com.by", "com.kz", "com.uz",
    "co.ao", "co.mz", "co.zw", "co.bw", "co.na",
}

_BUILTIN_WORDS: Tuple[str, ...] = (
    "www", "api", "app", "admin", "portal", "dev", "staging", "stage", "test",
    "qa", "uat", "beta", "preprod", "prod", "demo", "sandbox", "internal",
    "intranet", "extranet", "vpn", "secure", "login", "auth", "sso", "id",
    "account", "accounts", "dashboard", "console", "manage", "management",
    "static", "assets", "cdn", "img", "images", "media", "files", "download",
    "upload", "docs", "doc", "wiki", "help", "support", "status", "monitor",
    "metrics", "grafana", "kibana", "jenkins", "ci", "cd", "git", "gitlab",
    "github", "bitbucket", "registry", "docker", "k8s", "kubernetes", "db",
    "database", "mysql", "postgres", "redis", "mongo", "cache", "queue",
    "mail", "smtp", "imap", "webmail", "ns1", "ns2", "dns", "mx", "ftp",
    "sftp", "ssh", "remote", "gateway", "proxy", "edge", "origin", "lb",
    "shop", "store", "pay", "payments", "billing", "invoice", "crm", "erp",
    "hr", "jobs", "careers", "blog", "news", "forum", "community", "m",
    "mobile", "wap", "web", "www2", "www3", "old", "new", "legacy", "v1",
    "v2", "v3", "graphql", "ws", "socket", "realtime", "push", "notify",
    "service", "services", "ms", "micro", "partner", "partners", "client",
    "clients", "customer", "customers", "user", "users", "member", "members",
    "staff", "employee", "employees", "vendor", "vendors", "supplier",
)


@dataclass
class SubdomainReport:
    """Result of passive/active subdomain enumeration."""

    domain: str
    hosts: List[str] = field(default_factory=list)
    resolved: List[str] = field(default_factory=list)
    sources: Dict[str, List[str]] = field(default_factory=dict)
    wildcard: bool = False
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "hosts": list(self.hosts),
            "resolved": list(self.resolved),
            "sources": {key: list(value) for key, value in self.sources.items()},
            "wildcard": self.wildcard,
            "errors": list(self.errors),
        }


def normalize_host(host: str) -> str:
    host = (host or "").strip().lower().strip(".")
    host = re.sub(r"^[a-z]+://", "", host)
    host = host.split("/", 1)[0].split("@")[-1]
    host = host.split(":", 1)[0]
    if host.startswith("*."):
        host = host[2:]
    return host


def root_domain(host: str) -> str:
    """Return the registrable domain (eTLD+1) for a host or URL."""
    host = normalize_host(host)
    if not host or re.fullmatch(r"[\d.]+", host):
        return host
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    suffix = ".".join(labels[-2:])
    if suffix in _MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _valid_candidate(candidate: str, domain: str) -> bool:
    candidate = normalize_host(candidate)
    if not candidate or candidate == domain:
        return False
    if len(candidate) > 253 or "." not in candidate:
        return False
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?)+", candidate):
        return False
    return candidate.endswith("." + domain)


def _extract_hosts_from_text(text: str, domain: str) -> List[str]:
    found: List[str] = []
    for token in re.findall(r"[A-Za-z0-9*_.-]+", text or ""):
        host = normalize_host(token)
        if _valid_candidate(host, domain):
            found.append(host)
    return found


def parse_crtsh(text: str, domain: str) -> List[str]:
    hosts: List[str] = []
    try:
        rows = json.loads(text)
        for row in rows if isinstance(rows, list) else []:
            for name in str(row.get("name_value", "")).splitlines():
                host = normalize_host(name)
                if _valid_candidate(host, domain):
                    hosts.append(host)
    except Exception:
        hosts.extend(_extract_hosts_from_text(text, domain))
    return hosts


def parse_certspotter(text: str, domain: str) -> List[str]:
    hosts: List[str] = []
    try:
        rows = json.loads(text)
        for row in rows if isinstance(rows, list) else []:
            for name in row.get("dns_names", []) or []:
                host = normalize_host(name)
                if _valid_candidate(host, domain):
                    hosts.append(host)
    except Exception:
        hosts.extend(_extract_hosts_from_text(text, domain))
    return hosts


def parse_hackertarget(text: str, domain: str) -> List[str]:
    hosts: List[str] = []
    for line in (text or "").splitlines():
        host = normalize_host(line.split(",", 1)[0])
        if _valid_candidate(host, domain):
            hosts.append(host)
    return hosts


def parse_otx(text: str, domain: str) -> List[str]:
    hosts: List[str] = []
    try:
        data = json.loads(text)
        for row in data.get("passive_dns", []) or []:
            host = normalize_host(row.get("hostname", ""))
            if _valid_candidate(host, domain):
                hosts.append(host)
    except Exception:
        hosts.extend(_extract_hosts_from_text(text, domain))
    return hosts


def parse_urlscan(text: str, domain: str) -> List[str]:
    hosts: List[str] = []
    try:
        data = json.loads(text)
        for row in data.get("results", []) or []:
            page = row.get("page") or {}
            host = normalize_host(page.get("domain", "") or page.get("url", ""))
            if _valid_candidate(host, domain):
                hosts.append(host)
    except Exception:
        hosts.extend(_extract_hosts_from_text(text, domain))
    return hosts


def parse_rapiddns(text: str, domain: str) -> List[str]:
    return _extract_hosts_from_text(text, domain)


class SubdomainFinder:
    """Collect subdomains from public sources and resolve the live ones."""

    def __init__(
        self,
        http: HttpLike,
        console: ConsoleLike,
        *,
        sources: Optional[Sequence[str]] = None,
        timeout: float = 20.0,
        concurrency: int = 16,
        limit: int = 5000,
        resolvers: Optional[Sequence[str]] = None,
    ):
        self.http = http
        self.console = console
        self.timeout = max(3.0, timeout)
        self.concurrency = max(1, concurrency)
        self.limit = max(1, limit)
        self.resolvers = list(resolvers or [])
        self.sources = [
            source.strip().lower()
            for source in (sources or ("crtsh", "certspotter", "hackertarget", "otx", "urlscan"))
            if source.strip()
        ]

    # -- passive sources ----------------------------------------------------------
    async def _fetch(self, url: str, *, headers: Optional[Dict[str, str]] = None) -> str:
        try:
            response = await asyncio.wait_for(
                self.http.get(url, headers=headers, allow_redirects=True), timeout=self.timeout
            )
        except Exception as exc:
            raise RuntimeError(str(exc)) from exc
        if getattr(response, "error", None):
            raise RuntimeError(str(response.error))
        return getattr(response, "text", "") or ""

    async def _source_crtsh(self, domain: str) -> List[str]:
        text = await self._fetch(f"https://crt.sh/?q=%25.{quote(domain)}&output=json")
        return parse_crtsh(text, domain)

    async def _source_certspotter(self, domain: str) -> List[str]:
        url = (
            "https://api.certspotter.com/v1/issuances?domain="
            f"{quote(domain)}&include_subdomains=true&expand=dns_names"
        )
        text = await self._fetch(url)
        return parse_certspotter(text, domain)

    async def _source_hackertarget(self, domain: str) -> List[str]:
        text = await self._fetch(f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}")
        return parse_hackertarget(text, domain)

    async def _source_otx(self, domain: str) -> List[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/passive_dns"
        text = await self._fetch(url)
        return parse_otx(text, domain)

    async def _source_urlscan(self, domain: str) -> List[str]:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=1000"
        text = await self._fetch(url)
        return parse_urlscan(text, domain)

    async def _source_rapiddns(self, domain: str) -> List[str]:
        text = await self._fetch(f"https://rapiddns.io/subdomain/{quote(domain)}?full=1")
        return parse_rapiddns(text, domain)

    # -- active brute force -------------------------------------------------------
    async def _wordlist_candidates(self, domain: str, wordlist: Optional[str], limit: int) -> List[str]:
        words: List[str] = list(_BUILTIN_WORDS)
        if wordlist:
            try:
                with open(wordlist, "r", encoding="utf-8-sig", errors="replace") as handle:
                    for line in handle:
                        word = line.strip()
                        if word and not word.startswith("#"):
                            words.append(word.split(".", 1)[0])
            except OSError as exc:
                self.console.warn(f"Cannot read subdomain wordlist {wordlist}: {exc}")
        seen: Set[str] = set()
        candidates: List[str] = []
        for word in words:
            word = word.strip().lower()
            if not word or word in seen:
                continue
            seen.add(word)
            candidates.append(f"{word}.{domain}")
            if len(candidates) >= limit:
                break
        return candidates

    async def resolve_one(self, host: str) -> bool:
        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
                timeout=min(self.timeout, 6.0),
            )
            return True
        except Exception:
            return False

    async def resolve_many(self, hosts: Iterable[str]) -> List[str]:
        hosts = list(dict.fromkeys(hosts))
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check(host: str) -> Optional[str]:
            async with semaphore:
                return host if await self.resolve_one(host) else None

        results = await asyncio.gather(*(check(host) for host in hosts), return_exceptions=True)
        return [item for item in results if isinstance(item, str)]

    async def _wildcard(self, domain: str) -> bool:
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        return await self.resolve_one(f"{token}.{domain}")

    # -- public API ---------------------------------------------------------------
    async def enumerate(
        self,
        domain: str,
        *,
        wordlist: Optional[str] = None,
        brute_limit: int = 0,
        resolve: bool = True,
    ) -> SubdomainReport:
        domain = root_domain(domain)
        report = SubdomainReport(domain=domain)

        handlers = {
            "crtsh": self._source_crtsh,
            "certspotter": self._source_certspotter,
            "hackertarget": self._source_hackertarget,
            "otx": self._source_otx,
            "urlscan": self._source_urlscan,
            "rapiddns": self._source_rapiddns,
        }

        async def run_source(name: str) -> Tuple[str, List[str], Optional[str]]:
            handler = handlers.get(name)
            if handler is None:
                return name, [], "unknown source"
            try:
                return name, await handler(domain), None
            except Exception as exc:
                return name, [], str(exc)[:160]

        results = await asyncio.gather(
            *(run_source(name) for name in self.sources), return_exceptions=False
        )

        hosts: Set[str] = set()
        for name, found, error in results:
            report.sources[name] = sorted(set(found))[: self.limit]
            if error:
                report.errors.append(f"{name}: {error}")
                self.console.debug(f"Subdomain source {name} failed: {error}")
            else:
                self.console.debug(f"Subdomain source {name}: {len(found)} host(s)")
            hosts.update(found)

        # Detect wildcard DNS *before* brute-forcing: on a wildcard zone the
        # resolver answers for any random label, so every brute-force host
        # would "resolve" and the volume of fake hosts explodes.
        if resolve:
            report.wildcard = await self._wildcard(domain)
            if report.wildcard:
                self.console.warn(
                    f"Wildcard DNS detected for {domain}; brute-force hosts "
                    "(which would all 'resolve') are being skipped "
                    "(passive-source hosts are kept and still resolved)"
                )

        if brute_limit > 0 and not report.wildcard:
            candidates = await self._wordlist_candidates(domain, wordlist, brute_limit)
            self.console.debug(f"Resolving {len(candidates)} brute-force subdomain(s)")
            resolved_brute = set(await self.resolve_many(candidates))
            report.sources["bruteforce"] = sorted(resolved_brute)[: self.limit]
            hosts.update(resolved_brute)

        ordered = sorted(hosts)[: self.limit]
        report.hosts = ordered

        if resolve and ordered:
            report.resolved = sorted(await self.resolve_many(ordered))
        else:
            report.resolved = list(ordered)

        if report.resolved:
            self.console.info(
                f"Subdomain enumeration: {len(report.hosts)} host(s), "
                f"{len(report.resolved)} resolving"
            )
        return report


def builtin_words() -> Tuple[str, ...]:
    return _BUILTIN_WORDS


__all__ = [
    "SubdomainReport",
    "SubdomainFinder",
    "normalize_host",
    "root_domain",
    "parse_crtsh",
    "parse_certspotter",
    "parse_hackertarget",
    "parse_otx",
    "parse_urlscan",
    "parse_rapiddns",
    "builtin_words",
]
