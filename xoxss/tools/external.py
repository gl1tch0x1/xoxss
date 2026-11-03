"""
Adapters for external reconnaissance / XSS tools.

The scanner works standalone, but when well-known tools are installed it can
orchestrate them instead of re-implementing their databases:

* ``subfinder``        passive subdomain enumeration
* ``gau`` / ``waybackurls``  historic URLs
* ``katana``           JS-aware crawling (including XHR and form extraction)
* ``ffuf``             fast content discovery
* ``dalfox``           parameter analysis / XSS verification
* ``nuclei``           template-based XSS checks
* ``httpx``            live-host probing

Every command is executed with ``create_subprocess_exec`` (never a shell),
bounded by a timeout and an output cap.  A missing or failing tool is never
fatal: the caller simply gets fewer results.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

try:  # pragma: no cover
    from typing import Protocol
except Exception:  # pragma: no cover
    Protocol = object  # type: ignore


class ConsoleLike(Protocol):  # pragma: no cover
    def info(self, message: str, important: bool = True) -> None: ...
    def warn(self, message: str, important: bool = True) -> None: ...
    def debug(self, message: str) -> None: ...


MAX_OUTPUT = 8_000_000


@dataclass
class ToolResult:
    tool: str
    command: List[str]
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass
class ExternalFinding:
    tool: str
    url: str
    parameter: str = ""
    method: str = "GET"
    payload: str = ""
    evidence: str = ""
    severity: str = "medium"
    template: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity,
            "template": self.template,
        }


@dataclass
class ExternalCrawl:
    urls: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    tool: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"tool": self.tool, "urls": list(self.urls), "forms": list(self.forms)}


def available_tools() -> Dict[str, str]:
    names = (
        "subfinder", "assetfinder", "amass", "findomain",
        "gau", "waybackurls", "katana", "hakrawler", "gospider",
        "ffuf", "feroxbuster", "gobuster", "dirsearch",
        "dalfox", "nuclei", "httpx", "anew", "qsreplace",
    )
    return {name: path for name in names if (path := shutil.which(name))}


def parse_lines(text: str) -> List[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def parse_subfinder(text: str, domain: str = "") -> List[str]:
    hosts: List[str] = []
    for line in parse_lines(text):
        host = line.strip().lower().strip(".")
        if not host or " " in host:
            continue
        if domain and not (host == domain or host.endswith("." + domain)):
            continue
        hosts.append(host)
    return list(dict.fromkeys(hosts))


def parse_url_lines(text: str) -> List[str]:
    urls: List[str] = []
    for line in parse_lines(text):
        if line.startswith(("http://", "https://")):
            urls.append(line)
    return list(dict.fromkeys(urls))


def parse_katana(text: str) -> ExternalCrawl:
    crawl = ExternalCrawl(tool="katana")
    for line in parse_lines(text):
        try:
            row = json.loads(line)
        except Exception:
            if line.startswith(("http://", "https://")):
                crawl.urls.append(line)
            continue
        if not isinstance(row, dict):
            continue
        request = row.get("request") or {}
        endpoint = str(request.get("endpoint") or row.get("url") or "")
        if endpoint.startswith(("http://", "https://")):
            crawl.urls.append(endpoint)
        form = row.get("form") or {}
        if isinstance(form, dict) and form:
            crawl.forms.append(form)
        for item in row.get("forms") or []:
            if isinstance(item, dict):
                crawl.forms.append(item)
    crawl.urls = list(dict.fromkeys(crawl.urls))
    return crawl


def _first(mapping: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = mapping.get(key)
        if value:
            return str(value)
    return ""


def parse_dalfox(text: str) -> List[ExternalFinding]:
    findings: List[ExternalFinding] = []
    for line in parse_lines(text):
        row: Dict[str, Any]
        try:
            parsed = json.loads(line)
            row = parsed if isinstance(parsed, dict) else {"raw": parsed}
        except Exception:
            # Plain mode: [VULN] / [POC] blocks.
            if not re.search(r"\[(?:V|VULN|POC|FOUND)\]", line, re.I):
                continue
            row = {"raw": line}
        url = _first(row, "url", "target", "data", "endpoint")
        if not url:
            blob = json.dumps(row, ensure_ascii=False)
            match = re.search(r"https?://[^\s\"'<>]+", blob)
            url = match.group(0) if match else ""
        if not url:
            continue
        payload = _first(row, "payload", "poc", "proof", "raw")
        parameter = _first(row, "param", "parameter", "name")
        method = _first(row, "method", "verb") or "GET"
        severity = _first(row, "severity", "level") or "medium"
        findings.append(
            ExternalFinding(
                tool="dalfox",
                url=url,
                parameter=parameter,
                method=method.upper(),
                payload=payload,
                evidence=_first(row, "evidence", "message", "raw") or "dalfox reported a finding",
                severity=severity.lower(),
            )
        )
    return _dedupe_findings(findings)


def parse_nuclei(text: str) -> List[ExternalFinding]:
    findings: List[ExternalFinding] = []
    for line in parse_lines(text):
        try:
            row = json.loads(line)
        except Exception:
            continue
        if not isinstance(row, dict):
            continue
        info = row.get("info") or {}
        name = str(info.get("name") or row.get("template-id") or "")
        template = str(row.get("template-id") or "")
        blob = f"{template} {name}".lower()
        if "xss" not in blob and "cross-site" not in blob:
            continue
        url = _first(row, "matched-at", "url", "host", "matched")
        if not url:
            continue
        findings.append(
            ExternalFinding(
                tool="nuclei",
                url=url,
                parameter=_first(row, "matcher-name", "parameter"),
                method=_first(row, "type", "method").upper() if _first(row, "type", "method") else "GET",
                payload=_first(row, "request", "curl-command")[:2000],
                evidence=name or template or "nuclei XSS template matched",
                severity=str(info.get("severity") or "medium").lower(),
                template=template,
            )
        )
    return _dedupe_findings(findings)


def parse_ffuf(text: str) -> List[Dict[str, Any]]:
    stripped = (text or "").strip()
    if not stripped:
        return []
    start = stripped.find("{")
    if start < 0:
        return []
    try:
        payload = json.loads(stripped[start:])
    except Exception:
        return []
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return []
    rows: List[Dict[str, Any]] = []
    for row in results:
        if not isinstance(row, dict):
            continue
        rows.append(
            {
                "url": str(row.get("url") or ""),
                "status": int(row.get("status") or 0),
                "length": int(row.get("length") or 0),
                "words": int(row.get("words") or 0),
                "content_type": str(row.get("content-type") or ""),
                "redirect": str(row.get("redirectlocation") or ""),
            }
        )
    return rows


def _dedupe_findings(findings: Iterable[ExternalFinding]) -> List[ExternalFinding]:
    seen: Set[Tuple[str, str, str]] = set()
    result: List[ExternalFinding] = []
    for finding in findings:
        key = (finding.tool, finding.url.split("#", 1)[0], finding.parameter)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


class ToolRunner:
    """Run an external binary safely with a timeout and output cap."""

    def __init__(self, console: ConsoleLike, *, timeout: float = 120.0, cwd: Optional[str] = None):
        self.console = console
        self.timeout = max(5.0, timeout)
        self.cwd = cwd

    def which(self, name: str) -> str:
        return shutil.which(name) or ""

    async def run(self, tool: str, args: Sequence[str], *, timeout: Optional[float] = None) -> ToolResult:
        binary = self.which(tool)
        command = [binary or tool, *[str(arg) for arg in args]]
        if not binary:
            return ToolResult(tool=tool, command=command, returncode=127, stderr="not installed")
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.cwd,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout or self.timeout
            )
            return ToolResult(
                tool=tool,
                command=command,
                returncode=proc.returncode or 0,
                stdout=(stdout or b"").decode("utf-8", "replace")[:MAX_OUTPUT],
                stderr=(stderr or b"").decode("utf-8", "replace")[:MAX_OUTPUT // 4],
            )
        except asyncio.TimeoutError:
            if proc is not None:
                try:
                    proc.kill()
                    await proc.communicate()
                except Exception:
                    pass
            return ToolResult(tool=tool, command=command, returncode=-1, timed_out=True, stderr="timeout")
        except Exception as exc:
            return ToolResult(tool=tool, command=command, returncode=-1, stderr=str(exc))


class ExternalToolkit:
    """High-level wrappers around the supported tools."""

    def __init__(
        self,
        console: ConsoleLike,
        *,
        tools: Optional[Sequence[str]] = None,
        timeout: float = 120.0,
        max_results: int = 5000,
    ):
        self.console = console
        self.runner = ToolRunner(console, timeout=timeout)
        installed = available_tools()
        requested = [name.strip().lower() for name in (tools or []) if name.strip()]
        if requested and "auto" not in requested:
            self.tools = {name: installed[name] for name in requested if name in installed}
        else:
            self.tools = installed
        self.timeout = max(5.0, timeout)
        self.max_results = max(10, max_results)

    def enabled(self, name: str) -> bool:
        return name in self.tools

    def summary(self) -> str:
        return ", ".join(sorted(self.tools)) if self.tools else "none"

    async def subdomains(self, domain: str) -> List[str]:
        hosts: List[str] = []
        if self.enabled("subfinder"):
            result = await self.runner.run(
                "subfinder", ["-d", domain, "-silent", "-all", "-timeout", "10"], timeout=self.timeout
            )
            hosts.extend(parse_subfinder(result.stdout, domain))
        for tool in ("assetfinder", "findomain"):
            if self.enabled(tool):
                args = [domain] if tool == "assetfinder" else ["-t", domain, "-q"]
                result = await self.runner.run(tool, args, timeout=self.timeout)
                hosts.extend(parse_subfinder(result.stdout, domain))
        hosts = list(dict.fromkeys(hosts))[: self.max_results]
        if hosts:
            self.console.debug(f"External subdomain tools: {len(hosts)} host(s)")
        return hosts

    async def urls(self, domain: str) -> List[str]:
        urls: List[str] = []
        if self.enabled("gau"):
            result = await self.runner.run(
                "gau", ["--subs", domain, "--threads", "5", "--timeout", "20"], timeout=self.timeout
            )
            urls.extend(parse_url_lines(result.stdout))
        if self.enabled("waybackurls"):
            result = await self.runner.run("waybackurls", [domain], timeout=self.timeout)
            urls.extend(parse_url_lines(result.stdout))
        urls = list(dict.fromkeys(urls))[: self.max_results]
        if urls:
            self.console.debug(f"External URL tools: {len(urls)} URL(s)")
        return urls

    async def crawl(self, target: str, depth: int = 3, js_crawl: bool = True) -> ExternalCrawl:
        if not self.enabled("katana"):
            return ExternalCrawl()
        args = [
            "-u", target,
            "-d", str(max(1, depth)),
            "-silent",
            "-jsonl",
            "-timeout", "15",
            "-retry", "1",
            "-fx",
            "-xhr",
            "-kf", "all",
        ]
        if js_crawl:
            args.append("-jc")
        result = await self.runner.run("katana", args, timeout=self.timeout)
        crawl = parse_katana(result.stdout)
        crawl.urls = crawl.urls[: self.max_results]
        if crawl.urls:
            self.console.debug(
                f"katana: {len(crawl.urls)} URL(s), {len(crawl.forms)} form(s)"
            )
        return crawl

    async def discover(self, target: str, wordlist: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.enabled("ffuf"):
            return []
        wordlist = wordlist or self._default_wordlist()
        if not wordlist:
            return []
        url = target.rstrip("/") + "/FUZZ"
        args = [
            "-u", url,
            "-w", wordlist,
            "-of", "json",
            "-s",
            "-ac",
            "-t", "20",
            "-timeout", "10",
            "-fc", "404",
        ]
        result = await self.runner.run("ffuf", args, timeout=self.timeout)
        rows = parse_ffuf(result.stdout)
        if rows:
            self.console.debug(f"ffuf: {len(rows)} path(s) found")
        return rows[: self.max_results]

    def _default_wordlist(self) -> str:
        for candidate in (
            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ):
            if os.path.exists(candidate):
                return candidate
        # Generate a tiny temporary wordlist so ffuf still runs.
        words = ["admin", "api", "app", "backup", "config", "dashboard", "docs",
                 "graphql", "login", "robots.txt", "sitemap.xml", "swagger",
                 "uploads", "user", "v1", "v2", "webhook"]
        handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
        with handle:
            handle.write("\n".join(words))
        return handle.name

    async def dalfox(self, url: str, *, blind: str = "", extra_args: Optional[Sequence[str]] = None) -> List[ExternalFinding]:
        if not self.enabled("dalfox"):
            return []
        args = [
            "url", url,
            "--silent",
            "--no-color",
            "--format", "jsonl",
            "--skip-headless",
            "--timeout", "15",
            "--worker", "20",
        ]
        if blind:
            args.extend(["-b", blind])
        args.extend(extra_args or [])
        result = await self.runner.run("dalfox", args, timeout=self.timeout)
        findings = parse_dalfox(result.stdout)
        if findings:
            self.console.debug(f"dalfox: {len(findings)} finding(s) on {url}")
        return findings

    async def nuclei(self, targets: Sequence[str], *, tags: str = "xss", severity: str = "") -> List[ExternalFinding]:
        if not self.enabled("nuclei") or not targets:
            return []
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
            handle.write("\n".join(targets))
            list_path = handle.name
        args = [
            "-l", list_path,
            "-jsonl",
            "-silent",
            "-tags", tags,
            "-timeout", "10",
            "-retries", "1",
            "-no-color",
        ]
        if severity:
            args.extend(["-severity", severity])
        try:
            result = await self.runner.run("nuclei", args, timeout=self.timeout)
            findings = parse_nuclei(result.stdout)
        finally:
            try:
                os.unlink(list_path)
            except OSError:
                pass
        if findings:
            self.console.debug(f"nuclei: {len(findings)} XSS template match(es)")
        return findings

    async def live_hosts(self, hosts: Sequence[str]) -> List[str]:
        if not self.enabled("httpx") or not hosts:
            return []
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
            handle.write("\n".join(hosts))
            list_path = handle.name
        try:
            result = await self.runner.run(
                "httpx",
                ["-l", list_path, "-silent", "-no-color", "-timeout", "10", "-retries", "1"],
                timeout=self.timeout,
            )
            return parse_url_lines(result.stdout)
        finally:
            try:
                os.unlink(list_path)
            except OSError:
                pass


__all__ = [
    "ToolResult",
    "ExternalFinding",
    "ExternalCrawl",
    "ToolRunner",
    "ExternalToolkit",
    "available_tools",
    "parse_subfinder",
    "parse_url_lines",
    "parse_katana",
    "parse_dalfox",
    "parse_nuclei",
    "parse_ffuf",
]
