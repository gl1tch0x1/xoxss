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
* ``arjun`` / ``x8``    hidden parameter discovery

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
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlsplit

class ConsoleLike(Protocol):  # pragma: no cover
    def info(self, message: str, important: bool = False) -> None: ...
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
        "ffuf", "feroxbuster", "gobuster", "dirsearch", "wfuzz",
        "dalfox", "nuclei", "httpx", "arjun", "x8", "anew", "qsreplace", "kxss",
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


def parse_arjun_json(text: str) -> Dict[str, List[str]]:
    """Parse Arjun JSON exports into ``{url: [parameter, ...]}`` mappings.

    Arjun versions have emitted both URL-keyed maps and row-oriented objects;
    accept either shape and tolerate progress text surrounding the JSON.
    """
    raw = (text or "").strip()
    if not raw:
        return {}
    start = min((i for i in (raw.find("{"), raw.find("[")) if i >= 0), default=-1)
    if start >= 0:
        end = max(raw.rfind("}"), raw.rfind("]"))
        if end >= start:
            raw = raw[start:end + 1]
    try:
        document = json.loads(raw)
    except Exception:
        # Some builds write one JSON object per line.
        rows: List[Any] = []
        for line in (text or "").splitlines():
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
        document = rows

    output: Dict[str, Set[str]] = {}
    parameter_fields = {
        "params", "parameters", "found", "found_params", "found_parameters",
        "parameter_names", "get", "post", "json", "xml",
    }

    def names(value: Any, *, under_parameter_field: bool = False) -> Set[str]:
        found: Set[str] = set()
        if isinstance(value, str):
            if under_parameter_field and value.strip():
                found.add(value.strip())
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    found.add(item.strip())
                else:
                    found.update(names(item, under_parameter_field=under_parameter_field))
        elif isinstance(value, dict):
            for key, item in value.items():
                key_lower = str(key).lower()
                if key_lower in parameter_fields:
                    found.update(names(item, under_parameter_field=True))
                elif under_parameter_field and key_lower in ("name", "parameter", "param") and isinstance(item, str):
                    if item.strip():
                        found.add(item.strip())
                elif under_parameter_field and isinstance(item, (bool, int, float)) and item:
                    found.add(str(key))
                elif isinstance(item, (dict, list)):
                    found.update(names(item, under_parameter_field=under_parameter_field))
        return found

    def visit(value: Any, inherited_url: str = "") -> None:
        if isinstance(value, list):
            for item in value:
                visit(item, inherited_url)
            return
        if not isinstance(value, dict):
            return
        row_url = str(value.get("url") or value.get("target") or value.get("endpoint") or inherited_url)
        if row_url.startswith(("http://", "https://")):
            found = names(value)
            if found:
                output.setdefault(row_url, set()).update(found)
        for key, item in value.items():
            key_text = str(key)
            if key_text.startswith(("http://", "https://")):
                found = names(item)
                if found:
                    output.setdefault(key_text, set()).update(found)
            elif isinstance(item, (dict, list)):
                visit(item, row_url)

    visit(document)
    return {url: sorted(params) for url, params in output.items() if params}


def parse_x8_json(text: str, url: str = "") -> Dict[str, List[str]]:
    """Parse x8 JSON output, attaching a URL when its format omits one."""
    parsed = parse_arjun_json(text)
    if url and not parsed:
        # x8's json output has varied; fall back to collecting explicit
        # parameter-name arrays from a JSON object without treating text as names.
        try:
            document = json.loads((text or "").strip())
        except Exception:
            document = None
        collected: Set[str] = set()
        def collect(value: Any) -> None:
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        collected.add(item.strip())
                    else:
                        collect(item)
            elif isinstance(value, dict):
                named = value.get("name") or value.get("parameter") or value.get("param")
                if isinstance(named, str) and named.strip():
                    collected.add(named.strip())
                for key, item in value.items():
                    if str(key).lower() in (
                        "parameters", "params", "found", "found_params",
                        "found_parameters", "parameter_names",
                    ):
                        collect(item)

        if isinstance(document, dict):
            for key in ("parameters", "params", "found", "found_params", "found_parameters", "parameter_names"):
                value = document.get(key)
                collect(value)
        if collected:
            parsed[url] = sorted(collected)
    return parsed


def parse_kxss(text: str) -> List[Tuple[str, str, str]]:
    """Parse kxss unfiltered character findings into (url, param, unfiltered_chars)."""
    results: List[Tuple[str, str, str]] = []
    pattern = re.compile(
        r"(?:URL:\s*)?(https?://[^\s\"']+)\s+(?:Param|param):\s*(\S+)\s+(?:Unfiltered|unfiltered):\s*\[([^\]]*)\]",
        re.I,
    )
    for line in parse_lines(text):
        m = pattern.search(line)
        if m:
            url, param, chars = m.groups()
            results.append((url, param, chars.replace(" ", "")))
        else:
            m2 = re.search(r"(https?://\S+)\s+\[([^\]]+)\]", line)
            if m2:
                url, chars = m2.groups()
                parts = urlsplit(url)
                params = [k for k, _ in parse_qsl(parts.query)]
                param = params[0] if params else ""
                results.append((url, param, chars.replace(" ", "")))
    return results


def parse_wfuzz_json(text: str) -> List[ExternalFinding]:
    """Parse wfuzz JSON results into ExternalFinding instances."""
    findings: List[ExternalFinding] = []
    for line in parse_lines(text):
        try:
            items = json.loads(line)
            if not isinstance(items, list):
                items = [items]
            for row in items:
                if not isinstance(row, dict):
                    continue
                url = str(row.get("url") or "")
                payload = str(row.get("payload") or "")
                code = int(row.get("code") or 0)
                if url and code in (200, 301, 302, 500):
                    findings.append(
                        ExternalFinding(
                            tool="wfuzz",
                            url=url,
                            payload=payload,
                            evidence=f"HTTP {code}",
                            severity="medium" if code == 200 else "low",
                        )
                    )
        except Exception:
            continue
    return findings


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

    async def run(
        self,
        tool: str,
        args: Sequence[str],
        *,
        input_text: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> ToolResult:
        binary = self.which(tool)
        command = [binary or tool, *args]
        if not binary:
            return ToolResult(tool=tool, command=command, returncode=127, stderr="not installed")
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if input_text is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.cwd,
            )
            if input_text is not None and proc.stdin:
                try:
                    proc.stdin.write(input_text.encode("utf-8", errors="replace"))
                    await proc.stdin.drain()
                except Exception:
                    pass
                finally:
                    proc.stdin.close()
            stdout_data = await self._read_stream(proc.stdout, MAX_OUTPUT)
            stderr_data = await self._read_stream(proc.stderr, MAX_OUTPUT // 4 + 256)
            await asyncio.wait_for(proc.wait(), timeout=timeout or self.timeout)
            return ToolResult(
                tool=tool,
                command=command,
                returncode=proc.returncode or 0,
                stdout=stdout_data.decode("utf-8", "replace"),
                stderr=stderr_data.decode("utf-8", "replace"),
            )
        except asyncio.TimeoutError:
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass
            return ToolResult(tool=tool, command=command, returncode=-1, timed_out=True, stderr="timeout")
        except Exception as exc:
            return ToolResult(tool=tool, command=command, returncode=-1, stderr=str(exc))

    @staticmethod
    async def _read_stream(stream: Optional[asyncio.StreamReader], limit: int) -> bytes:
        """Read a child stream while keeping at most ``limit`` bytes in memory.

        Trailing output beyond the cap is drained (not stored) so the child
        never deadlocks on a full pipe, but a runaway tool cannot exhaust the
        host's memory either.
        """
        if stream is None:
            return b""
        buffer = bytearray()
        try:
            while True:
                block = await stream.read(65536)
                if not block:
                    break
                if len(buffer) < limit:
                    buffer.extend(block[: limit - len(buffer)])
        except Exception:
            pass
        return bytes(buffer)


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
        temp_path: Optional[str] = None
        if not wordlist:
            wordlist, temp_path = self._default_wordlist()
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
        try:
            result = await self.runner.run("ffuf", args, timeout=self.timeout)
            rows = parse_ffuf(result.stdout)
            if rows:
                self.console.debug(f"ffuf: {len(rows)} path(s) found")
            return rows[: self.max_results]
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def _default_wordlist(self) -> Tuple[str, Optional[str]]:
        """Return ``(selected_wordlist, temp_path_to_unlink)``."""
        for candidate in (
            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ):
            if os.path.exists(candidate):
                return candidate, None
        # Generate a tiny temporary wordlist so ffuf still runs; the caller
        # unlinks it after the run.
        words = ["admin", "api", "app", "backup", "config", "dashboard", "docs",
                 "graphql", "login", "robots.txt", "sitemap.xml", "swagger",
                 "uploads", "user", "v1", "v2", "webhook"]
        handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
        with handle:
            handle.write("\n".join(words))
        return handle.name, handle.name

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

    async def parameters(self, urls: Sequence[str]) -> Dict[str, List[str]]:
        """Run installed hidden-parameter tools and merge their results by URL."""
        if not urls or not (self.enabled("arjun") or self.enabled("x8") or self.enabled("wfuzz")):
            return {}
        merged: Dict[str, Set[str]] = {}
        names: Sequence[str] = (
            "admin", "callback", "debug", "dest", "email", "file", "id", "lang",
            "next", "page", "q", "query", "redirect", "return", "search", "url",
        )
        try:
            from xoxss.scan.fuzzer import PARAM_WORDS
            names = PARAM_WORDS
        except Exception:
            pass
        wordlist_handle = tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        )
        with wordlist_handle:
            wordlist_handle.write("\n".join(names) + "\n")
        wordlist = wordlist_handle.name
        try:
            semaphore = asyncio.Semaphore(4)

            async def inspect_url(url: str) -> Dict[str, Set[str]]:
                found: Dict[str, Set[str]] = {}
                async with semaphore:
                    if self.enabled("arjun"):
                        handle = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
                        output_path = handle.name
                        handle.close()
                        try:
                            result = await self.runner.run(
                                "arjun",
                                ["-u", url, "-m", "GET", "--disable-redirects", "-oJ", output_path],
                                timeout=self.timeout,
                            )
                            try:
                                exported = Path(output_path).read_text(encoding="utf-8", errors="replace")
                            except OSError:
                                exported = ""
                            for found_url, params in parse_arjun_json(exported or result.stdout).items():
                                found.setdefault(found_url, set()).update(params)
                        except Exception as exc:
                            self.console.debug(f"arjun failed for {url}: {exc}")
                        finally:
                            try:
                                os.unlink(output_path)
                            except OSError:
                                pass
                    if self.enabled("x8"):
                        handle = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
                        output_path = handle.name
                        handle.close()
                        try:
                            result = await self.runner.run(
                                "x8", ["-u", url, "-w", wordlist, "-O", "json", "-o", output_path],
                                timeout=self.timeout,
                            )
                            try:
                                exported = Path(output_path).read_text(encoding="utf-8", errors="replace")
                            except OSError:
                                exported = ""
                            for found_url, params in parse_x8_json(exported or result.stdout, url).items():
                                found.setdefault(found_url, set()).update(params)
                        except Exception as exc:
                            self.console.debug(f"x8 failed for {url}: {exc}")
                        finally:
                            try:
                                os.unlink(output_path)
                            except OSError:
                                pass
                    if not found and self.enabled("wfuzz"):
                        try:
                            wfuzz_hits = await self.fuzz_wfuzz(url, wordlist, param_fuzz=True)
                            for hit in wfuzz_hits:
                                if hit.parameter:
                                    found.setdefault(hit.url or url, set()).add(hit.parameter)
                        except Exception as exc:
                            self.console.debug(f"wfuzz failed for {url}: {exc}")
                return found

            results = await asyncio.gather(*(
                inspect_url(url)
                for url in list(dict.fromkeys(urls))[: min(100, self.max_results)]
            ), return_exceptions=True)
            for result in results:
                if not isinstance(result, dict):
                    self.console.debug(f"External parameter worker failed: {result}")
                    continue
                for found_url, params in result.items():
                    merged.setdefault(found_url, set()).update(params)
        finally:
            try:
                os.unlink(wordlist)
            except OSError:
                pass
        return {url: sorted(params) for url, params in merged.items() if params}

    async def probe_kxss(self, urls: Sequence[str]) -> List[Tuple[str, str, str]]:
        """Run kxss on targets to rapidly identify unescaped reflected characters."""
        if not urls or not self.enabled("kxss"):
            return []
        input_data = "\n".join(dict.fromkeys(urls))
        try:
            result = await self.runner.run(
                "kxss",
                [],
                input_text=input_data,
                timeout=self.timeout,
            )
            return parse_kxss(result.stdout)
        except Exception as exc:
            self.console.debug(f"kxss failed: {exc}")
            return []

    async def fuzz_wfuzz(
        self,
        url: str,
        wordlist_path: str,
        *,
        param_fuzz: bool = True,
    ) -> List[ExternalFinding]:
        """Run wfuzz against an endpoint to discover parameters or reflected inputs."""
        if not url or not wordlist_path or not self.enabled("wfuzz"):
            return []
        target = url
        if param_fuzz and "FUZZ" not in target:
            sep = "&" if "?" in target else "?"
            target = f"{target}{sep}FUZZ=xoxss"
        handle = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        output_path = handle.name
        handle.close()
        try:
            result = await self.runner.run(
                "wfuzz",
                ["-w", wordlist_path, "--sc", "200,301,302", "-f", f"{output_path},json", target],
                timeout=self.timeout,
            )
            try:
                exported = Path(output_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                exported = ""
            return parse_wfuzz_json(exported or result.stdout)
        except Exception as exc:
            self.console.debug(f"wfuzz failed for {url}: {exc}")
            return []
        finally:
            try:
                os.unlink(output_path)
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
    "parse_arjun_json",
    "parse_x8_json",
    "parse_kxss",
    "parse_wfuzz_json",
]
