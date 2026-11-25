"""The autonomous ``--auto`` workflow.

``run_auto`` is the only public entry point.  It owns the whole lifecycle so
the CLI stays thin:

1. normalise the operator's input (a bare domain is enough);
2. apply the curated ``--auto`` preset without trampling explicit flags;
3. run the main scanner (crawl, map, exploit, browser verification);
4. harvest the surface the scanner discovered;
5. run creative post-scan probes (redirects, host header, cache, CORS, CRLF,
   JSONP, GraphQL, static DOM/postMessage, source maps, secrets);
6. merge probe leads and derive chains;
7. write the reports once, with a coverage matrix that states what was tested.

Everything is bounded: request budgets, mutation limits and URL caps come from
the plan, and an operator override always wins.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple

from xoxss.auto.chains import build_chains
from xoxss.auto.plan import apply_auto_preset, build_plan
from xoxss.auto.probes import AutoProbeRunner, ProbeResult
from xoxss.auto.surface import SurfaceInventory
from xoxss.auto.target import TargetError, normalize_target
from xoxss.core.finding import ScanStats, meets_fail_threshold

_CONFIRMED = ("confirmed", "high")


@dataclass
class AutoCoverage:
    """Coverage counters printed at the end of an auto run."""

    target: str
    urls_total: int = 0
    urls_done: int = 0
    endpoints: int = 0
    parameters: int = 0
    forms: int = 0
    js_urls: int = 0
    injection_points: int = 0
    payloads: int = 0
    requests: int = 0
    browser_checks: int = 0
    subdomains: int = 0
    passive_urls: int = 0
    probe_requests: int = 0
    probe_leads: int = 0
    probe_kinds: Dict[str, int] = field(default_factory=dict)
    chains: int = 0
    findings: int = 0
    confirmed: int = 0
    gaps: List[str] = field(default_factory=list)

    def as_rows(self) -> List[Tuple[str, str]]:
        probe_detail = ", ".join(
            f"{name} x{count}" for name, count in sorted(self.probe_kinds.items())
        )
        return [
            (
                "recon",
                f"subdomains={self.subdomains} passive_urls={self.passive_urls} "
                f"js_files={self.js_urls}",
            ),
            ("crawl", f"{self.urls_done}/{self.urls_total} URLs scanned"),
            (
                "map",
                f"{self.endpoints} endpoint(s), {self.parameters} parameter(s), "
                f"{self.forms} form field(s), {self.injection_points} injection point(s)",
            ),
            (
                "probe",
                f"{self.requests} HTTP request(s), {self.payloads} payload(s), "
                f"{self.browser_checks} browser check(s)",
            ),
            (
                "post-scan probes",
                f"{self.probe_leads} lead(s) from {self.probe_requests} request(s)"
                + (f" [{probe_detail}]" if probe_detail else ""),
            ),
            ("chain", f"{self.chains} chain(s) derived"),
            (
                "report",
                f"{self.findings} finding(s), {self.confirmed} confirmed/high",
            ),
        ]


def _gaps(coverage: AutoCoverage, *, browser: bool) -> List[str]:
    gaps: List[str] = []
    if coverage.urls_total == 0:
        gaps.append("no URLs discovered; check the target and network access")
    if coverage.injection_points == 0:
        gaps.append("no injection points mapped; the site may be static or fully client-rendered")
    if coverage.js_urls == 0:
        gaps.append("no JavaScript files analysed; DOM sinks may be missed")
    if not browser:
        gaps.append("browser confirmation disabled; findings are HTTP-level evidence")
    if coverage.probe_leads == 0:
        gaps.append("no post-scan primitives (redirect/CORS/CRLF/JSONP) observed")
    return gaps


def _in_scope(scanner: Any, url: str) -> bool:
    try:
        return bool(scanner.scope.in_scope(url))
    except Exception:
        return True


def _harvest_surface(scanner: Any) -> SurfaceInventory:
    inventory = SurfaceInventory.from_scanner(scanner)
    inventory.urls = [url for url in inventory.urls if _in_scope(scanner, url)]
    inventory.js_urls = [url for url in inventory.js_urls if _in_scope(scanner, url)]
    return inventory


def _probe_http(scanner: Any, args: Any, console: Any) -> Any:
    from xoxss.core.http import HttpEngine

    return HttpEngine(
        console,
        ScanStats(),
        headers=scanner._parse_headers(getattr(args, "headers", None)),
        cookies=scanner._cookies,
        timeout=float(getattr(args, "timeout", 20) or 20),
        retries=int(getattr(args, "retries", 2) or 2),
        rate=float(getattr(args, "rate_limit", 0) or 0),
        concurrency=max(1, min(int(getattr(args, "concurrency", 16) or 16), 16)),
        per_host_concurrency=max(1, int(getattr(args, "per_host_concurrency", 4) or 4)),
        proxy=getattr(args, "proxy", None),
        insecure=bool(getattr(args, "insecure", False)),
        redirect_scope=scanner.scope.in_scope,
        max_response_bytes=int(
            getattr(args, "max_response_bytes", 5 * 1024 * 1024) or 5 * 1024 * 1024
        ),
        auth_state=getattr(args, "auth_state", None),
        http2=bool(getattr(args, "http2", False)),
        impersonate=getattr(args, "impersonate", None),
        auth_origin=scanner.target,
    )


async def _run_probes(
    scanner: Any,
    inventory: SurfaceInventory,
    args: Any,
    console: Any,
    plan: Any,
) -> Tuple[List[ProbeResult], int]:
    if not inventory.urls:
        return [], 0
    budget = int(plan.budgets.get("probe_limit", 400) or 400)
    max_urls = max(1, min(len(inventory.urls), int(getattr(args, "auto_probe_urls", 80) or 80)))
    http = _probe_http(scanner, args, console)
    try:
        await http.start()
        runner = AutoProbeRunner(
            http,
            console,
            inventory,
            budget=budget,
            max_urls=max_urls,
            concurrency=max(1, min(int(getattr(args, "concurrency", 8) or 8), 8)),
        )
        results = await runner.run()
        scanner.stats.requests += runner.requests
        return results, runner.requests
    finally:
        try:
            await http.close()
        except Exception:
            pass


def _merge_findings(scanner: Any, results: Sequence[ProbeResult]) -> int:
    added = 0
    for result in results:
        if not _in_scope(scanner, result.url):
            continue
        try:
            finding = result.to_finding()
        except Exception as exc:  # pragma: no cover - defensive
            scanner.console.debug(f"auto probe finding rejected: {exc}")
            continue
        if scanner.add_finding(finding):
            added += 1
    return added


def _coverage(
    scanner: Any,
    inventory: SurfaceInventory,
    results: Sequence[ProbeResult],
    plan: Any,
    probe_requests: int = 0,
) -> AutoCoverage:
    stats = scanner.stats
    kinds: Dict[str, int] = {}
    for result in results:
        family = result.kind.split(" (")[0]
        kinds[family] = kinds.get(family, 0) + 1
    findings = list(scanner.findings)
    confirmed = sum(1 for finding in findings if finding.confidence in _CONFIRMED)
    coverage = AutoCoverage(
        target=scanner.target,
        urls_total=int(stats.urls_total),
        urls_done=int(stats.urls_done),
        endpoints=len(inventory.urls),
        parameters=sum(len(names) for names in inventory.parameters.values()),
        forms=len(inventory.forms),
        js_urls=len(inventory.js_urls),
        injection_points=int(stats.points),
        payloads=int(stats.payloads),
        requests=int(stats.requests),
        browser_checks=int(stats.browser_checks),
        subdomains=int(stats.subdomains),
        passive_urls=int(stats.passive_urls),
        probe_requests=probe_requests,
        probe_leads=len(results),
        probe_kinds=kinds,
        chains=sum(
            1
            for finding in findings
            if finding.kind.startswith(("XSS chain", "Secret disclosure chain"))
        ),
        findings=len(findings),
        confirmed=confirmed,
    )
    coverage.gaps = _gaps(
        coverage, browser=not bool(getattr(scanner.args, "no_browser", False))
    )
    return coverage


def _print_coverage(console: Any, coverage: AutoCoverage, plan: Any) -> None:
    console.rule("auto coverage")
    console.raw("")
    width = max(len(label) for label, _ in coverage.as_rows())
    for label, value in coverage.as_rows():
        console.raw(f"  {label.ljust(width)}  {value}")
    console.raw("")
    console.raw(f"  phases: {', '.join(phase.key for phase in plan.phases)}")
    if coverage.gaps:
        console.raw("")
        for gap in coverage.gaps:
            console.warn(f"coverage gap: {gap}", important=False)
    console.raw("")


async def _run_one(
    target: str,
    args: Any,
    console: Any,
    plan: Any,
) -> Tuple[int, int]:
    from xoxss.scanner import XSSScanner

    scanner = XSSScanner(target, args, console)
    previous_defer = getattr(args, "defer_reports", False)
    args.defer_reports = True
    try:
        await scanner.run()
        inventory = _harvest_surface(scanner)
        results, probe_requests = await _run_probes(
            scanner, inventory, args, console, plan
        )
        _merge_findings(scanner, results)
        for chain in build_chains(list(scanner.findings)):
            scanner.add_finding(chain.finding)
        coverage = _coverage(scanner, inventory, results, plan, probe_requests)
    finally:
        args.defer_reports = previous_defer
        if scanner.pool is not None:
            try:
                await scanner.pool.stop()
            except Exception:
                pass
            scanner.pool = None

    console.rule("reports & summary")
    scanner.print_summary()
    _print_coverage(console, coverage, plan)
    scanner.write_reports()
    actionable = sum(
        1 for finding in scanner.findings if finding.confidence in _CONFIRMED
    )
    return (2 if meets_fail_threshold(scanner.findings, args.fail_on) else 0), actionable


async def run_auto(args: Any, console: Any) -> Tuple[int, int]:
    """Run the autonomous workflow for every requested target."""
    from xoxss.scanner import gather_targets

    raw_targets = gather_targets(args, console)
    if raw_targets is None:
        return 1, 0
    if not raw_targets:
        console.error(
            "auto mode needs a target: pass a domain (example.com) or --target-list"
        )
        return 1, 0

    targets: List[str] = []
    for raw in raw_targets:
        try:
            target = normalize_target(raw)
        except TargetError as exc:
            console.error(f"invalid target {raw!r}: {exc}")
            continue
        if target not in targets:
            targets.append(target)
    if not targets:
        console.error("no valid target after normalisation")
        return 1, 0

    explicit = set(getattr(args, "_explicit_flags", set()) or set())
    if not getattr(args, "_auto_preset_applied", False):
        apply_auto_preset(args, console, explicit)
    plan = build_plan(targets[0], args)
    console.info(
        f"auto target(s): {', '.join(targets)}",
        important=False,
    )

    code = 0
    actionable = 0
    for index, target in enumerate(targets, 1):
        if len(targets) > 1:
            console.raw("")
            console.info(f"[{index}/{len(targets)}] {target}")
        try:
            target_code, target_actionable = await _run_one(target, args, console, plan)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            console.error(f"auto scan failed for {target}: {exc}")
            if getattr(args, "verbose", False):
                import traceback

                console.raw(traceback.format_exc())
            code = max(code, 1)
            continue
        code = max(code, target_code)
        actionable += target_actionable

    return code, actionable


__all__ = ["AutoCoverage", "run_auto"]
