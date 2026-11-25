"""Phased attack plan for the autonomous scanner.

``--auto`` is not "god mode with a different name".  It is a curated plan:
recon first, then crawl, then map every injection surface, then probe and
exploit with escalating techniques, then verify and chain.  Every phase has a
budget and every flag is only raised when the operator did not set it
explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Set, Tuple


@dataclass(frozen=True)
class AutoPhase:
    """One stage of the autonomous workflow."""

    key: str
    title: str
    objective: str
    techniques: Tuple[str, ...]
    budget: Dict[str, int] = field(default_factory=dict)


AUTO_PHASES: Tuple[AutoPhase, ...] = (
    AutoPhase(
        key="recon",
        title="Reconnaissance",
        objective="Find every endpoint on the supplied origin before touching a parameter.",
        techniques=(
            "robots.txt / sitemap.xml / security.txt",
            "historical URLs (Wayback, Common Crawl, OTX)",
            "OpenAPI and Swagger discovery",
            "JavaScript endpoint and source-map mining",
            "subdomain enumeration (opt-in: --subdomains)",
        ),
        budget={"max_urls": 1200, "js_files": 80},
    ),
    AutoPhase(
        key="crawl",
        title="Crawl & route discovery",
        objective="Walk the site like a browser: links, forms, SPAs, fragments, service workers.",
        techniques=(
            "breadth-first crawl",
            "SPA hash/history routes",
            "form and input inventory",
            "fragment/hash vectors",
            "browser-driven route discovery",
        ),
        budget={"crawl_depth": 4, "max_urls": 1200, "browser_discovery_pages": 25},
    ),
    AutoPhase(
        key="map",
        title="Surface mapping",
        objective="Turn pages into injection points: query, path, headers, cookies, JSON, GraphQL, WebSocket.",
        techniques=(
            "query/path/form parameters",
            "header and cookie injection",
            "JSON body fields",
            "GraphQL arguments",
            "WebSocket handshakes",
            "postMessage and DOM sources/sinks",
        ),
        budget={"max_param_targets": 200, "fuzz_param_limit": 20},
    ),
    AutoPhase(
        key="probe",
        title="Probe & fingerprint",
        objective="Measure reflection, context, delimiter survival, encoding and WAF behaviour.",
        techniques=(
            "marker reflection",
            "context classification",
            "character matrix",
            "mutation probes",
            "WAF fingerprinting",
        ),
        budget={"mutation_probe_limit": 24, "char_matrix": 1},
    ),
    AutoPhase(
        key="exploit",
        title="Context-aware exploitation",
        objective="Fire the corpus, then mutate until the filter gives up.",
        techniques=(
            "context-aware corpus",
            "polyglots",
            "deterministic mutation/evasion",
            "mXSS",
            "DOM clobbering",
            "dangling markup",
            "CSP bypass",
            "prototype pollution",
            "template injection",
            "JSONP and postMessage",
        ),
        budget={"max_payloads": 24, "auto_evasion_limit": 48},
    ),
    AutoPhase(
        key="verify",
        title="Execution verification",
        objective="Prove execution in a real browser and prove persistence across sessions.",
        techniques=(
            "CDP sink telemetry",
            "dialog/sink confirmation",
            "stored re-fetch in a fresh session",
            "out-of-band callback",
            "screenshot evidence",
        ),
        budget={"stored_pages": 25, "browser_workers": 2},
    ),
    AutoPhase(
        key="chain",
        title="Chain analysis",
        objective="Combine primitives into higher-impact findings instead of reporting isolated hints.",
        techniques=(
            "open redirect + XSS",
            "CORS + XSS",
            "cache poisoning + XSS",
            "host header + XSS",
            "postMessage + DOM sink",
            "JSONP + script inclusion",
            "source map + secret disclosure",
        ),
        budget={"probe_limit": 400},
    ),
    AutoPhase(
        key="report",
        title="Evidence & coverage",
        objective="Write reproducible findings plus a coverage matrix of what was and was not tested.",
        techniques=(
            "confidence grading",
            "deduplication",
            "SARIF/JSON/Markdown/HTML",
            "coverage matrix",
        ),
    ),
)


@dataclass
class AutoPlan:
    """Resolved plan for one target."""

    target: str
    phases: Tuple[AutoPhase, ...] = AUTO_PHASES
    budgets: Dict[str, int] = field(default_factory=dict)
    enabled_techniques: Tuple[str, ...] = ()

    def phase(self, key: str) -> AutoPhase:
        for phase in self.phases:
            if phase.key == key:
                return phase
        raise KeyError(key)

    def summary(self) -> str:
        lines = [f"auto plan for {self.target}"]
        for phase in self.phases:
            lines.append(f"  {phase.key:<7} {phase.title}: {phase.objective}")
        return "\n".join(lines)


def build_plan(target: str, args: Any) -> AutoPlan:
    """Build the resolved plan, taking explicit operator budgets into account."""
    budgets = {
        "max_urls": int(getattr(args, "max_urls", 1200) or 1200),
        "crawl_depth": int(getattr(args, "crawl_depth", 4) or 4),
        "max_payloads": int(getattr(args, "max_payloads", 24) or 24),
        "js_files": int(getattr(args, "js_files", 80) or 80),
        "stored_pages": int(getattr(args, "stored_pages", 25) or 25),
    }
    techniques = tuple(
        technique for phase in AUTO_PHASES for technique in phase.techniques
    )
    return AutoPlan(target=target, budgets=budgets, enabled_techniques=techniques)


def _claimed(user_flags: Set[str], *flags: str) -> bool:
    return any(flag in user_flags for flag in flags)


def _enable(args: Any, dest: str, user_flags: Set[str]) -> None:
    """Enable ``dest`` unless the operator used its ``--no-*`` opt-out."""
    if _claimed(user_flags, f"--no-{dest.replace('_', '-')}"):
        return
    setattr(args, dest, True)


def _bump(args: Any, dest: str, value: int, user_flags: Set[str], flag: str) -> None:
    if _claimed(user_flags, flag):
        return
    current = getattr(args, dest, None)
    if current is None or int(current) < value:
        setattr(args, dest, value)


def apply_auto_preset(args: Any, console: Any, user_flags: Set[str]) -> None:
    """Raise the scanner to autonomous mode without trampling explicit flags.

    The preset is intentionally *safe by default*: state-changing HTTP methods
    (``--bypass-aggressive``) and third-party payload downloads remain off
    unless the operator asked for them.
    """
    args.auto = True
    args._auto_preset_applied = True

    # -- discovery ---------------------------------------------------------
    for dest in (
        "crawl",
        "discover",
        "discover_paths",
        "fuzz",
        "fuzz_params",
        "mine_params",
        "passive_urls",
        "openapi",
        "fuzz_paths",
        "spa_crawl",
        "browser_discovery",
    ):
        _enable(args, dest, user_flags)

    _bump(args, "crawl_depth", 4, user_flags, "--crawl-depth")
    _bump(args, "max_urls", 1200, user_flags, "--max-urls")
    _bump(args, "js_files", 80, user_flags, "--js-files")
    _bump(args, "fuzz_targets", 16, user_flags, "--fuzz-targets")
    _bump(args, "fuzz_words", 200, user_flags, "--fuzz-words")
    _bump(args, "fuzz_budget", 800, user_flags, "--fuzz-budget")
    _bump(args, "fuzz_param_targets", 50, user_flags, "--fuzz-param-targets")
    _bump(args, "max_param_targets", 200, user_flags, "--max-param-targets")
    _bump(args, "browser_discovery_pages", 25, user_flags, "--browser-discovery-pages")

    # -- injection surface -------------------------------------------------
    for dest in (
        "scan_headers",
        "path_xss",
        "fragment_xss",
        "dom",
        "dom_source_probes",
        "stored",
        "char_matrix",
        "mutation_probes",
        "adaptive_payloads",
        "polyglot",
        "per_char_probe",
        "jsonp",
        "csp_analyze",
        "csp_bypass",
        "mxss",
        "proto_pollution",
        "cors_analyze",
        "dom_clobbering",
        "trusted_types",
        "graphql",
        "graphql_xss",
        "websocket",
        "file_upload",
        "postmessage",
        "enhanced_sinks",
        "storage_xss",
        "service_worker",
        "bypass_403",
        "extended_analysis",
        "header_injection",
        "dangling_markup",
        "ast_analysis",
        "framework_bypass",
        "screenshot",
    ):
        _enable(args, dest, user_flags)

    _bump(args, "max_payloads", 24, user_flags, "--max-payloads")
    _bump(args, "payload_limit", 2000, user_flags, "--payload-limit")
    _bump(args, "stored_pages", 25, user_flags, "--stored-pages")
    _bump(args, "mutation_probe_limit", 14, user_flags, "--mutation-probe-limit")
    _bump(args, "param_wordlist_limit", 100, user_flags, "--param-wordlist-limit")
    _bump(args, "header_injection_limit", 24, user_flags, "--header-injection-limit")
    _bump(args, "header_injection_budget", 400, user_flags, "--header-injection-budget")

    # -- performance -------------------------------------------------------
    _bump(args, "threads", 20, user_flags, "--threads")
    _bump(args, "concurrency", 32, user_flags, "--concurrency")
    _bump(args, "per_host_concurrency", 6, user_flags, "--per-host-concurrency")
    _bump(args, "timeout", 25, user_flags, "--timeout")
    _bump(args, "retries", 3, user_flags, "--retries")
    _bump(args, "browser_workers", 2, user_flags, "--browser-workers")

    # -- verification / output --------------------------------------------
    if not getattr(args, "no_browser", False) and not _claimed(
        user_flags, "--confirm"
    ):
        args.confirm = "browser"
    if not _claimed(user_flags, "--report"):
        args.report = "all"
    if not _claimed(user_flags, "--fail-on"):
        # Keep CI semantics opt-in; auto mode should not invent a non-zero exit.
        pass

    # ``--auto`` should not silently download third-party payloads.
    if not _claimed(user_flags, "--remote-payloads", "--no-remote-payloads"):
        args.remote_payloads = False

    # Internal knobs consumed by the scanner/engine.
    args.auto_evasion_limit = int(getattr(args, "auto_evasion_limit", 48) or 48)

    console.info(
        "AUTO MODE: domain-first phased scan "
        f"({len(AUTO_PHASES)} phases, {len(user_flags)} explicit flag(s) preserved)",
        important=True,
    )
    console.info(
        "auto budgets: "
        f"{getattr(args, 'max_urls', 0)} URLs, depth {getattr(args, 'crawl_depth', 0)}, "
        f"{getattr(args, 'max_payloads', 0)} payloads/point, "
        f"{getattr(args, 'js_files', 0)} JS files, "
        f"{getattr(args, 'threads', 0)}x{getattr(args, 'concurrency', 0)} workers, "
        f"browser {getattr(args, 'browser', 'firefox') if not getattr(args, 'no_browser', False) else 'off'}",
        important=False,
    )


__all__ = [
    "AUTO_PHASES",
    "AutoPhase",
    "AutoPlan",
    "apply_auto_preset",
    "build_plan",
]
