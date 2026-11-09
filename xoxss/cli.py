"""Command-line parser construction for XOXSS."""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Collection

try:  # stdlib-only UI helpers; safe to import before the package is installed
    from xoxss.utils import ui as _ui
except Exception:  # pragma: no cover - standalone checkout edge case
    _ui = None


EXAMPLES = """
examples:
  xoxss https://target.tld --crawl --headless
  xoxss https://target.tld/?q=1 --browser chrome --headless --dom
  xoxss https://target.tld --god
  xoxss https://target.tld --deep --report all
  xoxss -l targets.txt --threads 20 --rate-limit 15 --report all
  xoxss https://target.tld --no-browser --report-reflections --report json
  xoxss https://target.tld --tamper all --max-payloads 12 --scan-headers
  xoxss https://target.tld --stored --stored-pages 20 --screenshot
  xoxss https://target.tld --show-browser          # visible Chromium/Selenium window
  xoxss --replay 1a2b3c4d5e6f7890 --replay-report .xoxss/reports/latest.json

evidence policy:
  default findings require a reflected payload whose breakout delimiters survive
  in an executable context.  Inert reflections and static DOM candidates are
  opt-in leads via --report-reflections; blind findings require a real callback.
"""

_HEADING_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 &/_-]{1,40}):$")
_OPTION_RE = re.compile(r"^(  )(-\S.*?)(\s{2,})(\S.*)$")
_POSITIONAL_RE = re.compile(r"^(  )([A-Za-z][\w.-]*)(\s{2,})(\S.*)$")
_LONE_OPTION_RE = re.compile(r"^(  )(-\S.*)$")
_EXAMPLE_RE = re.compile(r"^(  )(xoxss)(\s+)(.*)$")


def _styled_help(text: str) -> str:
    """Colour an aligned argparse help block without breaking its columns."""
    if _ui is None or not _ui.enabled():
        return text

    out = []
    for line in text.splitlines():
        stripped = line.strip()

        if line.startswith("usage:"):
            line = _ui.paint("usage:", _ui.BRAND, _ui.BOLD) + line[len("usage:"):]
        elif _HEADING_RE.match(line):
            arrow = _ui.glyphs().get("arrow", "->")
            line = (
                _ui.paint(f"{arrow} ", _ui.BRAND, _ui.BOLD)
                + _ui.paint(line, _ui.WHITE, _ui.BOLD)
            )
        else:
            example = _EXAMPLE_RE.match(line)
            option = _OPTION_RE.match(line)
            positional = _POSITIONAL_RE.match(line)
            if example:
                indent, prog, gap, rest = example.groups()
                comment = ""
                match = re.match(r"^(.*?)(\s+#.*)$", rest)
                if match:
                    rest, comment = match.groups()
                styled = _ui.paint(prog, _ui.BRAND, _ui.BOLD)
                styled += gap + _ui.paint(rest, _ui.WHITE)
                if comment:
                    styled += _ui.paint(comment, _ui.GREY)
                line = indent + styled
            elif option:
                indent, invocation, gap, body = option.groups()
                line = (
                    indent
                    + _ui.paint(invocation, _ui.WHITE, _ui.BOLD)
                    + gap
                    + body
                )
            elif _LONE_OPTION_RE.match(line):
                line = line[:2] + _ui.paint(line[2:], _ui.WHITE, _ui.BOLD)
            elif positional:
                indent, name, gap, body = positional.groups()
                line = (
                    indent
                    + _ui.paint(name, _ui.BRAND_BRIGHT)
                    + gap
                    + body
                )

        out.append(line)
    return "\n".join(out)


class XoxssHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Raw argparse help with a restrained red-team palette on a TTY."""

    def format_help(self) -> str:  # noqa: D102 - argparse hook
        return _styled_help(super().format_help())


def build_parser(
    app_name: str,
    version: str,
    default_state_dir: str,
    user_agent: str,
    tamper_names: Collection[str],
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xoxss",
        description=(
            f"{app_name} v{version} - evidence-first, context-aware XSS scanner\n"
            "authorised offensive testing only; every finding ships with a PoC"
        ),
        formatter_class=XoxssHelpFormatter,
        epilog=EXAMPLES,
    )
    parser.add_argument("target", nargs="*", help="target URL(s); http:// is assumed when missing")
    parser.add_argument("-l", "--target-list", help="file with one target URL/domain per line")
    parser.add_argument("--version", action="version", version=f"{app_name} {version}")
    parser.add_argument(
        "--profile", choices=("quick", "balanced", "deep"), default="balanced",
        help="scan preset: quick (HTTP-only, local payloads), balanced (default), or deep",
    )

    crawl = parser.add_argument_group("discovery", "map the attack surface before injecting")
    crawl.add_argument("--crawl", action="store_true", help="crawl the target before scanning")
    crawl.add_argument(
        "--deep",
        action="store_true",
        help="deep crawl preset: depth 5, 1500 URLs, robots/sitemap/JS + path discovery, parameter fuzzing",
    )
    godmode = parser.add_argument_group("god mode", "one flag for the full offensive workflow")
    godmode.add_argument(
        "--god",
        "--yolo",
        dest="god",
        action="store_true",
        help="full-automatic maximum-aggression preset: recon + deep crawl + fuzzing + browser "
        "verification + interactsh blind-XSS + external tools; no other flags needed",
    )
    crawl.add_argument("--crawl-depth", type=int, default=3, help="crawl depth (default: 3)")
    crawl.add_argument("--max-urls", type=int, default=500, help="maximum URLs to scan (default: 500)")
    crawl.add_argument("--allow-subdomains", action="store_true", help="treat subdomains as in scope")
    crawl.add_argument("--include", nargs="+", help="regexes URLs must match")
    crawl.add_argument("--exclude", nargs="+", help="regexes URLs must not match")
    crawl.add_argument(
        "--discover",
        dest="discover",
        action="store_true",
        default=True,
        help="discover endpoints from robots.txt, sitemaps and JavaScript (default: on when crawling)",
    )
    crawl.add_argument("--no-discover", dest="discover", action="store_false", help="disable robots/sitemap/JS discovery")
    crawl.add_argument("--discover-paths", action="store_true", help="probe common endpoint paths")
    crawl.add_argument("--endpoint-wordlist", help="extra endpoint paths to probe, one per line")
    crawl.add_argument("--js-files", type=int, default=25, help="maximum JavaScript files parsed per scan (default: 25)")
    crawl.add_argument(
        "--fuzz-params",
        dest="fuzz_params",
        action="store_true",
        default=False,
        help="test common parameter names on endpoints without a query string",
    )
    crawl.add_argument("--no-fuzz-params", dest="fuzz_params", action="store_false", help="disable parameter fuzzing")
    crawl.add_argument("--fuzz-param-limit", type=int, default=10, help="parameter names per endpoint (default: 10)")
    crawl.add_argument(
        "--subdomains",
        action="store_true",
        help="enumerate passive subdomains (crt.sh, certspotter, OTX, urlscan) before scanning",
    )
    crawl.add_argument(
        "--subdomain-brute",
        type=int,
        default=0,
        metavar="N",
        help="also resolve the first N built-in/wordlist subdomain candidates",
    )
    crawl.add_argument(
        "--passive-urls",
        action="store_true",
        help="collect historic URLs from Wayback, Common Crawl, urlscan and OTX",
    )
    crawl.add_argument(
        "--openapi",
        action="store_true",
        help="discover OpenAPI/Swagger documents and test their query/body parameters",
    )
    crawl.add_argument(
        "--fuzz-paths",
        action="store_true",
        help="brute-force common paths with the internal soft-404-aware fuzzer",
    )
    crawl.add_argument(
        "--mine-params",
        action="store_true",
        help="mine hidden query parameters by response delta and reflection",
    )
    crawl.add_argument(
        "--external-tools",
        action="store_true",
        help="use installed recon, parameter discovery (arjun/x8), and XSS verification tools",
    )
    crawl.add_argument(
        "--max-param-targets", type=int, default=100,
        help="maximum in-scope endpoints sent to external hidden-parameter tools (default: 100)",
    )

    injection = parser.add_argument_group("injection", "payload corpus, evasion and injection points")
    injection.add_argument(
        "--payload-file",
        help="custom payloads or JSON lists ('context|payload' supported; repeat with ':').",
    )
    injection.add_argument(
        "--payload-dir",
        action="append",
        metavar="DIR",
        help="load every .txt/.lst/.json payload corpus under DIR (repeatable)",
    )
    injection.add_argument(
        "--lazy-payloads",
        dest="lazy_payloads",
        action="store_true",
        default=True,
        help="load the bundled LazyXss payload pack (default: on)",
    )
    injection.add_argument(
        "--no-lazy-payloads",
        dest="lazy_payloads",
        action="store_false",
        help="disable the bundled LazyXss payload pack",
    )
    injection.add_argument(
        "--remote-payloads",
        dest="remote_payloads",
        action="store_true",
        default=True,
        help="download XSS payload lists from GitHub into temp storage (default: on)",
    )
    injection.add_argument(
        "--no-remote-payloads",
        dest="remote_payloads",
        action="store_false",
        help="disable the remote payload download",
    )
    injection.add_argument(
        "--payload-source",
        action="append",
        metavar="URL",
        help="extra GitHub raw payload URL (repeatable)",
    )
    injection.add_argument("--payload-limit", type=int, default=600, help="maximum remote payloads to keep (0 = unlimited, capped internally; default: 600)")
    injection.add_argument("--payload-tmp-dir", help="temp directory for downloaded payloads (default: system temp)")
    injection.add_argument("--keep-payloads", action="store_true", help="keep downloaded payloads after the scan")
    injection.add_argument(
        "--tamper",
        choices=sorted(tamper_names) + ["all"],
        help="payload evasion transform",
    )
    injection.add_argument(
        "--encoder",
        action="append",
        metavar="NAME",
        help="encoder registry transform applied after --tamper (repeatable; see --list-encoders)",
    )
    injection.add_argument("--max-payloads", type=int, default=6, help="payloads per injection point (default: 6)")
    injection.add_argument("--mutation-probes", action="store_true", help="probe one endpoint for bounded Unicode, decoding, byte-mask, and multibyte transformations")
    injection.add_argument("--mutation-probe-limit", type=int, default=12, help="maximum transformation probes per endpoint (default: 12, hard cap: 14)")
    injection.add_argument("--adaptive-payloads", action="store_true", help="add bounded whitespace/quote and empirically observed Unicode payload variants")
    injection.add_argument("--scan-headers", action="store_true", help="test header reflection (one marker per header, batched)")
    injection.add_argument("--header-list", nargs="+", help="custom header names to inject")
    injection.add_argument(
        "--exclude-header",
        nargs="+",
        metavar="NAME",
        help="header names to skip during header injection (case-insensitive)",
    )
    injection.add_argument(
        "--path-xss",
        dest="path_xss",
        action="store_true",
        default=False,
        help="test path segments for XSS (append, replace-last, and replace-each)",
    )
    injection.add_argument(
        "--no-path-xss", dest="path_xss", action="store_false", help="disable path-segment XSS testing"
    )
    injection.add_argument(
        "--fragment-xss",
        action="store_true",
        help="test URL fragment/hash vectors in a real browser (fragments never reach the server)",
    )
    injection.add_argument(
        "--char-matrix",
        action="store_true",
        help="probe which special characters survive at each reflection point (allowed/escaped/filtered/replaced)",
    )
    injection.add_argument(
        "--param-wordlist",
        metavar="PATH",
        help="parameter-name wordlist (one name per line) tested on every endpoint",
    )
    injection.add_argument(
        "--param-wordlist-limit",
        type=int,
        default=50,
        help="maximum wordlist parameter names per endpoint (default: 50)",
    )
    injection.add_argument("--dom", dest="dom", action="store_true", default=True, help="DOM XSS analysis (default: on)")
    injection.add_argument("--no-dom", dest="dom", action="store_false", help="disable DOM XSS analysis")
    injection.add_argument("--stored", action="store_true", help="look for persisted (stored) payloads")
    injection.add_argument("--stored-pages", type=int, default=10, help="pages checked for stored XSS (default: 10)")
    injection.add_argument(
        "--report-reflections",
        action="store_true",
        help="also report reflections / static candidates that could not be executed",
    )
    injection.add_argument(
        "--check-libs",
        dest="check_libs",
        action="store_true",
        default=True,
        help="check for vulnerable JavaScript libraries (default: on)",
    )
    injection.add_argument("--no-check-libs", dest="check_libs", action="store_false", help="disable library vulnerability checking")
    injection.add_argument(
        "--blind",
        metavar="CALLBACK_URL",
        help="blind XSS callback URL (XSS Hunter / Burp Collaborator / interactsh); "
        "injects out-of-band probes into every parameter and form",
    )

    oob = parser.add_argument_group("out-of-band", "confirm blind XSS through real callbacks")
    oob.add_argument(
        "--interactsh",
        nargs="?",
        const="oast.pro",
        metavar="SERVER",
        help="register with an interactsh server and poll it to confirm blind-XSS callbacks",
    )
    oob.add_argument(
        "--oob-poll",
        metavar="URL",
        help="poll a JSON/text collector endpoint for markers (XSS Hunter, Burp bridge, ...)",
    )
    oob.add_argument(
        "--oob-file",
        metavar="PATH",
        help="tail a local JSON-lines/text collector file (requires --blind for the callback)",
    )
    oob.add_argument("--oob-interval", type=float, default=5.0, help="seconds between OOB polls (default: 5)")
    oob.add_argument(
        "--oob-wait",
        type=float,
        default=0.0,
        help="seconds to wait after the scan for late out-of-band callbacks",
    )

    # Advanced features (Phase 1 & 2)
    advanced = parser.add_argument_group("advanced", "specialised XSS and browser-side analyses")
    advanced.add_argument("--polyglot", action="store_true", help="use polyglot payloads for faster scanning")
    advanced.add_argument("--per-char-probe", action="store_true", help="use per-character probing for precise context detection")
    advanced.add_argument("--jsonp", action="store_true", help="detect and test JSONP endpoints for XSS")
    advanced.add_argument("--csp-analyze", action="store_true", help="analyze CSP headers for bypass opportunities")
    advanced.add_argument("--mxss", action="store_true", help="detect mutation XSS vulnerabilities")
    advanced.add_argument("--proto-pollution", action="store_true", help="detect prototype pollution vulnerabilities")
    advanced.add_argument("--cors-analyze", action="store_true", help="analyze CORS misconfigurations")
    advanced.add_argument("--smart-rate", action="store_true", help="use adaptive smart rate limiting")
    advanced.add_argument("--dom-clobbering", action="store_true", help="detect DOM clobbering vulnerabilities")
    advanced.add_argument("--trusted-types", action="store_true", help="analyze Trusted Types CSP directive")
    advanced.add_argument("--graphql", action="store_true", help="detect GraphQL XSS vulnerabilities")
    advanced.add_argument("--websocket", action="store_true", help="detect WebSocket XSS vulnerabilities")
    advanced.add_argument(
        "--ws-active", action="store_true",
        help="actively inject marker frames into WebSocket endpoints discovered in page JavaScript (requires --websocket)",
    )
    advanced.add_argument("--file-upload", action="store_true", help="detect file upload XSS vulnerabilities")
    advanced.add_argument("--postmessage", action="store_true", help="detect postMessage XSS vulnerabilities")

    ai_group = parser.add_argument_group("ai fallback", "LLM candidates, still evidence-gated")
    ai_group.add_argument(
        "--ai",
        action="store_true",
        help="ask an LLM for breakout payloads when the standard corpus fails "
        "(candidates still require deterministic reflection/execution evidence)",
    )
    ai_group.add_argument(
        "--ai-only",
        action="store_true",
        help="skip the built-in payload corpus and test only AI-generated candidates (implies --ai)",
    )
    ai_group.add_argument(
        "--ai-key", metavar="KEY", help="API key (default: XOXSS_AI_KEY / OPENROUTER_API_KEY / .env)"
    )
    ai_group.add_argument(
        "--ai-model", metavar="MODEL", help="model id (default: deepseek/deepseek-chat)"
    )
    ai_group.add_argument(
        "--ai-url", metavar="URL", help="chat-completions endpoint (default: OpenRouter)"
    )
    ai_group.add_argument(
        "--ai-timeout", type=float, default=60.0, help="AI request timeout in seconds (default: 60)"
    )

    browser = parser.add_argument_group("browser", "execution verification and authenticated browsing")
    browser.add_argument(
        "--browser",
        choices=["firefox", "chrome", "chromium", "edge", "playwright"],
        default="firefox",
        help="browser backend for verification: selenium firefox/chrome/edge or playwright (default: firefox)",
    )
    browser.add_argument("--headless", action="store_true", help="run the browser headless (default: headless in CI/non-TTY, headed in a terminal)")
    browser.add_argument("--show-browser", action="store_true", help="force a visible (headed) browser window; implies --headless is off")
    browser.add_argument("--no-browser", action="store_true", help="HTTP-only mode (no Selenium)")
    browser.add_argument("--browser-workers", type=int, default=1, help="parallel browser instances (default: 1)")
    browser.add_argument("--browser-discovery", action="store_true", help="visit a bounded sample of crawled pages and scan same-scope XHR/fetch/navigation URLs")
    browser.add_argument("--browser-discovery-pages", type=int, default=10, help="maximum pages visited for browser route discovery (default: 10, max: 25)")
    browser.add_argument("--dom-source-probes", action="store_true", help="actively test storage, window.name, and postMessage DOM XSS sources (adds up to four browser reloads per candidate page)")
    browser.add_argument("--auth-state", metavar="PATH", help="Playwright storage-state JSON for authenticated browser discovery and verification")
    browser.add_argument("--confirm", choices=["auto", "browser", "http"], default="auto", help="verification strategy")
    browser.add_argument("--screenshot", action="store_true", help="save a screenshot for confirmed findings")
    browser.add_argument("--binary", help="explicit browser binary path")
    browser.add_argument("--user-agent", default=user_agent, help="User-Agent override")

    network = parser.add_argument_group("network", "transport, pacing and concurrency")
    network.add_argument("--threads", type=int, default=10, help="parallel URL workers (default: 10)")
    network.add_argument("--concurrency", type=int, default=16, help="parallel HTTP requests (default: 16)")
    network.add_argument("--per-host-concurrency", type=int, default=4, help="maximum simultaneous HTTP requests per host (default: 4)")
    network.add_argument("--timeout", type=float, default=20.0, help="request/browser timeout in seconds")
    network.add_argument("--retries", type=int, default=2, help="retries per request (default: 2)")
    network.add_argument("--rate-limit", type=float, default=0.0, help="requests per second (0 = unlimited)")
    network.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    network.add_argument("--insecure", action="store_true", help="ignore TLS certificate errors")
    network.add_argument(
        "--http2", action="store_true",
        help="multiplex requests over HTTP/2 via curl_cffi (requires the [http2] extra; falls back to aiohttp)",
    )
    network.add_argument(
        "--impersonate", metavar="PROFILE",
        help="curl_cffi browser TLS fingerprint to emulate, e.g. chrome124 or firefox133 (implies the curl transport)",
    )
    network.add_argument(
        "--max-response-bytes", type=int, default=5 * 1024 * 1024,
        metavar="N", help="maximum response body bytes analyzed (default: 5242880)",
    )
    network.add_argument("--headers", nargs="+", help="extra headers: 'Name: Value'")
    network.add_argument(
        "--cookies",
        nargs="+",
        help="cookies: 'name=value', 'a=b; c=d', or a JSON/Netscape cookies.txt path",
    )
    network.add_argument(
        "--cookie-file",
        metavar="PATH",
        help="cookie file (JSON, Playwright storage state, Netscape cookies.txt, or name=value lines)",
    )

    mass = parser.add_argument_group("mass mode", "stateless high-volume sweep")
    mass.add_argument(
        "--mass",
        action="store_true",
        help="stateless fast sweep: one request per parameter, no crawl/browser/state",
    )
    mass.add_argument(
        "--mass-params",
        metavar="NAMES",
        default="",
        help="comma-separated parameters tried on URLs without a query string",
    )
    mass.add_argument(
        "--mass-payloads",
        type=int,
        default=4,
        help="payloads tried per parameter in mass mode (default: 4)",
    )
    mass.add_argument(
        "--jsonl",
        metavar="PATH",
        help="append one JSON finding per line (mass mode or --param-audit)",
    )

    params = parser.add_argument_group("parameter audit", "harvest and reflection-check parameters")
    params.add_argument(
        "--param-audit",
        action="store_true",
        help="collect Wayback parameters and probe each one for reflection (collector + Gxss style) and exit",
    )
    params.add_argument(
        "--param-input",
        metavar="PATH",
        help="read seed URLs from a file (when set alone, Wayback harvesting is skipped)",
    )
    params.add_argument(
        "--param-source",
        choices=["wayback", "passive", "both", "none"],
        help="URL source for --param-audit (default: wayback, or none when --param-input is used)",
    )
    params.add_argument(
        "--param-limit",
        type=int,
        default=5000,
        help="maximum historic URLs to harvest for parameter audit (default: 5000)",
    )
    params.add_argument(
        "--param-max-checks",
        type=int,
        default=10000,
        help="maximum parameter reflection checks per audit (default: 10000)",
    )
    params.add_argument(
        "--param-batch-size", type=int, default=100,
        help="parameter names per reflection request (default: 100, max: 100)",
    )
    params.add_argument(
        "--param-marker",
        default="XoxssReflect",
        help="alphanumeric reflection marker used for each parameter (default: XoxssReflect)",
    )
    params.add_argument(
        "--param-data",
        metavar="BODY",
        help="POST URL-encoded form data or a JSON object for batched reflection checks",
    )
    params.add_argument(
        "--param-output",
        metavar="PATH",
        help="write the parameter-audit JSON report to this file",
    )
    params.add_argument(
        "--param-subs",
        dest="param_subs",
        action="store_true",
        default=True,
        help="include subdomains in Wayback harvesting (default: on)",
    )
    params.add_argument(
        "--no-param-subs",
        dest="param_subs",
        action="store_false",
        help="only harvest the exact host, not its subdomains",
    )

    output = parser.add_argument_group("output", "reports, logs and CI signals")
    output.add_argument("-o", "--output", help="write the full text log to this file")
    output.add_argument("--report", default="all", help="json, md, html, sarif, all or none (default: all)")
    output.add_argument("--report-dir", default=os.path.join(default_state_dir, "reports"), help="report directory")
    output.add_argument(
        "--events-jsonl", metavar="PATH",
        help="write versioned JSONL scan lifecycle, discovery, and finding events",
    )
    output.add_argument("--verbose", action="store_true", help="verbose (debug) output")
    output.add_argument("--quiet", action="store_true", help="only print findings and errors")
    output.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    output.add_argument("--fail-on-findings", action="store_true", help="exit with status 2 when findings exist")
    output.add_argument(
        "--replay",
        metavar="FINDING_ID",
        help="re-run one finding from a previous JSON report (one request + one browser check)",
    )
    output.add_argument(
        "--replay-report",
        metavar="PATH",
        help="JSON report to load for --replay (default: newest *.json in --report-dir)",
    )

    persistence = parser.add_argument_group("persistence", "resume checkpoints and scan state")
    persistence.add_argument("--state-dir", default=default_state_dir, help="state/report root (default: .xoxss)")
    persistence.add_argument("--no-state", action="store_true", help="disable checkpoints")
    persistence.add_argument("--no-resume", action="store_true", help="ignore and reset the existing checkpoint")

    misc = parser.add_argument_group("misc", "utilities and diagnostics")
    misc.add_argument("--list-payloads", action="store_true", help="print built-in payloads and exit")
    misc.add_argument("--doctor", action="store_true", help="check the installation and exit")
    misc.add_argument("--list-tampers", action="store_true", help="print available tampers and exit")
    misc.add_argument(
        "--list-encoders", action="store_true", help="print the encoder registry and exit"
    )
    return parser
