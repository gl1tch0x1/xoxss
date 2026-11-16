"""CLI application layer for XOX$$.

``xoxss.scanner`` owns the scanning engine; this module owns the command-line
entry point: argument parsing, profile/limit normalisation, mode dispatch and
top-level error handling.  Keeping it separate makes :func:`xoxss.scanner.main`
a thin, lazily-imported proxy and stops the scanner monolith from growing a UI
layer on top of the detection logic.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import traceback
from pathlib import Path
from typing import List, Optional, Sequence, Set

from xoxss import scanner as _scanner
from xoxss.core.config import load_dotenv
from xoxss.core.finding import meets_fail_threshold
from xoxss.scan.payloads import (
    PAYLOAD_SOURCES,
    cleanup_payload_lists,
    download_payload_lists,
    payload_workdir,
)
from xoxss.scanner import (
    HAS_AIOHTTP,
    HAS_BS4,
    HAS_PARAM_AUDIT,
    HAS_RECON,
    _ui,
    apply_god_preset,
    build_parser,
    encoder_names,
    install_uvloop,
    print_encoders,
    print_payload_catalog,
    print_payloads,
    print_tampers,
    resolve_headless,
    run_doctor,
    run_mass,
    run_param_audit,
    run_replay,
    run_targets,
)
from xoxss.utils.console import Console, banner, bcolors


def _parse_args(
    argv: Optional[Sequence[str]],
) -> tuple[argparse.Namespace, Set[str], bool]:
    """Load dotenv files, parse argv and derive the explicit-flag set."""
    load_dotenv()
    raw_args = list(argv) if argv is not None else sys.argv[1:]
    # Decide about colour before argparse renders --help, so `--no-color --help`
    # is plain even on a TTY.
    if "--no-color" in raw_args or os.environ.get("NO_COLOR"):
        bcolors.disable()
        if _ui is not None:
            _ui.disable()
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "config", None):
        load_dotenv(args.config, override=True)
    # ``--fail-on-findings`` predates ``--fail-on`` and is its "any" shorthand.
    if not getattr(args, "fail_on", None):
        args.fail_on = "any" if getattr(args, "fail_on_findings", False) else None
    explicit_flags = {token.split("=", 1)[0] for token in raw_args if token.startswith("--")}
    god_mode_requested = "--god" in explicit_flags or "--yolo" in explicit_flags
    if args.ai_only:
        args.ai = True
    return args, explicit_flags, god_mode_requested


def _apply_profile(
    args: argparse.Namespace, explicit_flags: Set[str], god_mode_requested: bool
) -> None:
    """Apply the ``quick``/``deep`` profile presets."""
    if args.profile == "quick" and not god_mode_requested:
        if "--crawl" not in explicit_flags and "--deep" not in explicit_flags:
            args.crawl = False
        if not {"--no-browser", "--browser", "--confirm"}.intersection(explicit_flags):
            args.no_browser = True
        if "--no-remote-payloads" not in explicit_flags and "--remote-payloads" not in explicit_flags:
            args.remote_payloads = False
    elif args.profile == "deep":
        args.deep = True


def _print_requested_listing(args: argparse.Namespace) -> Optional[int]:
    """Handle ``--list-*`` flags before any scanner work starts."""
    if args.list_payloads:
        print_payloads()
        return 0
    if getattr(args, "list_payload_catalog", False):
        print_payload_catalog()
        return 0
    if args.list_tampers:
        print_tampers()
        return 0
    if getattr(args, "list_encoders", False):
        print_encoders()
        return 0
    return None


def _check_inputs(args: argparse.Namespace, console: Console) -> Optional[int]:
    """Validate callback, encoder and OOB combinations."""
    if args.blind:
        if not re.match(r"^https?://", args.blind, re.IGNORECASE):
            console.error("--blind requires an http(s) callback URL, e.g. --blind https://xo.example")
            return 1
        console.info(
            f"Blind XSS: injecting out-of-band probes that call back to {args.blind}",
            important=False,
        )

    if getattr(args, "encoder", None):
        known = set(encoder_names()) if HAS_RECON else set()
        unknown = [name for name in args.encoder if name not in known]
        if unknown:
            console.error(
                "Unknown encoder(s): " + ", ".join(unknown) + ". Run --list-encoders."
            )
            return 1

    if getattr(args, "oob_file", None) and not (args.blind or args.interactsh):
        console.error(
            "--oob-file only reads observed callbacks; pair it with --blind <callback-url> "
            "or use --interactsh for a generated callback."
        )
        return 1
    return None


def _apply_god_mode(
    args: argparse.Namespace, argv: Optional[Sequence[str]], console: Console
) -> None:
    raw_tokens = list(argv) if argv is not None else sys.argv[1:]
    # Normalize `--flag=value` tokens so explicit user settings claim their
    # flag (otherwise god mode would override them).
    user_flags = {
        token.split("=", 1)[0]
        for token in raw_tokens
        if token.startswith("--") and token.split("=", 1)[0] not in ("--god", "--yolo")
    }
    apply_god_preset(args, console, user_flags)
    if _ui is not None and _ui.enabled() and not console.quiet:
        diamond = _ui.glyphs()["diamond"]
        console.raw(
            f"  {bcolors.FAIL}{bcolors.BOLD}{diamond} GOD MODE ENGAGED{bcolors.ENDC}"
            f"{bcolors.DIM}  full-automatic maximum-aggression preset  "
            f"{bcolors.FAIL}{diamond}{bcolors.ENDC}"
        )
    else:
        console.info("GOD MODE engaged: full-automatic maximum-aggression preset applied", important=True)
    console.info(
        f"god preset: crawl depth {args.crawl_depth}/{args.max_urls} URLs/{args.js_files} JS files, "
        f"{args.max_payloads} payloads per point, {args.threads} workers x {args.concurrency} requests, "
        f"browser {'off (HTTP-only)' if args.no_browser else args.browser}, "
        f"OOB {'interactsh' if getattr(args, 'interactsh', None) else ('blind callback' if args.blind else 'off')}",
    )


def _check_recon_support(args: argparse.Namespace, console: Console) -> Optional[int]:
    recon_flags = (
        getattr(args, "subdomains", False)
        or int(getattr(args, "subdomain_brute", 0) or 0) > 0
        or getattr(args, "passive_urls", False)
        or getattr(args, "openapi", False)
        or getattr(args, "fuzz_paths", False)
        or getattr(args, "mine_params", False)
        or getattr(args, "external_tools", False)
    )
    if recon_flags and not HAS_RECON:
        console.error(
            "Reconnaissance modules failed to import: "
            + str(getattr(_scanner, "_RECON_IMPORT_ERROR", "unknown error"))
        )
        return 1
    return None


def _check_required_dependencies(console: Console) -> Optional[int]:
    if not HAS_AIOHTTP:
        console.error("aiohttp is required: pip install -r requirements.txt")
        return 1
    if not HAS_BS4:
        console.error("beautifulsoup4 is required: pip install -r requirements.txt")
        return 1
    return None


def _normalize_limits(args: argparse.Namespace, console: Console) -> None:
    """Clamp user-supplied limits to values the engines can honour."""
    if args.no_browser:
        args.confirm = "http"
    if args.threads < 1:
        args.threads = 1
    if args.concurrency < 1:
        args.concurrency = 1
    if args.max_response_bytes < 1024:
        console.warn("--max-response-bytes is below 1024; using 1024 bytes")
        args.max_response_bytes = 1024
    if args.max_payloads < 1:
        args.max_payloads = 1
    if args.crawl_depth < 1:
        args.crawl_depth = 1
    if args.max_urls < 1:
        args.max_urls = 1
    if args.js_files < 0:
        args.js_files = 0
    if args.fuzz_param_limit < 1:
        args.fuzz_param_limit = 1
    if args.subdomain_brute < 0:
        args.subdomain_brute = 0
    if args.oob_interval < 1:
        args.oob_interval = 1.0
    if args.oob_wait < 0:
        args.oob_wait = 0.0


def _apply_deep_mode(args: argparse.Namespace, explicit_flags: Set[str]) -> None:
    if not args.deep:
        return
    args.crawl = True
    args.crawl_depth = max(args.crawl_depth, 5)
    args.max_urls = max(args.max_urls, 1500)
    args.discover = True
    args.discover_paths = True
    args.fuzz_params = True
    if "--no-path-xss" not in explicit_flags:
        args.path_xss = True


def _run_replay_mode(args: argparse.Namespace, console: Console) -> int:
    install_uvloop()
    try:
        return asyncio.run(run_replay(args, console))
    except KeyboardInterrupt:
        console.warn("Interrupted")
        return 130
    except Exception as exc:
        console.error(f"Replay failed: {exc}")
        if args.verbose:
            console.raw(traceback.format_exc())
        return 1


def _run_param_audit_mode(args: argparse.Namespace, console: Console) -> int:
    if not HAS_PARAM_AUDIT:
        console.error(
            "Parameter-audit modules failed to import: "
            + str(getattr(_scanner, "_PARAM_IMPORT_ERROR", "unknown error"))
        )
        return 1
    console.info(
        "Parameter audit: URL harvest + batched GET/JSON reflection probes",
        important=False,
    )
    install_uvloop()
    code = 0
    try:
        code, reflected = asyncio.run(run_param_audit(args, console))
        if meets_fail_threshold(reflected, args.fail_on):
            code = 2
    except KeyboardInterrupt:
        console.warn("Interrupted")
        code = 130
    except Exception as exc:
        console.error(f"Fatal error: {exc}")
        if args.verbose:
            console.raw(traceback.format_exc())
        code = 1
    return code


def _run_mass_mode(args: argparse.Namespace, console: Console) -> int:
    if args.blind:
        console.warn("--blind is ignored in mass mode (HTTP-only sweep)")
    console.info("Mass mode: stateless HTTP sweep (no crawl, browser or reports)", important=False)
    install_uvloop()
    code = 0
    try:
        code, findings = asyncio.run(run_mass(args, console))
        if meets_fail_threshold(findings, args.fail_on):
            code = 2
    except KeyboardInterrupt:
        console.warn("Interrupted")
        code = 130
    except Exception as exc:
        console.error(f"Fatal error: {exc}")
        if args.verbose:
            console.raw(traceback.format_exc())
        code = 1
    return code


def _run_full_scan(args: argparse.Namespace, console: Console) -> int:
    """Download optional payload lists, scan every target and clean up."""
    install_uvloop()
    payload_files: List[Path] = []
    payload_dir: Optional[Path] = None
    code = 0
    try:
        if args.remote_payloads:
            sources: List[str] = list(PAYLOAD_SOURCES)
            for extra in args.payload_source or []:
                if extra and extra not in sources:
                    sources.append(str(extra))
            payload_dir = payload_workdir(args.payload_tmp_dir)
            payload_files, payload_dir = download_payload_lists(
                console,
                sources,
                args.payload_limit,
                work_dir=payload_dir,
            )
        args.payload_files = [str(path) for path in payload_files]

        console.start_status()
        code, findings = asyncio.run(run_targets(args, console))
        if meets_fail_threshold(findings, args.fail_on):
            code = 2
    except KeyboardInterrupt:
        console.warn("Interrupted - checkpoints were saved")
        code = 130
    except Exception as exc:
        console.error(f"Fatal error: {exc}")
        if args.verbose:
            console.raw(traceback.format_exc())
        code = 1
    finally:
        console.stop_status()
        cleanup_payload_lists(payload_dir, keep=args.keep_payloads, console=console)
    return code


def main(argv: Optional[Sequence[str]] = None) -> int:
    args, explicit_flags, god_mode_requested = _parse_args(argv)
    _apply_profile(args, explicit_flags, god_mode_requested)

    listing = _print_requested_listing(args)
    if listing is not None:
        return listing

    console = Console(
        verbose=args.verbose, quiet=args.quiet, log_file=args.output,
        events_file=getattr(args, "events_jsonl", None),
    )
    if getattr(args, "doctor", False):
        return run_doctor(console, args)
    if not args.quiet:
        banner(console)

    rejected = _check_inputs(args, console)
    if rejected is not None:
        return rejected

    if getattr(args, "god", False):
        _apply_god_mode(args, argv, console)

    rejected = _check_recon_support(args, console)
    if rejected is not None:
        return rejected
    rejected = _check_required_dependencies(console)
    if rejected is not None:
        return rejected

    _normalize_limits(args, console)
    _apply_deep_mode(args, explicit_flags)

    # Headed vs headless is resolved from the terminal/CI context unless the
    # operator pinned it with --headless or --show-browser.
    resolve_headless(args, explicit_flags)

    if getattr(args, "replay", None):
        return _run_replay_mode(args, console)

    if args.mass and getattr(args, "param_audit", False):
        console.error("--mass and --param-audit are separate modes; choose one")
        return 1

    if getattr(args, "god", False) and (args.mass or getattr(args, "param_audit", False)):
        console.error("--god is a full-scan preset; it cannot be combined with --mass or --param-audit")
        return 1

    if getattr(args, "param_audit", False):
        return _run_param_audit_mode(args, console)

    if args.mass:
        return _run_mass_mode(args, console)

    if args.jsonl and not args.mass:
        console.warn("--jsonl is only written in --mass mode; full scans use --report json")

    return _run_full_scan(args, console)


__all__ = ["main"]
