#!/usr/bin/env python3
"""
XOXSS interactive installer.

Installs the scanner package plus its required dependencies from the
repository checkout, then offers the optional extras (interactsh,
Playwright, development tooling).

Usage:
    python installer.py              # interactive: asks about each optional extra
    python installer.py -y           # non-interactive: install everything, extras included
    python installer.py --check      # verify prerequisites and current state only
    python installer.py --no-extras  # skip the optional extras entirely

The script never modifies Python itself beyond `pip install` operations
performed through the running interpreter (`sys.executable -m pip`), so it is
safe to run inside virtual environments.
"""

from __future__ import annotations

import argparse
import importlib
import shutil
import subprocess
import sys
from pathlib import Path

MIN_PYTHON = (3, 9)

ROOT = Path(__file__).resolve().parent

sys.path.insert(0, str(ROOT))
try:
    from xoxss.utils import ui
except Exception:  # engine optional; scripts must install even from a broken checkout
    ui = None

# (extra name, import probe, one-line description)
OPTIONAL_EXTRAS = [
    ("interactsh", "cryptography", "native interactsh client for blind-XSS callbacks"),
    ("playwright", "playwright", "Playwright browser-verification backend"),
    ("dev", "pytest", "test / type-check tooling for development"),
]

REQUIRED_IMPORTS = [
    ("aiohttp", "aiohttp"),
    ("beautifulsoup4", "bs4"),
    ("selenium", "selenium"),
    ("webdriver-manager", "webdriver_manager"),
]


def _emit(label: str, color: str, message: str, stream=sys.stdout) -> None:
    if ui is not None and ui.enabled():
        print(
            f"{ui.paint('[', ui.GREY)}{ui.paint(label, color)}"
            f"{ui.paint(']', ui.GREY)} {message}", file=stream,
        )
    else:
        print(f"[{label}] {message}", file=stream)


def info(message: str) -> None:
    _emit("+", ui.GREEN if ui else "", message)


def warn(message: str) -> None:
    _emit("!", ui.YELLOW if ui else "", message)


def step(message: str) -> None:
    if ui is not None and ui.enabled():
        print(f"{ui.paint(ui.glyphs()['arrow'] + ' ', ui.BRAND_BRIGHT, ui.BOLD)}{message}")
    else:
        print(f"->  {message}")


def section(title: str) -> None:
    print()
    if ui is not None and ui.enabled():
        print(ui.rule(title))
    else:
        print(f"-- {title.upper()} " + "-" * 44)


def die(message: str, code: int = 1) -> "None":
    warn(message)
    sys.exit(code)


def is_maybe_interactive() -> bool:
    """Best-effort guess whether stdin is an interactive terminal."""
    return sys.stdin is not None and sys.stdin.isatty()


def module_available(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except Exception:
        return False


def pip(args: list[str], *, capture: bool = False) -> int:
    """Run pip through the same interpreter that runs this script."""
    command = [sys.executable, "-m", "pip", *args]
    if capture:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0 and result.stderr.strip():
            print(result.stderr.strip()[-800:])
        return result.returncode
    result = subprocess.run(command)
    return result.returncode


def git_available() -> bool:
    return shutil.which("git") is not None


def precheck() -> bool:
    """Verify it makes sense to install; returns True when all is well."""
    if sys.version_info < MIN_PYTHON:
        die(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required; "
            f"you are running {sys.version_info.major}.{sys.version_info.minor}.")
    info(f"Python {sys.version_info.major}.{sys.version_info.minor} "
         f"({sys.executable})")

    if pip(["--version"], capture=True) != 0:
        die("pip is not available for this interpreter. "
            "Re-run with the Python that shipped pip, or install pip first.")
    info("pip available")

    if not (ROOT / "pyproject.toml").exists():
        die(f"This script must run from an XOXSS repository checkout; "
            f"no pyproject.toml found next to {Path(__file__).name}.")
    info(f"Repository checkout found: {ROOT}")

    if not git_available():
        warn("git is not on PATH; only needed by updater.py, not for installation.")
    return True


def report_state() -> int:
    """--check: report versions and optional-extra state without changing anything."""
    if ui is not None and ui.enabled():
        print(ui.panel("xoxss installer - state check", [
            f"{ui.paint('python', ui.GREY)}     {sys.version.split()[0]}",
            f"{ui.paint('checkout', ui.GREY)}  {ROOT}",
        ]))
    else:
        print("XOXSS installation check")
        print("=" * 60)
    ok = precheck()
    missing_required = [name for name, mod in REQUIRED_IMPORTS if not module_available(mod)]
    if missing_required:
        warn(f"missing required modules: {', '.join(missing_required)}")
        ok = False
    else:
        info("required modules present (aiohttp, beautifulsoup4, selenium, webdriver-manager)")

    for extra, module, description in OPTIONAL_EXTRAS:
        if module_available(module):
            info(f"optional {extra} present ({description})")
        else:
            warn(f"optional {extra} not installed ({description})")

    installed = (ROOT / "xoxss" / "scanner.py").exists()
    if installed:
        try:
            result = subprocess.run(
                [sys.executable, "-c", "from xoxss.scanner import VERSION; print(VERSION)"],
                capture_output=True, text=True, timeout=30,
            )
            version = result.stdout.strip() or "unknown"
        except Exception:
            version = "unknown"
        info(f"scanner code present (version {version}); try: {sys.executable} -m xoxss --help")
    else:
        warn("xoxss package source not found in this checkout")
        ok = False
    return 0 if ok else 1


def ask(name: str, description: str, default: bool = False) -> bool:
    """Interactive yes/no prompt for one optional extra."""
    suffix = "[Y/n]" if default else "[y/N]"
    if ui is not None and ui.enabled():
        prompt = (f"    {ui.paint('install ' + name + '?', ui.BOLD)} "
                  f"{ui.paint(description, ui.DIM)} "
                  f"{ui.paint(suffix, ui.GREY)} ")
    else:
        prompt = f"    Install {name}? ({description}) {suffix}: "
    try:
        answer = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not answer:
        return default
    return answer in ("y", "yes")


def run_installer(args: argparse.Namespace) -> int:
    if args.check:
        return report_state()

    print()
    if ui is not None and ui.enabled():
        art = "".join(
            f"{ui.paint('XOXSS', ui.BRAND, ui.BOLD)}"
            f"{ui.paint(' · installer', ui.GREY)}"
        )
        print(ui.panel(art, [
            f"{ui.paint('engine', ui.GREY)}   {sys.version.split()[0]}  "
            f"{ui.paint('pip', ui.GREY)} {sys.executable}",
            f"{ui.paint('policy', ui.GREY)}   authorized testing only - know your target",
        ]))
    else:
        print("=" * 60)
        print(" XOXSS installation")
        print("=" * 60)
    print()

    precheck()

    # 1. Refresh packaging tooling (best effort; managed Pythons may refuse).
    step("Upgrading pip / setuptools / wheel (best effort)")
    if pip(["install", "--upgrade", "pip", "setuptools", "wheel"], capture=True) != 0:
        warn("could not upgrade pip tooling; continuing with the installed versions")

    # 2. Core install: package + hard dependencies.
    section("core install")
    step("Installing XOXSS core (package + required dependencies)")
    if pip(["install", "."]) != 0:
        die("core installation failed; see the pip output above for details.", 1)
    info("XOXSS core installed")

    # 3. Optional extras.
    section("optional extras")
    selected: list[str] = []
    if args.no_extras:
        info("optional extras skipped (--no-extras)")
    else:
        auto = args.yes
        if auto:
            selected = [name for name, _module, _desc in OPTIONAL_EXTRAS]
            info(f"--yes: installing all optional extras ({', '.join(selected)})")
        elif not is_maybe_interactive():
            warn("stdin is not interactive; skipping optional extras. "
                 "Re-run with -y to install them automatically.")
        else:
            for name, _module, description in OPTIONAL_EXTRAS:
                if ask(name, description):
                    selected.append(name)
        if not selected:
            info("nothing selected - core scanner only")
        else:
            for name in selected:
                step(f"Installing optional extra '{name}'")
                if pip(["install", f".[{name}]"]) != 0:
                    warn(f"optional extra '{name}' failed; the core scanner still works.")
                    continue
                if name == "playwright":
                    step("Downloading the Chromium browser for Playwright")
                    result = subprocess.run(
                        [sys.executable, "-m", "playwright", "install", "chromium"])
                    if result.returncode != 0:
                        warn("Chromium download failed; run "
                             f"{sys.executable} -m playwright install chromium later.")
                    else:
                        info("Chromium installed")

    # 4. Sanity check.
    section("verify")
    step("Verifying the installation")
    result = subprocess.run(
        [sys.executable, "-m", "xoxss", "--version"],
        capture_output=True, text=True, timeout=60,
    )
    installed_ok = result.returncode == 0
    if installed_ok:
        info(f"scanner reports: {result.stdout.strip()}")
    else:
        warn("could not run `python -m xoxss --version`; inspect with --doctor")

    print()
    if ui is not None and ui.enabled():
        verdict = (f"{ui.paint(ui.glyphs()['tick'] + ' installation complete', ui.GREEN, ui.BOLD)}"
                   if installed_ok else
                   f"{ui.paint('installation finished with warnings', ui.YELLOW, ui.BOLD)}")
        print(ui.panel(verdict, [
            f"{ui.paint('doctor', ui.GREY)}   {sys.executable} -m xoxss --doctor",
            f"{ui.paint('fire', ui.GREY)}    {sys.executable} -m xoxss example.com --god",
            f"{ui.paint('', ui.GREY)}         "
            f"{ui.paint('(authorized targets only)', ui.DIM)}",
            f"{ui.paint('update', ui.GREY)}  {sys.executable} updater.py",
        ]))
    else:
        print("=" * 60)
        info("Installation finished")
        print(f"    next: {sys.executable} -m xoxss --doctor")
        print(f"          {sys.executable} -m xoxss example.com --god   # authorized targets only")
        print("=" * 60)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="installer.py",
        description="Install the XOXSS XSS scanner and its dependencies.",
        epilog="Example: python installer.py -y   (install everything, no prompts)",
    )
    parser.add_argument("-y", "--yes", action="store_true",
                        help="non-interactive mode: install all optional extras too")
    parser.add_argument("--no-extras", action="store_true",
                        help="skip all optional extras (interactsh / playwright / dev)")
    parser.add_argument("--check", action="store_true",
                        help="only verify prerequisites and current state; change nothing")
    args = parser.parse_args()

    try:
        return run_installer(args)
    except KeyboardInterrupt:
        print()
        warn("installation cancelled by user")
        return 130


if __name__ == "__main__":
    sys.exit(main())
