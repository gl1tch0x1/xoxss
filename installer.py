#!/usr/bin/env python3
"""
XOXSS automated installer.

Installs the scanner package plus its required dependencies into an isolated
virtual environment (automatically created so you don't have to manage it manually),
then offers optional extras (interactsh, Playwright, HTTP/2 curl_cffi, AST analysis, dev tooling).

Usage:
    python installer.py              # interactive: creates .venv, installs core, prompts for extras
    python installer.py -y           # non-interactive: creates .venv, installs everything including extras
    python installer.py --check      # verify prerequisites, virtualenv, and package state only
    python installer.py --no-extras  # install core only, skip optional extras
    python installer.py --no-venv    # install directly into current Python without creating/using .venv
"""

from __future__ import annotations

import argparse
import importlib
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path
from typing import Optional

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
    ("http2", "curl_cffi", "HTTP/2 transport with browser TLS impersonation"),
    ("ast", "tree_sitter", "tree-sitter CST analysis for DOM XSS detection"),
    ("dev", "pytest", "test and type-check tooling for development"),
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


def in_venv() -> bool:
    """Return True if running inside a virtual environment."""
    return (
        getattr(sys, "base_prefix", sys.prefix) != sys.prefix
        or hasattr(sys, "real_prefix")
    )


def find_venv_python(venv_dir: Path) -> Optional[Path]:
    """Find the Python executable inside a given virtualenv directory."""
    if os.name == "nt":
        candidates = [venv_dir / "Scripts" / "python.exe", venv_dir / "python.exe"]
    else:
        candidates = [venv_dir / "bin" / "python", venv_dir / "python"]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def ensure_venv(venv_dir: Path) -> Path:
    """Ensure a virtual environment exists; create it if missing."""
    venv_py = find_venv_python(venv_dir)
    if venv_py and venv_py.exists():
        info(f"Found existing virtual environment at {venv_dir}")
        return venv_py

    step(f"Creating isolated Python virtual environment at {venv_dir}...")
    venv_dir.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        builder = venv.EnvBuilder(with_pip=True, clear=False, symlinks=(os.name != "nt"))
        builder.create(venv_dir)
        created = True
    except Exception as exc:
        warn(f"Standard venv module creation failed ({exc}); trying subprocess fallback")

    if not created:
        result = subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], capture_output=True, text=True)
        if result.returncode != 0:
            die(f"Failed to create virtual environment:\n{result.stderr.strip()}")

    venv_py = find_venv_python(venv_dir)
    if not venv_py or not venv_py.exists():
        die(f"Virtual environment created at {venv_dir}, but python binary could not be found.")

    info(f"Virtual environment created successfully at {venv_dir}")
    return venv_py


def create_launcher_scripts(venv_dir: Path) -> None:
    """Create root launcher scripts so the operator never has to manually activate the venv."""
    # 1. Windows launcher: xoxss.bat
    bat_path = ROOT / "xoxss.bat"
    bat_content = (
        "@echo off\r\n"
        "setlocal\r\n"
        "set \"SCRIPT_DIR=%~dp0\"\r\n"
        "if exist \"%SCRIPT_DIR%.venv\\Scripts\\python.exe\" (\r\n"
        "    \"%SCRIPT_DIR%.venv\\Scripts\\python.exe\" -m xoxss %*\r\n"
        ") else if exist \"%SCRIPT_DIR%venv\\Scripts\\python.exe\" (\r\n"
        "    \"%SCRIPT_DIR%venv\\Scripts\\python.exe\" -m xoxss %*\r\n"
        ") else (\r\n"
        "    python -m xoxss %*\r\n"
        ")\r\n"
    )
    try:
        bat_path.write_text(bat_content, encoding="ascii")
    except OSError:
        pass

    # 2. POSIX launcher: xoxss
    sh_path = ROOT / "xoxss"
    sh_content = (
        "#!/usr/bin/env bash\n"
        "set -e\n"
        "DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
        "if [ -f \"$DIR/.venv/bin/python\" ]; then\n"
        "    exec \"$DIR/.venv/bin/python\" -m xoxss \"$@\"\n"
        "elif [ -f \"$DIR/venv/bin/python\" ]; then\n"
        "    exec \"$DIR/venv/bin/python\" -m xoxss \"$@\"\n"
        "else\n"
        "    exec python3 -m xoxss \"$@\"\n"
        "fi\n"
    )
    try:
        sh_path.write_text(sh_content, encoding="utf-8")
        if os.name != "nt":
            sh_path.chmod(0o755)
    except OSError:
        pass


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
    """Run pip through the active interpreter."""
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
    """Verify prerequisites before installing."""
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
    """--check: report versions, virtualenv status, and package state."""
    venv_status = "active virtualenv" if in_venv() else "system Python (no venv active)"
    venv_path = ROOT / ".venv"
    has_stored_venv = venv_path.is_dir()

    if ui is not None and ui.enabled():
        print(ui.panel("xoxss installer - state check", [
            f"{ui.paint('python', ui.GREY)}     {sys.version.split()[0]} ({sys.executable})",
            f"{ui.paint('env', ui.GREY)}        {venv_status}",
            f"{ui.paint('.venv exists', ui.GREY)} {'yes' if has_stored_venv else 'no'}",
            f"{ui.paint('checkout', ui.GREY)}   {ROOT}",
        ]))
    else:
        print("XOXSS installation check")
        print("=" * 60)
        info(f"Python: {sys.version.split()[0]} ({sys.executable})")
        info(f"Environment: {venv_status}")
        info(f".venv directory: {'present' if has_stored_venv else 'not found'}")

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
        info(f"scanner code present (version {version}); run: {sys.executable} -m xoxss --help")
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

    # 1. Virtual environment guard: automatically create & re-exec into .venv
    # so the operator never has to create a virtual environment manually.
    if not in_venv() and not args.no_venv:
        venv_dir = Path(args.venv_dir).resolve() if args.venv_dir else (ROOT / ".venv")
        venv_py = ensure_venv(venv_dir)
        create_launcher_scripts(venv_dir)

        section("switching to virtual environment")
        info(f"Re-executing installer inside {venv_py}")
        env = os.environ.copy()
        env["VIRTUAL_ENV"] = str(venv_dir)
        env.pop("PYTHONHOME", None)
        sub_args = [arg for arg in sys.argv[1:] if arg not in ("--no-venv",)]
        result = subprocess.run([str(venv_py), str(ROOT / "installer.py"), *sub_args], env=env)
        return result.returncode

    # 2. Main install lifecycle (running inside the virtual environment or with --no-venv)
    print()
    if ui is not None and ui.enabled():
        art = "".join(
            f"{ui.paint('XOXSS', ui.BRAND, ui.BOLD)}"
            f"{ui.paint(' · installer', ui.GREY)}"
        )
        print(ui.panel(art, [
            f"{ui.paint('engine', ui.GREY)}   {sys.version.split()[0]}  "
            f"{ui.paint('pip', ui.GREY)} {sys.executable}",
            f"{ui.paint('env', ui.GREY)}      {'virtualenv (.venv)' if in_venv() else 'system Python'}",
            f"{ui.paint('policy', ui.GREY)}   authorized testing only - know your target",
        ]))
    else:
        print("=" * 60)
        print(" XOXSS installation")
        print("=" * 60)
    print()

    precheck()

    # 3. Refresh packaging tooling inside the environment.
    step("Upgrading pip / setuptools / wheel (best effort)")
    if pip(["install", "--prefer-binary", "--upgrade", "pip", "setuptools", "wheel"], capture=True) != 0:
        warn("could not upgrade pip tooling; continuing with existing versions")

    # 4. Core install: package + required dependencies.
    section("core install")
    step("Installing XOXSS core (package + required dependencies)")
    if pip(["install", "--prefer-binary", "--upgrade", "--upgrade-strategy", "only-if-needed", "."]) != 0:
        die("core installation failed; see the pip output above for details.", 1)
    info("XOXSS core installed")

    # 5. Optional extras.
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
                if pip(["install", "--prefer-binary", "--upgrade", "--upgrade-strategy", "only-if-needed", f".[{name}]"]) != 0:
                    warn(f"optional extra '{name}' failed; the core scanner still works.")
                    continue
                if name == "playwright":
                    step("Downloading the Chromium browser for Playwright")
                    result = subprocess.run(
                        [sys.executable, "-m", "playwright", "install", "chromium"]
                    )
                    if result.returncode != 0:
                        warn("Chromium download failed; run "
                             f"{sys.executable} -m playwright install chromium later.")
                    else:
                        info("Chromium installed")

    # 6. Ensure launcher scripts exist.
    create_launcher_scripts(ROOT / ".venv")

    # 7. Verification.
    section("verify")
    step("Verifying the installation")
    result = subprocess.run(
        [sys.executable, "-m", "xoxss", "--version"],
        capture_output=True, text=True, timeout=60,
    )
    installed_ok = result.returncode == 0
    reported_version = result.stdout.strip() if installed_ok else "unknown"
    if installed_ok:
        info(f"scanner reports: {reported_version}")
    else:
        warn("could not run `python -m xoxss --version`; inspect with --doctor")

    launcher_cmd = r".\xoxss.bat" if os.name == "nt" else "./xoxss"

    print()
    if ui is not None and ui.enabled():
        verdict = (f"{ui.paint(ui.glyphs()['tick'] + ' installation complete', ui.GREEN, ui.BOLD)}"
                   if installed_ok else
                   f"{ui.paint('installation finished with warnings', ui.YELLOW, ui.BOLD)}")
        print(ui.panel(verdict, [
            f"{ui.paint('launcher', ui.GREY)} {launcher_cmd} --help",
            f"{ui.paint('doctor', ui.GREY)}   {launcher_cmd} --doctor",
            f"{ui.paint('fire', ui.GREY)}     {launcher_cmd} example.com --god",
            f"{ui.paint('update', ui.GREY)}   {sys.executable} updater.py",
        ]))
    else:
        print("=" * 60)
        info("Installation finished successfully")
        print(f"    quick run:  {launcher_cmd} --help")
        print(f"    doctor:     {launcher_cmd} --doctor")
        print(f"    updater:    {sys.executable} updater.py")
        print("=" * 60)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="installer.py",
        description="Install the XOXSS XSS scanner and its dependencies in an isolated virtual environment.",
        epilog="Example: python installer.py -y   (create .venv and install everything, no prompts)",
    )
    parser.add_argument("-y", "--yes", action="store_true",
                        help="non-interactive mode: install all optional extras too")
    parser.add_argument("--no-extras", action="store_true",
                        help="skip all optional extras (interactsh / playwright / http2 / ast / dev)")
    parser.add_argument("--no-venv", action="store_true",
                        help="do not create or use a virtual environment; install into current Python")
    parser.add_argument("--venv-dir", metavar="PATH", default="",
                        help="custom path for virtual environment (default: .venv in repository root)")
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
