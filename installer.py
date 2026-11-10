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
import tempfile
import venv
from pathlib import Path
from typing import Optional, Tuple

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


def get_free_space_mb(path: Path | str) -> int:
    """Return free disk space in megabytes for a given path."""
    try:
        usage = shutil.disk_usage(str(path))
        return int(usage.free / (1024 * 1024))
    except Exception:
        return 999999


def configure_safe_temp_dir() -> Optional[Path]:
    """
    Ensure pip build environments use a location with sufficient disk space.
    Linux systems (e.g. Kali, Debian, Docker) often mount /tmp as a small tmpfs RAM disk
    (e.g. 512MB-1GB), which runs out of space during Playwright or C-extension builds ([Errno 28]).
    If /tmp has < 1500 MB free but ROOT has significantly more free space,
    redirect TMPDIR to ROOT / '.tmp'.
    """
    try:
        sys_tmp = Path(tempfile.gettempdir())
        tmp_free = get_free_space_mb(sys_tmp)
        root_free = get_free_space_mb(ROOT)
        if tmp_free < 1500 and root_free > (tmp_free + 200):
            safe_tmp = ROOT / ".tmp"
            safe_tmp.mkdir(parents=True, exist_ok=True)
            os.environ["TMPDIR"] = str(safe_tmp)
            os.environ["TEMP"] = str(safe_tmp)
            os.environ["TMP"] = str(safe_tmp)
            return safe_tmp
    except Exception:
        pass
    return None


def clean_build_artifacts() -> None:
    """Clean transient build artifacts and temporary files."""
    for pattern in ("build", "*.egg-info", "pip-wheel-metadata"):
        for item in ROOT.glob(pattern):
            try:
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                elif item.is_file():
                    item.unlink(missing_ok=True)
            except Exception:
                pass
    safe_tmp = ROOT / ".tmp"
    if safe_tmp.is_dir():
        try:
            shutil.rmtree(safe_tmp, ignore_errors=True)
        except Exception:
            pass


def print_disk_space_help() -> None:
    """Emit clear, actionable instructions when out-of-disk condition occurs."""
    tmp_dir = tempfile.gettempdir()
    free_tmp = get_free_space_mb(tmp_dir)
    free_root = get_free_space_mb(ROOT)
    free_prefix = get_free_space_mb(sys.prefix)

    lines = [
        f"Available disk space: /tmp: {free_tmp} MB | repo: {free_root} MB | env: {free_prefix} MB",
        "Common remedies for Linux/Debian/Kali:",
        "  1. Clean packages:  sudo apt-get clean && sudo apt-get autoremove -y",
        "  2. Purge pip cache: python -m pip cache purge",
        "  3. Free /tmp tmpfs: sudo mount -o remount,size=2G /tmp  (or rm -rf /tmp/pip-*)",
        "  4. Minimal install: ./installer.py --no-extras",
    ]
    if ui is not None and ui.enabled():
        print(ui.panel("out of disk space ([Errno 28])", lines, accent=ui.YELLOW))
    else:
        print("\n" + "=" * 60)
        print(" [!] OUT OF DISK SPACE ([Errno 28])")
        for line in lines:
            print(f"     {line}")
        print("=" * 60 + "\n")


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


def pip(args: list[str], *, capture: bool = False, no_cache: bool = False) -> int:
    """Run pip through the active interpreter with space-awareness and error recovery."""
    cmd_args = list(args)
    free_temp = get_free_space_mb(tempfile.gettempdir())
    free_prefix = get_free_space_mb(sys.prefix)
    low_space = (free_temp < 1200 or free_prefix < 1200)

    # Proactively inject --no-cache-dir if low space or explicitly requested
    if (no_cache or low_space) and "--no-cache-dir" not in cmd_args and "install" in cmd_args and "cache" not in cmd_args:
        idx = cmd_args.index("install") + 1
        cmd_args.insert(idx, "--no-cache-dir")

    command = [sys.executable, "-m", "pip", *cmd_args]
    if capture:
        result = subprocess.run(command, capture_output=True, text=True)
        err_output = (result.stderr or "") + (result.stdout or "")
        is_no_space = "Errno 28" in err_output or "No space left on device" in err_output or "ENOSPC" in err_output
        if result.returncode != 0:
            if is_no_space:
                warn("pip ran out of disk or temporary space ([Errno 28] No space left on device).")
                try:
                    subprocess.run([sys.executable, "-m", "pip", "cache", "purge"], capture_output=True, timeout=15)
                except Exception:
                    pass
                configure_safe_temp_dir()
                if "--no-cache-dir" not in cmd_args and "install" in cmd_args:
                    step("Retrying with --no-cache-dir...")
                    retry_args = list(cmd_args)
                    retry_args.insert(retry_args.index("install") + 1, "--no-cache-dir")
                    retry_res = subprocess.run([sys.executable, "-m", "pip", *retry_args], capture_output=True, text=True)
                    if retry_res.returncode == 0:
                        return 0
                print_disk_space_help()
            elif err_output.strip():
                print(err_output.strip()[-800:])
        return result.returncode

    # Real-time streaming output
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    collected_lines: list[str] = []
    if proc.stdout:
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            collected_lines.append(line)
            if len(collected_lines) > 80:
                collected_lines.pop(0)
    proc.wait()
    ret = proc.returncode

    if ret != 0:
        tail_text = "".join(collected_lines)
        is_no_space = "Errno 28" in tail_text or "No space left on device" in tail_text or "ENOSPC" in tail_text
        if is_no_space:
            warn("pip ran out of disk or temporary space ([Errno 28] No space left on device).")
            try:
                subprocess.run([sys.executable, "-m", "pip", "cache", "purge"], capture_output=True, timeout=15)
            except Exception:
                pass
            configure_safe_temp_dir()
            if "--no-cache-dir" not in cmd_args and "install" in cmd_args:
                step("Retrying with --no-cache-dir...")
                retry_args = list(cmd_args)
                retry_args.insert(retry_args.index("install") + 1, "--no-cache-dir")
                return pip(retry_args, capture=False, no_cache=True)
            print_disk_space_help()
    return ret


def git_available() -> bool:
    return shutil.which("git") is not None


def precheck() -> bool:
    """Verify prerequisites and check available disk space before installing."""
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

    # Inspect disk space early to prevent out-of-disk failures
    free_temp = get_free_space_mb(tempfile.gettempdir())
    free_root = get_free_space_mb(ROOT)
    free_prefix = get_free_space_mb(sys.prefix)
    info(f"Disk space available: {free_root} MB (repo), {free_temp} MB (temp), {free_prefix} MB (env)")
    if free_temp < 500 or free_prefix < 500:
        warn("Low disk space detected (< 500 MB free). Installation of heavy packages like Playwright may fail.")

    if not git_available():
        warn("git is not on PATH; only needed by updater.py, not for installation.")
    return True


def report_state() -> int:
    """--check: report versions, virtualenv status, and package state."""
    venv_status = "active virtualenv" if in_venv() else "system Python (no venv active)"
    venv_path = ROOT / ".venv"
    has_stored_venv = venv_path.is_dir()
    free_temp = get_free_space_mb(tempfile.gettempdir())
    free_root = get_free_space_mb(ROOT)

    if ui is not None and ui.enabled():
        print(ui.panel("xoxss installer - state check", [
            f"{ui.paint('python', ui.GREY)}     {sys.version.split()[0]} ({sys.executable})",
            f"{ui.paint('env', ui.GREY)}        {venv_status}",
            f"{ui.paint('.venv exists', ui.GREY)} {'yes' if has_stored_venv else 'no'}",
            f"{ui.paint('checkout', ui.GREY)}   {ROOT}",
            f"{ui.paint('disk space', ui.GREY)} {free_root} MB repo / {free_temp} MB temp",
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

    configure_safe_temp_dir()
    precheck()

    # 3. Refresh packaging tooling inside the environment.
    step("Upgrading pip / setuptools / wheel (best effort)")
    if pip(["install", "--prefer-binary", "--upgrade", "pip", "setuptools", "wheel"], capture=True, no_cache=args.no_cache) != 0:
        warn("could not upgrade pip tooling; continuing with existing versions")

    # 4. Optional extras selection upfront
    section("optional extras")
    selected: list[str] = []
    if args.no_extras:
        info("optional extras skipped (--no-extras)")
    else:
        auto = args.yes
        if auto:
            selected = [name for name, _module, _desc in OPTIONAL_EXTRAS]
            info(f"--yes: selected all optional extras ({', '.join(selected)})")
        elif not is_maybe_interactive():
            warn("stdin is not interactive; skipping optional extras. "
                 "Re-run with -y to install them automatically.")
        else:
            for name, _module, description in OPTIONAL_EXTRAS:
                if ask(name, description):
                    selected.append(name)

    # 5. Core + extras install:
    # Single-pass batch install builds the wheel ONCE and resolves dependencies together,
    # preventing out-of-disk errors ([Errno 28]) from repeated wheel builds in /tmp.
    section("installation")
    if not selected:
        step("Installing XOXSS core (package + required dependencies)")
        if pip(["install", "--prefer-binary", "--upgrade", "--upgrade-strategy", "only-if-needed", "."], no_cache=args.no_cache) != 0:
            die("core installation failed; see the pip output above for details.", 1)
        info("XOXSS core installed")
    else:
        batch_spec = f".[{','.join(selected)}]"
        step(f"Installing XOXSS with selected extras ({', '.join(selected)}) in a single pass")
        batch_status = pip(["install", "--prefer-binary", "--upgrade", "--upgrade-strategy", "only-if-needed", batch_spec], no_cache=args.no_cache)
        if batch_status == 0:
            info(f"XOXSS and selected extras ({', '.join(selected)}) installed successfully")
        else:
            warn("Single-pass install encountered an issue; falling back to core install followed by individual extras.")
            if pip(["install", "--prefer-binary", "--upgrade", "--upgrade-strategy", "only-if-needed", "."], no_cache=args.no_cache) != 0:
                die("core installation failed; see the pip output above for details.", 1)
            info("XOXSS core installed")
            for name in selected:
                step(f"Installing optional extra '{name}'")
                if pip(["install", "--prefer-binary", "--upgrade", "--upgrade-strategy", "only-if-needed", f".[{name}]"], no_cache=args.no_cache) != 0:
                    warn(f"optional extra '{name}' failed; the core scanner still works.")

    # 6. Playwright Chromium download (with free disk space safety check)
    if "playwright" in selected and module_available("playwright"):
        free_mb = get_free_space_mb(sys.prefix)
        if free_mb < 500:
            warn(f"Low disk space detected ({free_mb} MB available; Playwright Chromium requires ~350 MB).")
            warn("Skipping automatic Playwright Chromium download to avoid [Errno 28] disk exhaustion.")
            warn("XOXSS will run with standard Selenium (using system Chrome/Chromium).")
            warn(f"To download Chromium later after freeing space, run:\n    {sys.executable} -m playwright install chromium")
        else:
            step("Downloading the Chromium browser for Playwright")
            result = subprocess.run(
                [sys.executable, "-m", "playwright", "install", "chromium"]
            )
            if result.returncode != 0:
                warn("Chromium download failed; run "
                     f"{sys.executable} -m playwright install chromium later.")
            else:
                info("Chromium installed")

    # 7. Clean up temporary build artifacts
    clean_build_artifacts()

    # 8. Ensure launcher scripts exist.
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
    parser.add_argument("--no-cache", action="store_true",
                        help="disable pip caching (--no-cache-dir) to save disk space on small partitions")
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
