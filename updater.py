#!/usr/bin/env python3
"""
XOXSS updater.

Keeps a git-based installation up to date: fetches the latest code from the
origin remote, fast-forwards the current branch, and refreshes the installed
package in the active or repository virtual environment so code and dependencies
stay in sync.

Usage:
    python updater.py            # preserve local changes, fast-forward, reinstall
    python updater.py --check    # report only (no changes)
    python updater.py --no-auto-stash  # refuse to update a dirty checkout
    python updater.py --extras interactsh,playwright   # also refresh named extras
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

ROOT = Path(__file__).resolve().parent

sys.path.insert(0, str(ROOT))
try:
    from xoxss.utils import ui
except Exception:  # engine optional; keep the updater alive on broken checkouts
    ui = None


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


def version_line(old: str, new: str) -> str:
    if ui is not None and ui.enabled():
        return (f"{ui.paint(old, ui.GREY)} "
                f"{ui.paint('\u2192', ui.BRAND, ui.BOLD)} "
                f"{ui.paint(new, ui.GREEN, ui.BOLD)}")
    return f"{old} -> {new}"


def die(message: str, code: int = 1) -> "None":
    warn(message)
    sys.exit(code)


def in_venv() -> bool:
    """Return True if running inside a virtual environment."""
    return (
        getattr(sys, "base_prefix", sys.prefix) != sys.prefix
        or hasattr(sys, "real_prefix")
    )


def find_venv_python() -> Optional[Path]:
    """Find Python binary in repository .venv or venv directory."""
    for name in (".venv", "venv"):
        candidate_dir = ROOT / name
        if not candidate_dir.is_dir():
            continue
        if os.name == "nt":
            py = candidate_dir / "Scripts" / "python.exe"
        else:
            py = candidate_dir / "bin" / "python"
        if py.exists():
            return py
    return None


def git(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True
        )
    except FileNotFoundError:
        raise RuntimeError("git is not installed or not found on PATH.")
    if check and result.returncode != 0:
        detail = (result.stderr.strip() or result.stdout.strip()).splitlines()
        raise RuntimeError(
            f"git {' '.join(args)} failed: {detail[-1] if detail else 'unknown error'}"
        )
    return result


def out(result: subprocess.CompletedProcess) -> str:
    return (result.stdout or "").strip()


def local_version() -> str:
    try:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
        return match.group(1) if match else "unknown"
    except OSError:
        return "unknown"


def is_dirty() -> bool:
    return bool(out(git(["status", "--porcelain"])))


def ensure_repo() -> str:
    if not (ROOT / ".git").exists():
        die("updater.py must run inside a git clone of XOXSS. "
            "Clone it first:\n    git clone https://github.com/gl1tch0x1/xoxss.git")
    info(f"repository: {ROOT}")
    branch = out(git(["rev-parse", "--abbrev-ref", "HEAD"])) or "main"
    if branch == "HEAD":
        die("this checkout is in a detached-HEAD state; "
            "switch to a branch first (git switch main).")
    info(f"branch: {branch}")

    remotes = [r.strip() for r in out(git(["remote"])).splitlines() if r.strip()]
    if "origin" not in remotes:
        die("no 'origin' remote configured; add one or update manually.")
    return branch


def resolve_tracking_branch(branch: str) -> str:
    """Return the upstream tracking branch ref, falling back to origin/main."""
    tracking = f"origin/{branch}"
    exists = git(["rev-parse", "--verify", "--quiet", tracking], check=False)
    if exists.returncode != 0:
        warn(f"no origin/{branch} branch; comparing against origin/main instead")
        return "origin/main"
    return tracking


def fetch_state(branch: str) -> tuple[int, int]:
    """Return (behind, ahead) commit counts versus origin tracking ref."""
    try:
        git(["fetch", "origin", "--quiet"])
    except RuntimeError as exc:
        warn(f"git fetch failed ({exc}); update check might be inaccurate")
        return 0, 0

    tracking = resolve_tracking_branch(branch)
    counts = out(git(["rev-list", "--left-right", "--count", f"HEAD...{tracking}"]))
    behind_s, ahead_s = (counts.split() + ["0", "0"])[:2]
    return int(behind_s), int(ahead_s)


def check_only(branch: str) -> int:
    if ui is not None and ui.enabled():
        print(ui.panel("xoxss updater - update check", [
            f"{ui.paint('version', ui.GREY)}  {local_version()}",
            f"{ui.paint('branch', ui.GREY)}   {branch}",
            f"{ui.paint('env', ui.GREY)}      {'virtualenv' if in_venv() else 'system'}",
        ]))
    else:
        print("XOXSS update check")
        print("=" * 60)
    behind, ahead = fetch_state(branch)
    if behind:
        info(f"{behind} commit(s) behind origin, {ahead} ahead - an update is available")
        tracking = resolve_tracking_branch(branch)
        log = out(git(["log", "--oneline", f"HEAD..{tracking}", "-n", "15"]))
        lines = [
            f"{ui.paint(ui.glyphs()['bullet'] + ' ' + commit, ui.CYAN)}"
            if ui is not None and ui.enabled() else f"      {commit}"
            for commit in log.splitlines()
        ]
        if ui is not None and ui.enabled():
            print(ui.panel("incoming commits", lines, accent=ui.CYAN))
        else:
            print("    incoming commits:")
            for line_text in lines:
                print(f"    {line_text}")
        warn("run `python updater.py` to update")
        return 1
    if ui is not None and ui.enabled():
        print(f"{ui.paint(ui.glyphs()['tick'] + ' already up to date', ui.GREEN)} "
              f"{ui.paint(f'({ahead} ahead)', ui.DIM)}")
    else:
        info(f"already up to date ({ahead} ahead)")
    return 0


def stash_if_needed(auto_stash: bool = True) -> Optional[str]:
    if not is_dirty():
        return None
    if not auto_stash:
        die("uncommitted local changes would block the update. "
            "Commit or stash them, or allow the updater to temporarily stash them.")

    previous_stash = out(git(["rev-parse", "--verify", "refs/stash"], check=False))
    step("Uncommitted changes found; preserving them in a temporary stash")
    git(["stash", "push", "-u", "-m", "xoxss updater temporary stash"])
    stash_commit = out(git(["rev-parse", "--verify", "refs/stash"], check=False))
    if not stash_commit or stash_commit == previous_stash or is_dirty():
        if stash_commit and stash_commit != previous_stash:
            restore_stash(stash_commit)
        raise RuntimeError(
            "could not safely stash all local changes; no update was attempted"
        )
    return stash_commit


def restore_stash(stash_commit: str) -> bool:
    """Restore the updater's exact stash, attempting index restoration first."""
    # First attempt: apply with index preservation
    result = git(["stash", "apply", "--index", stash_commit], check=False)
    if result.returncode != 0:
        # Fallback: attempt applying without --index to handle untracked file index differences
        fallback = git(["stash", "apply", stash_commit], check=False)
        if fallback.returncode != 0:
            warn(
                "local changes could not be reapplied cleanly. The stash is preserved; "
                "resolve conflicts, then restore it with `git stash apply "
                f"{stash_commit}`."
            )
            return False

    commits = out(git(["stash", "list", "--format=%H"])).splitlines()
    try:
        stash_index = commits.index(stash_commit)
        git(["stash", "drop", f"stash@{{{stash_index}}}"])
    except (ValueError, RuntimeError):
        warn(f"restored local changes; temporary stash remains at {stash_commit}")
        return True
    info("local changes were restored after the update")
    return True


def update(branch: str, auto_stash: bool, extras: list[str]) -> int:
    old_version = local_version()
    if ui is not None and ui.enabled():
        print(ui.panel("xoxss updater", [
            f"{ui.paint('version', ui.GREY)}  {old_version}",
            f"{ui.paint('branch', ui.GREY)}   {branch}",
            f"{ui.paint('env', ui.GREY)}      {'virtualenv' if in_venv() else 'system'}",
            f"{ui.paint('policy', ui.GREY)}   fast-forward only - history is never rewritten",
        ]))
    else:
        print("XOXSS updater")
        print("=" * 60)
        info(f"current version: {old_version}")

    stash_commit = stash_if_needed(auto_stash)
    try:
        behind, ahead = fetch_state(branch)

        if ahead:
            warn(f"local branch is {ahead} commit(s) ahead of origin/{branch}; "
                 "your commits stay intact, the update only fast-forwards shared history.")
        if behind == 0:
            if ui is not None and ui.enabled():
                print(f"{ui.paint(ui.glyphs()['tick'] + ' code is already up to date', ui.GREEN)}")
            else:
                info("code is already up to date")
            new_version = old_version
        else:
            tracking = resolve_tracking_branch(branch)
            target_remote_branch = tracking.replace("origin/", "", 1)
            log = out(git(["log", "--oneline", f"HEAD..{tracking}", "-n", "15"]))
            incoming = len(out(git(["rev-list", f"HEAD..{tracking}"])).splitlines())
            log_lines = [
                f"{ui.paint(ui.glyphs()['bullet'] + ' ' + commit, ui.CYAN)}"
                if ui is not None and ui.enabled() else commit
                for commit in log.splitlines()
            ]
            if ui is not None and ui.enabled():
                print(ui.panel(f"{incoming} incoming commit(s)", log_lines, accent=ui.CYAN))
            else:
                info(f"{incoming} new commit(s) available:")
                for line_text in log_lines:
                    print(f"      {line_text}")

            step(f"Fast-forwarding {branch} to {tracking}")
            result = git(["pull", "--ff-only", "origin", target_remote_branch], check=False)
            if result.returncode != 0:
                raise RuntimeError(
                    f"update failed:\n{(result.stderr or result.stdout).strip()}\n"
                    "If you rebased or rewrote history locally, resolve it manually "
                    "or re-clone."
                )
            new_version = local_version()
            info(f"updated {branch}: {version_line(old_version, new_version)}")
    except BaseException:
        if stash_commit:
            restore_stash(stash_commit)
        raise

    if stash_commit and not restore_stash(stash_commit):
        raise RuntimeError(
            "the code update completed, but local changes need conflict resolution; "
            "the temporary stash has been preserved"
        )

    # Refresh the installed package so the running tool matches the new code.
    step("Refreshing the installed package (pip install --upgrade)")
    pip_result = subprocess.run(
        [
            sys.executable, "-m", "pip", "install", "--prefer-binary",
            "--upgrade", "--upgrade-strategy", "only-if-needed", ".",
        ],
        cwd=ROOT,
    )
    if pip_result.returncode != 0:
        warn("pip refresh failed; the previously installed version still works.")

    for extra in extras:
        step(f"Refreshing optional extra '{extra}'")
        result = subprocess.run(
            [
                sys.executable, "-m", "pip", "install", "--prefer-binary",
                "--upgrade", "--upgrade-strategy", "only-if-needed", f".[{extra}]",
            ],
            cwd=ROOT,
        )
        if result.returncode != 0:
            warn(f"extra '{extra}' refresh failed; it keeps its previous version.")

    # Sanity check.
    result = subprocess.run(
        [sys.executable, "-m", "xoxss", "--version"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    reported_version = result.stdout.strip() or "unknown"
    if result.returncode == 0:
        if ui is not None and ui.enabled():
            print(f"{ui.paint(ui.glyphs()['tick'] + ' scanner now reports', ui.GREEN)} "
                  f"{ui.paint(reported_version, ui.BOLD)}")
        else:
            info(f"scanner now reports: {reported_version}")
    info(f"verify with: {sys.executable} -m xoxss --doctor")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="updater.py",
        description="Update the XOXSS scanner from its git origin and refresh the install.",
        epilog="Example: python updater.py -y --extras interactsh,playwright",
    )
    parser.add_argument("-y", "--yes", action="store_true",
                        help="legacy alias for automatic local-change preservation")
    parser.add_argument("--no-auto-stash", dest="auto_stash", action="store_false", default=True,
                        help="refuse to update when local changes are present")
    parser.add_argument("--check", action="store_true",
                        help="only report whether an update is available; change nothing")
    parser.add_argument("--extras", default="",
                        help="comma-separated optional extras to refresh after updating "
                             "(e.g. interactsh,playwright,http2,ast)")
    parser.add_argument("--no-venv", action="store_true",
                        help="do not switch to repository .venv even if present")
    args = parser.parse_args()

    # Automatically re-exec with repository .venv if executed with system Python
    if not in_venv() and not args.no_venv:
        venv_py = find_venv_python()
        if venv_py and venv_py.resolve() != Path(sys.executable).resolve():
            info(f"Using virtual environment: {venv_py}")
            env = os.environ.copy()
            env["VIRTUAL_ENV"] = str(venv_py.parent.parent)
            env.pop("PYTHONHOME", None)
            result = subprocess.run([str(venv_py), str(ROOT / "updater.py"), *sys.argv[1:]], env=env)
            return result.returncode

    branch = ensure_repo()
    extras = [name.strip() for name in args.extras.split(",") if name.strip()]

    try:
        if args.check:
            return check_only(branch)
        return update(branch, args.auto_stash or args.yes, extras)
    except RuntimeError as exc:
        die(str(exc))
    except KeyboardInterrupt:
        print()
        warn("update cancelled by user")
        return 130


if __name__ == "__main__":
    sys.exit(main())
