#!/usr/bin/env python3
"""
XOXSS updater.

Keeps a git-based installation up to date: fetches the latest code from the
origin remote, fast-forwards the current branch, and refreshes the installed
package so code and dependencies stay in sync.

Usage:
    python updater.py            # fetch, fast-forward, reinstall
    python updater.py --check    # report only (no changes)
    python updater.py -y         # auto-stash uncommitted local changes and continue
    python updater.py --extras interactsh,playwright   # also refresh named extras

The update performs two guarded operations:

1. `git pull --ff-only` - never rewrites history; aborts on unexpected divergence.
2. `pip install -U .`   - refreshes the installed package after new code lands.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def info(message: str) -> None:
    print(f"[+] {message}")


def warn(message: str) -> None:
    print(f"[!] {message}")


def step(message: str) -> None:
    print(f"->  {message}")


def die(message: str, code: int = 1) -> "None":
    warn(message)
    sys.exit(code)


def git(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True)
    if check and result.returncode != 0:
        detail = (result.stderr.strip() or result.stdout.strip()).splitlines()
        raise RuntimeError(
            f"git {' '.join(args)} failed: {detail[-1] if detail else 'unknown error'}")
    return result


def out(result: subprocess.CompletedProcess) -> str:
    return (result.stdout or "").strip()


def local_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    return match.group(1) if match else "unknown"


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

    if out(git(["remote"])) != "origin":
        die("no 'origin' remote configured; add one or update manually.")
    return branch


def fetch_state(branch: str) -> tuple[int, int]:
    """Return (behind, ahead) commit counts versus origin/<branch>."""
    git(["fetch", "origin", "--quiet"])
    tracking = f"origin/{branch}"
    exists = git(["rev-parse", "--verify", "--quiet", tracking], check=False)
    if exists.returncode != 0:
        warn(f"no origin/{branch} branch; comparing against origin/main instead")
        tracking = "origin/main"
    counts = out(git(["rev-list", "--left-right", "--count", f"HEAD...{tracking}"]))
    behind_s, ahead_s = (counts.split() + ["0", "0"])[:2]
    return int(behind_s), int(ahead_s)


def check_only(branch: str) -> int:
    print("XOXSS update check")
    print("=" * 60)
    info(f"installed / checked-out version: {local_version()}")
    behind, ahead = fetch_state(branch)
    info(f"{branch}: {behind} commit(s) behind origin, {ahead} ahead")
    if behind:
        log = out(git(["log", "--oneline", f"HEAD..origin/{branch}", "-n", "15"]))
        print("    incoming commits:")
        for line in log.splitlines():
            print(f"      {line}")
        warn("run `python updater.py` to update")
        return 1
    info("already up to date")
    return 0


def stash_if_needed(auto_yes: bool) -> None:
    if not is_dirty():
        return
    if auto_yes:
        step("Uncommitted changes found; stashing them (git stash -u)")
        git(["stash", "push", "-u", "-m", "xoxss updater auto-stash"])
        warn("your changes were stashed - restore with `git stash pop` afterwards.")
    else:
        die("uncommitted local changes would block the update. "
            "Commit or stash them, or re-run with -y to auto-stash.")


def update(branch: str, auto_yes: bool, extras: list[str]) -> int:
    old_version = local_version()
    print("XOXSS updater")
    print("=" * 60)
    info(f"current version: {old_version}")

    stash_if_needed(auto_yes)
    behind, ahead = fetch_state(branch)

    if ahead:
        warn(f"local branch is {ahead} commit(s) ahead of origin/{branch}; "
             "your commits stay intact, the update only fast-forwards shared history.")
    if behind == 0:
        info("code is already up to date")
    else:
        log = out(git(["log", "--oneline", f"HEAD..origin/{branch}", "-n", "15"]))
        incoming = len(out(git(["rev-list", f"HEAD..origin/{branch}"])).splitlines())
        info(f"{incoming} new commit(s) available:")
        for line in log.splitlines():
            print(f"      {line}")

        step(f"Fast-forwarding {branch} to origin/{branch}")
        result = git(["pull", "--ff-only", "origin", branch], check=False)
        if result.returncode != 0:
            die(f"update failed:\n{(result.stderr or result.stdout).strip()}\n"
                "If you rebased or rewrote history locally, resolve it manually "
                "or re-clone.", 1)
        info(f"updated {branch}: {old_version} -> {local_version()}")

    # Refresh the installed package so the running tool matches the new code.
    step("Refreshing the installed package (pip install -U .)")
    pip_result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-U", "."], cwd=ROOT)
    if pip_result.returncode != 0:
        warn("pip refresh failed; the previously installed version still works.")

    for extra in extras:
        step(f"Refreshing optional extra '{extra}'")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-U", f".[{extra}]"], cwd=ROOT)
        if result.returncode != 0:
            warn(f"extra '{extra}' refresh failed; it keeps its previous version.")

    # Sanity check.
    result = subprocess.run(
        [sys.executable, "-m", "xoxss", "--version"], capture_output=True,
        text=True, timeout=60)
    new_version = result.stdout.strip() or "unknown"
    if result.returncode == 0:
        info(f"scanner now reports: {new_version}")
    info(f"verify with: {sys.executable} -m xoxss --doctor")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="updater.py",
        description="Update the XOXSS scanner from its git origin and refresh the install.",
        epilog="Example: python updater.py -y --extras interactsh,playwright",
    )
    parser.add_argument("-y", "--yes", action="store_true",
                        help="non-interactive: auto-stash uncommitted local changes")
    parser.add_argument("--check", action="store_true",
                        help="only report whether an update is available; change nothing")
    parser.add_argument("--extras", default="",
                        help="comma-separated optional extras to refresh after updating "
                             "(e.g. interactsh,playwright)")
    args = parser.parse_args()

    branch = ensure_repo()
    extras = [name.strip() for name in args.extras.split(",") if name.strip()]

    try:
        if args.check:
            return check_only(branch)
        return update(branch, args.yes, extras)
    except RuntimeError as exc:
        die(str(exc))
    except KeyboardInterrupt:
        print()
        warn("update cancelled by user")
        return 130


if __name__ == "__main__":
    sys.exit(main())
