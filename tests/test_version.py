"""The package version must have exactly one source of truth."""

from __future__ import annotations

import re
from pathlib import Path

import xoxss
from xoxss.reports import common
from xoxss.utils import console

try:  # Python 3.11+
    # `tomllib` is stdlib from 3.11 on; the fallback below keeps the suite
    # runnable on 3.9/3.10.  pyright resolves imports against the running
    # interpreter, so the import is expected to be missing there.
    import tomllib  # pyright: ignore[reportMissingImports]
except ImportError:  # pragma: no cover - Python 3.9/3.10
    tomllib = None  # type: ignore[assignment]


def _pyproject_version(root: Path) -> str:
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    if tomllib is not None:
        return tomllib.loads(text)["project"]["version"]
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "version missing from pyproject.toml"
    return match.group(1)


def test_package_version_is_a_string() -> None:
    assert isinstance(xoxss.__version__, str)
    assert re.fullmatch(r"\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?", xoxss.__version__)


def test_console_version_tracks_package() -> None:
    # Regression: console.py used to hardcode "2.0.0", which drifted from the
    # package metadata on every release.
    assert console.VERSION == xoxss.__version__


def test_report_version_tracks_package() -> None:
    assert common.VERSION == xoxss.__version__


def test_pyproject_version_tracks_package(repo_root: Path) -> None:
    assert _pyproject_version(repo_root) == xoxss.__version__
