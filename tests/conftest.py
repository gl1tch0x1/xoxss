"""Shared pytest fixtures.

The suite is intentionally dependency-light: it exercises pure helpers and the
detection/analysis layers that do not need a live target, a browser, or the
network.  End-to-end behaviour stays in ``benchmarks/``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT
