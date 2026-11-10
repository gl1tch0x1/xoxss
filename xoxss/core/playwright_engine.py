"""
Playwright browser engine for XSS verification.

Canonical implementation lives in :mod:`xoxss.core.browser`.
"""

from __future__ import annotations

from xoxss.core.browser import (
    HAS_PLAYWRIGHT,
    HOOK_JS,
    PlaywrightEngine,
)

__all__ = ["PlaywrightEngine", "HAS_PLAYWRIGHT", "HOOK_JS"]
