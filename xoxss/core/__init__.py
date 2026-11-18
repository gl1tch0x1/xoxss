"""
Core modules for XOXSS scanner.
"""

from xoxss.core.config import ScanConfig
from xoxss.core.browser import BrowserEngine, BrowserPool, PlaywrightEngine
from xoxss.core.state import StateStore

__all__ = [
    "BrowserEngine",
    "BrowserPool",
    "PlaywrightEngine",
    "ScanConfig",
    "StateStore",
]
