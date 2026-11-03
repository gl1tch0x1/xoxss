"""
Core modules for XOXSS scanner.
"""

from xoxss.core.config import ScanConfig
from xoxss.core.browser import BrowserEngine, BrowserPool, PlaywrightEngine

__all__ = [
    "ScanConfig",
    "BrowserEngine",
    "BrowserPool",
    "PlaywrightEngine",
]
