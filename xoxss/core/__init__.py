"""
Core modules for XOXSS scanner.
"""

from xoxss.core.compliance import (
    compliance_for_kind,
    cwe_for_kind,
    cvss_for_finding,
    finding_dedupe_fingerprint,
)
from xoxss.core.config import ScanConfig
from xoxss.core.browser import BrowserEngine, BrowserPool, PlaywrightEngine
from xoxss.core.state import StateStore

__all__ = [
    "BrowserEngine",
    "BrowserPool",
    "PlaywrightEngine",
    "ScanConfig",
    "StateStore",
    "compliance_for_kind",
    "cvss_for_finding",
    "cwe_for_kind",
    "finding_dedupe_fingerprint",
]
