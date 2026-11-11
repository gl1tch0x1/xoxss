"""
Advanced CSP bypass automation module (compatibility shim).

Canonical implementation has been unified into :mod:`xoxss.analysis.csp`.
"""

from __future__ import annotations

from xoxss.analysis.csp import (
    CSPAnalysis,
    CSPAnalyzer,
    CSPBypass,
    CSPBypassAutomator,
    CSPDirective,
    CSPIssue,
    CSPSeverity,
)

__all__ = [
    "CSPSeverity",
    "CSPDirective",
    "CSPIssue",
    "CSPBypass",
    "CSPAnalysis",
    "CSPAnalyzer",
    "CSPBypassAutomator",
]
