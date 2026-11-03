"""
XSS detection modules.
"""

from xoxss.detection.reflection import ReflectionAnalyzer
from xoxss.detection.dom import DOMAnalyzer
from xoxss.detection.context import ContextDetector
from xoxss.detection.payload import PayloadGenerator, build_blind_payloads
from xoxss.detection.waf import fingerprint as fingerprint_waf, looks_blocked

__all__ = [
    "ReflectionAnalyzer",
    "DOMAnalyzer",
    "ContextDetector",
    "PayloadGenerator",
    "build_blind_payloads",
    "fingerprint_waf",
    "looks_blocked",
]
