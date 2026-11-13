"""
XSS detection modules.
"""

from xoxss.detection.reflection import ReflectionAnalyzer
from xoxss.detection.dom import DOMAnalyzer
from xoxss.detection.context import ContextDetector
from xoxss.detection.payload import (
    CATALOG_SOURCE,
    PAYLOAD_CATALOG,
    CatalogPayload,
    PayloadCategory,
    PayloadGenerator,
    build_blind_payloads,
    catalog_by_context,
    catalog_counts,
    catalog_total,
)
from xoxss.detection.waf import fingerprint as fingerprint_waf, looks_blocked

__all__ = [
    "ReflectionAnalyzer",
    "DOMAnalyzer",
    "ContextDetector",
    "PayloadGenerator",
    "build_blind_payloads",
    "CATALOG_SOURCE",
    "PAYLOAD_CATALOG",
    "CatalogPayload",
    "PayloadCategory",
    "catalog_by_context",
    "catalog_counts",
    "catalog_total",
    "fingerprint_waf",
    "looks_blocked",
]
