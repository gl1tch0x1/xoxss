"""Out-of-band verification (blind XSS / SSRF-style callbacks)."""

from xoxss.oob.base import (
    MarkerRegistration,
    OOBHit,
    OOBManager,
    OOBSource,
    extract_marker,
    parse_generic_payload,
)
from xoxss.oob.interactsh import InteractshClient
from xoxss.oob.poller import CallbackPoller, FilePoller
from xoxss.oob.dns_blind import DNSBlindXSSDetector, DNSExfiltrationMethod, DNSXSSVulnerability
from xoxss.oob.smtp_blind import SMTPBlindXSSDetector, SMTPExfiltrationMethod, SMTPXSSVulnerability
from xoxss.oob.websocket_oob import WebSocketExfiltrationMethod, WebSocketOOBDetector, WebSocketXSSVulnerability

__all__ = [
    "CallbackPoller",
    "DNSBlindXSSDetector",
    "DNSExfiltrationMethod",
    "DNSXSSVulnerability",
    "FilePoller",
    "InteractshClient",
    "MarkerRegistration",
    "OOBHit",
    "OOBManager",
    "OOBSource",
    "SMTPBlindXSSDetector",
    "SMTPExfiltrationMethod",
    "SMTPXSSVulnerability",
    "WebSocketExfiltrationMethod",
    "WebSocketOOBDetector",
    "WebSocketXSSVulnerability",
    "extract_marker",
    "parse_generic_payload",
]
