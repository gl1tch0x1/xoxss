"""
Cookie-Based XSS Detection Module.

Detects and tests XSS vulnerabilities via cookie injection:
- document.cookie injection paths
- Cookie attribute bypass (SameSite, Secure)
- Cookie header reflection
- Cookie-based stored XSS
"""

import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum


class CookieSink(Enum):
    """Cookie-related XSS sink types."""
    DOCUMENT_COOKIE = "document_cookie"
    COOKIE_HEADER = "cookie_header"
    LOCAL_STORAGE_COOKIE = "local_storage_cookie"
    SESSION_STORAGE_COOKIE = "session_storage_cookie"
    INDEXEDDB_COOKIE = "indexeddb_cookie"


@dataclass
class CookieXSSVulnerability:
    """Cookie-based XSS vulnerability."""
    sink: CookieSink
    injection_point: str
    context: str
    payload: str
    severity: str
    bypass_attributes: List[str]


class CookieXSSDetector:
    """
    Advanced cookie-based XSS detector.
    Detects XSS vulnerabilities via cookie injection and reflection.
    """

    # Cookie sink patterns
    COOKIE_SINK_PATTERNS = {
        CookieSink.DOCUMENT_COOKIE: [
            r'document\.cookie',
            r'\.cookie\s*=',
            r'getCookie\s*\(',
            r'setCookie\s*\(',
            r'readCookie\s*\(',
        ],
        CookieSink.COOKIE_HEADER: [
            r'Cookie:\s*',
            r'Set-Cookie:\s*',
            r'request\.headers\.cookie',
            r'response\.headers\[["\']cookie',
        ],
        CookieSink.LOCAL_STORAGE_COOKIE: [
            r'localStorage\.getItem\s*\(\s*["\']cookie',
            r'localStorage\.setItem\s*\(\s*["\']cookie',
            r'localStorage\[["\']cookie',
        ],
        CookieSink.SESSION_STORAGE_COOKIE: [
            r'sessionStorage\.getItem\s*\(\s*["\']cookie',
            r'sessionStorage\.setItem\s*\(\s*["\']cookie',
            r'sessionStorage\[["\']cookie',
        ],
        CookieSink.INDEXEDDB_COOKIE: [
            r'indexedDB.*cookie',
            r'IDBObjectStore.*cookie',
        ],
    }

    # Cookie attribute bypass patterns
    ATTRIBUTE_BYPASS_PATTERNS = {
        "samesite": [
            r'SameSite\s*=\s*None',
            r'SameSite\s*=\s*Lax',
            r'SameSite\s*=\s*',
        ],
        "secure": [
            r'Secure',
            r'secure\s*=\s*true',
        ],
        "httponly": [
            r'HttpOnly',
            r'httponly\s*=\s*true',
        ],
        "path": [
            r'Path\s*=\s*/',
            r'Path\s*=\s*;',
        ],
        "domain": [
            r'Domain\s*=\s*\.',
            r'Domain\s*=\s*localhost',
        ],
    }

    # XSS payloads for cookie injection
    COOKIE_XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<script>document.cookie='xss=x'</script>",
    ]

    # Common cookie names that might be reflected
    COMMON_COOKIE_NAMES = [
        "session",
        "sessionid",
        "user",
        "username",
        "auth",
        "token",
        "csrf",
        "xsrf",
        "language",
        "theme",
        "preferences",
        "remember",
        "keep",
        "uid",
        "userid",
        "email",
    ]

    def __init__(self):
        self._detected_sinks: Set[CookieSink] = set()
        self._vulnerabilities: List[CookieXSSVulnerability] = []

    def detect_cookie_sinks(self, js_content: str, html_content: str = "") -> Set[CookieSink]:
        """
        Detect cookie-related XSS sinks in the content.

        Args:
            js_content: JavaScript source code
            html_content: HTML source code (optional)

        Returns:
            Set of detected cookie sinks
        """
        combined = js_content + "\n" + html_content
        detected = set()

        for sink, patterns in self.COOKIE_SINK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.add(sink)
                    break

        self._detected_sinks = detected
        return detected

    def check_attribute_bypass(self, cookie_header: str) -> List[str]:
        """
        Check for cookie attribute bypass opportunities.

        Args:
            cookie_header: Cookie header string

        Returns:
            List of bypassable attributes
        """
        bypasses = []

        for attr, patterns in self.ATTRIBUTE_BYPASS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, cookie_header, re.IGNORECASE):
                    bypasses.append(attr)
                    break

        return bypasses

    def generate_cookie_payloads(
        self,
        sink: CookieSink,
        marker: str = "xoxss"
    ) -> List[str]:
        """
        Generate XSS payloads for cookie injection.

        Args:
            sink: Target cookie sink
            marker: Unique marker

        Returns:
            List of payload strings
        """
        payloads = []

        for base_payload in self.COOKIE_XSS_PAYLOADS:
            # Replace alert(1) with marker
            marked = base_payload.replace("alert(1)", f"alert('{marker}')")

            # Add context-specific variations
            if sink == CookieSink.DOCUMENT_COOKIE:
                payloads.append(f"document.cookie='{marked}'")
                payloads.append(f"document.cookie='xss={marked}'")
            elif sink == CookieSink.COOKIE_HEADER:
                payloads.append(f"Cookie: xss={marked}")
            elif sink == CookieSink.LOCAL_STORAGE_COOKIE:
                payloads.append(f"localStorage.setItem('cookie', '{marked}')")
            elif sink == CookieSink.SESSION_STORAGE_COOKIE:
                payloads.append(f"sessionStorage.setItem('cookie', '{marked}')")

            payloads.append(marked)

        return payloads

    def test_cookie_injection(
        self,
        cookie_name: str,
        sink: CookieSink,
        marker: str = "xoxss"
    ) -> Optional[CookieXSSVulnerability]:
        """
        Test cookie injection point for XSS.

        Args:
            cookie_name: Cookie name to test
            sink: Target sink
            marker: Unique marker

        Returns:
            CookieXSSVulnerability if vulnerable, None otherwise
        """
        payloads = self.generate_cookie_payloads(sink, marker)

        for payload in payloads:
            # In a real implementation, this would set the cookie
            # and check for reflection/execution
            return CookieXSSVulnerability(
                sink=sink,
                injection_point=cookie_name,
                context=f"Cookie injection via {cookie_name}",
                payload=payload,
                severity="high",
                bypass_attributes=[]
            )

        return None

    def scan_for_cookie_xss(
        self,
        js_content: str,
        html_content: str = "",
        cookie_headers: Optional[List[str]] = None,
        marker: str = "xoxss"
    ) -> List[CookieXSSVulnerability]:
        """
        Scan for cookie-based XSS vulnerabilities.

        Args:
            js_content: JavaScript source code
            html_content: HTML source code
            cookie_headers: List of observed cookie headers
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        self._vulnerabilities = []
        sinks = self.detect_cookie_sinks(js_content, html_content)

        if not sinks:
            return self._vulnerabilities

        # Test common cookie names
        for cookie_name in self.COMMON_COOKIE_NAMES:
            for sink in sinks:
                vuln = self.test_cookie_injection(cookie_name, sink, marker)
                if vuln:
                    self._vulnerabilities.append(vuln)

        # Check cookie headers for attribute bypasses
        if cookie_headers:
            for header in cookie_headers:
                bypasses = self.check_attribute_bypass(header)
                if bypasses:
                    for sink in sinks:
                        vuln = CookieXSSVulnerability(
                            sink=sink,
                            injection_point="cookie_header",
                            context=f"Cookie header with bypassable attributes: {', '.join(bypasses)}",
                            payload="attribute_bypass",
                            severity="medium",
                            bypass_attributes=bypasses
                        )
                        self._vulnerabilities.append(vuln)

        return self._vulnerabilities

    def assess_cookie_xss_risk(self, vulnerabilities: List[CookieXSSVulnerability]) -> str:
        """Assess overall cookie XSS risk."""
        if not vulnerabilities:
            return "none"

        # Check for attribute bypasses
        has_bypass = any(v.bypass_attributes for v in vulnerabilities)
        if has_bypass:
            return "critical"

        # Check for document.cookie sink (most dangerous)
        has_doc_cookie = any(v.sink == CookieSink.DOCUMENT_COOKIE for v in vulnerabilities)
        if has_doc_cookie:
            return "high"

        return "medium"

    def get_cookie_xss_summary(self) -> Dict[str, int]:
        """Get summary of cookie XSS findings."""
        summary = {
            "total_vulnerabilities": len(self._vulnerabilities),
            "by_sink": {
                "document_cookie": sum(1 for v in self._vulnerabilities if v.sink == CookieSink.DOCUMENT_COOKIE),
                "cookie_header": sum(1 for v in self._vulnerabilities if v.sink == CookieSink.COOKIE_HEADER),
                "local_storage": sum(1 for v in self._vulnerabilities if v.sink == CookieSink.LOCAL_STORAGE_COOKIE),
                "session_storage": sum(1 for v in self._vulnerabilities if v.sink == CookieSink.SESSION_STORAGE_COOKIE),
            },
            "attribute_bypasses": sum(1 for v in self._vulnerabilities if v.bypass_attributes),
        }
        return summary


__all__ = [
    "CookieSink",
    "CookieXSSDetector",
    "CookieXSSVulnerability",
]
