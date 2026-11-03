"""
JSONP endpoint detection and analysis module.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


@dataclass
class JSONPEndpoint:
    """Discovered JSONP endpoint."""
    url: str
    callback_param: str
    callback_value: Optional[str]
    response_format: str


@dataclass
class JSONPVulnerability:
    """JSONP XSS vulnerability result."""
    is_vulnerable: bool
    evidence: str
    details: str
    payload: Optional[str]


class JSONPAnalyzer:
    """
    Advanced JSONP endpoint analyzer.
    Detects and tests JSONP endpoints for XSS vulnerabilities.
    """

    # Common JSONP callback parameter names
    CALLBACK_PARAMS = [
        'callback', 'jsonp', 'cb', 'jsoncallback', 'callback_func',
        'callbackFunction', 'jsonpCallback', 'jsonpcallback',
        'successCallback', 'jsonp_callback', 'json_callback',
    ]

    # Known JSONP gadgets from public services
    KNOWN_GADGETS = {
        'google_apis': 'https://ajax.googleapis.com/ajax/services/feed/find?v=1.0&q=test&callback=',
        'flickr': 'https://api.flickr.com/services/feeds/photos_public.gne?format=json&jsoncallback=',
        'youtube': 'https://gdata.youtube.com/feeds/api/videos?q=test&alt=json-in-script&callback=',
        'github': 'https://api.github.com/users/test?callback=',
        'yql': 'https://query.yahooapis.com/v1/public/yql?q=select%20*%20from%20yahoo.finance.quotes%20where%20symbol%20in%20(%22YHOO%22)&format=json&callback=',
    }

    # JSONP response pattern
    JSONP_PATTERN = re.compile(r'^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(', re.MULTILINE)

    def __init__(self):
        self._discovered_endpoints: List[JSONPEndpoint] = []

    def is_jsonp_response(self, body: str) -> bool:
        """Check if the response body is a JSONP response."""
        if not body:
            return False
        return bool(self.JSONP_PATTERN.match(body.strip()))

    def detect_callback_param(self, url: str) -> Optional[str]:
        """Detect the callback parameter from a URL."""
        for param in self.CALLBACK_PARAMS:
            if f"{param}=" in url:
                return param
        return None

    def discover_jsonp_endpoints(
        self,
        url: str,
        body: str,
        content_type: str = ""
    ) -> List[JSONPEndpoint]:
        """
        Discover JSONP endpoints from a response.

        Args:
            url: Request URL
            body: Response body
            content_type: Content-Type header

        Returns:
            List of discovered JSONP endpoints
        """
        callbacks: List[JSONPEndpoint] = []

        if not self.is_jsonp_response(body):
            return callbacks

        callback_param = self.detect_callback_param(url)
        if callback_param:
            callbacks.append(JSONPEndpoint(
                url=url,
                callback_param=callback_param,
                callback_value=None,
                response_format=content_type
            ))
            return callbacks

        # A JavaScript body wrapping JSON in a call is only worth reporting as
        # an inferred endpoint when no callback parameter was found explicitly,
        # and only once per URL.
        if 'application/javascript' in content_type or 'text/javascript' in content_type:
            if self.is_jsonp_response(body):
                callbacks.append(JSONPEndpoint(
                    url=url,
                    callback_param="inferred",
                    callback_value=None,
                    response_format=content_type
                ))

        return callbacks

    def test_jsonp_injection(
        self,
        endpoint: JSONPEndpoint,
        marker: str
    ) -> List[JSONPVulnerability]:
        """
        Test if a JSONP endpoint is vulnerable to XSS.

        Args:
            endpoint: JSONPEndpoint to test
            marker: Unique marker for verification

        Returns:
            List of vulnerability results
        """
        results = []

        # Generate test payload
        payload = f"<script>window.__xoxss_jsonp.push('{marker}')</script>"

        # Check if callback is reflected without sanitization
        # This is a placeholder - actual testing requires HTTP requests
        results.append(JSONPVulnerability(
            is_vulnerable=False,
            evidence="Not tested (requires HTTP request)",
            details="JSONP endpoint detected - requires active testing",
            payload=payload
        ))

        return results

    def check_known_gadgets(self, domain: str) -> List[str]:
        """
        Check if domain uses known JSONP gadgets.

        Args:
            domain: Target domain

        Returns:
            List of known gadget URLs that might be usable
        """
        gadgets = []
        for gadget_name, gadget_url in self.KNOWN_GADGETS.items():
            if domain in gadget_url:
                gadgets.append(gadget_url)
        return gadgets

    def generate_jsonp_payload(
        self,
        callback_param: str,
        marker: str
    ) -> str:
        """Generate a JSONP XSS payload."""
        return f"{callback_param}=window.__xoxss_jsonp.push('{marker}')"

    def analyze_jsonp_security_headers(
        self,
        headers: Dict[str, str]
    ) -> Dict[str, bool]:
        """
        Analyze security headers for JSONP protection.

        Args:
            headers: Response headers

        Returns:
            Dictionary with security assessment
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}

        return {
            'has_x_content_type_options': 'x-content-type-options' in headers_lower,
            'nosniff_enabled': headers_lower.get('x-content-type-options', '') == 'nosniff',
            'has_csp': 'content-security-policy' in headers_lower,
            'xss_protection': 'x-xss-protection' in headers_lower,
        }
