"""
Mutation XSS (mXSS) detection module.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class SanitizerType(Enum):
    """HTML sanitizer types."""
    DOMPURIFY = "DOMPurify"
    SANITIZE_HTML = "sanitize-html"
    JS_XSS = "js-xss"
    HTML_SANITIZER = "html-sanitizer"
    UNKNOWN = "unknown"


@dataclass
class MXSSAnalysis:
    """Mutation XSS analysis result."""
    has_mutation_xss: bool
    sanitizer: Optional[SanitizerType]
    version: Optional[str]
    vulnerable: bool
    contexts: List[str]
    cve_ids: List[str]


class MXSSDetector:
    """
    Advanced mutation XSS detector.
    Detects mXSS vulnerabilities in HTML sanitizers.
    """

    # Known vulnerable sanitizer versions
    VULNERABLE_VERSIONS = {
        SanitizerType.DOMPURIFY: [
            '0.6.0', '0.7.0', '0.8.0', '0.9.0',
            '1.0.0', '1.0.1', '1.0.2',
            '2.0.0', '2.0.1', '2.0.2', '2.0.3',
            '2.0.7', '2.0.8', '2.0.10', '2.0.12',
            '2.0.13', '2.0.14', '2.0.15', '2.0.16',
            '2.0.17', '2.1.0', '2.1.1', '2.1.2',
            '2.1.3', '2.2.0', '2.2.1', '2.2.2',
            '2.2.3', '2.2.6', '2.2.7', '2.2.8',
            '2.3.0', '2.3.1', '2.3.2', '2.3.3',
            '2.3.4', '2.3.5', '2.3.6', '2.3.7',
            '2.3.8', '2.4.0', '2.4.1', '2.4.2',
            '2.4.3', '2.4.4', '2.4.5', '2.4.6',
            '2.4.7', '2.4.8', '3.0.0', '3.0.1',
            '3.0.2', '3.0.3', '3.0.4', '3.0.5',
            '3.0.6', '3.0.7', '3.0.8', '3.0.9',
            '3.0.10', '3.0.11', '3.0.12', '3.1.0',
            '3.1.1', '3.1.2', '3.1.3', '3.1.4',
            '3.1.5', '3.1.6', '3.1.7',
        ],
        SanitizerType.SANITIZE_HTML: [
            '1.0.0', '1.0.1', '1.0.2',
            '2.0.0', '2.0.1', '2.0.2', '2.0.3',
            '2.1.0', '2.2.0', '2.3.0', '2.4.0',
            '2.5.0', '2.6.0', '2.7.0', '2.8.0',
            '2.9.0', '2.10.0', '2.11.0',
        ],
        SanitizerType.JS_XSS: [
            '0.3.0', '0.3.1', '0.3.2',
            '1.0.0', '1.0.1', '1.0.2',
        ],
    }

    # CVE IDs for known vulnerabilities
    CVE_MAPPING = {
        SanitizerType.DOMPURIFY: {
            '2.0.17': 'CVE-2020-7660',
            '2.0.14': 'CVE-2019-16770',
            '2.0.13': 'CVE-2019-16770',
            '2.0.12': 'CVE-2019-16770',
            '2.0.11': 'CVE-2019-16770',
            '2.0.10': 'CVE-2019-16770',
            '2.0.8': 'CVE-2019-16770',
            '2.0.7': 'CVE-2019-16770',
            '2.0.3': 'CVE-2019-16770',
            '2.0.1': 'CVE-2019-16770',
            '2.0.0': 'CVE-2019-16770',
            '1.0.0': 'CVE-2019-16770',
        },
    }

    # Sanitizer detection patterns
    SANITIZER_PATTERNS = {
        SanitizerType.DOMPURIFY: re.compile(r'DOMPurify[.\s]+version\s*[:=]\s*["\']?([\d.]+)', re.I),
        SanitizerType.SANITIZE_HTML: re.compile(r'sanitize-html[.\s]+version\s*[:=]\s*["\']?([\d.]+)', re.I),
        SanitizerType.JS_XSS: re.compile(r'js-xss[.\s]+version\s*[:=]\s*["\']?([\d.]+)', re.I),
        SanitizerType.HTML_SANITIZER: re.compile(r'html-sanitizer[.\s]+version\s*[:=]\s*["\']?([\d.]+)', re.I),
    }

    # mXSS vulnerability patterns
    MXSS_PATTERNS = [
        r'innerHTML',
        r'outerHTML',
        r'insertAdjacentHTML',
        r'document\.write',
        r'document\.writeln',
    ]

    # Contexts where mXSS can occur
    MXSS_CONTEXTS = [
        'svg',
        'math',
        'template',
        'foreignObject',
        'noscript',
        'xmp',
        'iframe',
    ]

    def __init__(self):
        self._cache: Dict[str, MXSSAnalysis] = {}

    def detect_mutation_xss(self, js_content: str, url: str = "") -> MXSSAnalysis:
        """
        Detect mutation XSS vulnerabilities in JavaScript content.

        Args:
            js_content: JavaScript source code
            url: URL of the JavaScript file (for reporting)

        Returns:
            MXSSAnalysis with detailed findings
        """
        has_mutation_xss = False
        sanitizer = None
        version = None
        vulnerable = False
        contexts = []
        cve_ids = []

        # Detect sanitizers
        for sanitizer_type, pattern in self.SANITIZER_PATTERNS.items():
            match = pattern.search(js_content)
            if match:
                sanitizer = sanitizer_type
                version = match.group(1)
                if version in self.VULNERABLE_VERSIONS.get(sanitizer_type, []):
                    vulnerable = True
                    has_mutation_xss = True
                    # Get CVE ID
                    cve_id = self.CVE_MAPPING.get(sanitizer_type, {}).get(version)
                    if cve_id:
                        cve_ids.append(cve_id)
                break

        # Detect mXSS contexts
        for context in self.MXSS_CONTEXTS:
            if context in js_content.lower():
                contexts.append(context)

        # Check for dangerous patterns
        for pattern in self.MXSS_PATTERNS:
            if re.search(pattern, js_content):
                if not contexts:
                    contexts.append("generic_html")
                has_mutation_xss = True

        return MXSSAnalysis(
            has_mutation_xss=has_mutation_xss,
            sanitizer=sanitizer,
            version=version,
            vulnerable=vulnerable,
            contexts=contexts,
            cve_ids=cve_ids
        )

    def generate_test_payloads(self, analysis: MXSSAnalysis, marker: str) -> List[str]:
        """Generate mXSS test payloads."""
        payloads = []

        if not analysis.has_mutation_xss:
            return payloads

        # SVG-based mXSS payload
        payloads.append(
            f'<svg><animate attributeName=href values=javascript:window.__xoxss_mxss.push(\'{marker}\')></animate></svg>'
        )

        # Template-based mXSS
        payloads.append(
            f'<template><iframe srcdoc="<script>window.__xoxss_mxss.push(\'{marker}\')</script>"></iframe></template>'
        )

        # foreignObject mXSS
        payloads.append(
            f'<svg><foreignObject><script>window.__xoxss_mxss.push(\'{marker}\')</script></foreignObject></svg>'
        )

        # noscript mXSS
        payloads.append(
            f'<noscript><p title="</noscript><script>window.__xoxss_mxss.push(\'{marker}\')</script>">'
        )

        # formaction mXSS
        payloads.append(
            f'<form><button formaction="javascript:window.__xoxss_mxss.push(\'{marker}\')">test</button></form>'
        )

        return payloads

    def check_html_sanitizer_usage(self, js_content: str) -> bool:
        """Check if any HTML sanitizer is being used."""
        for pattern in self.SANITIZER_PATTERNS.values():
            if pattern.search(js_content):
                return True
        return False

    def get_sanitizer_recommendation(self, analysis: MXSSAnalysis) -> str:
        """Get recommendation for sanitizer upgrade."""
        if not analysis.vulnerable:
            return "Current sanitizer version appears safe"

        if analysis.sanitizer == SanitizerType.DOMPURIFY:
            return "Upgrade DOMPurify to version 3.1.7 or later"
        elif analysis.sanitizer == SanitizerType.SANITIZE_HTML:
            return "Upgrade sanitize-html to version 2.11.0 or later"
        elif analysis.sanitizer == SanitizerType.JS_XSS:
            return "Upgrade js-xss to version 1.0.2 or later"
        else:
            return "Review and upgrade HTML sanitizer"
