"""
DOM Clobbering detection module.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class ClobberingType(Enum):
    """DOM clobbering attack types."""
    ID_CLOBBERING = "id_clobbering"
    NAME_CLOBBERING = "name_clobbering"
    FORM_CLOBBERING = "form_clobbering"
    WINDOW_PROPERTY = "window_property"
    PROTOTYPE_OVERRIDE = "prototype_override"


@dataclass
class ClobberingVulnerability:
    """DOM clobbering vulnerability."""
    clobbering_type: ClobberingType
    target_property: str
    element: str
    context: str
    severity: str


class DOMClobberingDetector:
    """
    Advanced DOM clobbering detector.
    Detects DOM clobbering vulnerabilities that can override JavaScript properties.
    """

    # Properties that can be clobbered
    CLOBBERABLE_PROPERTIES = [
        'location',
        'location.href',
        'location.hash',
        'location.search',
        'document.cookie',
        'document.domain',
        'document.referrer',
        'document.URL',
        'window.name',
        'localStorage',
        'sessionStorage',
        'navigator',
        'history',
    ]

    # Clobbering patterns
    CLOBBERING_PATTERNS = {
        ClobberingType.ID_CLOBBERING: [
            r'id\s*=\s*["\']({})["\']',
            r'id\s*=\s*({})',
        ],
        ClobberingType.NAME_CLOBBERING: [
            r'name\s*=\s*["\']({})["\']',
            r'name\s*=\s*({})',
        ],
        ClobberingType.FORM_CLOBBERING: [
            r'<form\s+[^>]*name\s*=\s*["\']({})["\']',
        ],
    }

    # Dangerous elements for clobbering
    DANGEROUS_ELEMENTS = [
        'a',
        'img',
        'iframe',
        'form',
        'input',
        'button',
        'object',
        'embed',
    ]

    def __init__(self):
        self._cache: Dict[str, List[ClobberingVulnerability]] = {}

    def detect_dom_clobbering(self, html_content: str, url: str = "") -> List[ClobberingVulnerability]:
        """
        Detect DOM clobbering vulnerabilities in HTML content.

        Args:
            html_content: HTML source code
            url: URL of the page (for reporting)

        Returns:
            List of detected clobbering vulnerabilities
        """
        vulnerabilities = []

        # Check for ID-based clobbering
        for prop in self.CLOBBERABLE_PROPERTIES:
            pattern = f'id=["\']?{re.escape(prop)}["\']?'
            if re.search(pattern, html_content, re.I):
                vulnerabilities.append(ClobberingVulnerability(
                    clobbering_type=ClobberingType.ID_CLOBBERING,
                    target_property=prop,
                    element='any',
                    context=f'Element with id="{prop}" can clobber window.{prop}',
                    severity='medium'
                ))

        # Check for name-based clobbering
        for prop in self.CLOBBERABLE_PROPERTIES:
            pattern = f'name=["\']?{re.escape(prop)}["\']?'
            if re.search(pattern, html_content, re.I):
                vulnerabilities.append(ClobberingVulnerability(
                    clobbering_type=ClobberingType.NAME_CLOBBERING,
                    target_property=prop,
                    element='any',
                    context=f'Element with name="{prop}" can clobber window.{prop}',
                    severity='medium'
                ))

        # Check for dangerous element clobbering
        for element in self.DANGEROUS_ELEMENTS:
            element_pattern = rf'<{element}[^>]*(?:id|name)\s*=\s*["\']?(location|cookie|name)["\']?'
            matches = re.finditer(element_pattern, html_content, re.I)
            for match in matches:
                prop = match.group(1)
                vulnerabilities.append(ClobberingVulnerability(
                    clobbering_type=ClobberingType.FORM_CLOBBERING,
                    target_property=prop,
                    element=element,
                    context=f'<{element}> element can clobber window.{prop}',
                    severity='high'
                ))

        return vulnerabilities

    def generate_clobbering_payload(self, prop: str, marker: str) -> str:
        """Generate a DOM clobbering payload."""
        return f'<img id="{prop}" src="/nonexistent" onerror="window.__xoxss_clobber.push(\'{marker}\')">'

    def check_property_clobbering(self, html_content: str, property_name: str) -> bool:
        """Check if a specific property can be clobbered."""
        patterns = [
            f'id=["\']?{re.escape(property_name)}["\']?',
            f'name=["\']?{re.escape(property_name)}["\']?',
        ]
        for pattern in patterns:
            if re.search(pattern, html_content, re.I):
                return True
        return False

    def assess_clobbering_risk(self, vulnerabilities: List[ClobberingVulnerability]) -> str:
        """Assess overall DOM clobbering risk."""
        if not vulnerabilities:
            return "none"

        high_severity = [v for v in vulnerabilities if v.severity == 'high']
        if high_severity:
            return "high"

        return "medium"
