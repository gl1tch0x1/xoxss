"""
Lightweight JavaScript taint analysis for DOM-XSS.

This is deliberately dependency-free.  It is not a full ECMAScript parser: it
tokenises just enough structure to follow the two things that matter for DOM
XSS — attacker-controlled *sources* flowing into dangerous *sinks* — including
simple aliases, string concatenation and one level of function arguments.

The analyser is intentionally conservative.  A flow is reported only when a
source (or a variable that was assigned a source) appears in the sink
expression, which keeps false positives manageable on real-world bundles.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set, Tuple

from xoxss.analysis.framework_sinks import (
    is_framework_internal_sink,
    is_sanitizer_barrier,
    is_static_or_feature_detection,
    is_third_party_analytics,
)


SOURCE_PATTERNS: Dict[str, str] = {
    # --- original ---
    "location.hash": r"\b(?:window\.|document\.|self\.|top\.)?location\s*\.\s*hash\b",
    "location.search": r"\b(?:window\.|document\.|self\.|top\.)?location\s*\.\s*search\b",
    "location.href": r"\b(?:window\.|document\.|self\.|top\.)?location\s*\.\s*href\b",
    "location.pathname": r"\b(?:window\.|document\.|self\.|top\.)?location\s*\.\s*pathname\b",
    "document.URL": r"\bdocument\s*\.\s*URL\b",
    "document.documentURI": r"\bdocument\s*\.\s*documentURI\b",
    "document.referrer": r"\bdocument\s*\.\s*referrer\b",
    "document.cookie": r"\bdocument\s*\.\s*cookie\b",
    "window.name": r"\bwindow\s*\.\s*name\b",
    "localStorage": r"\b(?:window\s*\.\s*)?localStorage\s*(?:\.\s*(?:getItem|key)\s*\(|\[)",
    "sessionStorage": r"\b(?:window\s*\.\s*)?sessionStorage\s*(?:\.\s*(?:getItem|key)\s*\(|\[)",
    "history.state": r"\bhistory\s*\.\s*state\b",
    "postMessage.data": r"\b(?:event|e|evt|message)\s*\.\s*data\b",
    "URLSearchParams": r"\bURLSearchParams\b",
    "document.location": r"\bdocument\s*\.\s*location\b",
    "window.location": r"\bwindow\s*\.\s*location\b",
    "indexedDB": r"\b(?:window\s*\.\s*)?indexedDB\s*\.\s*open\b",

    # --- added: window / frame handles ---
    "self.location": r"\bself\s*\.\s*location\b",
    "top.location": r"\btop\s*\.\s*location\b",
    "parent.location": r"\bparent\s*\.\s*location\b",
    "opener.location": r"\bopener\s*\.\s*location\b",
    "frames[...].location": r"\bframes?\s*\[[^\]]{0,40}\]\s*\.\s*location\b",
    "window.ancestorOrigins": r"\bwindow\s*\.\s*ancestorOrigins\b",

    # --- added: document sources ---
    "document.baseURI": r"\bdocument\s*\.\s*baseURI\b",
    "document.domain": r"\bdocument\s*\.\s*domain\b",
    "document.documentElement.innerHTML": r"\bdocument\s*\.\s*documentElement\s*\.\s*innerHTML\b",
    "document.title": r"\bdocument\s*\.\s*title\b",
    "document.currentScript": r"\bdocument\s*\.\s*currentScript\b",
    "document.scripts.src": r"\bdocument\s*\.\s*scripts\b|\bcurrentScript\s*\.\s*src\b",

    # --- added: element sources ---
    "element.value": r"\b(?:el|elem|e|input|field|txt|textarea|select)\s*\.\s*value\b",
    "element.innerHTML(read)": r"\.\s*innerHTML\b",
    "element.getAttribute": r"\.\s*getAttribute\s*\(\s*['\"][^'\"]{1,80}['\"]\s*\)",
    "element.dataset": r"\.\s*dataset\b",
    "element.getAttributeNS": r"\bgetAttributeNS\s*\([^)]{0,120}\)",

    # --- added: jQuery read helpers ---
    "jQuery.attr.read": r"\.\s*attr\s*\(\s*['\"][^'\"]{1,80}['\"]\s*\)",
    "jQuery.val.read": r"\.\s*val\s*\(\s*\)",
    "jQuery.data.read": r"\.\s*data\s*\(\s*['\"][^'\"]{1,80}['\"]\s*\)",
    "jQuery.serialize": r"\.\s*serialize(?:Array)?\s*\(\s*\)",

    # --- added: history / routing ---
    "history.pushState.state": r"\bhistory\s*\.\s*(?:pushState|replaceState)\s*\([^,]{0,200},\s*[^,]{0,200},\s*[^,]{0,200},\s*[^)]{0,600}\)",
    "React.useLocation": r"\buseLocation\s*\(|\bprops\s*\.\s*location\b|\bthis\s*\.\s*props\s*\.\s*location\b",
    "React.useSearchParams": r"\buseSearchParams\s*\(|\buseParams\s*\(",
    "Vue.$route": r"\$route\s*\.\s*(?:query|params|hash|fullPath)",
    "Angular.route": r"\b(?:queryParamMap|queryParams|fragment|params)\b|\brouter\s*\.\s*url\b",

    # --- added: network / messaging sources ---
    "BroadcastChannel": r"\bBroadcastChannel\b",
    "MessagePort": r"\bMessagePort\b|\b\.\s*onmessage\s*=",
    "WebSocket": r"\bnew\s+WebSocket\b",
    "XMLHttpRequest": r"\bnew\s+XMLHttpRequest\b|\b(?:xhr|XMLHttpRequest)\s*\.\s*response(?:Text|XML|URL)?\b",
    "fetch.text": r"\b(?:await\s+)?[^;\n]{0,200}\.\s*text\s*\(\s*\)",
    "postMessage.listener": r"\baddEventListener\s*\(\s*['\"]message['\"]|\bwindow\s*\.\s*onmessage\s*=",

    # --- added: URL helpers ---
    "new URL": r"\bnew\s+URL\s*\(",
    "URLSearchParams.get": r"\bsearchParams\s*\.\s*get\b",
    "String(location)": r"\bString\s*\(\s*(?:window\s*\.\s*)?location\b|\blocation\s*\.\s*toString\s*\(",
    "import.meta.url": r"\bimport\s*\.\s*meta\s*\.\s*url\b",

    # --- added: obfuscated location / document access ---
    "location[bracket]": r"\[\s*['\"]location['\"]\s*\]",
    "location concat": r"['\"]loc(?:a)?['\"]\s*\+\s*['\"]ation['\"]",
    "location split/join": r"['\"]lo[|.]ca[|.]tion['\"]\s*\.\s*split\s*\(",
    "hash[bracket]": r"\[\s*['\"]hash['\"]\s*\]",
    "hash concat": r"['\"]ha['\"]\s*\+\s*['\"]sh['\"]",
    "search[bracket]": r"\[\s*['\"]search['\"]\s*\]",
    "search concat": r"['\"]sea['\"]\s*\+\s*['\"]rch['\"]",
    "cookie[bracket]": r"document\s*\[\s*['\"]cookie['\"]\s*\]",
    "cookie concat": r"['\"]coo['\"]\s*\+\s*['\"]kie['\"]",
    "window.name[bracket]": r"window\s*\[\s*['\"]name['\"]\s*\]",
    "localStorage[bracket]": r"\[\s*['\"](?:localStorage|sessionStorage)['\"]\s*\]",
    "storage.getItem[bracket]": r"\[\s*['\"]getItem['\"]\s*\]",
    "event.data[bracket]": r"\.\s*\[\s*['\"]data['\"]\s*\]",

    # --- added: generic obfuscation primitives (often wrap a source) ---
    "atob.decoded": r"\batob\s*\(\s*['\"][A-Za-z0-9+/=]{16,}['\"]\s*\)",
    "String.fromCharCode": r"\bString\s*\.\s*fromCharCode\s*\(",
    "unescape": r"\bunescape\s*\(",
    "hex escape sequence": r"(?:\\x[0-9a-fA-F]{2}){4,}",
    "unicode escape sequence": r"(?:\\u[0-9a-fA-F]{4}){4,}",
    "split/join obfuscation": r"\.\s*split\s*\(\s*['\"][^'\"]{0,8}['\"]\s*\)\s*\.\s*join\s*\(\s*['\"]['\"]\s*\)",
    "reverse obfuscation": r"\.\s*split\s*\(\s*['\"]['\"]\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*['\"]['\"]\s*\)",
}

# Sinks are (name, regex, context, needs_string_argument).
SINK_PATTERNS: List[Tuple[str, str, str, bool]] = [
    # --- original ---
    ("innerHTML", r"\.\s*innerHTML\s*=\s*([^;\n]{0,600})", "html", False),
    ("outerHTML", r"\.\s*outerHTML\s*=\s*([^;\n]{0,600})", "html", False),
    ("insertAdjacentHTML", r"\.\s*insertAdjacentHTML\s*\(\s*[^,]{1,80},\s*([^)]{0,600})", "html", False),
    ("document.write", r"\bdocument\s*\.\s*write(?:ln)?\s*\(\s*([^)]{0,600})", "html", False),
    ("eval", r"(?<![\w$.])eval\s*\(\s*([^)]{0,600})", "js", False),
    ("Function", r"\b(?:new\s+)?Function\s*\(\s*([^)]{0,600})", "js", False),
    ("setTimeout", r"\bsetTimeout\s*\(\s*([^,)]{0,600})", "js", True),
    ("setInterval", r"\bsetInterval\s*\(\s*([^,)]{0,600})", "js", True),
    ("location.assign", r"\blocation\s*\.\s*assign\s*\(\s*([^)]{0,600})", "url", False),
    ("location.replace", r"\blocation\s*\.\s*replace\s*\(\s*([^)]{0,600})", "url", False),
    ("location.href", r"\blocation\s*\.\s*href\s*=\s*([^;\n]{0,600})", "url", False),
    ("location", r"(?<![\w$.])location\s*=\s*([^;\n]{0,600})", "url", False),
    ("setAttribute", r"\.\s*setAttribute\s*\(\s*['\"](?:href|src|srcdoc|action|formaction|style|on\w+)['\"]\s*,\s*([^)]{0,600})", "url", False),
    ("srcdoc", r"\.\s*srcdoc\s*=\s*([^;\n]{0,600})", "html", False),
    ("jquery.html", r"\.\s*html\s*\(\s*([^)]{0,600})", "html", False),
    ("jquery.append", r"\.\s*append\s*\(\s*([^)]{0,600})", "html", False),
    ("jquery.prepend", r"\.\s*prepend\s*\(\s*([^)]{0,600})", "html", False),
    ("jquery.before", r"\.\s*before\s*\(\s*([^)]{0,600})", "html", False),
    ("jquery.after", r"\.\s*after\s*\(\s*([^)]{0,600})", "html", False),
    ("jquery.replaceWith", r"\.\s*replaceWith\s*\(\s*([^)]{0,600})", "html", False),
    ("createContextualFragment", r"\bcreateContextualFragment\s*\(\s*([^)]{0,600})", "html", False),
    ("DOMParser.parseFromString", r"\bparseFromString\s*\(\s*([^,)]{0,600})", "html", False),
    ("setHTMLUnsafe", r"\.\s*setHTMLUnsafe\s*\(\s*([^)]{0,600})", "html", False),
    ("setHTML", r"\.\s*setHTML\s*\(\s*([^)]{0,600})", "html", False),
    ("createElement.script", r"createElement\s*\(\s*['\"]script['\"]\s*\)", "js", False),

    # --- added: compound assignment / bracket variants of classic sinks ---
    ("innerHTML+=", r"\.\s*innerHTML\s*\+=\s*([^;\n]{0,600})", "html", False),
    ("outerHTML+=", r"\.\s*outerHTML\s*\+=\s*([^;\n]{0,600})", "html", False),
    ("innerHTML[bracket]", r"\.\s*\[\s*['\"]innerHTML['\"]\s*\]\s*=\s*([^;\n]{0,600})", "html", False),
    ("outerHTML[bracket]", r"\.\s*\[\s*['\"]outerHTML['\"]\s*\]\s*=\s*([^;\n]{0,600})", "html", False),
    ("document.write[bracket]", r"\bdocument\s*\[\s*['\"]write(?:ln)?['\"]\s*\]\s*\(\s*([^)]{0,600})", "html", False),
    ("insertAdjacentHTML[bracket]", r"\.\s*\[\s*['\"]insertAdjacentHTML['\"]\s*\]\s*\(\s*[^,]{1,80},\s*([^)]{0,600})", "html", False),
    ("srcdoc[bracket]", r"\[\s*['\"]srcdoc['\"]\s*\]\s*=\s*([^;\n]{0,600})", "html", False),

    # --- added: eval / Function via bracket, indirect, constructor chains ---
    ("eval[bracket]", r"\b(?:window|self|top|globalThis|this)\s*\[\s*['\"]eval['\"]\s*\]\s*\(\s*([^)]{0,600})", "js", False),
    ("eval.indirect", r"\(\s*(?:0\s*,\s*|window\s*\.\s*)?eval\s*\)\s*\(\s*([^)]{0,600})", "js", False),
    ("eval.call/apply", r"\beval\s*\.\s*(?:call|apply)\s*\(\s*[^,)]{0,120},?\s*([^)]{0,600})", "js", False),
    ("Function[bracket]", r"\b(?:window|self|top|globalThis)\s*\[\s*['\"]Function['\"]\s*\]\s*\(\s*([^)]{0,600})", "js", False),
    ("Function[constructor]", r"\[\s*['\"]constructor['\"]\s*\]\s*\[\s*['\"]constructor['\"]\s*\]\s*\(\s*([^)]{0,600})", "js", False),
    ("Function.via.constructor", r"\.\s*constructor\s*\(\s*([^)]{0,600})\)\s*\(", "js", False),
    ("eval via constructor", r"\[\s*['\"]constructor['\"]\s*\]\s*\(\s*['\"]return\s+this['\"]\s*\)\s*\(\s*\)\s*\.\s*eval\s*\(\s*([^)]{0,600})", "js", False),

    # --- added: timer sinks with obfuscated names ---
    ("setTimeout[bracket]", r"\bwindow\s*\[\s*['\"]setTimeout['\"]\s*\]\s*\(\s*([^,)]{0,600})", "js", True),
    ("setInterval[bracket]", r"\bwindow\s*\[\s*['\"]setInterval['\"]\s*\]\s*\(\s*([^,)]{0,600})", "js", True),
    ("setImmediate", r"\bsetImmediate\s*\(\s*([^,)]{0,600})", "js", False),
    ("requestAnimationFrame.obf", r"\brequestAnimationFrame\s*\(\s*(?:function|\(\s*\)\s*=>)\s*\{?\s*([^)]{0,600})", "js", False),

    # --- added: navigation sinks (top / parent / self / document) ---
    ("top.location=", r"\btop\s*\.\s*location\s*(?:\.\s*href\s*)?=\s*([^;\n]{0,600})", "url", False),
    ("self.location=", r"\bself\s*\.\s*location\s*(?:\.\s*href\s*)?=\s*([^;\n]{0,600})", "url", False),
    ("parent.location=", r"\bparent\s*\.\s*location\s*(?:\.\s*href\s*)?=\s*([^;\n]{0,600})", "url", False),
    ("document.location=", r"\bdocument\s*\.\s*location\s*(?:\.\s*href\s*)?=\s*([^;\n]{0,600})", "url", False),
    ("window.location[bracket]=", r"\bwindow\s*\[\s*['\"]location['\"]\s*\]\s*=\s*([^;\n]{0,600})", "url", False),
    ("location.hash=", r"\blocation\s*\.\s*hash\s*=\s*([^;\n]{0,600})", "url", False),
    ("window.open", r"\bwindow\s*\.\s*open\s*\(\s*([^)]{0,600})", "url", False),
    ("window.open[bracket]", r"\bwindow\s*\[\s*['\"]open['\"]\s*\]\s*\(\s*([^)]{0,600})", "url", False),

    # --- added: attribute / element sinks ---
    ("element.href/src/action", r"\.\s*(?:href|src|action|formaction|data)\s*=\s*([^;\n]{0,600})", "url", False),
    ("setAttributeNS", r"\bsetAttributeNS\s*\([^,]{0,80},\s*['\"](?:href|src|srcdoc|action|formaction|style|on\w+)['\"]\s*,\s*([^)]{0,600})", "url", False),
    ("jQuery.attr(sink)", r"\.\s*attr\s*\(\s*['\"](?:href|src|srcdoc|action|formaction|style|on\w+)['\"]\s*,\s*([^)]{0,600})", "url", False),
    ("jQuery.attr[bracket]", r"\.\s*\[\s*['\"]attr['\"]\s*\]\s*\(\s*['\"](?:href|src|on\w+)['\"]\s*,\s*([^)]{0,600})", "url", False),
    ("jQuery.prop(sink)", r"\.\s*prop\s*\(\s*['\"](?:innerHTML|outerHTML|href|src|srcdoc)['\"]\s*,\s*([^)]{0,600})", "html", False),
    ("jQuery.html[bracket]", r"\.\s*\[\s*['\"]html['\"]\s*\]\s*\(\s*([^)]{0,600})", "html", False),
    ("jQuery.append[bracket]", r"\.\s*\[\s*['\"]append['\"]\s*\]\s*\(\s*([^)]{0,600})", "html", False),
    ("jQuery.globalEval", r"\$\s*\.\s*globalEval\s*\(\s*([^)]{0,600})", "js", False),
    ("jQuery.parseHTML", r"\$\s*\.\s*parseHTML\s*\(\s*([^)]{0,600})", "html", False),
    ("jQuery.getScript", r"\$\s*\.\s*getScript\s*\(\s*([^)]{0,600})", "url", False),
    ("jQuery.ajax.dataType.script", r"\bdataType\s*:\s*['\"]script['\"]", "url", False),

    # --- added: React / Angular / Vue ---
    ("dangerouslySetInnerHTML", r"dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*([^}]{0,600})", "html", False),
    ("Angular.trustAsHtml", r"\btrustAsHtml\s*\(\s*([^)]{0,600})", "html", False),
    ("Angular.bypassSecurityTrust", r"\bbypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style|ScriptUrl)\s*\(\s*([^)]{0,600})", "url", False),
    ("Vue.v-html", r"\bv-html\s*=\s*\"([^\"]{0,600})\"", "html", False),

    # --- added: script / iframe / worker creation ---
    ("createElement(concat script)", r"\bcreateElement\s*\(\s*['\"]scr['\"]\s*\+\s*['\"]ipt['\"]\s*\)", "js", False),
    ("createElement('iframe')", r"\bcreateElement\s*\(\s*['\"]iframe['\"]\s*\)", "url", False),
    ("createHTMLDocument", r"\bcreateHTMLDocument\s*\(\s*([^)]{0,600})", "html", False),
    ("script.text", r"\b(?:script|s)\s*\.\s*text\s*=\s*([^;\n]{0,600})", "js", False),
    ("script.textContent", r"\b(?:script|s)\s*\.\s*textContent\s*=\s*([^;\n]{0,600})", "js", False),
    ("script.src", r"\b(?:script|s)\s*\.\s*src\s*=\s*([^;\n]{0,600})", "url", False),
    ("new Worker", r"\bnew\s+Worker\s*\(\s*([^)]{0,600})", "js", False),
    ("importScripts", r"\bimportScripts\s*\(\s*([^)]{0,600})", "url", False),
    ("dynamic import()", r"\bimport\s*\(\s*([^)]{0,600})", "url", False),
    ("executeScript.code", r"\bexecuteScript\s*\(\s*\{[^}]{0,200}code\s*:\s*([^}]{0,600})", "js", False),

    # --- added: style-based sinks (legacy CSS XSS / exfil) ---
    ("style.cssText", r"\.\s*cssText\s*=\s*([^;\n]{0,600})", "html", False),
    ("style.cssText[bracket]", r"\.\s*\[\s*['\"]cssText['\"]\s*\]\s*=\s*([^;\n]{0,600})", "html", False),
    ("style.backgroundImage", r"\.\s*style\s*\.\s*(?:background|backgroundImage|listStyleImage|content)\s*=\s*([^;\n]{0,600})", "html", False),

    # --- added: dangerous URL schemes / document.domain ---
    ("javascript: URL", r"(['\"]\s*javascript\s*:[^'\"]{0,600}['\"])", "url", False),
    ("data:text/html URL", r"(['\"]\s*data\s*:\s*text/html[^'\"]{0,600}['\"])", "url", False),
    ("vbscript: URL", r"(['\"]\s*vbscript\s*:[^'\"]{0,600}['\"])", "url", False),
    ("document.domain=", r"\bdocument\s*\.\s*domain\s*=\s*([^;\n]{0,600})", "url", False),

    # --- added: common obfuscated payload primitives used at sink sites ---
    ("atob(arg)", r"\batob\s*\(\s*([^)]{0,600})", "js", False),
    ("String.fromCharCode(arg)", r"\bString\s*\.\s*fromCharCode\s*\(\s*([^)]{0,600})", "js", False),
    ("unescape(arg)", r"\bunescape\s*\(\s*([^)]{0,600})", "js", False),
    ("decodeURIComponent(arg)", r"\bdecodeURIComponent\s*\(\s*([^)]{0,600})", "js", False),
]

SANITIZER_PATTERNS: List[Tuple[str, str]] = [
    # --- original ---
    ("DOMPurify", r"\bDOMPurify\s*\.\s*sanitize\b"),
    ("sanitize-html", r"\bsanitizeHtml\b|\bsanitize\s*\("),
    ("escapeHtml", r"\bescape(?:Html|HTML)\b"),
    ("encodeURIComponent", r"\bencodeURIComponent\b"),
    ("encodeURI", r"\bencodeURI\b"),
    ("textContent", r"\.\s*textContent\b"),
    ("innerText", r"\.\s*innerText\b"),
    ("validator", r"\bvalidator\s*\.\s*escape\b"),
    ("xss", r"\bxss\s*\(|\bfilterXSS\b"),
    ("trustedTypes", r"\bTrustedTypes\b"),

    # --- added: DOMPurify / sanitizers in obfuscated forms ---
    ("DOMPurify.sanitize[bracket]", r"\bDOMPurify\s*\[\s*['\"]sanitize['\"]\s*\]"),
    ("DOMPurify.setConfig", r"\bDOMPurify\s*\.\s*setConfig\b"),
    ("sanitizeHtml[bracket]", r"\[\s*['\"]sanitizeHtml?['\"]\s*\]"),
    ("htmlspecialchars", r"\bhtmlspecialchars\b|\bescapeHTMLSpecialChars\b"),
    ("htmlEscape", r"\bhtmlEscape\b|\bescapeHTML\b|\besc_html\b"),
    ("stripTags", r"\bstripTags?\b|\bstriptags\b"),
    ("he.encode", r"\bhe\s*\.\s*(?:encode|escape)\b"),
    ("entities.encode", r"\bentities\s*\.\s*(?:encode|escape)\b"),
    ("lodash.escape", r"\b_\s*\.\s*escape\b|\blodash\s*\.\s*escape\b"),
    ("mustache.escape", r"\bmustache\s*\.\s*escape\b"),
    ("Handlebars.escapeExpression", r"\bHandlebars\s*\.\s*escapeExpression\b"),
    ("validator", r"\bvalidator\s*\.\s*(?:escape|blacklist|whitelist|trim)\b"),
    ("bleach.clean", r"\bbleach\s*\.\s*clean\b"),
    ("nh3.clean", r"\bnh3\s*\.\s*clean\b"),
    ("Angular.sanitize", r"\bDomSanitizer\s*\.\s*sanitize\b|\bsanitizer\s*\.\s*sanitize\b"),
    ("TrustedTypes.createPolicy", r"\bTrustedTypes\s*\.\s*createPolicy\b"),
    ("CSS.escape", r"\bCSS\s*\.\s*escape\b"),
    ("jQuery.text", r"\.\s*text\s*\(\s*([^)]{0,600})\)"),
    ("React.escape", r"\bReact\s*\.\s*escape\b|\bReactDOM\s*\.\s*escape\b"),
]

SAFE_MINIFIED_NAMES: Set[str] = {
    # single letters
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    # common globals / minified helpers
    "$", "_", "$$",
    "aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "ii", "jj", "kk",
    "ll", "mm", "nn", "oo", "pp", "qq", "rr", "ss", "tt", "uu", "vv",
    "ww", "xx", "yy", "zz",
    "a1", "b1", "c1", "x1", "y1", "z1", "i0", "j0", "n1", "m1", "k1", "v1", "t1", "r1",
    # common short names
    "id", "db", "el", "fn", "cb", "obj", "key", "val", "res", "req",
    "err", "doc", "win", "evt", "msg", "ctx", "ref", "idx", "num", "str",
    "node", "item", "data", "it", "to", "at", "in", "of", "on", "up",
    "elem", "elt", "elms", "cfg", "opt", "opts", "tmp", "ret", "out",
    "buf", "acc", "tag", "cls", "src", "url", "uri", "loc", "xhr",
    "http", "ws", "ch", "chan", "port", "ok", "ko", "c2", "s2", "p2",
    "get", "set", "map", "all", "list", "els", "root", "body", "head",
    "args", "argv", "opts2", "cached", "loaded", "ready", "state",
}

_ASSIGN_RE = re.compile(
    r"(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)"
    r"\s*(\+=|=)\s*([^;\n]{0,800})"
)
_FUNCTION_RE = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|"
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>|"
    r"([A-Za-z_$][\w$]*)\s*[=:]\s*function\s*\(([^)]*)\))"
)
_CALL_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(([^()]{0,400})\)")

# --- added helper regexes for obfuscated-payload detection ---
_OBFUSC_STR_RE = re.compile(r"['\"][^'\"]{0,40}['\"]\s*\+\s*['\"][^'\"]{0,40}['\"]")
_ATOB_RE = re.compile(r"\batob\s*\(\s*['\"][A-Za-z0-9+/=]{16,}['\"]\s*\)")
_CHR_RE = re.compile(r"\bString\s*\.\s*fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){3,}\s*\)")
_HEX_ESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_UNI_ESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
_JS_URL_RE = re.compile(
    r"['\"]\s*(?:javascript|vbscript|data\s*:\s*text/html)\s*:", re.IGNORECASE
)
_BRACKET_SINK_RE = re.compile(
    r"\[\s*['\"](?:innerHTML|outerHTML|eval|write|writeln|location|href|hash|search|"
    r"cookie|name|src|srcdoc|append|html|attr|on\w+)['\"]\s*\]"
)
_CONSTRUCTOR_CHAIN_RE = re.compile(
    r"\[\s*['\"]constructor['\"]\s*\]\s*\[\s*['\"]constructor['\"]\s*\]"
)


@dataclass
class TaintFlow:
    """A source -> sink data-flow edge."""

    source: str
    sink: str
    context: str
    line: int
    snippet: str
    url: str = ""
    sanitized: bool = False
    sanitizer: str = ""
    path: List[str] = field(default_factory=list)
    confidence: float = 0.7

    def key(self) -> str:
        return f"{self.url}|{self.source}|{self.sink}|{self.line}"

    def to_dict(self) -> Dict[str, object]:
        return {
            "source": self.source,
            "sink": self.sink,
            "context": self.context,
            "line": self.line,
            "snippet": self.snippet,
            "url": self.url,
            "sanitized": self.sanitized,
            "sanitizer": self.sanitizer,
            "path": list(self.path),
            "confidence": round(self.confidence, 3),
        }


def strip_comments(code: str) -> str:
    """Remove JS/HTML comments while preserving offsets and newlines."""
    code = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), code, flags=re.S)
    code = re.sub(r"(?m)(^|[^:])//[^\n]*", r"\1", code)
    code = re.sub(r"<!--.*?-->", lambda m: "\n" * m.group(0).count("\n"), code, flags=re.S)
    return code


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _snippet(text: str, offset: int, limit: int = 220) -> str:
    start = max(0, text.rfind("\n", 0, offset) + 1)
    end = text.find("\n", offset)
    if end < 0:
        end = min(len(text), offset + limit)
    line = text[start : min(end, start + limit)].strip()
    return line[:limit]


def _word_in(name: str, text: str) -> bool:
    if not name:
        return False
    return re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", text) is not None


def find_sources(code: str) -> List[Tuple[str, int, str]]:
    """Return ``(source, line, snippet)`` triples found in the code."""
    hits: List[Tuple[str, int, str]] = []
    for name, pattern in SOURCE_PATTERNS.items():
        for match in re.finditer(pattern, code, flags=re.I):
            hits.append((name, _line_of(code, match.start()), _snippet(code, match.start())))
    return hits


def _collect_assignments(code: str) -> Dict[str, List[Tuple[str, int, int, str]]]:
    assignments: Dict[str, List[Tuple[str, int, int, str]]] = {}
    for match in _ASSIGN_RE.finditer(code):
        name = re.sub(r"\s+", "", match.group(1)).split(".")[-1]
        if not name or name in ("if", "for", "while", "return", "typeof"):
            continue
        expr = match.group(3).strip()
        if not expr or expr.startswith("="):
            continue
        assignments.setdefault(name, []).append(
            (expr, _line_of(code, match.start()), match.start(), match.group(2))
        )
    return assignments


def _tainted_variables(code: str, assignments: Dict[str, List[Tuple[str, int, int, str]]]) -> Dict[str, Tuple[str, int, int]]:
    """Propagate taint through simple assignments/aliases.

    Returns ``{variable: (source, line, pos)}`` for every tainted alias.
    """
    tainted: Dict[str, Tuple[str, int, int]] = {}
    source_patterns = list(SOURCE_PATTERNS.items())

    for name, entries in assignments.items():
        for expr, line, pos, _op in entries:
            for source_name, pattern in source_patterns:
                if re.search(pattern, expr, flags=re.I):
                    tainted.setdefault(name, (source_name, line, pos))
                    break

    # Propagate through an explicit dependency graph. Unlike a fixed number of
    # passes, a work queue handles long alias chains in linear time.
    # CRITICAL: Do NOT propagate single-character or common minified names
    # globally, as they collide across thousands of distinct closures in bundles.
    dependencies: Dict[str, List[Tuple[str, int, int]]] = {}
    assignment_names = set(assignments)
    for target, entries in assignments.items():
        if target in SAFE_MINIFIED_NAMES:
            continue
        for expr, line, pos, _op in entries:
            for identifier in set(re.findall(r"[A-Za-z_$][\w$]*", expr)):
                if identifier in assignment_names and identifier != target and identifier not in SAFE_MINIFIED_NAMES:
                    dependencies.setdefault(identifier, []).append((target, line, pos))

    pending = list(tainted)
    visited = set(pending)
    while pending:
        source_var = pending.pop()
        source_name, source_line, source_pos = tainted[source_var]
        for target, line, pos in dependencies.get(source_var, ()):
            if target in tainted:
                continue
            tainted[target] = (source_name, line or source_line, pos or source_pos)
            if target not in visited:
                pending.append(target)
                visited.add(target)
    return tainted


def _sanitizer_in(expr: str) -> Tuple[bool, str]:
    for name, pattern in SANITIZER_PATTERNS:
        if re.search(pattern, expr, flags=re.I):
            return True, name
    return False, ""


def analyze_javascript(code: str, url: str = "") -> List[TaintFlow]:
    """Extract DOM-XSS source -> sink flows from a JavaScript blob.

    Uses the scope-aware tree-sitter backend when it is installed, and falls
    back to the dependency-free regex analyser otherwise.  Set
    ``XOXSS_AST_BACKEND=regex`` to force the regex path, or
    ``XOXSS_AST_BACKEND=tree-sitter`` to require the CST path when available.
    """
    if not code:
        return []
    backend = os.environ.get("XOXSS_AST_BACKEND", "auto").strip().lower()
    if backend != "regex":
        try:
            from xoxss.analysis.cst_taint import AVAILABLE, analyze_javascript_cst

            if AVAILABLE:
                return analyze_javascript_cst(code, url)
        except Exception:
            pass
    return analyze_javascript_regex(code, url)


def analyze_javascript_regex(code: str, url: str = "") -> List[TaintFlow]:
    """Dependency-free regex taint analysis (fallback backend)."""
    if not code:
        return []
    # Cap pathological bundles; the caller normally already truncates.
    code = code[:3_000_000]
    cleaned = strip_comments(code)
    assignments = _collect_assignments(cleaned)
    tainted = _tainted_variables(cleaned, assignments)
    taint_names = set(tainted)

    flows: List[TaintFlow] = []
    seen: Set[str] = set()

    is_third_party = is_third_party_analytics(url, cleaned)

    for sink_name, pattern, context, needs_string in SINK_PATTERNS:
        for match in re.finditer(pattern, cleaned, flags=re.I):
            expr = (match.group(1) if match.groups() else "").strip()
            if not expr:
                continue

            # Guard 1: Static string literal or feature-detection probe (zero attacker input)
            if is_static_or_feature_detection(expr):
                continue

            snippet = _snippet(cleaned, match.start())

            # Guard 2: Framework runtime internal sink (Vue 3, Alpine, React, jQuery internals)
            if is_framework_internal_sink(cleaned, snippet, match.start()):
                continue

            direct_source = ""
            for source_name, source_pattern in SOURCE_PATTERNS.items():
                if re.search(source_pattern, expr, flags=re.I):
                    direct_source = source_name
                    break

            alias = ""
            if not direct_source:
                for name in taint_names:
                    if _word_in(name, expr):
                        # Guard 3: Minified variable name collision
                        # If the name is short (e.g. 'e', 'id', 'db'), verify lexical proximity (within 800 chars)
                        if name in SAFE_MINIFIED_NAMES:
                            assign_entries = assignments.get(name, [])
                            if not any(0 <= match.start() - entry[2] <= 800 for entry in assign_entries):
                                continue
                        alias = name
                        break

            if not direct_source and not alias:
                continue

            # setTimeout('literal') is harmless; only flag dynamic arguments.
            if needs_string and re.fullmatch(r"['\"][^'\"]*['\"]", expr):
                continue

            sanitized, sanitizer = _sanitizer_in(expr)
            if not sanitized:
                barrier, barrier_name = is_sanitizer_barrier(expr)
                if barrier:
                    sanitized, sanitizer = True, barrier_name

            if alias and not sanitized:
                # Inspect the assignments that produced the alias.
                chain: List[str] = [alias]
                for entry_expr, _line, _pos, _op in assignments.get(alias, []):
                    if _sanitizer_in(entry_expr)[0]:
                        sanitized, sanitizer = _sanitizer_in(entry_expr)
                    else:
                        barrier, barrier_name = is_sanitizer_barrier(entry_expr)
                        if barrier:
                            sanitized, sanitizer = True, barrier_name
                    for other in taint_names:
                        if other != alias and _word_in(other, entry_expr) and other not in chain:
                            chain.append(other)

            source_name = direct_source
            if not source_name and alias:
                preceding_entries = [e for e in assignments.get(alias, []) if e[2] < match.start()]
                if not preceding_entries:
                    continue
                last_assign = preceding_entries[-1]
                last_expr = last_assign[0]

                # If the variable was reassigned to a static literal or empty value, it is safe
                if is_static_or_feature_detection(last_expr):
                    continue

                for s_name, s_pat in SOURCE_PATTERNS.items():
                    if re.search(s_pat, last_expr, flags=re.I):
                        source_name = s_name
                        break

                if not source_name and alias not in SAFE_MINIFIED_NAMES:
                    for t_name in taint_names:
                        if _word_in(t_name, last_expr):
                            source_name = tainted.get(t_name, ("unknown", 0, 0))[0]
                            if source_name and source_name != "unknown":
                                break

            if not source_name or source_name == "unknown":
                continue

            line = _line_of(cleaned, match.start())
            flow_confidence = (
                0.2
                if sanitized or is_third_party
                else (0.9 if direct_source else 0.72)
            )

            flow = TaintFlow(
                source=source_name,
                sink=sink_name,
                context="third-party-analytics" if is_third_party else context,
                line=line,
                snippet=snippet,
                url=url,
                sanitized=sanitized,
                sanitizer=sanitizer,
                path=[alias] if alias else [],
                confidence=flow_confidence,
            )
            if flow.key() not in seen:
                seen.add(flow.key())
                flows.append(flow)

    flows.sort(key=lambda item: (not item.sanitized, -item.confidence, item.line))
    return flows


def summarize_flows(flows: Sequence[TaintFlow]) -> Dict[str, object]:
    """Small summary used by reports."""
    return {
        "total": len(flows),
        "executable": sum(1 for flow in flows if not flow.sanitized),
        "sanitized": sum(1 for flow in flows if flow.sanitized),
        "sources": sorted({flow.source for flow in flows}),
        "sinks": sorted({flow.sink for flow in flows}),
    }


__all__ = [
    "SINK_PATTERNS",
    "SOURCE_PATTERNS",
    "TaintFlow",
    "analyze_javascript",
    "analyze_javascript_regex",
    "find_sources",
    "strip_comments",
    "summarize_flows",
]
