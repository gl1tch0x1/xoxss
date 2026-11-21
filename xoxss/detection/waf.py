"""
WAF fingerprint database and matcher.

Separated from the scan coordinator so the signature list can be extended and
tested without importing aiohttp/Selenium.  Parity target: 30+ appliances.
"""

from typing import Dict, List, Optional

"""
WAF / CDN / bot-management signatures.

HEADER_SIGNATURES  — response-header names/values that identify the fronting layer.
BODY_SIGNATURES    — response-body strings that identify the fronting layer.
BLOCK_WORDS        — phrases that indicate a request was blocked (any WAF).

Grouped by category for maintainability.
"""

# ============================================================================
# HEADER SIGNATURES
# ============================================================================
HEADER_SIGNATURES = {

    # ------------------------------------------------------------------
    # Major CDN / edge providers
    # ------------------------------------------------------------------
    "Cloudflare": [
        "cf-ray", "cf-cache-status", "__cf_bm",
        # --- Expanded ---
        "cf-request-id", "cf-mitigated", "cf-chl-bypass",
        "__cfduid",                                              # legacy pre-2021
        "cf-worker", "cf-polished", "cf-apo-via",
        "x-cf-ray", "server: cloudflare",
    ],
    "Akamai": [
        "akamai-gtm", "ak_bmsc", "akamai-origin-hop",
        # --- Expanded ---
        "akamai-x-cache", "akamai-x-get-cache-key",
        "akamai-x-get-true-cache-key", "x-akamai-transformed",
        "x-akamai-request-id", "akamai-grn",
        "x-akamai-session-info", "akamai-x-feo-trace",
    ],
    "Fastly": [
        "fastly-ssl", "x-served-by",
        # --- Expanded ---
        "x-cache-hits", "x-fastly-request-id", "x-timer",
        "fastly-client-ip", "fastly-orig-accept-encoding",
        "fastly-debug-digest", "x-fastly-cache-status",
    ],
    "AWS CloudFront": [
        "x-amz-cf-id", "x-amz-cf-pop",
        # --- Expanded ---
        "x-cache: hit from cloudfront",
        "x-cache: miss from cloudfront",
        "via: 1.1 .*cloudfront",
    ],
    "Azure Front Door": [
        "x-azure-ref", "x-fd-int-roxy-purgeid",
        # --- Expanded ---
        "x-azure-fdid", "x-azure-requestchain",
        "x-msedge-ref", "x-cache: tcp_hit",
    ],
    "Google Cloud CDN / Armor": [
        "x-cloud-trace-context", "x-goog-generation",
        # --- Expanded ---
        "x-gcdn-waf", "x-goog-hash", "x-goog-stored-content-length",
        "x-guploader-uploadid", "via: 1.1 google",
        "server: Google Frontend",
    ],
    "StackPath": [
        "x-sp-gateway", "x-sp-waf",
        # --- Expanded ---
        "x-sp-cache", "x-sp-request-id",
    ],
    "Bunny CDN": [
        "server: BunnyCDN", "cdn-pullzone",
        "cdn-requestid", "cdn-uid",
    ],
    "KeyCDN": ["server: keycdn-engine", "x-cache: HIT"],
    "Edgio / Limelight": ["x-llnw-request-id", "x-llnw-pop"],
    "CacheFly": ["x-cachefly-request-id"],

    # ------------------------------------------------------------------
    # Cloud WAFs
    # ------------------------------------------------------------------
    "Imperva/Incapsula": [
        "x-iinfo", "incap_ses", "visid_incap",
        # --- Expanded ---
        "x-cdn: Incapsula", "incap-cache",
        "x-iinfo: ", "nlbi_",                                    # load-balancer cookie
        "x-imperva-request-id",
    ],
    "AWS WAF": [
        "x-amzn-waf", "x-amzn-errortype: waf",
        # --- Expanded ---
        "x-amzn-requestid", "x-amz-apigw-id",
        "x-amzn-trace-id",
    ],
    "F5 BIG-IP ASM / Advanced WAF": [
        "bigipserver", "x-wa-info",
        # --- Expanded ---
        "x-cnection", "x-waf-status",
        "x-waf-event-info", "ts_",                               # TS cookie prefix
        "bigip", "x-forwarded-for: .*bigip",
    ],
    "Fortinet FortiWeb": [
        "fortiwafsid",
        # --- Expanded ---
        "fortiweb", "fortigate", "x-fortiweb",
    ],
    "Barracuda": [
        "barra_counter_session",
        # --- Expanded ---
        "barra", "bnmsg", "x-barracuda",
    ],
    "Citrix NetScaler": [
        "citrix_ns_id", "ns_af=",
        # --- Expanded ---
        "x-ns-", "citrix", "netscaler", "ns_af", "nsc_",
    ],
    "Radware": [
        "x-rdwr", "radware", "rdwr",
        # --- Expanded ---
        "x-radware", "x-rdwr-", "rdwr-",
    ],
    "Wallarm": [
        "x-wallarm", "wallarm",
        # --- Expanded ---
        "x-wallarm-mode", "wallarm-node",
    ],
    "Signal Sciences / Fastly Next-Gen WAF": [
        "x-sigsci", "sigscidbg",
        # --- Expanded ---
        "x-sigsci-requestid", "x-sigsci-decision-ms",
        "sigscidbgw", "sigscidbge", "sigscidbgw1",
        "x-sigsci-waf-version",
    ],
    "Cloudflare Turnstile / Managed Challenge": [
        "cf-chl-", "cf_chl_opt",
        # --- Expanded ---
        "cf-chl-bypass", "cf-chl-widget",
        "cf-mitigated: challenge",
        "cf-mitigated: managed",
    ],
    "DataDome": [
        "x-datadome", "datadome",
        # --- Expanded ---
        "x-datadome-cid", "datadome-cookie",
        "x-dd-b", "x-dd-r",
    ],
    "PerimeterX / HUMAN": [
        "x-px", "_px", "perimeterx",
        # --- Expanded ---
        "x-px-authorization", "x-px-original-token",
        "px-captcha", "_pxhd", "_px3", "_pxvid",
    ],
    "Kasada": [
        "x-kpsdk", "kasada",
        # --- Expanded ---
        "x-kpsdk-ct", "x-kpsdk-cd", "x-kpsdk-r",
        "x-kpsdk-st",
    ],
    "Distil (now Imperva)": [
        "x-distil", "distil",
        # --- Expanded ---
        "x-distil-cs", "distil_r_captcha",
    ],
    "Shape Security / F5 Distributed Cloud Bot Defense": [
        "x-shape", "shape-sec", "x-shape-shield",
    ],
    "Arkose Labs": ["arkose", "x-arkose", "funCaptcha"],
    "Forter": ["x-forter", "forterToken"],

    # ------------------------------------------------------------------
    # Open-source / self-hosted WAFs
    # ------------------------------------------------------------------
    "ModSecurity": [
        "mod_security", "noyb",
        # --- Expanded ---
        "x-modsecurity", "x-mod-security",
        "mod_security: ", "server: mod_security",
    ],
    "NAXSI": ["naxsi", "x-naxsi", "x-naxsi-block"],
    "Wordfence": [
        "wordfence_verifiedhuman",
        # --- Expanded ---
        "x-wordfence", "wfvt_", "wordfence",
        "server: wordfence",
    ],
    "Shadow Daemon": ["x-shadow-daemon"],
    "Iron Bee": ["x-ironbee"],
    "Squid": [
        "x-squid-error",
        # --- Expanded ---
        "x-cache: from squid", "x-squid",
    ],
    "Varnish": [
        "x-varnish",
        # --- Expanded ---
        "x-varnish-cache", "via: 1.1 varnish",
        "x-varnish: ", "age: ",
    ],
    "OpenResty": [
        "x-openresty", "openresty",
        # --- Expanded ---
        "server: openresty",
    ],
    "LiteSpeed": [
        "x-litespeed", "litespeed",
        # --- Expanded ---
        "server: litespeed", "x-lsadc-cache",
        "x-litespeed-cache", "x-turbo-charged-by",
    ],
    # "Nginx" removed - web server, not a WAF
    "Apache": ["server: apache", "x-powered-by: apache"],
    "HAProxy": ["x-haproxy-", "server: haproxy"],
    "Traefik": ["x-traefik-", "server: traefik"],

    # ------------------------------------------------------------------
    # Hosting-provider / APAC WAFs
    # ------------------------------------------------------------------
    "Cloudbric": [
        "x-cloudbric", "cloudbric",
        # --- Expanded ---
        "x-cb-", "cloudbric-waf",
    ],
    "Comodo cWatch": [
        "x-cwatch", "cwaf", "cwatch",
        # --- Expanded ---
        "x-cwaf", "comodo-waf", "server: cwatch",
    ],
    "West263": ["x-west263", "west263"],
    "Reblaze": [
        "x-reblaze", "reblaze", "rbzid",
        # --- Expanded ---
        "x-rbz-", "server: reblaze",
    ],
    "SafeDog (安全狗)": [
        "safedog", "waf_safedog",
        # --- Expanded ---
        "safedog-flow-item", "x-safedog",
        "server: safedog",
    ],
    "360 WAF (360网站卫士)": [
        "x-360waf", "360waf",
        # --- Expanded ---
        "x-360waf-request", "wangzhan.360.cn",
    ],
    "Alibaba Cloud WAF (阿里云盾)": [
        "aliyundun", "x-ali-waf",
        # --- Expanded ---
        "x-aliyundun", "aliyundun-",
        "errors.aliyun.com",
    ],
    "Tencent Cloud WAF (腾讯云WAF)": [
        "tencent-waf", "x-waf-tencent",
        # --- Expanded ---
        "x-tencent-waf", "waf.tencent",
    ],
    "Baidu Yunjiasu (百度云加速)": [
        "yunjiasu", "x-baidu-waf",
        # --- Expanded ---
        "x-yunjiasu", "yunjiasu-nginx",
    ],
    "Huawei Cloud WAF (华为云WAF)": [
        "huaweicloudwaf", "x-hw-waf",
        # --- Expanded ---
        "x-huaweicloud-waf", "server: huaweicloud",
    ],
    "NSFOCUS (绿盟)": [
        "nsfocus", "x-nsfocus",
        # --- Expanded ---
        "x-nsfocus-waf", "server: nsfocus",
    ],
    "Chaitin SafeLine (长亭雷池)": [
        "safeline", "x-safeline",
        # --- Expanded ---
        "x-safeline-request-id", "server: safeline",
    ],
    "AnQuanBao (安全宝)": ["x-anquanbao", "anquanbao"],
    "Yunsuo (云锁)": ["yunsuo", "x-yunsuo"],

    # ------------------------------------------------------------------
    # Bot management / anti-scraping
    # ------------------------------------------------------------------
    "Imunify360": [
        "imunify360",
        # --- Expanded ---
        "x-imunify360", "server: imunify360",
    ],
    "BitNinja": [
        "bitninja",
        # --- Expanded ---
        "x-bitninja", "server: bitninja",
    ],
    "ShieldSquare (now Radware Bot Manager)": [
        "x-shieldsquare", "shieldsquare",
    ],
    "White Ops / HUMAN": ["x-whiteops", "whiteops"],
    "mPulse (Akamai RUM)": ["x-mpulse"],

    # ------------------------------------------------------------------
    # Enterprise / legacy WAFs
    # ------------------------------------------------------------------
    "Airlock": ["airlock"],
    "DenyAll": ["x-denyall", "denyall"],                          # merged duplicates
    "SonicWall": ["sonicwall", "x-sonicwall"],
    "Sophos UTM / XG": [
        "x-sophos", "sophos",
        # --- Expanded ---
        "server: sophos", "x-sophos-utm",
    ],
    "Palo Alto Networks": ["x-paloalto", "paloalto"],             # fixed leading space
    "IBM Cloud WAF / DataPower": [
        "x-ibm-waf",
        # --- Expanded ---
        "x-datapower", "server: datapower",
    ],
    "Oracle WAF / OCI WAF": ["x-oracle-waf", "x-oci-waf"],
    "Microsoft Azure WAF": ["x-azure-waf", "x-azure-fdid"],
    "Zscaler": ["x-zscaler", "x-zscaler-"],
    "Yandex WAF / Yandex Cloud": ["x-yandex-waf", "x-yandex-req-id"],
    "Mitra": ["x-mitra"],
    "Quotient": ["x-quotient"],
    "Securi": ["x-securi"],
    "Proventia": ["x-proventia"],
    "Teros": ["x-teros"],
    "BeeWare": ["x-beeware"],
    "eEye": ["x-eeye"],
    "HyperGuard": ["x-hyperguard"],
    "Imperva (legacy)": ["x-imperva"],                            # distinct from Incapsula
    "Juniper": ["x-juniper", "juniper"],
    "NetContinuum": ["x-netcontinuum"],
    "Network Appliance": ["x-networkappliance"],
    "Prolexic (now Akamai)": ["x-prolexic", "prolexic"],
    "RSA": ["x-rsa"],
    "SanSec": ["x-sansec"],
    "Trustwave": ["x-trustwave"],
    "Verisign": ["x-verisign"],
    "WatchGuard": ["x-watchguard"],
    "Websense / Forcepoint": ["x-websense", "x-forcepoint"],
    "WhiteHat": ["x-whitehat"],
    "Zenedge (now Oracle)": ["x-zenedge"],
    "A10 Thunder": ["a10", "x-a10"],
    "Riverbed / SteelApp": ["x-riverbed"],
    "Array Networks": ["x-array-"],
    "Audiocodes": ["x-audiocodes"],
    "Cisco ACE": ["ace-", "server: cisco-ace"],
    "Cisco ASA": ["x-cisco-asa"],
    "Checkpoint": ["x-checkpoint", "checkpoint"],
    "Corero": ["x-corero"],
    "DBAPPSecurity (安恒)": ["dbappsecurity", "x-das-"],
    "Hillstone (山石)": ["hillstone", "x-hillstone"],
    "KnownSec (知道创宇)": ["x-knownsec", "knownsec"],
    "Penta Security (WAPPLES)": ["wapples", "x-wapples"],
    "Sangfor (深信服)": ["sangfor", "x-sangfor"],
    "TrustKeeper": ["x-trustkeeper"],
    "Venustech (启明星辰)": ["x-venustech", "venustech"],

    # ------------------------------------------------------------------
    # Protocol / transport layer (useful for WAF detection)
    # ------------------------------------------------------------------
    "HTTP/2 fronting": ["alt-svc: h2", "alt-svc: h3"],
    "QUIC fronting": ["alt-svc: h3-"],
    "Managed DNS (Cloudflare)": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    "Managed DNS (Route53)": ["awsdns-"],
    "Managed DNS (Akamai)": ["akam.net", "akamaiedge.net"],
    "Managed DNS (Azure)": ["azure-dns.com", "azure-dns.net"],
    "Managed DNS (Google)": ["googledomains.com", "ns-cloud-"],
}


# ============================================================================
# BODY SIGNATURES
# ============================================================================
BODY_SIGNATURES = {

    # ------------------------------------------------------------------
    # Major CDN / edge providers
    # ------------------------------------------------------------------
    "Cloudflare": [
        "attention required! | cloudflare",
        "cf-error-details",
        # --- Expanded ---
        "cloudflare ray id", "please enable cookies",
        "checking your browser before accessing",
        "ddos protection by cloudflare",
        "cf-browser-verification", "cf_chl_opt",
        "ray id:", "cloudflare-nginx",
        "sorry, you have been blocked",
        "<title>just a moment...</title>",
    ],
    "Akamai": [
        "reference #18.",
        "access denied",
        # --- Expanded ---
        "reference #9.", "reference #7.",
        "you don't have permission to access",
        "akamai bot manager", "_abck",
        "the requested url was rejected. please consult with your administrator",
    ],
    "Fastly": [
        "fastly error: unknown domain",
        "fastly error: unknown backend",
        # --- Expanded ---
        "fastly-request-id", "x-fastly",
        "you have no permission to access this server",
    ],
    "AWS CloudFront": [
        "the request could not be satisfied",
        "cloudfront",
        # --- Expanded ---
        "generated by cloudfront", "error from cloudfront",
        "request blocked",
    ],
    "Azure Front Door": [
        "our services aren't available right now",
        # --- Expanded ---
        "azure front door", "x-azure-ref",
        "the request is blocked",
    ],
    "Google Cloud Armor": [
        "google cloud armor", "x-gcdn-waf",
        "sorry, this request has been blocked",
    ],
    "StackPath": ["stackpath", "x-sp-gateway"],

    # ------------------------------------------------------------------
    # Cloud WAFs
    # ------------------------------------------------------------------
    "Imperva/Incapsula": [
        "incapsula incident id",
        "_incapsula_resource",
        # --- Expanded ---
        "incap_ses_", "visid_incap_",
        "request unsuccessful. incapsula incident id",
        "powered by incapsula",
        "blocked by imperva",
    ],
    "AWS WAF": [
        "request blocked",
        "aws waf",
        # --- Expanded ---
        "the request could not be satisfied",
        "forbidden: access is denied",
    ],
    "F5 BIG-IP ASM": [
        "the requested url was rejected",
        # --- Expanded ---
        "please consult with your administrator",
        "your support id is:",
        "this request has been blocked",
    ],
    "Barracuda": [
        "barracuda networks",
        # --- Expanded ---
        "barracuda web application firewall",
        "blocked by barracuda",
    ],
    "Fortinet FortiWeb": [
        "fortiweb", "web application firewall",
        # --- Expanded ---
        "the page you are trying to access has been blocked",
        "fortigate", "blocked by fortiweb",
    ],
    "Radware": [
        "radware",
        # --- Expanded ---
        "request blocked by radware",
        "radware bot manager",
        "shieldsquare",                                            # acquired by Radware
    ],
    "Signal Sciences / Fastly NGWAF": [
        "sigsci", "signal sciences",
        # --- Expanded ---
        "request blocked by fastly", "x-sigsci",
    ],
    "DataDome": [
        "datadome",
        # --- Expanded ---
        "dd_block", "blocked by datadome",
        "datadome captcha",
    ],
    "PerimeterX / HUMAN": [
        "perimeterx", "px-captcha",
        # --- Expanded ---
        "px-block", "press & hold to confirm",
        "please verify you are a human",
    ],
    "Kasada": [
        "kasada",
        # --- Expanded ---
        "kasada bot defense", "kpsdk",
    ],
    "Distil": [
        "distil",
        # --- Expanded ---
        "distil networks", "blocked by distil",
    ],
    "Shape Security": ["shape security", "shape-shield"],

    # ------------------------------------------------------------------
    # Open-source / self-hosted WAFs
    # ------------------------------------------------------------------
    "ModSecurity": [
        "mod_security",
        "not acceptable!",
        # --- Expanded ---
        "modsecurity", "this error was generated by mod_security",
        "rule id:", "hostname for modsecurity",
    ],
    "NAXSI": [
        "naxsi",
        # --- Expanded ---
        "blocked by naxsi", "naxsi/waf",
    ],
    "Wordfence": [
        "wordfence",
        # --- Expanded ---
        "your access to this site has been limited",
        "wordfence firewall",
        "this response was generated by wordfence",
    ],
    "Squid": [
        "squid error",
        "squid proxy",
        # --- Expanded ---
        "the requested url could not be retrieved",
    ],
    "Varnish": ["varnish cache server", "x-varnish"],

    # ------------------------------------------------------------------
    # Hosting-provider / APAC WAFs
    # ------------------------------------------------------------------
    "Cloudbric": [
        "cloudbric",
        # --- Expanded ---
        "blocked by cloudbric", "cloudbric waf",
    ],
    "Comodo cWatch": [
        "comodo waf", "cwatch",
        # --- Expanded ---
        "blocked by comodo", "comodo firewall",
    ],
    "West263": ["west263"],
    "Reblaze": [
        "reblaze",
        # --- Expanded ---
        "blocked by reblaze", "x-reblaze",
    ],
    "Wallarm": [
        "wallarm",
        # --- Expanded ---
        "blocked by wallarm", "wallarm waf",
    ],
    "SafeDog (安全狗)": [
        "safedog",
        # --- Expanded ---
        "安全狗", "safedog waf", "blocked by safedog",
    ],
    "360 WAF (360网站卫士)": [
        "360waf", "360网站卫士",
        # --- Expanded ---
        "360 waf", "网站卫士拦截",
    ],
    "Alibaba Cloud WAF (阿里云盾)": [
        "aliyundun", "errors.aliyun.com",
        # --- Expanded ---
        "阿里云盾", "aliyun waf", "aliyundun error",
    ],
    "Tencent Cloud WAF (腾讯云WAF)": [
        "tencent cloud waf", "waf.tencent",
        # --- Expanded ---
        "腾讯云waf", "tcloud waf",
    ],
    "Baidu Yunjiasu (百度云加速)": [
        "yunjiasu",
        # --- Expanded ---
        "百度云加速", "yunjiasu error",
    ],
    "Huawei Cloud WAF (华为云WAF)": [
        "huaweicloud waf", "huawei cloud waf",
        # --- Expanded ---
        "华为云waf", "huaweicloudwaf",
    ],
    "NSFOCUS (绿盟)": [
        "nsfocus",
        # --- Expanded ---
        "绿盟", "nsfocus waf",
    ],
    "Chaitin SafeLine (长亭雷池)": [
        "safeline", "chaitin",
        # --- Expanded ---
        "长亭雷池", "safeline waf", "blocked by safeline",
    ],
    "DBAPPSecurity (安恒)": [
        "dbappsecurity", "安恒",
        "blocked by das-waf",
    ],
    "Sangfor (深信服)": ["sangfor", "深信服", "blocked by sangfor"],
    "Hillstone (山石)": ["hillstone", "山石"],

    # ------------------------------------------------------------------
    # Bot management / anti-scraping
    # ------------------------------------------------------------------
    "Imunify360": [
        "imunify360",
        # --- Expanded ---
        "blocked by imunify360", "imunify",
    ],
    "BitNinja": [
        "bitninja",
        # --- Expanded ---
        "blocked by bitninja",
    ],
    "Arkose Labs": ["arkose", "funcaptcha", "arkoselabs"],
    "hCaptcha": ["hcaptcha", "h-captcha"],
    "reCAPTCHA": [
        "recaptcha", "g-recaptcha",
        "www.google.com/recaptcha",
    ],

    # ------------------------------------------------------------------
    # Enterprise / legacy WAFs
    # ------------------------------------------------------------------
    "Airlock": ["airlock"],
    "DenyAll": ["denyall", "blocked by denyall"],
    "SonicWall": ["sonicwall", "blocked by sonicwall"],
    "Sophos UTM / XG": [
        "sophos web appliance",
        "sophos utm",
        # --- Expanded ---
        "blocked by sophos", "sophos xg firewall",
    ],
    "Palo Alto Networks": [
        "palo alto",
        "blocked by palo alto",
    ],
    "IBM Cloud WAF / DataPower": [
        "ibm datapower", "ibm cloud waf",
    ],
    "Oracle WAF": ["oracle waf", "oci waf"],
    "Azure WAF": ["azure waf", "azure firewall"],
    "Zscaler": ["zscaler", "blocked by zscaler"],
    "Yandex WAF": ["yandex waf", "yandex cloud waf"],
    "Cisco ACE": ["cisco ace", "blocked by cisco ace"],
    "Checkpoint": ["checkpoint", "blocked by checkpoint"],
    "Trustwave": ["trustwave", "blocked by trustwave"],
    "WatchGuard": ["watchguard", "blocked by watchguard"],
    "Websense / Forcepoint": [
        "websense",
        "forcepoint",
        "blocked by forcepoint",
    ],

    # ------------------------------------------------------------------
    # Generic / status-code based
    # ------------------------------------------------------------------
    "Generic 403": [
        "403 forbidden", "access forbidden",
        "you don't have permission",
        "forbidden: you don't have permission",
    ],
    "Generic 406": [
        "406 not acceptable",
        "not acceptable",
    ],
    "Generic 429": [
        "429 too many requests",
        "rate limit exceeded",
        "too many requests",
    ],
    "Generic 503": [
        "503 service unavailable",
        "service temporarily unavailable",
    ],
    "Generic bot challenge": [
        "please verify you are a human",
        "please complete the security check",
        "checking your browser",
        "verify you are not a robot",
        "unusual traffic from your computer network",
    ],
}


# ============================================================================
# BLOCK WORDS
# ============================================================================
BLOCK_WORDS = (
    # --- Original ---
    "access denied",
    "request blocked",
    "blocked by",
    "web application firewall",
    "security policy",
    "malicious request",
    "not acceptable",
    "forbidden",

    # --- Generic block / deny phrases ---
    "permission denied",
    "unauthorized access",
    "you don't have permission",
    "your request has been blocked",
    "your request was blocked",
    "request has been blocked",
    "the request was blocked",
    "blocked by security",
    "blocked by waf",
    "blocked due to security",
    "security violation",
    "security threat",
    "threat detected",
    "security check",
    "security reasons",
    "suspicious activity",
    "suspicious request",
    "malicious activity",
    "malicious payload",
    "malicious input",
    "attack detected",
    "attack identified",
    "attack blocked",
    "sql injection",
    "xss detected",
    "rce detected",
    "path traversal detected",

    # --- CAPTCHA / bot-challenge phrases ---
    "captcha",
    "please verify you are a human",
    "verify you are not a robot",
    "i'm not a robot",
    "robot check",
    "human verification",
    "please complete the security check",
    "checking your browser",
    "press & hold",
    "press and hold",
    "unusual traffic",
    "automated requests",

    # --- Rate limit phrases ---
    "rate limit",
    "too many requests",
    "slow down",
    "please wait",
    "temporarily blocked",
    "temporary block",
    "quota exceeded",
    "limit exceeded",

    # --- Vendor-specific canonical strings ---
    "incident id",                       # Imperva
    "ray id",                            # Cloudflare
    "support id",                        # F5 / Akamai
    "reference #",                       # Akamai
    "attention required",                # Cloudflare
    "just a moment",                     # Cloudflare
    "the requested url was rejected",    # F5 / Akamai
    "the request could not be satisfied",# CloudFront / generic
    "our services aren't available",     # Azure Front Door
    "generated by cloudfront",           # CloudFront
    "mod_security",                      # ModSecurity
    "modsecurity",                       # ModSecurity
    "naxsi",                             # NAXSI
    "wordfence",                         # WordPress
    "imunify360",                        # Imunify
    "bitninja",                          # BitNinja
    "datadome",                          # DataDome
    "perimeterx",                        # PerimeterX
    "kasada",                            # Kasada
    "distil",                            # Distil
    "sigsci",                            # Signal Sciences
    "sucuri website firewall",           # Sucuri
    "cloudproxy",                        # Sucuri

    # --- Non-English canonical phrases ---
    "访问被拒绝",                          # Chinese "access denied"
    "访问被拦截",                          # Chinese "access blocked"
    "安全狗",                              # SafeDog
    "网站卫士",                            # 360 WAF
    "阿里云盾",                            # Aliyun WAF
    "腾讯云waf",                           # Tencent WAF
    "华为云waf",                           # Huawei WAF
    "绿盟",                                # NSFOCUS
    "雷池",                                # SafeLine
    "安恒",                                # DBAPPSecurity
    "深信服",                              # Sangfor
    "アクセスが拒否されました",             # Japanese "access denied"
    "アクセスがブロックされました",         # Japanese "access blocked"
    "접근이 거부되었습니다",                # Korean "access denied"
    "차단되었습니다",                      # Korean "blocked"
    "Доступ запрещён",                    # Russian "access denied"
    "Доступ заблокирован",                # Russian "access blocked"
    "Zugriff verweigert",                 # German "access denied"
    "Accès refusé",                       # French "access denied"
    "Acceso denegado",                    # Spanish "access denied"
    "Acesso negado",                      # Portuguese "access denied"
)


def fingerprint(
    headers: Dict[str, str],
    body: str,
    cookies: str = "",
) -> List[str]:
    """Return the sorted list of WAF names matching the response."""
    haystack = " ".join(f"{key}: {value}" for key, value in headers.items()).lower()
    cookie_blob = (cookies or "").lower()
    body_low = (body or "")[:200000].lower()

    names = set()
    for name, signatures in HEADER_SIGNATURES.items():
        if any(sig in haystack or sig in cookie_blob for sig in signatures):
            names.add(name)
    for name, signatures in BODY_SIGNATURES.items():
        if any(sig in body_low for sig in signatures):
            names.add(name)
    return sorted(names)


def looks_blocked(status: int, body: str, words: Optional[tuple] = None) -> bool:
    """Heuristic: did the WAF reject the payload probe?"""
    body_low = (body or "")[:100000].lower()
    if status in (403, 406, 429, 501, 503):
        return True
    return any(word in body_low for word in (words or BLOCK_WORDS))
