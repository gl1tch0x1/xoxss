"""
WAF fingerprint database and matcher.

Separated from the scan coordinator so the signature list can be extended and
tested without importing aiohttp/Selenium.  Parity target: 30+ appliances.
"""

from typing import Dict, List, Optional

HEADER_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cf_bm"],
    "Akamai": ["akamai-gtm", "ak_bmsc", "akamai-origin-hop"],
    "Imperva/Incapsula": ["x-iinfo", "incap_ses", "visid_incap"],
    "Sucuri": ["x-sucuri-id", "sucuri-clientside"],
    "ModSecurity": ["mod_security", "noyb"],
    "F5 BIG-IP": ["bigipserver", "x-wa-info"],
    "Barracuda": ["barra_counter_session"],
    "Citrix NetScaler": ["citrix_ns_id", "ns_af="],
    "AWS WAF": ["x-amz-cf-id", "x-amzn-requestid"],
    "Wordfence": ["wordfence_verifiedhuman"],
    "Fortinet FortiWeb": ["fortiwafsid"],
    "Varnish": ["x-varnish", "via"],
    "StackPath": ["x-sp-gateway"],
    "Fastly": ["fastly-ssl", "x-served-by"],
    "Azure Front Door": ["x-azure-ref", "x-fd-int-roxy-purgeid"],
    "Cloudflare Turnstile": ["cf-chl-", "cf_chl_opt"],
    # Additional appliances (parity with XSStrike's 30+ fingerprints).
    "Cloudbric": ["x-cloudbric", "cloudbric"],
    "Comodo cWatch": ["x-cwatch", "cwaf", "cwatch"],
    "West263": ["x-west263", "west263"],
    "Reblaze": ["x-reblaze", "reblaze", "rbzid"],
    "Radware": ["x-rdwr", "radware", "rdwr"],
    "Wallarm": ["x-wallarm", "wallarm"],
    "SafeDog": ["safedog", "waf_safedog"],
    "360 WAF": ["x-360waf", "360waf"],
    "Alibaba Cloud WAF": ["aliyundun", "x-ali-waf"],
    "Tencent Cloud WAF": ["tencent-waf", "x-waf-tencent"],
    "Baidu Yunjiasu": ["yunjiasu", "x-baidu-waf"],
    "Huawei Cloud WAF": ["huaweicloudwaf", "x-hw-waf"],
    "NSFOCUS": ["nsfocus", "x-nsfocus"],
    "Chaitin SafeLine": ["safeline", "x-safeline"],
    "DataDome": ["x-datadome", "datadome"],
    "PerimeterX/HUMAN": ["x-px", "_px", "perimeterx"],
    "Kasada": ["x-kpsdk", "kasada"],
    "Distil": ["x-distil", "distil"],
    "Signal Sciences": ["x-sigsci", "sigscidbg"],
    "Imunify360": ["imunify360"],
    "BitNinja": ["bitninja"],
    "LiteSpeed": ["x-litespeed", "litespeed"],
    "OpenResty": ["x-openresty", "openresty"],
    "NAXSI": ["naxsi"],
    "SonicWall": ["sonicwall", "x-sonicwall"],
    "Sophos UTM": ["x-sophos", "sophos"],
    "Airlock": ["airlock"],
    "DenyAll": ["denyall", "x-denyall"],
    "Squid": ["x-squid-error"],
    "Varnish Cache": ["x-varnish-cache"],
}

BODY_SIGNATURES = {
    "Cloudflare": ["attention required! | cloudflare", "cf-error-details"],
    "Akamai": ["reference #18.", "access denied"],
    "Imperva/Incapsula": ["incapsula incident id", "_incapsula_resource"],
    "Sucuri": ["sucuri website firewall", "cloudproxy"],
    "ModSecurity": ["mod_security", "not acceptable!"],
    "AWS WAF": ["request blocked", "aws waf"],
    "F5 BIG-IP": ["the requested url was rejected"],
    "Barracuda": ["barracuda networks"],
    "Fortinet FortiWeb": ["fortiweb", "web application firewall"],
    "Azure Front Door": ["our services aren't available right now"],
    "Cloudbric": ["cloudbric"],
    "Comodo cWatch": ["comodo waf", "cwatch"],
    "West263": ["west263"],
    "Reblaze": ["reblaze"],
    "Radware": ["radware"],
    "Wallarm": ["wallarm"],
    "SafeDog": ["safedog"],
    "360 WAF": ["360waf", "360网站卫士"],
    "Alibaba Cloud WAF": ["aliyundun", "errors.aliyun.com"],
    "Tencent Cloud WAF": ["tencent cloud waf", "waf.tencent"],
    "Baidu Yunjiasu": ["yunjiasu"],
    "Huawei Cloud WAF": ["huaweicloud waf", "huawei cloud waf"],
    "NSFOCUS": ["nsfocus"],
    "Chaitin SafeLine": ["safeline", "chaitin"],
    "DataDome": ["datadome"],
    "PerimeterX/HUMAN": ["perimeterx", "px-captcha"],
    "Kasada": ["kasada"],
    "Distil": ["distil"],
    "Signal Sciences": ["sigsci", "signal sciences"],
    "Imunify360": ["imunify360"],
    "BitNinja": ["bitninja"],
    "NAXSI": ["naxsi"],
    "SonicWall": ["sonicwall"],
    "Sophos UTM": ["sophos web appliance", "sophos utm"],
    "Airlock": ["airlock"],
    "DenyAll": ["denyall"],
    "Wordfence": ["wordfence"],
}

BLOCK_WORDS = (
    "access denied", "request blocked", "blocked by", "web application firewall",
    "security policy", "malicious request", "not acceptable", "forbidden",
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
