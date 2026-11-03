"""Reconnaissance helpers: subdomains, historic URLs, JS intel, OpenAPI."""

from xoxss.recon.subdomains import SubdomainFinder, SubdomainReport, root_domain
from xoxss.recon.passive import PassiveURLCollector, PassiveURLReport
from xoxss.recon.jsintel import JSIntel, SecretHit, analyze_javascript_intel
from xoxss.recon.openapi import APIOperation, OpenAPIFinder

__all__ = [
    "SubdomainFinder",
    "SubdomainReport",
    "root_domain",
    "PassiveURLCollector",
    "PassiveURLReport",
    "JSIntel",
    "SecretHit",
    "analyze_javascript_intel",
    "APIOperation",
    "OpenAPIFinder",
]
