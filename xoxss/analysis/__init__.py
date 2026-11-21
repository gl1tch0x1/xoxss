"""
Analysis modules for advanced security testing.
"""

from xoxss.analysis.polyglot import PolyglotGenerator
from xoxss.analysis.per_char import PerCharProbe
from xoxss.analysis.jsonp import JSONPAnalyzer
from xoxss.analysis.csp import CSPAnalyzer
from xoxss.analysis.cors import CORSAnalyzer
from xoxss.analysis.mxss import MXSSDetector
from xoxss.analysis.proto_pollution import PrototypePollutionDetector
from xoxss.analysis.rate_limit import SmartRateLimiter
from xoxss.analysis.dom_clobbering import DOMClobberingDetector
from xoxss.analysis.trusted_types import TrustedTypesAnalyzer
from xoxss.analysis.graphql import GraphQLAnalyzer
from xoxss.analysis.websocket import WebSocketAnalyzer
from xoxss.analysis.file_upload import FileUploadAnalyzer
from xoxss.analysis.postmessage import PostMessageAnalyzer
from xoxss.analysis.template_injection import TemplateInjectionDetector
from xoxss.analysis.hpp import HPPDetector
from xoxss.analysis.cookie_xss import CookieXSSDetector
from xoxss.analysis.web_components import WebComponentDetector
from xoxss.analysis.wasm_xss import WASMXSSDetector
from xoxss.analysis.clipboard_xss import ClipboardXSSDetector

__all__ = [
    "CORSAnalyzer",
    "CSPAnalyzer",
    "ClipboardXSSDetector",
    "CookieXSSDetector",
    "DOMClobberingDetector",
    "FileUploadAnalyzer",
    "GraphQLAnalyzer",
    "HPPDetector",
    "JSONPAnalyzer",
    "MXSSDetector",
    "PerCharProbe",
    "PolyglotGenerator",
    "PostMessageAnalyzer",
    "PrototypePollutionDetector",
    "SmartRateLimiter",
    "TemplateInjectionDetector",
    "TrustedTypesAnalyzer",
    "WASMXSSDetector",
    "WebComponentDetector",
    "WebSocketAnalyzer",
]
