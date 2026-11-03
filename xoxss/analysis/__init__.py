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

__all__ = [
    "PolyglotGenerator",
    "PerCharProbe",
    "JSONPAnalyzer",
    "CSPAnalyzer",
    "CORSAnalyzer",
    "MXSSDetector",
    "PrototypePollutionDetector",
    "SmartRateLimiter",
    "DOMClobberingDetector",
    "TrustedTypesAnalyzer",
    "GraphQLAnalyzer",
    "WebSocketAnalyzer",
    "FileUploadAnalyzer",
    "PostMessageAnalyzer",
]
