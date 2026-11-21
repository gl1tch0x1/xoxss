"""
Enhanced sink tracking module.
Tracks additional sinks: postMessage, Web Speech API, Web Audio API, etc.
"""

import re
from typing import List
from dataclasses import dataclass
from enum import Enum

from xoxss.analysis.framework_sinks import (
    is_framework_internal_sink,
    is_static_or_feature_detection,
)


class EnhancedSink(Enum):
    """Additional XSS sinks beyond the basic ones."""
    POSTMESSAGE = "postmessage"
    WEBSPEECH_SYNTHESIS = "web_speech_synthesis"
    WEBSPEECH_RECOGNITION = "web_speech_recognition"
    WEBAUDIO_SCRIPT = "webaudio_script"
    WEBGL_SHADER = "webgl_shader"
    SVG_ANIMATION = "svg_animation"
    CSS_EXPRESSION = "css_expression"
    CSS_VAR_INJECTION = "css_var_injection"
    WORKER_IMPORTSCRIPTS = "worker_importscripts"
    IFRAME_SANDBOX = "iframe_sandbox"
    OBJECT_SRCDOC = "object_srcdoc"
    EMBED_SRCDOC = "embed_srcdoc"
    DATA_URI_SCRIPT = "data_uri_script"
    JAVASCRIPT_URI = "javascript_uri"
    DOCUMENT_REFERRER = "document_referrer"
    OPENER = "window_opener"
    NAME = "window_name"
    WEBSQL_EXECUTE = "websql_execute"
    INDEXEDDB_EXECUTE = "indexeddb_execute"
    BROADCAST_CHANNEL = "broadcast_channel"
    SHARED_WORKER = "shared_worker"
    NAVIGATION_API = "navigation_api"
    DOM_PARSER = "dom_parser"
    RANGE_FRAGMENT = "range_fragment"
    INSERT_ADJACENT = "insert_adjacent"
    OUTER_HTML = "outer_html"
    SCRIPT_TEXT = "script_text"
    ATTACH_SHADOW = "attach_shadow"
    CONTENT_DOCUMENT_WRITE = "content_document_write"
    SET_TIMEOUT_STRING = "set_timeout_string"
    NEW_FUNCTION = "new_function"
    LOCATION_ASSIGN = "location_assign"
    WINDOW_OPEN = "window_open"
    DOCUMENT_DOMAIN = "document_domain"
    HISTORY_API = "history_api"
    SEND_BEACON = "send_beacon"
    EVENTSOURCE = "eventsource"
    DYNAMIC_IMPORT = "dynamic_import"
    WEBSOCKET_SEND = "websocket_send"
    PROTOCOL_HANDLER = "protocol_handler"
    NAV_CREDENTIALS = "nav_credentials"
    WEB_SHARE = "web_share"
    TEMPLATE_CONTENT = "template_content"
    SLOT_ASSIGN = "slot_assign"
    CUSTOM_ELEMENT = "custom_element"
    SHADOW_ROOT_HTML = "shadow_root_html"
    IFRAME_SRCDOC = "iframe_srcdoc"
    OBJECT_DATA = "object_data"
    EMBED_SRC = "embed_src"
    SCRIPT_SRC = "script_src"
    LINK_HREF = "link_href"
    META_REFRESH = "meta_refresh"
    BASE_HREF = "base_href"
    FORM_ACTION = "form_action"
    BUTTON_FORM_ACTION = "button_formaction"
    INPUT_FORM_ACTION = "input_formaction"
    AREA_HREF = "area_href"
    SVG_USE_HREF = "svg_use_href"
    MATHML_HREF = "mathml_href"
    IFRAME_LONGDESC = "iframe_longdesc"
    FRAME_LONGDESC = "frame_longdesc"
    ISINDEX_ACTION = "isindex_action"
    BGSOUND_SRC = "bgsound_src"
    LAYER_SRC = "layer_src"
    XML_DATA_ISLAND = "xml_data_island"
    CSS_IMPORT = "css_import"
    CSS_URL = "css_url"
    CSS_IMAGESET = "css_imageset"
    CSS_CURSOR = "css_cursor"
    CSS_LIST_STYLE = "css_list_style"
    CSS_CONTENT_URL = "css_content_url"
    CSS_BEHAVIOR = "css_behavior"
    CSS_MOZ_BINDING = "css_moz_binding"
    CSS_FILTER_PROGID = "css_filter_progid"
    CSS_EXPRESSION_FUNC = "css_expression_func"
    CSS_JAVASCRIPT_URL = "css_javascript_url"
    CSS_VBSCRIPT_URL = "css_vbscript_url"
    CSS_DATA_URL = "css_data_url"
    CSS_BLOB_URL = "css_blob_url"
    CSS_FILESYSTEM_URL = "css_filesystem_url"


@dataclass
class SinkMatch:
    """Matched sink with context."""
    sink: EnhancedSink
    line: int
    code: str
    context: str
    confidence: float


class EnhancedSinkTracker:
    """
    Enhanced sink tracker.
    Detects and tracks additional XSS sinks beyond basic HTML/JavaScript.
    """

    # Sink patterns
    SINK_PATTERNS = {
        EnhancedSink.POSTMESSAGE: [
            r"addEventListener\s*\(\s*[\"']message[\"']",
            r"window\.onmessage\s*=",
            r"postMessage\s*\(",
        ],
        EnhancedSink.WEBSPEECH_SYNTHESIS: [
            r"speechSynthesis\.speak\s*\(",
            r"SpeechSynthesisUtterance\s*\(",
        ],
        EnhancedSink.WEBSPEECH_RECOGNITION: [
            r"webkitSpeechRecognition\s*\(",
            r"SpeechRecognition\s*\(",
        ],
        EnhancedSink.WEBAUDIO_SCRIPT: [
            r"AudioContext\.",
            r"createScriptProcessor\s*\(",
        ],
        EnhancedSink.WEBGL_SHADER: [
            r"createShader\s*\(",
            r"shaderSource\s*\(",
        ],
        EnhancedSink.SVG_ANIMATION: [
            r"<animate",
            r"<animateTransform",
            r"<set",
        ],
        EnhancedSink.CSS_EXPRESSION: [
            r"expression\s*\(",
            r"-moz-binding\s*:",
        ],
        EnhancedSink.CSS_VAR_INJECTION: [
            r"style\s*=\s*['\"][^'\"]*var\s*\([^)]*javascript:",
            r"setProperty\s*\(\s*['\"]--[^'\"]+['\"]\s*,\s*[^)]*javascript:",
        ],
        EnhancedSink.WORKER_IMPORTSCRIPTS: [
            r"\bimportScripts\s*\(",
        ],
        EnhancedSink.IFRAME_SANDBOX: [
            r"<iframe[^>]*sandbox\s*=\s*['\"][^'\"]*allow-scripts",
        ],
        EnhancedSink.OBJECT_SRCDOC: [
            r"<object[^>]*srcdoc\s*=",
        ],
        EnhancedSink.EMBED_SRCDOC: [
            r"<embed[^>]*srcdoc\s*=",
        ],
        EnhancedSink.DATA_URI_SCRIPT: [
            r"['\"]data:(?:text|application)/javascript",
        ],
        EnhancedSink.JAVASCRIPT_URI: [
            r"['\"]javascript:[^'\"]+",
        ],
        EnhancedSink.DOCUMENT_REFERRER: [
            r"\bdocument\.referrer\b",
        ],
        EnhancedSink.OPENER: [
            r"\bwindow\.opener\s*\.\s*(?:location|eval|document\.write)",
        ],
        EnhancedSink.NAME: [
            r"(?:eval|Function|document\.write|\.innerHTML\s*=)[^;]*\bwindow\.name\b",
        ],
        EnhancedSink.WEBSQL_EXECUTE: [
            r"\.executeSql\s*\(\s*['\"]SELECT\b",
        ],
        EnhancedSink.INDEXEDDB_EXECUTE: [
            r"\.objectStore\s*\([^)]*\)\s*\.\s*(?:add|put)\s*\(",
            r"\bIDBObjectStore\.prototype\.(?:add|put)\b",
        ],
        # --- modern DOM / network sinks --------------------------------------
        EnhancedSink.BROADCAST_CHANNEL: [
            r"\bnew\s+BroadcastChannel\s*\(",
            r"\.postMessage\s*\([^)]*\.(?:name|data|payload)",
        ],
        EnhancedSink.SHARED_WORKER: [
            r"\bnew\s+SharedWorker\s*\(",
        ],
        EnhancedSink.NAVIGATION_API: [
            r"\bnavigation\.(?:navigate|reload|traverseTo|back|forward)\s*\(",
            r"\bonnavigate\s*=",
            r"\bNavigateEvent\b",
        ],
        EnhancedSink.DOM_PARSER: [
            r"\bnew\s+DOMParser\s*\(\s*\)\s*\.\s*parseFromString\s*\(",
            r"\.parseFromString\s*\([^)]*text/html",
        ],
        EnhancedSink.RANGE_FRAGMENT: [
            r"\.createContextualFragment\s*\(",
            r"\bRange\.prototype\.createContextualFragment\b",
        ],
        EnhancedSink.INSERT_ADJACENT: [
            r"\.insertAdjacentHTML\s*\(",
            r"\.insertAdjacentElement\s*\(",
            r"\.insertAdjacentText\s*\(",
        ],
        EnhancedSink.OUTER_HTML: [
            r"\.outerHTML\s*=",
            r"\.outerHTML\s*\+=",
        ],
        EnhancedSink.SCRIPT_TEXT: [
            r"\.createElement\s*\(\s*['\"]script['\"]\s*\)[\s\S]{0,200}\.text\s*=",
            r"\.createElement\s*\(\s*['\"]script['\"]\s*\)[\s\S]{0,200}\.textContent\s*=",
            r"\.createElement\s*\(\s*['\"]script['\"]\s*\)[\s\S]{0,200}\.innerHTML\s*=",
        ],
        EnhancedSink.ATTACH_SHADOW: [
            r"\.attachShadow\s*\([^)]*\)\s*\.\s*innerHTML\s*=",
            r"\.attachShadow\s*\([^)]*\)[\s\S]{0,300}\.innerHTML\s*=",
        ],
        EnhancedSink.CONTENT_DOCUMENT_WRITE: [
            r"\.contentDocument\.write\s*\(",
            r"\.contentWindow\.document\.write\s*\(",
            r"\.contentWindow\.eval\s*\(",
            r"\.contentDocument\.open\s*\(",
        ],
        EnhancedSink.SET_TIMEOUT_STRING: [
            r"\bsetTimeout\s*\(\s*['\"`]",
            r"\bsetInterval\s*\(\s*['\"`]",
            r"\bsetImmediate\s*\(\s*['\"`]",
            r"\brequestIdleCallback\s*\(\s*['\"`]",
        ],
        EnhancedSink.NEW_FUNCTION: [
            r"\bnew\s+Function\s*\(",
            r"\bFunction\s*\(\s*['\"`]",
        ],
        EnhancedSink.LOCATION_ASSIGN: [
            r"\.location\s*=\s*[^;]{0,80}",
            r"\.location\.href\s*=\s*[^;]{0,80}",
            r"\.location\.assign\s*\(",
            r"\.location\.replace\s*\(",
            r"\.location\.reload\s*\(",
        ],
        EnhancedSink.WINDOW_OPEN: [
            r"\bwindow\.open\s*\(",
            r"\bopen\s*\(\s*[^)]*['\"`]https?://",
            r"\bopen\s*\(\s*[^)]*['\"`]javascript:",
        ],
        EnhancedSink.DOCUMENT_DOMAIN: [
            r"\bdocument\.domain\s*=",
        ],
        EnhancedSink.HISTORY_API: [
            r"\bhistory\.(?:pushState|replaceState)\s*\(",
            r"\bhistory\.go\s*\(",
            r"\bhistory\.back\s*\(",
            r"\bhistory\.forward\s*\(",
        ],
        EnhancedSink.SEND_BEACON: [
            r"\bnavigator\.sendBeacon\s*\(",
            r"\bsendBeacon\s*\(\s*[^)]*['\"`]https?://",
        ],
        EnhancedSink.EVENTSOURCE: [
            r"\bnew\s+EventSource\s*\(",
        ],
        EnhancedSink.DYNAMIC_IMPORT: [
            r"\bimport\s*\(\s*[^)]*['\"`]https?://",
            r"\bimport\s*\(\s*[^)]*['\"`]/",
            r"\bimport\s*\(\s*[^)]*['\"`][^'\"`]*\.(?:js|mjs)",
        ],
        EnhancedSink.WEBSOCKET_SEND: [
            r"\.send\s*\(\s*[^)]*\.(?:name|data|payload|message|value)",
            r"new\s+WebSocket\s*\([^)]*\.(?:name|data|payload|url|host)",
        ],
        EnhancedSink.PROTOCOL_HANDLER: [
            r"\bnavigator\.registerProtocolHandler\s*\(",
            r"\bregisterProtocolHandler\s*\(",
        ],
        EnhancedSink.NAV_CREDENTIALS: [
            r"\bnavigator\.credentials\.(?:get|create|store)\s*\(",
            r"\bPublicKeyCredential\b",
            r"\bOTPCredential\b",
            r"\bIdentityCredential\b",
            r"\bPasswordCredential\b",
            r"\bFederatedCredential\b",
        ],
        EnhancedSink.WEB_SHARE: [
            r"\bnavigator\.share\s*\(",
            r"\bnavigator\.canShare\s*\(",
        ],
        EnhancedSink.TEMPLATE_CONTENT: [
            r"\.content\.cloneNode\s*\(",
            r"\.content\.appendChild\s*\(",
            r"\.content\.innerHTML\s*=",
        ],
        EnhancedSink.SLOT_ASSIGN: [
            r"\.slot\s*=",
            r"\.assignedSlot\b",
            r"\bHTMLSlotElement\b",
        ],
        EnhancedSink.CUSTOM_ELEMENT: [
            r"\bcustomElements\.define\s*\(",
            r"\bconnectedCallback\s*\(",
            r"\bdisconnectedCallback\s*\(",
            r"\battributeChangedCallback\s*\(",
            r"\badoptedCallback\s*\(",
        ],
        EnhancedSink.SHADOW_ROOT_HTML: [
            r"\.shadowRoot\.innerHTML\s*=",
            r"\.shadowRoot\.outerHTML\s*=",
            r"\.shadowRoot\.appendChild\s*\(",
            r"\.shadowRoot\.insertBefore\s*\(",
        ],
        EnhancedSink.IFRAME_SRCDOC: [
            r"\.srcdoc\s*=",
            r"\.srcdoc\s*\+=",
        ],
        EnhancedSink.OBJECT_DATA: [
            r"\.data\s*=\s*[^;]{0,80}",
            r"\.setAttribute\s*\(\s*['\"]data['\"]",
        ],
        EnhancedSink.EMBED_SRC: [
            r"\.src\s*=\s*[^;]{0,80}",
            r"\.setAttribute\s*\(\s*['\"]src['\"]",
        ],
        EnhancedSink.SCRIPT_SRC: [
            r"\.createElement\s*\(\s*['\"]script['\"]\s*\)[\s\S]{0,200}\.src\s*=",
            r"\.setAttribute\s*\(\s*['\"]src['\"]\s*,",
        ],
        EnhancedSink.LINK_HREF: [
            r"\.createElement\s*\(\s*['\"]link['\"]\s*\)[\s\S]{0,200}\.href\s*=",
            r"\.rel\s*=\s*['\"]import['\"]",
            r"<link[^>]*rel=[\"']import[\"']",
        ],
        EnhancedSink.META_REFRESH: [
            r"<meta[^>]*http-equiv=[\"']refresh[\"']",
            r"\.setAttribute\s*\(\s*['\"]http-equiv['\"]\s*,\s*['\"]refresh['\"]",
        ],
        EnhancedSink.BASE_HREF: [
            r"<base[^>]*href=",
            r"\.createElement\s*\(\s*['\"]base['\"]\s*\)[\s\S]{0,200}\.href\s*=",
            r"\.setAttribute\s*\(\s*['\"]href['\"]\s*,",
        ],
        EnhancedSink.FORM_ACTION: [
            r"\.action\s*=\s*[^;]{0,80}",
            r"\.setAttribute\s*\(\s*['\"]action['\"]",
        ],
        EnhancedSink.BUTTON_FORM_ACTION: [
            r"\.formAction\s*=",
            r"\.setAttribute\s*\(\s*['\"]formaction['\"]",
        ],
        EnhancedSink.INPUT_FORM_ACTION: [
            r"\.formAction\s*=",
            r"\.setAttribute\s*\(\s*['\"]formaction['\"]",
        ],
        EnhancedSink.AREA_HREF: [
            r"\.href\s*=\s*[^;]{0,80}",
            r"\.setAttribute\s*\(\s*['\"]href['\"]",
        ],
        EnhancedSink.SVG_USE_HREF: [
            r"<use[^>]*(?:href|xlink:href)=",
            r"\.setAttribute\s*\(\s*['\"](?:href|xlink:href)['\"]",
        ],
        EnhancedSink.MATHML_HREF: [
            r"<math[^>]*href=",
            r"\.setAttribute\s*\(\s*['\"]href['\"]",
        ],
        EnhancedSink.IFRAME_LONGDESC: [
            r"<iframe[^>]*longdesc=",
        ],
        EnhancedSink.FRAME_LONGDESC: [
            r"<frame[^>]*longdesc=",
        ],
        EnhancedSink.ISINDEX_ACTION: [
            r"<isindex[^>]*action=",
        ],
        EnhancedSink.BGSOUND_SRC: [
            r"<bgsound[^>]*src=",
        ],
        EnhancedSink.LAYER_SRC: [
            r"<layer[^>]*src=",
            r"<ilayer[^>]*src=",
        ],
        EnhancedSink.XML_DATA_ISLAND: [
            r"<xml[^>]*src=",
            r"<xml[^>]*data=",
        ],
        EnhancedSink.CSS_IMPORT: [
            r"@import\s+(?:url\s*\(\s*)?[\"']?([^\"'\s)]+)[\"']?\s*\)?",
        ],
        EnhancedSink.CSS_URL: [
            r"url\s*\(\s*[\"']?([^\"'\s)]+)[\"']?\s*\)",
        ],
        EnhancedSink.CSS_IMAGESET: [
            r"image-set\s*\(\s*([^)]{2,300})\)",
        ],
        EnhancedSink.CSS_CURSOR: [
            r"cursor\s*:\s*url\s*\(\s*[\"']?([^\"'\s)]+)[\"']?\s*\)",
        ],
        EnhancedSink.CSS_LIST_STYLE: [
            r"list-style(?:-image)?\s*:\s*url\s*\(\s*[\"']?([^\"'\s)]+)[\"']?\s*\)",
        ],
        EnhancedSink.CSS_CONTENT_URL: [
            r"content\s*:\s*url\s*\(\s*[\"']?([^\"'\s)]+)[\"']?\s*\)",
        ],
        EnhancedSink.CSS_BEHAVIOR: [
            r"behavior\s*:\s*url\s*\(\s*[\"']?([^\"'\s)]+)[\"']?\s*\)",
        ],
        EnhancedSink.CSS_MOZ_BINDING: [
            r"-moz-binding\s*:\s*url\s*\(\s*[\"']?([^\"'\s)]+)[\"']?\s*\)",
        ],
        EnhancedSink.CSS_FILTER_PROGID: [
            r"filter\s*:\s*progid:DXImageTransform\.Microsoft\.([^)]{2,300})\)",
        ],
        EnhancedSink.CSS_EXPRESSION_FUNC: [
            r"expression\s*\(\s*([^)]{2,300})\)",
        ],
        EnhancedSink.CSS_JAVASCRIPT_URL: [
            r"javascript\s*:\s*([^\"'\s;)]+)",
        ],
        EnhancedSink.CSS_VBSCRIPT_URL: [
            r"vbscript\s*:\s*([^\"'\s;)]+)",
        ],
        EnhancedSink.CSS_DATA_URL: [
            r"data\s*:\s*([^\"'\s;)]+)",
        ],
        EnhancedSink.CSS_BLOB_URL: [
            r"blob\s*:\s*([^\"'\s;)]+)",
        ],
        EnhancedSink.CSS_FILESYSTEM_URL: [
            r"filesystem\s*:\s*([^\"'\s;)]+)",
        ],
    }

    def __init__(self):
        self._matches: List[SinkMatch] = []

    def analyze(self, content: str, content_type: str = "text/html") -> List[SinkMatch]:
        """
        Analyze content for enhanced sinks with bounded snippet extraction
        and framework runtime suppression.
        """
        self._matches = []
        if not content:
            return self._matches

        # Check by regex matches across the content rather than entire lines
        # to prevent megabyte-long minified lines from exploding snippets
        seen_keys = set()
        for sink, patterns in self.SINK_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    start = match.start()
                    line_num = content.count('\n', 0, start) + 1
                    snippet_start = max(0, start - 60)
                    snippet_end = min(len(content), match.end() + 100)
                    snippet = content[snippet_start:snippet_end].replace('\n', ' ').strip()

                    # Guard against framework internals and static/feature checks
                    if is_framework_internal_sink(content, snippet, start):
                        continue
                    if is_static_or_feature_detection(snippet):
                        continue

                    key = (sink, line_num, snippet[:80])
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)

                    self._matches.append(SinkMatch(
                        sink=sink,
                        line=line_num,
                        code=snippet,
                        context=content_type,
                        confidence=0.7
                    ))
                    if len(self._matches) >= 50:
                        break
                if len(self._matches) >= 50:
                    break

        return self._matches

    def get_sink_importance(self, sink: EnhancedSink) -> float:
        """Get importance score for a sink (0-1)."""
        high_importance = {
            EnhancedSink.POSTMESSAGE,
            EnhancedSink.WEBSPEECH_SYNTHESIS,
            EnhancedSink.DATA_URI_SCRIPT,
            EnhancedSink.JAVASCRIPT_URI,
        }

        medium_importance = {
            EnhancedSink.WEBAUDIO_SCRIPT,
            EnhancedSink.WEBGL_SHADER,
            EnhancedSink.IFRAME_SANDBOX,
            EnhancedSink.OBJECT_SRCDOC,
        }

        if sink in high_importance:
            return 0.9
        elif sink in medium_importance:
            return 0.7
        else:
            return 0.5

    def generate_test_payload(
        self,
        sink: EnhancedSink,
        marker: str
    ) -> str:
        """Generate a test payload for a specific sink."""
        payloads = {
            EnhancedSink.POSTMESSAGE: f'<script>postMessage("{marker}", "*")</script>',
            EnhancedSink.WEBSPEECH_SYNTHESIS: f'<script>speechSynthesis.speak(new SpeechSynthesisUtterance("{marker}"))</script>',
            EnhancedSink.DATA_URI_SCRIPT: f'data:text/javascript,{marker}',
            EnhancedSink.JAVASCRIPT_URI: f'javascript:{marker}',
            EnhancedSink.WEBGL_SHADER: f'<script>createShader(gl.{marker})</script>',
            EnhancedSink.IFRAME_SANDBOX: f'<iframe sandbox="allow-scripts" srcdoc="<script>{marker}</script>"></iframe>',
            EnhancedSink.OBJECT_SRCDOC: f'<object srcdoc="<script>{marker}</script>"></object>',
            EnhancedSink.CSS_EXPRESSION: f'<div style="expression:alert(\'{marker}\')"></div>',
            EnhancedSink.CSS_VAR_INJECTION: f'<div style="--x:alert(\'{marker}\')" x="var(--x)"></div>',
        }

        return payloads.get(sink, f'<script>{marker}</script>')

    def filter_by_context(
        self,
        matches: List[SinkMatch],
        min_confidence: float = 0.5
    ) -> List[SinkMatch]:
        """Filter matches by confidence threshold."""
        return [m for m in matches if m.confidence >= min_confidence]

    def get_high_risk_sinks(self) -> List[SinkMatch]:
        """Get all high-risk sink matches."""
        return [m for m in self._matches if self.get_sink_importance(m.sink) >= 0.7]
