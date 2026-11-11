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
