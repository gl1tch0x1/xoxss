"""
Per-character probe module for precise XSS context detection.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class ProbeContext(Enum):
    """Contexts detected by character probing."""
    HTML = "html"
    ATTR_DOUBLE = "attr_double"
    ATTR_SINGLE = "attr_single"
    ATTR_UNQUOTED = "attr_unquoted"
    SCRIPT = "script"
    STYLE = "style"
    COMMENT = "comment"
    JSON = "json"
    UNKNOWN = "unknown"


@dataclass
class CharProbeResult:
    """Result of probing a single character."""
    char: str
    reflected: bool
    escaped: bool
    encoded: bool
    position: int
    context_hints: List[str]


@dataclass
class ProbeAnalysis:
    """Complete analysis from per-character probing."""
    detected_context: ProbeContext
    surviving_chars: Set[str]
    escaped_chars: Set[str]
    encoded_chars: Set[str]
    blocked_chars: Set[str]
    confidence: float
    snippet: str
    position: int
    suggested_payloads: List[str]


class PerCharProbe:
    """
    Advanced per-character probe analyzer.
    Performs character-by-character probing to determine exact injection context.
    """

    # Special characters to probe
    PROBE_CHARS = [
        '<', '>', '"', "'", '(', ')', '=', '/', '\\', '&', ';',
        ' ', '\t', '\n', '\r', '{', '}', '[', ']', '|', '`', '!',
        '@', '#', '$', '%', '^', '*', '~', '+', '-', '.', ',',
        ':', '?', '%', '.', '@', '_', '-', '+',
    ]

    # Context detection: anchored on the probe reflection and delegated to the
    # parser-based ContextDetector (regex heuristics hard-coding specific
    # letters misclassify almost any page text, so they were removed).

    def __init__(self):
        self._probe_marker = "X0XSS_CH4R_PR0B3"

    # Character survival rules per context
    CONTEXT_CHAR_RULES = {
        ProbeContext.HTML: {
            'surviving': ['<', '>', '"', "'", ';'],
            'escaped': ['<', '>', '"', "'"],
        },
        ProbeContext.ATTR_DOUBLE: {
            'surviving': ['"', '>', '<'],
            'escaped': ['"', '<'],
        },
        ProbeContext.ATTR_SINGLE: {
            'surviving': ["'", '>', '<'],
            'escaped': ["'", '<'],
        },
        ProbeContext.ATTR_UNQUOTED: {
            'surviving': [' ', '>', '<', '"', "'"],
            'escaped': ['<', '>'],
        },
        ProbeContext.SCRIPT: {
            'surviving': [';', '(', ')', '{', '}', '[', ']'],
            'escaped': [],
        },
        ProbeContext.STYLE: {
            'surviving': [';', '{', '}'],
            'escaped': [],
        },
    }

    def generate_probe_string(self, unique_marker: str) -> str:
        """
        Generate a probe string with all special characters.

        Args:
            unique_marker: Unique identifier for this probe

        Returns:
            Probe string with special characters
        """
        parts = []
        for char in self.PROBE_CHARS:
            parts.append(f"{char}{unique_marker}")
        return "".join(parts)

    def analyze_probe(
        self,
        response: str,
        probe_marker: str,
        position: Optional[int] = None
    ) -> ProbeAnalysis:
        """
        Analyze the response to a character probe.

        Args:
            response: Response body
            probe_marker: Marker used in the probe
            position: Known position of reflection (optional)

        Returns:
            ProbeAnalysis with detailed results
        """
        surviving = set()
        escaped = set()
        encoded = set()
        blocked = set()

        # Find position if not provided
        if position is None:
            position = response.find(probe_marker)

        # Analyze each character
        for char in self.PROBE_CHARS:
            test_pattern = f"{char}{probe_marker}"
            if test_pattern in response:
                surviving.add(char)
            elif self._is_escaped(response, char, probe_marker):
                escaped.add(char)
            elif self._is_encoded(response, char, probe_marker):
                encoded.add(char)
            else:
                blocked.add(char)

        # Detect context
        detected_context = self._detect_context(response, probe_marker)

        # Calculate confidence
        confidence = self._calculate_confidence(detected_context, surviving, escaped)

        # Generate suggested payloads
        suggested_payloads = self._generate_payloads(detected_context, surviving)

        return ProbeAnalysis(
            detected_context=detected_context,
            surviving_chars=surviving,
            escaped_chars=escaped,
            encoded_chars=encoded,
            blocked_chars=blocked,
            confidence=confidence,
            snippet=response[:200] if response else "",
            position=position if position is not None else -1,
            suggested_payloads=suggested_payloads
        )

    def _is_escaped(self, response: str, char: str, marker: str) -> bool:
        """Check if a character is HTML escaped around the probe reflection."""
        escaped_map = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
        }
        window = self._reflection_window(response, marker)
        if not window:
            return False
        escaped = escaped_map.get(char, '')
        if escaped and escaped in window:
            return True
        # Check for numeric entities
        if f"&#{ord(char)};" in window:
            return True
        return False

    def _is_encoded(self, response: str, char: str, marker: str) -> bool:
        """Check if a character is URL encoded around the probe reflection."""
        import urllib.parse
        window = self._reflection_window(response, marker)
        if not window:
            return False
        return urllib.parse.quote(char) in window

    @staticmethod
    def _reflection_window(response: str, marker: str, radius: int = 200) -> str:
        """Text around the first probe reflection (whole-document defaults to
        false positives: one unrelated ``&lt;`` in a nav bar would otherwise
        mark every probe as escaped)."""
        if not response or not marker:
            return ""
        index = response.find(marker)
        if index == -1:
            return ""
        start = max(0, index - radius)
        end = min(len(response), index + len(marker) + radius)
        return response[start:end]

    def _detect_context(self, response: str, marker: str) -> ProbeContext:
        """Detect the injection context anchored on the probe reflection.

        Delegates to the parser-based :class:`ContextDetector`, which parses
        the markup before the reflection instead of scoring regexes that
        hard-code probe characters.
        """
        if not response or not marker:
            return ProbeContext.UNKNOWN
        index = response.find(marker)
        if index == -1:
            return ProbeContext.UNKNOWN
        try:
            from xoxss.detection.context import ContextDetector, ContextType
        except Exception:
            return ProbeContext.UNKNOWN
        analysis = ContextDetector().detect_context(response, index, marker=marker)
        mapping = {
            ContextType.HTML_BODY: ProbeContext.HTML,
            ContextType.HTML_TAG: ProbeContext.HTML,
            ContextType.SVG_DATA: ProbeContext.HTML,
            ContextType.MATHML: ProbeContext.HTML,
            ContextType.TEMPLATE_LITERAL: ProbeContext.HTML,
            ContextType.ATTR_DOUBLE_QUOTED: ProbeContext.ATTR_DOUBLE,
            ContextType.ATTR_SINGLE_QUOTED: ProbeContext.ATTR_SINGLE,
            ContextType.ATTR_UNQUOTED: ProbeContext.ATTR_UNQUOTED,
            ContextType.JAVASCRIPT_STRING_DOUBLE: ProbeContext.SCRIPT,
            ContextType.JAVASCRIPT_STRING_SINGLE: ProbeContext.SCRIPT,
            ContextType.JAVASCRIPT_TEMPLATE: ProbeContext.SCRIPT,
            ContextType.JAVASCRIPT_CODE: ProbeContext.SCRIPT,
            ContextType.HTML_COMMENT: ProbeContext.COMMENT,
            ContextType.JAVASCRIPT_COMMENT: ProbeContext.COMMENT,
            ContextType.CSS_STRING: ProbeContext.STYLE,
            ContextType.CSS_PROPERTY: ProbeContext.STYLE,
            ContextType.JSON_STRING: ProbeContext.JSON,
            ContextType.JSON_VALUE: ProbeContext.JSON,
        }
        return mapping.get(analysis.context_type, ProbeContext.UNKNOWN)

    def _calculate_confidence(
        self,
        context: ProbeContext,
        surviving: Set[str],
        escaped: Set[str]
    ) -> float:
        """Calculate confidence score for the detected context."""
        if not surviving:
            return 0.0

        # Get expected characters for this context
        rules = self.CONTEXT_CHAR_RULES.get(context, {})
        expected_surviving = set(rules.get('surviving', []))
        expected_escaped = set(rules.get('escaped', []))

        # Calculate match score
        surviving_match = len(surviving & expected_surviving) / max(1, len(expected_surviving))
        escaped_match = len(escaped & expected_escaped) / max(1, len(expected_escaped))

        confidence = (surviving_match + escaped_match) / 2

        # Boost confidence for certain contexts
        if context in (ProbeContext.SCRIPT, ProbeContext.ATTR_DOUBLE, ProbeContext.ATTR_SINGLE):
            confidence = min(1.0, confidence + 0.2)

        return round(confidence, 2)

    def _generate_payloads(
        self,
        context: ProbeContext,
        surviving: Set[str]
    ) -> List[str]:
        """Generate context-specific payload suggestions."""
        payloads = []

        if context == ProbeContext.HTML:
            if '<' in surviving and '>' in surviving:
                payloads.append("<script>alert(1)</script>")
            if '"' in surviving and "'" in surviving:
                payloads.append("\"'><script>alert(1)</script>")

        elif context == ProbeContext.ATTR_DOUBLE:
            if '"' in surviving:
                payloads.append('" onerror="alert(1)"')
            if '>' in surviving:
                payloads.append('"><script>alert(1)</script>')

        elif context == ProbeContext.ATTR_SINGLE:
            if "'" in surviving:
                payloads.append("' onerror='alert(1)'")
            if '>' in surviving:
                payloads.append("'><script>alert(1)</script>")

        elif context == ProbeContext.ATTR_UNQUOTED:
            if ' ' in surviving and '>' in surviving:
                payloads.append(" onerror=alert(1) ")
            if '>' in surviving:
                payloads.append("><script>alert(1)</script>")

        elif context == ProbeContext.SCRIPT:
            if ';' in surviving:
                payloads.append(";alert(1)//")
            if ')' in surviving and '(' in surviving:
                payloads.append(");alert(1)//")

        elif context == ProbeContext.STYLE:
            if ';' in surviving and '}' in surviving:
                payloads.append(";expression(alert(1))")

        return payloads

    def compare_probes(
        self,
        analyses: List[ProbeAnalysis]
    ) -> Dict[str, List[str]]:
        """
        Compare multiple probe analyses to identify consistent patterns.

        Args:
            analyses: List of ProbeAnalysis objects

        Returns:
            Dictionary with comparison results
        """
        if not analyses:
            return {}

        # Find common surviving characters
        common_surviving = set(analyses[0].surviving_chars)
        for analysis in analyses[1:]:
            common_surviving &= analysis.surviving_chars

        # Find common escaped characters
        common_escaped = set(analyses[0].escaped_chars)
        for analysis in analyses[1:]:
            common_escaped &= analysis.escaped_chars

        # Check for consistent context
        contexts = [a.detected_context for a in analyses]
        consistent_context = len(set(contexts)) == 1

        return {
            'common_surviving': list(common_surviving),
            'common_escaped': list(common_escaped),
            'consistent_context': consistent_context,
            'context_distribution': {c: contexts.count(c) for c in set(contexts)},
        }
