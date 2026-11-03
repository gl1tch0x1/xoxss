"""
Reflection analysis module for detecting XSS vulnerabilities.
"""

import html
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


class XSSContext(Enum):
    """XSS injection contexts."""
    HTML = "html"
    ATTR_DOUBLE = "attr_double"
    ATTR_SINGLE = "attr_single"
    ATTR_UNQUOTED = "attr_unquoted"
    SCRIPT = "script"
    STYLE = "style"
    COMMENT = "comment"
    JSON = "json"
    URL = "url"
    CSS_URL = "css_url"
    SVG = "svg"
    TEMPLATE = "template"


@dataclass
class ReflectionInfo:
    """Information about payload reflection."""
    reflected: bool
    context: XSSContext
    executable: bool
    detail: str
    position: int
    escaped: bool
    encoded: bool
    tags_before: List[str]
    tags_after: List[str]
    attributes: Dict[str, str]
    efficiency_score: float = 0.0
    distortion_percentage: float = 0.0


class ReflectionAnalyzer:
    """
    Advanced reflection analyzer for XSS detection.
    Performs deep analysis of how payloads are reflected in responses.
    """

    # Context detection patterns
    CONTEXT_PATTERNS = {
        XSSContext.HTML: [
            r'&lt;[a-zA-Z]',  # Tag start after HTML entity
            r'^[^"]*<[^>]',  # Tag in unquoted context
            r'[^<]*<[^>]*(?=>)',  # Tag with attributes
        ],
        XSSContext.ATTR_DOUBLE: [
            r'="[^"]*x',  # Inside double-quoted attribute
            r'\s\w+="[^"]*x',  # Attribute with name
        ],
        XSSContext.ATTR_SINGLE: [
            r"=\'[^\']*x",  # Inside single-quoted attribute
            r"\s\w+='[^\']*x",  # Attribute with name
        ],
        XSSContext.ATTR_UNQUOTED: [
            r'=[^"\'<>\s]*x',  # Unquoted attribute value
            r'=\S+x',  # Unquoted without spaces
        ],
        XSSContext.SCRIPT: [
            r';\s*x',  # After statement
            r'\]\s*x',  # After array
            r'\}\s*x',  # After object
            r'\(\s*x',  # Inside function call
            r'"[^"]*x"',  # Inside string
            r"'[^']*x'",  # Inside single-quoted string
        ],
        XSSContext.STYLE: [
            r'{[^}]*x',  # Inside CSS block
            r':[^;]*x',  # CSS property value
        ],
        XSSContext.COMMENT: [
            r'<!--.*x',  # HTML comment
            r'/\*.*x',  # Multi-line comment
            r'//.*x',  # Single-line comment
        ],
        XSSContext.JSON: [
            r'"{[^}]*x',  # JSON string
            r':\s*"[^"]*x"',  # JSON value
        ],
        XSSContext.URL: [
            r'javascript:',  # JavaScript URL
            r'data:',  # Data URL
        ],
        XSSContext.CSS_URL: [
            r'url\([^)]*x',  # CSS url()
        ],
        XSSContext.SVG: [
            r'<svg.*>.*x',  # SVG content
        ],
        XSSContext.TEMPLATE: [
            r'\{\{.*x.*\}\}',  # Template expression
        ],
    }

    # Special characters for context detection
    SPECIAL_CHARS = ['<', '>', '"', "'", '(', ')', '=', '/', '\\', '&', ';']

    def __init__(self):
        self._cache = {}

    def analyze_reflection(
        self,
        response: str,
        payload: str,
        marker: str,
        content_type: str = ""
    ) -> ReflectionInfo:
        """
        Analyze how a payload is reflected in the response.

        Args:
            response: Response body
            payload: Original payload sent
            marker: Unique marker for detection
            content_type: Content-Type header

        Returns:
            ReflectionInfo with detailed analysis
        """
        # Check if reflected
        if marker not in response and payload not in response:
            return ReflectionInfo(
                reflected=False,
                context=XSSContext.HTML,
                executable=False,
                detail="Payload not reflected",
                position=-1,
                escaped=False,
                encoded=False,
                tags_before=[],
                tags_after=[],
                attributes={}
            )

        # Find reflection position
        position = response.find(marker) if marker in response else response.find(payload)

        # Detect context at the start of the *sent payload*, not at the marker:
        # the marker usually sits inside the payload (e.g. after "<script>"),
        # which would otherwise misclassify HTML-body reflections as script.
        marker_offset = payload.find(marker) if marker else -1
        context_position = position - marker_offset if marker_offset >= 0 else position
        context_position = max(0, min(context_position, len(response) - 1))

        # Detect context
        context = self._detect_context(response, context_position)

        # Check if escaped/encoded
        escaped = self._is_escaped(response, position)
        encoded = self._is_encoded(response, position)

        # Extract surrounding context
        snippet = self._get_snippet(response, position, 200)
        tags_before = self._extract_tags_before(snippet)
        tags_after = self._extract_tags_after(snippet)
        attributes = self._extract_attributes(snippet)

        # Determine if executable
        executable = self._is_executable(context, escaped, encoded, snippet)

        # Calculate efficiency score using Levenshtein distance
        efficiency_score = self._calculate_efficiency_score(payload, response, position, marker)
        distortion_percentage = self._calculate_distortion(payload, response, position, marker)

        detail = self._generate_detail(context, escaped, encoded, executable)

        return ReflectionInfo(
            reflected=True,
            context=context,
            executable=executable,
            detail=detail,
            position=position,
            escaped=escaped,
            encoded=encoded,
            tags_before=tags_before,
            tags_after=tags_after,
            attributes=attributes,
            efficiency_score=efficiency_score,
            distortion_percentage=distortion_percentage
        )

    # Map the detailed ContextType enum onto the coarser XSSContext families.
    _CONTEXT_MAP = {
        "HTML_BODY": XSSContext.HTML,
        "HTML_TAG": XSSContext.HTML,
        "ATTR_DOUBLE_QUOTED": XSSContext.ATTR_DOUBLE,
        "ATTR_SINGLE_QUOTED": XSSContext.ATTR_SINGLE,
        "ATTR_UNQUOTED": XSSContext.ATTR_UNQUOTED,
        "JAVASCRIPT_STRING_DOUBLE": XSSContext.SCRIPT,
        "JAVASCRIPT_STRING_SINGLE": XSSContext.SCRIPT,
        "JAVASCRIPT_TEMPLATE": XSSContext.SCRIPT,
        "JAVASCRIPT_CODE": XSSContext.SCRIPT,
        "JAVASCRIPT_COMMENT": XSSContext.COMMENT,
        "CSS_STRING": XSSContext.STYLE,
        "CSS_PROPERTY": XSSContext.STYLE,
        "HTML_COMMENT": XSSContext.COMMENT,
        "JSON_STRING": XSSContext.JSON,
        "JSON_VALUE": XSSContext.JSON,
        "URL_PATH": XSSContext.URL,
        "URL_QUERY": XSSContext.URL,
        "URL_FRAGMENT": XSSContext.URL,
        "DATA_URI": XSSContext.URL,
        "SVG_DATA": XSSContext.SVG,
        "MATHML": XSSContext.HTML,
        "TEMPLATE_LITERAL": XSSContext.TEMPLATE,
    }

    def _detect_context(self, response: str, position: int) -> XSSContext:
        """Detect the XSS context from the response."""
        try:
            from xoxss.detection.context import ContextDetector

            detailed = ContextDetector().detect_context(response, position)
            mapped = self._CONTEXT_MAP.get(detailed.context_type.name)
            if mapped is not None:
                return mapped
        except Exception:
            pass

        # Fallback: legacy pattern voting (kept for callers that pass unusual
        # responses where markup parsing is inconclusive).
        snippet = self._get_snippet(response, position, 100)
        for context, patterns in self.CONTEXT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, snippet, re.I | re.DOTALL):
                    return context
        return XSSContext.HTML

    def _is_escaped(self, response: str, position: int) -> bool:
        """Check if the reflection is HTML escaped."""
        snippet = self._get_snippet(response, position, 50)
        escaped_chars = ['&lt;', '&gt;', '&quot;', '&#x', '&#']
        return any(char in snippet for char in escaped_chars)

    def _is_encoded(self, response: str, position: int) -> bool:
        """Check if the reflection is URL encoded."""
        snippet = self._get_snippet(response, position, 50)
        encoded_patterns = ['%3C', '%3E', '%22', '%27', '%3D']
        return any(pattern in snippet for pattern in encoded_patterns)

    def _is_executable(
        self,
        context: XSSContext,
        escaped: bool,
        encoded: bool,
        snippet: str
    ) -> bool:
        """Determine if the reflected payload can execute."""
        if escaped or encoded:
            return False

        # Context-specific execution checks
        if context in (XSSContext.HTML, XSSContext.ATTR_DOUBLE, XSSContext.ATTR_SINGLE):
            # Check if we can break out
            for char in self.SPECIAL_CHARS:
                if char in snippet and not snippet.count(char) > 1:
                    return True
            return False

        if context == XSSContext.SCRIPT:
            # Check if we're in an executable context
            if any(x in snippet for x in [';', '(', ')', ',']):
                return True
            return False

        if context == XSSContext.URL:
            # Check if javascript: or data: protocol
            if 'javascript:' in snippet or 'data:' in snippet:
                return True
            return False

        return True

    def _get_snippet(self, response: str, position: int, length: int) -> str:
        """Extract a snippet around the reflection position."""
        start = max(0, position - length // 2)
        end = min(len(response), position + length // 2)
        return response[start:end]

    def _extract_tags_before(self, snippet: str) -> List[str]:
        """Extract HTML tags before the reflection."""
        tags = re.findall(r'<[^>]+>', snippet)
        return tags[-5:] if tags else []

    def _extract_tags_after(self, snippet: str) -> List[str]:
        """Extract HTML tags after the reflection."""
        # Find the reflection point and extract tags after
        tags = re.findall(r'<[^>]+>', snippet)
        # Simplified - in real implementation, would need position awareness
        return tags[:5] if tags else []

    def _extract_attributes(self, snippet: str) -> Dict[str, str]:
        """Extract HTML attributes from the snippet."""
        attributes = {}
        attr_pattern = r'(\w+)=["\']([^"\']*)["\']'
        for match in re.finditer(attr_pattern, snippet):
            attributes[match.group(1)] = match.group(2)
        return attributes

    def _generate_detail(
        self,
        context: XSSContext,
        escaped: bool,
        encoded: bool,
        executable: bool
    ) -> str:
        """Generate a detailed description of the reflection."""
        parts = [f"context: {context.value}"]
        if escaped:
            parts.append("HTML escaped")
        if encoded:
            parts.append("URL encoded")
        if executable:
            parts.append("potentially executable")
        else:
            parts.append("not executable")
        return ", ".join(parts)

    def _decoded_start(self, response: str, position: int, count: int) -> int:
        """
        Walk backwards from ``position`` over ``count`` *decoded* characters.

        This keeps the alignment correct when the server entity- or
        percent-encodes the payload: e.g. ``&lt;`` counts as one character and
        ``%3C`` as one character, not four and three.
        """
        index = max(0, min(position, len(response)))
        seen = 0
        while index > 0 and seen < count:
            if index >= 3 and response[index - 1] == ";":
                window = response[max(0, index - 32):index]
                match = re.search(r"&(?:#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);$", window)
                if match:
                    index -= len(match.group(0))
                    seen += 1
                    continue
            if index >= 3 and response[index - 3] == "%" and re.fullmatch(
                r"%[0-9a-fA-F]{2}", response[index - 3:index]
            ):
                index -= 3
                seen += 1
                continue
            index -= 1
            seen += 1
        return max(0, index)

    def _best_window(
        self,
        payload: str,
        response: str,
        position: int,
        marker: str = "",
    ) -> Optional[Tuple[float, int, int]]:
        """
        Align the sent payload against the reflected response.

        The naive approach (``response[position:position + len(payload)]``) is
        only correct when the payload is echoed byte-for-byte, which makes the
        score useless for the cases we care about: truncation, entity encoding,
        and character stripping.  We locate the payload start by walking back
        over the encoded prefix, then probe small offsets for stripped chars.

        Returns ``(normalised_distance, distance, window_length)`` or ``None``.
        """
        if not payload or position < 0 or position >= len(response):
            return None

        # Fast path: byte-for-byte reflection (the common case) at C speed.
        if payload in response:
            return (0.0, 0, len(payload))

        offset = payload.find(marker) if marker else -1
        if offset < 0:
            offset = 0
        anchor = self._decoded_start(response, position, offset)
        remaining = len(response) - anchor
        if remaining <= 0:
            return None

        best: Optional[Tuple[float, int, int]] = None
        # The decoded start is exact; probing shifts allows a degenerate match
        # that drops the payload's head and keeps a substring, which inflates
        # efficiency.  Instead vary only the window length to absorb encoding
        # expansion (``&lt;`` is 3 chars longer, ``%3C`` is 2 chars longer).
        starts = {anchor}
        lengths = {len(payload), len(payload) + 6, len(payload) + 12, len(payload) * 2}
        for start in starts:
            available = len(response) - start
            for target_len in lengths:
                length = min(available, max(1, target_len))
                candidate = response[start:start + length]
                distance = levenshtein_distance(payload, candidate)
                denominator = max(len(payload), len(candidate))
                if denominator == 0:
                    continue
                score = distance / denominator
                if best is None or (score, distance) < (best[0], best[1]):
                    best = (score, distance, len(candidate))
        return best

    def _calculate_efficiency_score(
        self,
        payload: str,
        response: str,
        position: int,
        marker: str = "",
    ) -> float:
        """Calculate efficiency score (0-100%) using Levenshtein distance."""
        best = self._best_window(payload, response, position, marker)
        if best is None:
            return 0.0
        score, _, _ = best
        return round(max(0.0, (1.0 - score) * 100.0), 2)

    def _calculate_distortion(
        self,
        payload: str,
        response: str,
        position: int,
        marker: str = "",
    ) -> float:
        """Percentage of the payload that was distorted by the backend."""
        if not payload:
            return 100.0
        return round(100.0 - self._calculate_efficiency_score(payload, response, position, marker), 2)

    def analyze_multiple_reflections(
        self,
        response: str,
        payloads: List[str],
        marker: str
    ) -> List[ReflectionInfo]:
        """Analyze multiple payload reflections in a single response."""
        results = []
        for payload in payloads:
            info = self.analyze_reflection(response, payload, marker)
            if info.reflected:
                results.append(info)
        return results


def score_reflection(payload: str, response: str, marker: str = "") -> Tuple[float, float]:
    """
    Score how faithfully ``payload`` survived in ``response``.

    Returns ``(efficiency, distortion)`` as percentages (0-100).  This is the
    single shared implementation used by both the package analyzers and the
    scanner, so the console, JSON and SARIF reports agree on the metric.
    """
    if not payload or not response:
        return 0.0, 100.0

    position = -1
    anchors = [marker] if marker else []
    if marker and len(marker) >= 8:
        anchors.append(marker[:6])
    anchors.append(payload)

    haystacks = (response, html.unescape(response))
    for anchor in anchors:
        if not anchor:
            continue
        for haystack in haystacks:
            found = haystack.find(anchor)
            if found < 0:
                continue
            if haystack is response:
                position = found
            else:
                # The anchor only matched after entity decoding; map it back to
                # an offset in the raw response so the window stays aligned.
                raw = response.find(anchor[: min(6, len(anchor))])
                position = raw if raw >= 0 else min(found, len(response) - 1)
            break
        if position >= 0:
            break

    if position < 0:
        return 0.0, 100.0

    analyzer = ReflectionAnalyzer()
    efficiency = analyzer._calculate_efficiency_score(payload, response, position, marker)
    distortion = analyzer._calculate_distortion(payload, response, position, marker)
    return efficiency, distortion
