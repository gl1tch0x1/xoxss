"""
Context detection module for precise XSS context identification.
"""

import html as html_lib
import re
from typing import List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum


# Characters whose survival determines whether markup can break out of a
# context.  ``&`` and ``-`` matter for comment/entity breakouts.
SPECIAL_CHARS = set("<>\"'`()=/\\ \t\r\n&-")

# One HTML entity reference (named, decimal or hexadecimal).
ENTITY_RE = re.compile(r"&(?:#[xX][0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]+);")


def decode_with_origin(text: str) -> List[Tuple[str, bool]]:
    """Decode entities while remembering whether each character was raw.

    Returns ``[(character, was_raw), ...]``.  ``was_raw`` is ``False`` when the
    character came from ``&lt;``-style output, which is the signal that the
    server encoded the payload instead of reflecting it verbatim.
    """
    value = str(text or "")
    decoded: List[Tuple[str, bool]] = []
    position = 0
    for match in ENTITY_RE.finditer(value):
        for char in value[position:match.start()]:
            decoded.append((char, True))
        unescaped = html_lib.unescape(match.group(0))
        for char in unescaped:
            decoded.append((char, False))
        position = match.end()
    for char in value[position:]:
        decoded.append((char, True))
    return decoded


def analyze_char_survival(
    response: str,
    position: int,
    token: str,
    sent_payload: str,
) -> Tuple[Set[str], Set[str]]:
    """Position-aware character survival for the tail after ``token``.

    Only characters that appear at the corresponding offset *after* the marker
    count.  A raw presence elsewhere in the document (a legitimate ``<`` in
    surrounding markup, for example) never marks the payload executable.
    """
    body = str(response or "")
    marker = str(token or "")
    payload = str(sent_payload or "")
    survived: Set[str] = set()
    encoded: Set[str] = set()
    if not body or not marker or marker not in payload:
        return survived, encoded
    marker_offset = payload.find(marker)
    sent_tail = payload[marker_offset + len(marker):]
    marker_at = max(0, min(int(position), len(body)))
    if sent_tail:
        start = marker_at + len(marker)
        # Bound the windows so a pathological page cannot make this quadratic.
        received = body[start:start + max(256, len(sent_tail) * 16 + 64)]
        decoded = decode_with_origin(received)
        for offset, char in enumerate(sent_tail):
            if offset >= len(decoded):
                break
            received_char, was_raw = decoded[offset]
            if received_char != char:
                continue
            if char in SPECIAL_CHARS:
                (survived if was_raw else encoded).add(char)

    # Delimiters *before* the marker matter too: a breakout payload such as
    # ``"><script>TOKEN`` puts the quote first, and the marker often sits near
    # the end.  Align the reflected prefix from the end so a value that the
    # server slightly normalises still contributes its leading delimiters.
    sent_prefix = payload[:marker_offset]
    if sent_prefix:
        window = body[max(0, marker_at - max(256, len(sent_prefix) * 16 + 64)):marker_at]
        decoded_prefix = decode_with_origin(window)
        if len(decoded_prefix) >= len(sent_prefix):
            aligned = decoded_prefix[-len(sent_prefix):]
            for char, (received_char, was_raw) in zip(sent_prefix, aligned):
                if received_char != char:
                    continue
                if char in SPECIAL_CHARS:
                    (survived if was_raw else encoded).add(char)
    return survived, encoded


def inert_zone(response: str, position: int, token: str = "") -> Tuple[str, bool]:
    """Classify the reflection as inert and report whether a breakout is present.

    Returns ``(reason, breakout)``.  ``reason`` is one of ``html_comment``,
    ``textarea`` or ``""``.  ``breakout`` is true when the reflected payload
    itself closes the inert region (``-->`` / ``</textarea>``), which is the
    only way a reflection inside it becomes executable.
    """
    body = str(response or "")
    index = max(0, min(int(position), len(body)))
    before = body[:index]
    low_before = before.lower()
    if low_before.rfind("<!--") > low_before.rfind("-->"):
        tail = body[index:]
        return "html_comment", "-->" in tail[:2000]
    if low_before.rfind("<textarea") > low_before.rfind("</textarea"):
        tail = body[index:].lower()
        return "textarea", "</textarea" in tail[:2000]
    return "", False


def strip_inert_regions(snippet: str) -> str:
    """Remove comments, textarea bodies and entity references from a snippet.

    Used by context character accounting so a ``<`` inside a comment or
    ``&lt;`` output is not counted as a surviving delimiter.
    """
    text = str(snippet or "")
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(r"<textarea\b[^>]*>.*?</textarea\s*>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = ENTITY_RE.sub("", text)
    return text


class ContextType(Enum):
    """XSS injection context types."""
    HTML_BODY = "html_body"
    HTML_TAG = "html_tag"
    ATTR_DOUBLE_QUOTED = "attr_double_quoted"
    ATTR_SINGLE_QUOTED = "attr_single_quoted"
    ATTR_UNQUOTED = "attr_unquoted"
    JAVASCRIPT_STRING_DOUBLE = "js_string_double"
    JAVASCRIPT_STRING_SINGLE = "js_string_single"
    JAVASCRIPT_TEMPLATE = "js_template"
    JAVASCRIPT_CODE = "js_code"
    CSS_STRING = "css_string"
    CSS_PROPERTY = "css_property"
    HTML_COMMENT = "html_comment"
    TEXTAREA = "textarea"
    JAVASCRIPT_COMMENT = "js_comment"
    JSON_STRING = "json_string"
    JSON_VALUE = "json_value"
    URL_PATH = "url_path"
    URL_QUERY = "url_query"
    URL_FRAGMENT = "url_fragment"
    DATA_URI = "data_uri"
    SVG_DATA = "svg_data"
    MATHML = "mathml"
    TEMPLATE_LITERAL = "template_literal"


@dataclass
class ContextAnalysis:
    """Detailed context analysis result."""
    context_type: ContextType
    confidence: float
    depth: int
    parent_tag: Optional[str]
    parent_attribute: Optional[str]
    escaping_method: Optional[str]
    encoding_method: Optional[str]
    special_chars_allowed: Set[str]
    special_chars_blocked: Set[str]
    suggested_payloads: List[str]
    escaped_chars: Set[str] = field(default_factory=set)
    entity_encoded: bool = False
    inert_reason: str = ""


class ContextDetector:
    """
    Advanced context detector for precise XSS injection point identification.
    Uses multi-layered analysis to determine exact injection context.
    """

    # HTML tag patterns
    TAG_PATTERNS = {
        'script': r'<script[^>]*>',
        'style': r'<style[^>]*>',
        'textarea': r'<textarea[^>]*>',
        'title': r'<title[^>]*>',
        'iframe': r'<iframe[^>]*>',
        'object': r'<object[^>]*>',
        'embed': r'<embed[^>]*>',
        'svg': r'<svg[^>]*>',
        'math': r'<math[^>]*>',
    }

    # Attribute patterns
    ATTR_PATTERNS = {
        'href': r'\bhref\s*=',
        'src': r'\bsrc\s*=',
        'action': r'\baction\s*=',
        'data': r'\bdata\s*=',
        'value': r'\bvalue\s*=',
        'name': r'\bname\s*=',
        'id': r'\bid\s*=',
        'class': r'\bclass\s*=',
        'onclick': r'\bon\w+\s*=',
        'onerror': r'\bonerror\s*=',
        'onload': r'\bonload\s*=',
    }

    # Context detection patterns
    CONTEXT_PATTERNS = {
        ContextType.HTML_BODY: [
            r'>[^<]*x',
            r'<body[^>]*>.*x',
        ],
        ContextType.HTML_TAG: [
            r'<\w+[^>]*x',
        ],
        ContextType.ATTR_DOUBLE_QUOTED: [
            r'="[^"]*x',
        ],
        ContextType.ATTR_SINGLE_QUOTED: [
            r"='[^']*x",
        ],
        ContextType.ATTR_UNQUOTED: [
            r'=[^"\'<>\s]*x',
        ],
        ContextType.JAVASCRIPT_STRING_DOUBLE: [
            r'"[^"]*x"',
        ],
        ContextType.JAVASCRIPT_STRING_SINGLE: [
            r"'[^']*x'",
        ],
        ContextType.JAVASCRIPT_TEMPLATE: [
            r'`[^`]*x`',
        ],
        ContextType.JAVASCRIPT_CODE: [
            r';\s*x',
            r'\(\s*x',
            r'\s+x\s*[=\+\-\*\/]',
        ],
        ContextType.CSS_STRING: [
            r'"[^"]*x"',
            r"'[^']*x'",
        ],
        ContextType.CSS_PROPERTY: [
            r':[^;]*x',
        ],
        ContextType.HTML_COMMENT: [
            r'<!--.*x',
        ],
        ContextType.JAVASCRIPT_COMMENT: [
            r'//.*x',
            r'/\*.*x',
        ],
        ContextType.JSON_STRING: [
            r'"{[^}]*x',
        ],
        ContextType.JSON_VALUE: [
            r':\s*["\']?x',
        ],
        ContextType.URL_PATH: [
            r'/[^?\s]*x',
        ],
        ContextType.URL_QUERY: [
            r'\?[^#]*x',
        ],
        ContextType.URL_FRAGMENT: [
            r'#.*x',
        ],
        ContextType.DATA_URI: [
            r'data:[^,]*,.*x',
        ],
        ContextType.SVG_DATA: [
            r'<svg[^>]*>.*x',
        ],
        ContextType.MATHML: [
            r'<math[^>]*>.*x',
        ],
    }

    # Special characters for each context
    CONTEXT_SPECIAL_CHARS = {
        ContextType.HTML_BODY: {'<', '>', '"', "'", '(', ')', ';'},
        ContextType.ATTR_DOUBLE_QUOTED: {'"', '>', '<', ';'},
        ContextType.ATTR_SINGLE_QUOTED: {"'", '>', '<', ';'},
        ContextType.ATTR_UNQUOTED: {' ', '>', '<', '"', "'", ';'},
        ContextType.JAVASCRIPT_STRING_DOUBLE: {'"', '\\', '\n'},
        ContextType.JAVASCRIPT_STRING_SINGLE: {"'", '\\', '\n'},
        ContextType.JAVASCRIPT_CODE: {';', '(', ')', '{', '}'},
        ContextType.CSS_STRING: {'"', "'", '\\'},
        ContextType.CSS_PROPERTY: {';', '}'},
    }

    def __init__(self):
        self._depth = 0

    def detect_context(
        self,
        response: str,
        position: int,
        marker: Optional[str] = None,
        probe_chars: Optional[str] = None
    ) -> ContextAnalysis:
        """
        Detect the exact XSS context from the response.

        Args:
            response: Response body
            position: Position of the reflection (start of ``marker``)
            marker: Text that was reflected; used to anchor the analysis when
                it appears in the injected payload
            probe_chars: Special characters used in probe (optional)

        Returns:
            ContextAnalysis with detailed context information
        """
        snippet = self._get_snippet(response, position, 500)

        # Detect context type from everything *before* the reflection.
        context_type = self._detect_context_type(response, position, marker)

        # Calculate confidence
        confidence = self._calculate_confidence(context_type)

        # Determine depth
        depth = self._calculate_depth(snippet)

        # Extract parent tag
        parent_tag = self._extract_parent_tag(snippet)

        # Extract parent attribute
        parent_attribute = self._extract_parent_attribute(snippet)

        # Detect escaping
        escaping_method = self._detect_escaping(snippet)

        # Detect encoding
        encoding_method = self._detect_encoding(snippet)

        # Determine allowed/blocked special characters
        special_chars_allowed, special_chars_blocked = self._analyze_special_chars(
            snippet, context_type, probe_chars
        )

        # Position-aware inert-zone and entity encoding flags.  These stop a
        # raw character elsewhere in the document from being mistaken for a
        # surviving delimiter inside a comment/textarea/entity output.
        inert_reason, _breakout = inert_zone(response, position, marker or "")
        vicinity = response[max(0, position - 64): position + len(marker or "") + 320]
        entity_encoded = bool(ENTITY_RE.search(vicinity)) and not any(
            char in strip_inert_regions(vicinity) for char in "<>\"'`"
        )

        # Generate suggested payloads
        suggested_payloads = self._generate_payloads(context_type, special_chars_allowed)

        return ContextAnalysis(
            context_type=context_type,
            confidence=confidence,
            depth=depth,
            parent_tag=parent_tag,
            parent_attribute=parent_attribute,
            escaping_method=escaping_method,
            encoding_method=encoding_method,
            special_chars_allowed=special_chars_allowed,
            special_chars_blocked=special_chars_blocked,
            suggested_payloads=suggested_payloads,
            entity_encoded=entity_encoded,
            inert_reason=inert_reason,
        )

    def _detect_context_type(
        self,
        response: str,
        position: int,
        marker: Optional[str] = None
    ) -> ContextType:
        """
        Detect the exact context type by parsing the markup before the sink.

        The previous implementation scored regexes that hard-coded the letter
        ``x`` as the probe, so real reflections (and the test-suite markers)
        were almost always misclassified as ``HTML_BODY``.  Parsing backwards
        from the injection point is both more accurate and cheaper.
        """
        if not response:
            return ContextType.HTML_BODY

        pos = max(0, min(position, len(response)))
        before = response[:pos]
        low = before.lower()

        # Comments win over everything else.
        if low.rfind("<!--") > low.rfind("-->"):
            return ContextType.HTML_COMMENT

        # Textarea content is inert unless the payload closes the element.
        if low.rfind("<textarea") > low.rfind("</textarea"):
            return ContextType.TEXTAREA

        # <script> ... </script>
        script_open = low.rfind("<script")
        if script_open > low.rfind("</script"):
            tail = before[script_open:]
            if ">" in tail:
                tail = tail[tail.rfind(">") + 1:]
            if tail.rfind("//") > tail.rfind("\n"):
                return ContextType.JAVASCRIPT_COMMENT
            if tail.rfind("/*") > tail.rfind("*/"):
                return ContextType.JAVASCRIPT_COMMENT
            if tail.count("`") % 2 == 1:
                return ContextType.JAVASCRIPT_TEMPLATE
            if tail.count('"') % 2 == 1:
                return ContextType.JAVASCRIPT_STRING_DOUBLE
            if tail.count("'") % 2 == 1:
                return ContextType.JAVASCRIPT_STRING_SINGLE
            return ContextType.JAVASCRIPT_CODE

        # <style> ... </style>
        style_open = low.rfind("<style")
        if style_open > low.rfind("</style"):
            tail = before[style_open:]
            if ">" in tail:
                tail = tail[tail.rfind(">") + 1:]
            if tail.count('"') % 2 == 1 or tail.count("'") % 2 == 1:
                return ContextType.CSS_STRING
            return ContextType.CSS_PROPERTY

        # Inside an open tag?
        last_lt = before.rfind("<")
        last_gt = before.rfind(">")
        if last_lt > last_gt:
            segment = before[last_lt:]
            if segment.count('"') % 2 == 1:
                return ContextType.ATTR_DOUBLE_QUOTED
            if segment.count("'") % 2 == 1:
                return ContextType.ATTR_SINGLE_QUOTED
            if re.search(r"=\s*[^\s\"'>]*$", segment):
                return ContextType.ATTR_UNQUOTED
            return ContextType.HTML_TAG

        # JSON documents (API endpoints that echo a parameter).
        stripped = response.lstrip()
        if stripped[:1] in ("{", "["):
            before_json = low.rstrip()
            if before_json.endswith((":", ",")):
                return ContextType.JSON_VALUE
            return ContextType.JSON_STRING

        # ``javascript:``/``data:`` are only live inside a URL-bearing
        # attribute value, and quoted/unquoted attribute positions are already
        # resolved above.  A bare scheme in a text node is inert, so matching
        # it here turned escaped output such as
        # ``&lt;img onerror=javascript:...&gt;`` into a phantom data-URI sink.
        # ``ContextType.DATA_URI`` is retained for callers that classify URL
        # attributes directly.
        return ContextType.HTML_BODY

    def _calculate_confidence(self, context_type: ContextType) -> float:
        """Confidence for the parsed context (parsing beats pattern voting)."""
        confidence = {
            ContextType.HTML_COMMENT: 0.95,
            ContextType.TEXTAREA: 0.4,
            ContextType.ATTR_DOUBLE_QUOTED: 0.9,
            ContextType.ATTR_SINGLE_QUOTED: 0.9,
            ContextType.ATTR_UNQUOTED: 0.85,
            ContextType.JAVASCRIPT_STRING_DOUBLE: 0.9,
            ContextType.JAVASCRIPT_STRING_SINGLE: 0.9,
            ContextType.JAVASCRIPT_TEMPLATE: 0.9,
            ContextType.JAVASCRIPT_CODE: 0.75,
            ContextType.JAVASCRIPT_COMMENT: 0.85,
            ContextType.CSS_STRING: 0.75,
            ContextType.CSS_PROPERTY: 0.7,
            ContextType.JSON_STRING: 0.8,
            ContextType.JSON_VALUE: 0.8,
            ContextType.DATA_URI: 0.8,
            ContextType.HTML_TAG: 0.55,
            ContextType.HTML_BODY: 0.6,
        }
        return confidence.get(context_type, 0.5)

    def _calculate_depth(self, snippet: str) -> int:
        """Calculate nesting depth of the injection point."""
        open_tags = len(re.findall(r'<[^/][^>]*>', snippet))
        close_tags = len(re.findall(r'</[^>]+>', snippet))
        return abs(open_tags - close_tags)

    def _extract_parent_tag(self, snippet: str) -> Optional[str]:
        """Extract the parent HTML tag."""
        match = re.search(r'<(\w+)[^>]*>[^<]*$', snippet[:200])
        if match:
            return match.group(1)
        return None

    def _extract_parent_attribute(self, snippet: str) -> Optional[str]:
        """Extract the parent attribute name."""
        for attr_name, pattern in self.ATTR_PATTERNS.items():
            if re.search(pattern, snippet):
                return attr_name
        return None

    def _detect_escaping(self, snippet: str) -> Optional[str]:
        """Detect the escaping method used."""
        if '&lt;' in snippet or '&gt;' in snippet:
            return "HTML entity"
        if '&#x' in snippet or '&#' in snippet:
            return "Numeric entity"
        if '\\' in snippet:
            return "Backslash escape"
        return None

    def _detect_encoding(self, snippet: str) -> Optional[str]:
        """Detect the encoding method used."""
        if '%3C' in snippet or '%3E' in snippet:
            return "URL encoding"
        if '\\u' in snippet:
            return "Unicode escape"
        return None

    def _analyze_special_chars(
        self,
        snippet: str,
        context_type: ContextType,
        probe_chars: Optional[str]
    ) -> Tuple[Set[str], Set[str]]:
        """Analyze which special characters are allowed or blocked."""
        default_allowed = self.CONTEXT_SPECIAL_CHARS.get(context_type, set())

        if not probe_chars:
            return default_allowed, set()

        allowed = set()
        blocked = set()

        # Only raw, non-entity characters in markup outside comments and
        # textarea bodies count as surviving delimiters.
        visible = strip_inert_regions(snippet)
        for char in probe_chars:
            if char in visible:
                allowed.add(char)
            else:
                blocked.add(char)

        return allowed, blocked

    def _generate_payloads(
        self,
        context_type: ContextType,
        allowed_chars: Set[str]
    ) -> List[str]:
        """Generate context-specific payload suggestions."""
        payloads = []

        if context_type == ContextType.HTML_BODY:
            payloads.append("<script>alert(1)</script>")
            payloads.append("<img src=x onerror=alert(1)>")

        elif context_type == ContextType.ATTR_DOUBLE_QUOTED:
            if '"' in allowed_chars:
                payloads.append('" onerror="alert(1)"')
            payloads.append('"><script>alert(1)</script>')

        elif context_type == ContextType.ATTR_SINGLE_QUOTED:
            if "'" in allowed_chars:
                payloads.append("' onerror='alert(1)'")
            payloads.append("'><script>alert(1)</script>")

        elif context_type == ContextType.ATTR_UNQUOTED:
            payloads.append(" onerror=alert(1) ")
            payloads.append("><script>alert(1)</script>")

        elif context_type == ContextType.TEXTAREA:
            payloads.append("</textarea><script>alert(1)</script>")

        elif context_type in (ContextType.JAVASCRIPT_STRING_DOUBLE, ContextType.JAVASCRIPT_STRING_SINGLE):
            payloads.append('";alert(1);//')
            payloads.append("';alert(1);//")

        elif context_type == ContextType.JAVASCRIPT_CODE:
            payloads.append(";alert(1)//")
            payloads.append(");alert(1)//")

        elif context_type == ContextType.CSS_PROPERTY:
            payloads.append(";expression(alert(1))")
            payloads.append("};alert(1);{")

        elif context_type == ContextType.URL_QUERY:
            payloads.append("<script>alert(1)</script>")
            payloads.append("javascript:alert(1)")

        return payloads

    def _get_snippet(self, response: str, position: int, length: int) -> str:
        """Extract a snippet around the reflection position."""
        start = max(0, position - length // 2)
        end = min(len(response), position + length // 2)
        return response[start:end]
