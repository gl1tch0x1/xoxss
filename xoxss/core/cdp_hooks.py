"""
CDP Runtime Taint & Source/Sink Instrumentation.

Generates an early-injected JavaScript payload compatible with both:
1. Playwright: context.add_init_script()
2. Selenium Chromium: execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", ...)

Hooks browser sources and sinks, captures caller stack traces and script provenance,
and provides a Zero-FP execution verification oracle hook: window.__xoxss_verify(token).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def build_cdp_instrumentation(canary_prefix: str = "xoxss_canary_") -> str:
    """
    Build the JavaScript payload to evaluate before any page script executes.
    """
    prefix_json = json.dumps(canary_prefix)
    return f"""
(function () {{
  'use strict';
  try {{
    if (window.__xoxss_cdp_active) {{ return; }}
    window.__xoxss_cdp_active = true;

    var CANARY_PREFIX = {prefix_json};

    // Telemetry storage structure
    window.__xoxss_telemetry = window.__xoxss_telemetry || {{
      hits: [],
      sinks: [],
      sources: [],
      verified: [],
      alerts: [],
      errors: []
    }};

    // Backward compatibility mirrors
    window.__xoxss_hits = window.__xoxss_hits || [];
    window.__xoxss_alerts = window.__xoxss_alerts || [];
    window.__xoxss_sinks = window.__xoxss_sinks || [];
    window.__xoxss_requests = window.__xoxss_requests || [];

    var recordRequest = function (value) {{
      try {{
        var text = String(value || '');
        if (!/^https?:\\/\\//i.test(text)) {{ text = new URL(text, location.href).href; }}
        if (window.__xoxss_requests.length < 5000 && window.__xoxss_requests.indexOf(text) < 0) {{
          window.__xoxss_requests.push(text);
        }}
      }} catch (e) {{}}
    }};

    try {{
      var originalFetch = window.fetch;
      if (originalFetch) {{
        window.fetch = function (input) {{
          recordRequest(input && input.url ? input.url : input);
          return originalFetch.apply(this, arguments);
        }};
      }}
      var originalOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function (method, url) {{
        recordRequest(url);
        return originalOpen.apply(this, arguments);
      }};
      var originalPushState = history.pushState;
      history.pushState = function () {{
        var result = originalPushState.apply(this, arguments);
        recordRequest(location.href);
        return result;
      }};
      var originalReplaceState = history.replaceState;
      history.replaceState = function () {{
        var result = originalReplaceState.apply(this, arguments);
        recordRequest(location.href);
        return result;
      }};
    }} catch (e) {{}}

    // Helper: Parse script URL and line number from stack trace
    var parseCaller = function () {{
      try {{
        var stack = new Error().stack || '';
        var lines = stack.split('\\n');
        for (var i = 1; i < lines.length; i++) {{
          var line = lines[i];
          if (!line.includes('__xoxss') && !line.includes('cdp_hooks') && line.includes('http')) {{
            var match = line.match(/(https?:\\/\\/[^:\\s)]+)(?::(\\d+))?(?::(\\d+))?/);
            if (match) {{
              return {{
                raw: line.trim(),
                url: match[1],
                line: match[2] ? parseInt(match[2], 10) : 0,
                column: match[3] ? parseInt(match[3], 10) : 0
              }};
            }}
          }}
        }}
        return {{ raw: lines[2] ? lines[2].trim() : '', url: '', line: 0, column: 0 }};
      }} catch (e) {{
        return {{ raw: '', url: '', line: 0, column: 0 }};
      }}
    }};

    // Helper: Describe DOM path to node
    var describeNode = function (node) {{
      try {{
        if (!node) {{ return ''; }}
        if (node.nodeType === 9) {{ return 'document'; }}
        if (!node.tagName && node.parentNode) {{ node = node.parentNode; }}
        if (!node || !node.tagName) {{ return ''; }}
        var parts = [];
        var current = node;
        var depth = 0;
        while (current && current.nodeType === 1 && depth < 6) {{
          var part = current.tagName.toLowerCase();
          if (current.id) {{
            var safeId = String(current.id).replace(/[^A-Za-z0-9_-]/g, '');
            if (safeId) {{ part += '#' + safeId; parts.unshift(part); break; }}
          }}
          var parent = current.parentNode;
          if (parent && parent.children && parent.children.length > 1) {{
            var idx = 0;
            for (var i = 0; i < parent.children.length; i++) {{
              if (parent.children[i] === current) {{ idx = i + 1; break; }}
            }}
            if (idx) {{ part += ':nth-child(' + idx + ')'; }}
          }}
          parts.unshift(part);
          current = parent;
          depth++;
        }}
        return parts.join(' > ');
      }} catch (e) {{
        return '';
      }}
    }};

    // Helper: Record sink execution
    var recordSink = function (sinkName, value, targetNode) {{
      try {{
        if (window.__xoxss_telemetry.sinks.length > 500) {{ return; }}
        var strVal = String(value == null ? '' : value);
        if (!strVal.trim()) {{ return; }} // Ignore empty string clearing

        // Feature detection filter (e.g. div.innerHTML = "<svg></svg>")
        if (strVal === '<svg></svg>' || strVal === '<table></table>' || strVal === '<xyz>') {{
          return;
        }}

        var caller = parseCaller();
        var entry = {{
          sink: sinkName,
          value: strVal.length > 600 ? strVal.slice(0, 600) : strVal,
          dom_path: describeNode(targetNode),
          script_url: caller.url,
          caller_line: caller.line,
          caller_stack: caller.raw,
          has_canary: strVal.includes(CANARY_PREFIX),
          timestamp: Date.now()
        }};

        window.__xoxss_telemetry.sinks.push(entry);
        window.__xoxss_sinks.push(entry);

        if (entry.has_canary) {{
          window.__xoxss_telemetry.hits.push(entry);
        }}
      }} catch (e) {{}}
    }};

    // 1. Zero-FP Verification Oracle Global Hook
    window.__xoxss_verify = function (token) {{
      try {{
        var tok = String(token || '');
        var caller = parseCaller();
        var record = {{
          token: tok,
          timestamp: Date.now(),
          script_url: caller.url,
          caller_stack: caller.raw,
          type: 'oracle-verify'
        }};
        window.__xoxss_telemetry.verified.push(record);
        window.__xoxss_hits.push(tok);
        return true;
      }} catch (e) {{
        return false;
      }}
    }};

    // 2. Dialog Overrides
    var _origAlert = window.alert;
    var _origConfirm = window.confirm;
    var _origPrompt = window.prompt;
    window.alert = function (msg) {{
      try {{
        var str = String(msg || '');
        window.__xoxss_telemetry.alerts.push(str);
        window.__xoxss_alerts.push(str);
        if (str.includes(CANARY_PREFIX)) {{
          window.__xoxss_verify(str);
        }}
      }} catch (e) {{}}
      try {{ if (window.__xoxss_pw && _origAlert) {{ return _origAlert.call(window, msg); }} }} catch (e) {{}}
    }};
    window.confirm = function (msg) {{
      try {{
        var str = String(msg || '');
        window.__xoxss_telemetry.alerts.push(str);
        window.__xoxss_alerts.push(str);
        if (str.includes(CANARY_PREFIX)) {{
          window.__xoxss_verify(str);
        }}
      }} catch (e) {{}}
      return true;
    }};
    window.prompt = function (msg) {{
      try {{
        var str = String(msg || '');
        window.__xoxss_telemetry.alerts.push(str);
        window.__xoxss_alerts.push(str);
        if (str.includes(CANARY_PREFIX)) {{
          window.__xoxss_verify(str);
        }}
      }} catch (e) {{}}
      return null;
    }};

    window.addEventListener('error', function (event) {{
      try {{
        window.__xoxss_telemetry.errors.push(String(event.message || ''));
      }} catch (e) {{}}
    }});

    // 3. Prototype Sink Hooks: Element.prototype.innerHTML, outerHTML, insertAdjacentHTML
    try {{
      var innerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
      if (innerDesc && innerDesc.set) {{
        Object.defineProperty(Element.prototype, 'innerHTML', {{
          configurable: true,
          get: function () {{ return innerDesc.get.call(this); }},
          set: function (val) {{
            recordSink('innerHTML', val, this);
            return innerDesc.set.call(this, val);
          }}
        }});
      }}
    }} catch (e) {{}}

    try {{
      var outerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
      if (outerDesc && outerDesc.set) {{
        Object.defineProperty(Element.prototype, 'outerHTML', {{
          configurable: true,
          get: function () {{ return outerDesc.get.call(this); }},
          set: function (val) {{
            recordSink('outerHTML', val, this);
            return outerDesc.set.call(this, val);
          }}
        }});
      }}
    }} catch (e) {{}}

    try {{
      var origInsert = Element.prototype.insertAdjacentHTML;
      Element.prototype.insertAdjacentHTML = function (pos, markup) {{
        recordSink('insertAdjacentHTML', markup, this);
        return origInsert.apply(this, arguments);
      }};
    }} catch (e) {{}}

    // 4. Document Sinks: document.write, document.writeln
    try {{
      var origWrite = document.write;
      document.write = function () {{
        var val = Array.prototype.join.call(arguments, '');
        recordSink('document.write', val, document);
        return origWrite.apply(document, arguments);
      }};
      var origWriteln = document.writeln;
      document.writeln = function () {{
        var val = Array.prototype.join.call(arguments, '');
        recordSink('document.writeln', val, document);
        return origWriteln.apply(document, arguments);
      }};
    }} catch (e) {{}}

    // 5. JavaScript Execution Sinks: eval, Function, setTimeout, setInterval
    try {{
      var origEval = window.eval;
      window.eval = function (code) {{
        recordSink('eval', code, null);
        return origEval(code);
      }};
    }} catch (e) {{}}

    try {{
      var origTimeout = window.setTimeout;
      window.setTimeout = function (handler) {{
        if (typeof handler === 'string') {{ recordSink('setTimeout', handler, null); }}
        return origTimeout.apply(window, arguments);
      }};
      var origInterval = window.setInterval;
      window.setInterval = function (handler) {{
        if (typeof handler === 'string') {{ recordSink('setInterval', handler, null); }}
        return origInterval.apply(window, arguments);
      }};
    }} catch (e) {{}}

    // 6. DOM Attribute Sinks: setAttribute (srcdoc, href, on*)
    try {{
      var origSetAttr = Element.prototype.setAttribute;
      Element.prototype.setAttribute = function (name, value) {{
        var attr = String(name || '').toLowerCase();
        if (attr === 'srcdoc' || attr === 'href' || attr === 'src' || attr === 'action' || /^on[a-z]+$/.test(attr)) {{
          recordSink('setAttribute:' + attr, value, this);
        }}
        return origSetAttr.apply(this, arguments);
      }};
    }} catch (e) {{}}

    // 7. Contextual Fragments & DOMParser
    try {{
      var origFragment = Range.prototype.createContextualFragment;
      Range.prototype.createContextualFragment = function (markup) {{
        recordSink('createContextualFragment', markup, this.startContainer || null);
        return origFragment.apply(this, arguments);
      }};
      var origParse = DOMParser.prototype.parseFromString;
      DOMParser.prototype.parseFromString = function (source, type) {{
        recordSink('DOMParser.parseFromString:' + type, source, null);
        return origParse.apply(this, arguments);
      }};
    }} catch (e) {{}}

    // 8. Storage Prototype Instrumentation (localStorage, sessionStorage)
    try {{
      var origGetItem = Storage.prototype.getItem;
      Storage.prototype.getItem = function (key) {{
        var val = origGetItem.apply(this, arguments);
        try {{
          var caller = parseCaller();
          window.__xoxss_telemetry.sources.push({{
            type: 'storage.getItem',
            key: String(key || ''),
            script_url: caller.url,
            has_canary: String(val || '').includes(CANARY_PREFIX)
          }});
        }} catch (e) {{}}
        return val;
      }};
    }} catch (e) {{}}

    // 9. IndexedDB Prototype Instrumentation
    try {{
      if (window.IDBObjectStore && window.IDBObjectStore.prototype) {{
        var origIdbGet = window.IDBObjectStore.prototype.get;
        if (origIdbGet) {{
          window.IDBObjectStore.prototype.get = function (query) {{
            var req = origIdbGet.apply(this, arguments);
            try {{
              var caller = parseCaller();
              window.__xoxss_telemetry.sources.push({{
                type: 'indexedDB.get',
                store: this.name,
                query: String(query || ''),
                script_url: caller.url
              }});
            }} catch (e) {{}}
            return req;
          }};
        }}
      }}
    }} catch (e) {{}}

  }} catch (e) {{}}
}})();
"""


COLLECT_TELEMETRY_JS = """
return (function() {
  var t = window.__xoxss_telemetry || {};
  return {
    hits: t.hits || [],
    sinks: t.sinks || [],
    sources: t.sources || [],
    verified: t.verified || [],
    alerts: t.alerts || window.__xoxss_alerts || [],
    errors: t.errors || [],
    html: document.documentElement ? document.documentElement.outerHTML : ''
  };
})();
"""

CLEAR_TELEMETRY_JS = """
(function() {
  if (window.__xoxss_telemetry) {
    window.__xoxss_telemetry.hits = [];
    window.__xoxss_telemetry.verified = [];
    window.__xoxss_telemetry.alerts = [];
  }
  window.__xoxss_hits = [];
  window.__xoxss_alerts = [];
})();
"""


class CdpTelemetryParser:
    """
    Parses telemetry captured from the browser instrumentation.
    """

    @staticmethod
    def extract_verified_tokens(telemetry: Dict[str, Any]) -> List[str]:
        """Extract all tokens verified by window.__xoxss_verify() or alert/dialogs."""
        tokens: List[str] = []
        for item in telemetry.get("verified", []):
            if isinstance(item, dict) and item.get("token"):
                tokens.append(str(item["token"]))
            elif isinstance(item, str):
                tokens.append(item)
        for alert_msg in telemetry.get("alerts", []):
            tokens.append(str(alert_msg))
        return list(dict.fromkeys(tokens))

    @staticmethod
    def match_canary_hit(telemetry: Dict[str, Any], canary: str) -> Optional[Dict[str, Any]]:
        """
        Check if a specific canary token reached a monitored sink,
        returning exact sink name, DOM path, and calling script URL.
        """
        if not canary:
            return None

        # Check direct execution hits first
        for verified in telemetry.get("verified", []):
            tok = verified.get("token") if isinstance(verified, dict) else str(verified)
            if canary in str(tok):
                return {
                    "status": "confirmed_execution",
                    "sink": "window.__xoxss_verify",
                    "script_url": verified.get("script_url", "") if isinstance(verified, dict) else "",
                    "caller_stack": verified.get("caller_stack", "") if isinstance(verified, dict) else "",
                    "dom_path": "",
                    "value": str(tok),
                }

        # Check sink hits with canary presence
        for hit in telemetry.get("hits", []):
            val = str(hit.get("value") or "")
            if canary in val:
                return {
                    "status": "sink_reached",
                    "sink": hit.get("sink", ""),
                    "script_url": hit.get("script_url", ""),
                    "caller_stack": hit.get("caller_stack", ""),
                    "dom_path": hit.get("dom_path", ""),
                    "value": val,
                }

        # Check general sinks list in case canary was slightly transformed
        for sink in telemetry.get("sinks", []):
            val = str(sink.get("value") or "")
            if canary in val:
                return {
                    "status": "sink_reached",
                    "sink": sink.get("sink", ""),
                    "script_url": sink.get("script_url", ""),
                    "caller_stack": sink.get("caller_stack", ""),
                    "dom_path": sink.get("dom_path", ""),
                    "value": val,
                }

        return None

