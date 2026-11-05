"""
WebSocket XSS detection module.

Passive analysis inspects handlers for dangerous sinks.  The active probe
connects to a discovered endpoint over ``aiohttp.ClientSession.ws_connect``,
sends unique marker payloads as text frames and records frames that echo the
marker back.  A reflected frame is evidence of frame reflection, not proof of
DOM execution, so the scanner reports it conservatively.
"""

import asyncio
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

try:  # aiohttp is a core dependency, but keep imports defensive
    import aiohttp
except Exception:  # pragma: no cover - caller reports the missing dependency
    aiohttp = None  # type: ignore


class WebSocketSink(Enum):
    """WebSocket message sink types."""
    ONMESSAGE = "onmessage"
    MESSAGE_EVENT = "message_event"
    EVAL = "eval"
    INNERHTML = "innerHTML"
    DOCUMENT_WRITE = "document_write"


@dataclass
class WebSocketVulnerability:
    """WebSocket XSS vulnerability."""
    sink_type: WebSocketSink
    location: str
    payload: str
    description: str


@dataclass
class WebSocketFrameHit:
    """One active frame-injection attempt and its observed response."""

    url: str
    payload: str
    marker: str
    response: str = ""
    reflected: bool = False
    executable: bool = False
    context: str = ""
    evidence: str = ""
    error: str = ""


class WebSocketAnalyzer:
    """
    Advanced WebSocket XSS analyzer.
    Detects XSS vulnerabilities in WebSocket message handlers.
    """

    # WebSocket sink patterns
    SINK_PATTERNS = {
        WebSocketSink.ONMESSAGE: [
            r'\.onmessage\s*=',
            r'addEventListener\s*\(\s*["\']message["\']',
        ],
        WebSocketSink.EVAL: [
            r'\beval\s*\(',
            r'new\s+Function\s*\(',
        ],
        WebSocketSink.INNERHTML: [
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
        ],
        WebSocketSink.DOCUMENT_WRITE: [
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
        ],
    }

    # WebSocket connection patterns
    CONNECTION_PATTERNS = [
        r'new\s+WebSocket\s*\(',
        r'new\s+Socket\s*\(',
        r'\.connect\s*\(',
    ]

    def __init__(self):
        self._cache: Dict[str, List[WebSocketVulnerability]] = {}

    def detect_websocket_usage(self, js_content: str) -> bool:
        """Check if WebSocket is used in the JavaScript."""
        for pattern in self.CONNECTION_PATTERNS:
            if re.search(pattern, js_content):
                return True
        return False

    def analyze_websocket_handlers(self, js_content: str, marker: str) -> List[WebSocketVulnerability]:
        """
        Analyze WebSocket message handlers for XSS vulnerabilities.

        Args:
            js_content: JavaScript source code
            marker: Unique marker for verification

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        if not self.detect_websocket_usage(js_content):
            return vulnerabilities

        # Check for onmessage handler
        if re.search(r'\.onmessage\s*=', js_content):
            # Check if data is used dangerously
            for sink_type, patterns in self.SINK_PATTERNS.items():
                if sink_type == WebSocketSink.ONMESSAGE:
                    continue
                for pattern in patterns:
                    if re.search(pattern, js_content):
                        vulnerabilities.append(WebSocketVulnerability(
                            sink_type=sink_type,
                            location="onmessage handler",
                            payload=self._generate_payload(sink_type, marker),
                            description=f"WebSocket message data flows into {sink_type.value}"
                        ))

        # Check for addEventListener('message')
        if re.search(r'addEventListener\s*\(\s*["\']message["\']', js_content):
            for sink_type, patterns in self.SINK_PATTERNS.items():
                if sink_type == WebSocketSink.ONMESSAGE:
                    continue
                for pattern in patterns:
                    if re.search(pattern, js_content):
                        vulnerabilities.append(WebSocketVulnerability(
                            sink_type=sink_type,
                            location="message event listener",
                            payload=self._generate_payload(sink_type, marker),
                            description=f"WebSocket message data flows into {sink_type.value}"
                        ))

        return vulnerabilities

    def _generate_payload(self, sink_type: WebSocketSink, marker: str) -> str:
        """Generate a WebSocket XSS payload."""
        if sink_type == WebSocketSink.INNERHTML:
            return f'<script>window.__xoxss_ws.push(\'{marker}\')</script>'
        elif sink_type == WebSocketSink.EVAL:
            return f'window.__xoxss_ws.push(\'{marker}\')'
        elif sink_type == WebSocketSink.DOCUMENT_WRITE:
            return f'<script>window.__xoxss_ws.push(\'{marker}\')</script>'
        else:
            return f'<script>window.__xoxss_ws.push(\'{marker}\')</script>'

    def generate_websocket_test_message(self, marker: str) -> str:
        """Generate a test WebSocket message."""
        return f'{{"data": "<script>window.__xoxss_ws.push(\'{marker}\')</script>"}}'

    def check_websocket_origin_validation(self, js_content: str) -> bool:
        """Check if WebSocket origin is validated."""
        origin_patterns = [
            r'origin',
            r'checkOrigin',
            r'validateOrigin',
        ]
        return any(re.search(pattern, js_content) for pattern in origin_patterns)


def extract_websocket_urls(js_content: str, base_url: str = "") -> List[str]:
    """Resolve literal ``new WebSocket('…')`` endpoints found in JavaScript."""
    if not js_content:
        return []
    candidates = re.findall(
        r"new\s+(?:WebSocket|Socket)\s*\(\s*(['\"])(.*?)\1", js_content, flags=re.S
    )
    results: List[str] = []
    base = urlsplit(base_url)
    for _quote, raw in candidates:
        value = raw.strip()
        if not value or any(char in value for char in "\r\n\t "):
            continue
        if value.startswith(("ws://", "wss://")):
            url = value
        elif value.startswith("//"):
            scheme = "wss" if base.scheme == "https" else "ws"
            url = f"{scheme}:{value}"
        elif value.startswith("/"):
            scheme = "wss" if base.scheme == "https" else "ws"
            url = urlunsplit((scheme, base.netloc, value, "", ""))
        else:
            joined = urljoin(base_url, value)
            parts = urlsplit(joined)
            scheme = "wss" if parts.scheme == "https" else "ws"
            url = urlunsplit((scheme, parts.netloc, parts.path, parts.query, ""))
        if url and url not in results:
            results.append(url)
    return results


def websocket_http_equivalent(url: str) -> str:
    """Map a ws/wss URL onto http/https for scope checks."""
    parts = urlsplit(url)
    scheme = "https" if parts.scheme == "wss" else "http"
    return urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _payload_variants(marker: str) -> List[str]:
    analyzer = WebSocketAnalyzer()
    return [
        analyzer.generate_websocket_test_message(marker),
        f'<script>window.__xoxss_ws.push(\'{marker}\')</script>',
        f'"><img src=x onerror="window.__xoxss_ws.push(\'{marker}\')">',
    ]


class WebSocketActiveProbe:
    """Inject marker frames into a live WebSocket and record reflections."""

    def __init__(
        self,
        console: Any = None,
        *,
        timeout: float = 8.0,
        frame_timeout: float = 3.0,
        max_frames: int = 8,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        origin: str = "",
        insecure: bool = False,
        proxy: Optional[str] = None,
    ) -> None:
        self.console = console
        self.timeout = max(1.0, float(timeout))
        self.frame_timeout = max(0.5, float(frame_timeout))
        self.max_frames = max(1, int(max_frames))
        self.headers = dict(headers or {})
        self.cookies = dict(cookies or {})
        self.origin = origin
        self.insecure = insecure
        self.proxy = proxy

    def _debug(self, message: str) -> None:
        if self.console is not None:
            try:
                self.console.debug(message)
            except Exception:
                pass

    async def probe(
        self,
        url: str,
        *,
        markers: Sequence[str],
        payloads: Optional[Sequence[str]] = None,
    ) -> List[WebSocketFrameHit]:
        """Connect once and try every payload/marker pair.

        Returns one hit per payload, including non-reflected attempts, so the
        caller can distinguish "server did not echo" from "connection failed".
        """
        hits: List[WebSocketFrameHit] = []
        if aiohttp is None:
            return [WebSocketFrameHit(url=url, payload="", marker="", error="aiohttp is not installed")]
        if not markers:
            return hits

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        try:
            session = aiohttp.ClientSession(
                timeout=timeout,
                headers=self.headers or None,
                cookies=self.cookies or None,
            )
        except Exception as exc:  # pragma: no cover - constructor failures are rare
            return [WebSocketFrameHit(url=url, payload="", marker="", error=str(exc)[:300])]

        try:
            kwargs: Dict[str, Any] = {"max_msg_size": 4 * 1024 * 1024}
            if self.origin:
                kwargs["origin"] = self.origin
            if self.insecure:
                kwargs["ssl"] = False
            if self.proxy:
                kwargs["proxy"] = self.proxy
            async with session.ws_connect(url, **kwargs) as ws:
                for marker in markers:
                    for payload in (payloads or _payload_variants(marker)):
                        response, error, reflected = await self._send_and_read(ws, payload, marker)
                        if error:
                            hits.append(
                                WebSocketFrameHit(
                                    url=url, payload=payload, marker=marker, error=error[:300]
                                )
                            )
                            continue
                        hit = self._classify(url, payload, marker, response)
                        hit.reflected = reflected or hit.reflected
                        hits.append(hit)
                        if hit.reflected:
                            return hits
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            hits.append(
                WebSocketFrameHit(
                    url=url, payload="", marker=markers[0], error=f"{type(exc).__name__}: {exc}"[:300]
                )
            )
        finally:
            try:
                await session.close()
            except Exception:
                pass
        return hits

    async def _send_and_read(self, ws: Any, payload: str, marker: str) -> Tuple[str, str, bool]:
        try:
            await ws.send_str(payload)
        except Exception as exc:
            return "", f"send failed: {exc}", False
        parts: List[str] = []
        reflected = False
        for _ in range(self.max_frames):
            try:
                message = await asyncio.wait_for(ws.receive(), timeout=self.frame_timeout)
            except asyncio.TimeoutError:
                break
            except Exception as exc:
                if parts:
                    break
                return "", f"receive failed: {exc}", False
            if message.type in (aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY):
                data = message.data
                text = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
                parts.append(text)
                if marker in text:
                    reflected = True
                    break
            elif message.type in (
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSING,
                aiohttp.WSMsgType.ERROR,
            ):
                break
        response = "\n".join(parts)[:8000]
        return response, "", reflected or marker in response

    def _classify(self, url: str, payload: str, marker: str, response: str) -> WebSocketFrameHit:
        hit = WebSocketFrameHit(url=url, payload=payload, marker=marker, response=response)
        if marker not in response:
            hit.evidence = "marker was not reflected in the received frame"
            return hit
        hit.reflected = True
        # Reuse the HTTP reflection classifier so context/executability labels
        # match the rest of the scanner.
        try:
            from xoxss.scan.reflection import analyze_reflection

            info = analyze_reflection(response, marker, payload, "text/html")
            hit.context = info.context
            hit.executable = bool(info.executable)
            hit.evidence = (
                f"WebSocket frame reflected the injected marker "
                f"(context: {hit.context or 'unknown'}, executable: {hit.executable})"
            )
        except Exception:
            hit.context = "unknown"
            hit.evidence = "WebSocket frame reflected the injected marker"
        return hit


__all__ = [
    "WebSocketSink",
    "WebSocketVulnerability",
    "WebSocketFrameHit",
    "WebSocketAnalyzer",
    "WebSocketActiveProbe",
    "extract_websocket_urls",
    "websocket_http_equivalent",
]
