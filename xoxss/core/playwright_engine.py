"""
Playwright browser engine for XSS verification.
"""

import asyncio
import json
import os
import time
from typing import Any, Dict, List, Optional, Protocol
from urllib.parse import urljoin

try:
    from playwright.async_api import async_playwright
    from playwright.async_api import Browser as PlaywrightBrowser
    from playwright.async_api import Page
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False


class PlaywrightEngine:
    """
    Playwright-based browser engine for XSS verification.
    """

    def __init__(
        self,
        console,
        kind: str = "playwright",
        headless: bool = True,
        page_timeout: float = 30.0,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        binary: Optional[str] = None,
        insecure: bool = False,
        auth_state: Optional[str] = None,
    ):
        self.console = console
        self.kind = kind
        self.headless = headless
        self.page_timeout = page_timeout
        self.user_agent = user_agent
        self.proxy = proxy
        self.binary = binary
        self.insecure = insecure
        self.auth_state = auth_state

        self._playwright: Optional[PlaywrightBrowser] = None
        self._context: Optional[Any] = None
        self._page: Optional[Page] = None
        self._started = False

    async def start(self) -> bool:
        """Start the Playwright browser instance."""
        if not HAS_PLAYWRIGHT:
            self.console.error("Playwright not installed: pip install playwright && playwright install")
            return False

        try:
            async with async_playwright() as p:
                # Configure launch options
                launch_args = {
                    "headless": self.headless,
                    "timeout": self.page_timeout * 1000,
                }

                if self.proxy:
                    launch_args["proxy"] = {"server": self.proxy}

                if self.insecure:
                    launch_args["ignore_default_args"] = ["--ignore-certificate-errors"]

                if self.binary:
                    launch_args["executable_path"] = self.binary

                if self.user_agent:
                    launch_args["user_agent"] = self.user_agent

                # Select browser type
                if self.kind == "playwright":
                    # Use default (chromium)
                    pass
                elif self.kind == "chrome":
                    launch_args["channel"] = "chrome"
                elif self.kind == "edge":
                    launch_args["channel"] = "msedge"
                elif self.kind == "firefox":
                    launch_args["channel"] = "firefox"

                self._playwright = await p.chromium.launch(**launch_args)

                # Create context
                if self.auth_state:
                    self._context = await self._playwright.new_context(
                        storage_state=self.auth_state
                    )
                else:
                    self._context = await self._playwright.new_context()

                # Create page
                self._page = await self._context.new_page()
                self._started = True
                return True

        except Exception as exc:
            self.console.error(f"Playwright startup failed: {exc}")
            return False

    async def stop(self) -> None:
        """Stop the Playwright browser instance."""
        if self._page:
            await self._page.close()
            self._page = None

        if self._context:
            await self._context.close()
            self._context = None

        if self._playwright:
            await self._playwright.close()
            self._playwright = None

        self._started = False

    async def navigate(self, url: str) -> str:
        """Navigate to a URL and return the final URL."""
        if not self._page:
            return "error: no page"

        try:
            await self._page.goto(url, timeout=self.page_timeout * 1000)
            return ""
        except Exception as exc:
            return f"error: {exc}"

    async def collect(self) -> Dict[str, Any]:
        """Collect page data."""
        if not self._page:
            return {}

        try:
            return {
                "url": self._page.url,
                "title": await self._page.title(),
                "content": await self._page.content(),
            }
        except Exception as exc:
            self.console.debug(f"Collection failed: {exc}")
            return {}

    async def check_token(
        self,
        token: str,
        timeout: float = 2.5
    ) -> Optional[Dict[str, str]]:
        """Check if a token appears in the page (alerts, dialogs, sinks)."""
        if not self._page:
            return None

        deadline = time.monotonic() + timeout

        try:
            # Inject instrumentation script
            script = f"""
            (async (token) => {{
                const hits = [];
                const alerts = [];
                const dialogs = [];
                const errors = [];
                const sinks = [];

                // Override alert
                window.alert = (msg) => {{
                    if (token && String(msg).includes(token)) {{
                        alerts.push(msg);
                    }}
                }};

                // Override dialogs
                const nativeConfirm = window.confirm;
                window.confirm = (msg) => {{
                    if (token && String(msg).includes(token)) {{
                        dialogs.push(msg);
                    }}
                    return nativeConfirm(msg);
                }};

                // Override console.log for hits
                const originalLog = console.log;
                console.log = (...args) => {{
                    if (token && args.some(a => String(a).includes(token))) {{
                        hits.push(args);
                    }}
                    originalLog.apply(console, args);
                }};

                // Track innerHTML/setAttribute sinks
                const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
                const originalSet = descriptor.set;
                descriptor.set = function (value) {{
                    if (token && String(value).includes(token)) {{
                        sinks.push({{ sink: 'innerHTML', value: String(value) }});
                    }}
                    return originalSet.call(this, value);
                }};
                Object.defineProperty(Element.prototype, 'innerHTML', descriptor);

                const setAttr = Element.prototype.setAttribute;
                Element.prototype.setAttribute = function (name, value) {{
                    if (token && String(value).includes(token)) {{
                        sinks.push({{ sink: 'setAttribute:' + name, value: String(value) }});
                    }}
                    return setAttr.call(this, name, value);
                }};

                // Check for token in HTML
                const html = document.documentElement.outerHTML;
                const in_dom = html.includes(token) ? 'yes' : 'no';

                return {{
                    hits,
                    alerts,
                    dialogs,
                    errors,
                    sinks,
                    html,
                    in_dom
                }};
            }})('{token}');
            """

            result = await self._page.evaluate(script, token)

            return {
                "evidence": " | ".join(result.get("hits", []) + result.get("alerts", []) + result.get("dialogs", [])),
                "executed": "yes" if result.get("alerts") or result.get("dialogs") else "no",
                "in_dom": result.get("in_dom", "no"),
                "sink": str(result.get("sinks", [{}])[0].get("sink", "")) if result.get("sinks") else "",
                "dom_path": str(result.get("sinks", [{}])[0].get("dom_path", "")) if result.get("sinks") else "",
            }

        except Exception as exc:
            self.console.debug(f"Token check failed: {exc}")
            return None

    async def evaluate(self, script: str, arg: Any = None) -> Any:
        """Evaluate JavaScript in the page context."""
        if not self._page:
            return None

        try:
            return await self._page.evaluate(script, arg)
        except Exception as exc:
            self.console.debug(f"Evaluation failed: {exc}")
            return None

    async def screenshot(self, path: str) -> str:
        """Take a screenshot and save to path."""
        if not self._page:
            return ""

        try:
            await self._page.screenshot(path=path, full_page=True)
            return path
        except Exception as exc:
            self.console.debug(f"Screenshot failed: {exc}")
            return ""
