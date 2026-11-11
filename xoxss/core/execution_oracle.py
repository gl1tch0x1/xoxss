"""
Headless Execution Verification Oracle (Zero-FP Gate).

Replays candidate payloads in a clean browser session with CDP instrumentation,
captures execution proofs via window.__xoxss_verify() or intercepted dialogs,
and strictly separates findings into:
- CONFIRMED (Zero-FP guaranteed)
- POTENTIAL (UNVERIFIED)
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from xoxss.core.cdp_hooks import (
    CLEAR_TELEMETRY_JS,
    COLLECT_TELEMETRY_JS,
    CdpTelemetryParser,
    build_cdp_instrumentation,
)


@dataclass
class OracleVerdict:
    """The verdict returned by the Zero-FP Execution Verification Oracle."""
    status: str  # "CONFIRMED" or "POTENTIAL"
    executed: bool
    token: str
    channel: str = ""
    sink_name: str = ""
    dom_path: str = ""
    script_url: str = ""
    evidence: str = ""
    block_reason: str = ""
    screenshot: str = ""


class ExecutionOracle:
    """
    Execution Verification Oracle that navigates a browser engine to test
    payload execution and verifies whether canary triggers execute.
    """

    def __init__(
        self,
        browser_pool: Any = None,
        page_timeout: float = 5.0,
        timeout: Optional[float] = None,
    ) -> None:
        self.browser_pool = browser_pool
        self.page_timeout = timeout if timeout is not None else page_timeout

    async def verify_url_payload(
        self,
        browser: Any,
        target_url: str,
        token: str,
        screenshot_path: str = "",
    ) -> OracleVerdict:
        """
        Verify whether an injected URL payload executes in a live browser context.
        """
        if browser is None:
            return OracleVerdict(
                status="POTENTIAL",
                executed=False,
                token=token,
                block_reason="No browser backend available for runtime verification",
            )

        try:
            # Navigate to target URL
            await browser.navigate(target_url)

            # Poll for execution or sink telemetry
            deadline = time.monotonic() + self.page_timeout
            while time.monotonic() < deadline:
                raw_telemetry = await self._collect_telemetry(browser)
                match = CdpTelemetryParser.match_canary_hit(raw_telemetry, token)

                # Check if verified execution occurred
                verified_tokens = CdpTelemetryParser.extract_verified_tokens(raw_telemetry)
                if token in verified_tokens:
                    screenshot = ""
                    if screenshot_path and hasattr(browser, "screenshot"):
                        try:
                            screenshot = await browser.screenshot(screenshot_path)
                        except Exception:
                            pass
                    return OracleVerdict(
                        status="CONFIRMED",
                        executed=True,
                        token=token,
                        channel="window.__xoxss_verify",
                        sink_name=match.get("sink", "execution-oracle") if match else "execution-oracle",
                        dom_path=match.get("dom_path", "") if match else "",
                        script_url=match.get("script_url", "") if match else "",
                        evidence=f"Oracle verified execution token {token}",
                        screenshot=screenshot,
                    )

                if match and match.get("status") == "confirmed_execution":
                    return OracleVerdict(
                        status="CONFIRMED",
                        executed=True,
                        token=token,
                        channel="cdp-verified",
                        sink_name=match.get("sink", ""),
                        dom_path=match.get("dom_path", ""),
                        script_url=match.get("script_url", ""),
                        evidence=f"CDP telemetry verified execution in {match.get('sink', '')}",
                    )

                await asyncio.sleep(0.2)

            # Check if token reached sink but did not execute (e.g. CSP or innerText)
            last_telemetry = await self._collect_telemetry(browser)
            sink_match = CdpTelemetryParser.match_canary_hit(last_telemetry, token)
            if sink_match:
                return OracleVerdict(
                    status="POTENTIAL",
                    executed=False,
                    token=token,
                    channel="sink-reached",
                    sink_name=sink_match.get("sink", ""),
                    dom_path=sink_match.get("dom_path", ""),
                    script_url=sink_match.get("script_url", ""),
                    evidence=f"Canary reached sink {sink_match.get('sink', '')} but execution was not verified",
                    block_reason="Taint reached DOM sink without triggering script execution (possible CSP or context mismatch)",
                )

            return OracleVerdict(
                status="POTENTIAL",
                executed=False,
                token=token,
                block_reason="Canary token not observed in DOM sinks or execution channels",
            )
        except Exception as exc:
            return OracleVerdict(
                status="POTENTIAL",
                executed=False,
                token=token,
                block_reason=f"Browser verification error: {exc}",
            )
        finally:
            await self._clear_telemetry(browser)

    async def verify_storage_payload(
        self,
        browser: Any,
        base_url: str,
        storage_type: str,
        key: str,
        payload: str,
        token: str,
    ) -> OracleVerdict:
        """
        Pre-populate Web Storage or IndexedDB, navigate to view page, and check execution.
        """
        if browser is None:
            return OracleVerdict(
                status="POTENTIAL",
                executed=False,
                token=token,
                block_reason="No browser backend available",
            )

        try:
            # 1. Navigate to base page to establish origin
            await browser.navigate(base_url)

            # 2. Inject payload into browser storage
            injection_script = ""
            if storage_type in ("localStorage", "localstorage"):
                injection_script = f"localStorage.setItem({repr(key)}, {repr(payload)});"
            elif storage_type in ("sessionStorage", "sessionstorage"):
                injection_script = f"sessionStorage.setItem({repr(key)}, {repr(payload)});"
            elif storage_type in ("indexedDB", "indexeddb"):
                injection_script = f"""
                (function() {{
                  try {{
                    var req = indexedDB.open('xoxss_test_db', 1);
                    req.onupgradeneeded = function(e) {{
                      var db = e.target.result;
                      if (!db.objectStoreNames.contains({repr(key)})) {{
                        db.createObjectStore({repr(key)}, {{ keyPath: 'id', autoIncrement: true }});
                      }}
                    }};
                    req.onsuccess = function(e) {{
                      var db = e.target.result;
                      if (db.objectStoreNames.contains({repr(key)})) {{
                        var tx = db.transaction([{repr(key)}], 'readwrite');
                        tx.objectStore({repr(key)}).put({{ id: 1, val: {repr(payload)} }});
                      }}
                    }};
                  }} catch (e) {{}}
                }})();
                """

            if injection_script:
                await self._evaluate(browser, injection_script)

            # 3. Reload or navigate to trigger consumption
            await browser.navigate(base_url)

            # 4. Check for oracle execution
            return await self.verify_url_payload(browser, base_url, token)
        except Exception as exc:
            return OracleVerdict(
                status="POTENTIAL",
                executed=False,
                token=token,
                block_reason=f"Storage replay failed: {exc}",
            )

    async def verify_postmessage_payload(
        self,
        browser: Any,
        target_url: str,
        payload: str,
        token: str,
    ) -> OracleVerdict:
        """
        Send cross-window or intra-window postMessage and verify execution.
        """
        if browser is None:
            return OracleVerdict(status="POTENTIAL", executed=False, token=token)

        try:
            await browser.navigate(target_url)
            pm_script = f"""
            try {{
              window.postMessage({repr(payload)}, '*');
            }} catch(e) {{}}
            """
            await self._evaluate(browser, pm_script)
            await asyncio.sleep(0.5)
            return await self.verify_url_payload(browser, target_url, token)
        except Exception as exc:
            return OracleVerdict(status="POTENTIAL", executed=False, token=token, block_reason=str(exc))

    async def _collect_telemetry(self, browser: Any) -> Dict[str, Any]:
        """Extract telemetry dictionary from browser instance."""
        try:
            if hasattr(browser, "page") and browser.page is not None:
                return await browser.page.evaluate(COLLECT_TELEMETRY_JS)
            elif hasattr(browser, "driver") and browser.driver is not None:
                return await asyncio.to_thread(browser.driver.execute_script, COLLECT_TELEMETRY_JS)
        except Exception:
            pass
        return {}

    async def _clear_telemetry(self, browser: Any) -> None:
        """Reset telemetry counters between runs."""
        try:
            if hasattr(browser, "page") and browser.page is not None:
                await browser.page.evaluate(CLEAR_TELEMETRY_JS)
            elif hasattr(browser, "driver") and browser.driver is not None:
                await asyncio.to_thread(browser.driver.execute_script, CLEAR_TELEMETRY_JS)
        except Exception:
            pass

    async def _evaluate(self, browser: Any, script: str) -> Any:
        """Execute script in page context."""
        try:
            if hasattr(browser, "page") and browser.page is not None:
                return await browser.page.evaluate(script)
            elif hasattr(browser, "driver") and browser.driver is not None:
                return await asyncio.to_thread(browser.driver.execute_script, script)
        except Exception:
            return None

