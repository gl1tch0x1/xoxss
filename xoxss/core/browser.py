"""
Browser backends for JavaScript-execution confirmation.

Selenium is the default.  Playwright is an opt-in alternative with the same
surface (``--browser playwright``): it needs no driver binaries, boots faster
and works well in containers.  Keeping both out of the scan coordinator makes
them independently testable.
"""

from __future__ import annotations

import asyncio
import importlib.util
import inspect
import json
import os
import re
import shutil
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol

#: Whether the optional Playwright backend can be imported in this environment.
HAS_PLAYWRIGHT = importlib.util.find_spec("playwright") is not None


class ConsoleLike(Protocol):
    def ok(self, message: str, important: bool = True) -> None: ...
    def info(self, message: str, important: bool = True) -> None: ...
    def warn(self, message: str, important: bool = True) -> None: ...
    def error(self, message: str, important: bool = True) -> None: ...
    def debug(self, message: str) -> None: ...


def _truncate(text: Any, limit: int = 200) -> str:
    value = str(text or "")
    return value if len(value) <= limit else value[: limit - 1] + "\u2026"


from xoxss.core.cdp_hooks import build_cdp_instrumentation

HOOK_JS = build_cdp_instrumentation()

COLLECT_JS = r"""
return {
  hits: window.__xoxss_hits || [],
  alerts: window.__xoxss_alerts || [],
  sinks: window.__xoxss_sinks || [],
  errors: window.__xoxss_errors || [],
  requests: window.__xoxss_requests || [],
  telemetry: window.__xoxss_telemetry || null,
  verifications: (window.__xoxss_telemetry && window.__xoxss_telemetry.verified) || [],
  href: String(location.href || ''),
  title: String(document.title || ''),
  ready: String(document.readyState || '')
};
"""

FILL_JS = r"""
var index = arguments[0], name = arguments[1], value = arguments[2];
var forms = document.forms, form = forms[index];
if (!form) {
  for (var i = 0; i < forms.length; i++) {
    if (forms[i].elements[name]) { form = forms[i]; break; }
  }
}
if (!form) { return 'noform'; }
var found = 0;
for (var j = 0; j < form.elements.length; j++) {
  var element = form.elements[j];
  if (element.name !== name) { continue; }
  try {
    element.value = value;
    element.dispatchEvent(new Event('input', { bubbles: true }));
    element.dispatchEvent(new Event('change', { bubbles: true }));
    found++;
  } catch (e) {}
}
return found ? 'ok' : 'nofield';
"""

SUBMIT_JS = r"""
var index = arguments[0];
var forms = document.forms, form = forms[index];
if (!form) { return 'noform'; }
var button = form.querySelector('button[type=submit],input[type=submit],button:not([type])');
if (button) {
  try { button.click(); return 'click'; } catch (e) {}
}
if (form.requestSubmit) {
  try { form.requestSubmit(); return 'requestSubmit'; } catch (e) {}
}
try { form.submit(); return 'submit'; } catch (e) {}
return 'failed';
"""

CHROME_ARGS = [
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--disable-notifications",
    "--disable-popup-blocking",
    "--disable-background-networking",
    "--disable-background-timer-throttling",
    "--disable-renderer-backgrounding",
    "--disable-blink-features=AutomationControlled",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1366,900",
]

# Well-known Chromium/Chrome locations.  Selenium Manager downloads a driver
# (and sometimes a browser) on demand; when a system Chromium already exists we
# point Selenium at it instead, which works offline and in hardened CI images.
CHROMIUM_CANDIDATES = [
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/snap/bin/chromium",
    "/usr/local/bin/chromium",
    "/usr/local/bin/chromium-browser",
    "/usr/local/bin/google-chrome",
    "/opt/google/chrome/chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
]

_WINDOWS_CHROMIUM = [
    r"ProgramFiles\Google\Chrome\Application\chrome.exe",
    r"ProgramFiles(x86)\Google\Chrome\Application\chrome.exe",
    r"LocalAppData\Chromium\Application\chrome.exe",
]


def chromium_candidates() -> List[str]:
    """Return candidate Chromium binaries in priority order."""
    candidates: List[str] = []
    for env_name in ("XOXSS_CHROMIUM", "CHROME_BIN", "CHROMIUM_BIN"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(value)
    candidates.extend(CHROMIUM_CANDIDATES)
    if os.name == "nt":
        for relative in _WINDOWS_CHROMIUM:
            root = os.environ.get(relative.split("\\", 1)[0], "")
            if root:
                candidates.append(str(Path(root) / relative.split("\\", 1)[1]))
    for executable in ("chromium", "chromium-browser", "google-chrome", "chrome"):
        found = shutil.which(executable)
        if found:
            candidates.append(found)
    return list(dict.fromkeys(candidates))


def detect_chromium_binary() -> Optional[str]:
    """Locate a system Chromium/Chrome executable, if one is installed."""
    for candidate in chromium_candidates():
        try:
            if candidate and Path(candidate).is_file():
                return candidate
        except OSError:
            continue
    return None


def headed_diagnostic() -> str:
    """Explain why headed mode may fail on a headless Linux host."""
    if os.name == "nt":
        return ""
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        return ""
    return (
        "headed mode needs an X/Wayland display and none is set (DISPLAY is empty); "
        "use --headless, or wrap the command with `xvfb-run -a xoxss ...`"
    )


class BrowserEngine:
    """Single Selenium driver guarded by an asyncio lock."""

    def __init__(
        self,
        console: ConsoleLike,
        kind: str = "firefox",
        headless: bool = False,
        page_timeout: float = 25.0,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        binary: Optional[str] = None,
        insecure: bool = False,
        url_allowed: Optional[Callable[[str], bool]] = None,
        auth_state: Optional[str] = None,
    ):
        self.console = console
        self.kind = (kind or "firefox").lower()
        self.headless = headless
        self.page_timeout = page_timeout
        self.user_agent = user_agent
        self.proxy = proxy
        self.binary = binary
        self.insecure = insecure
        self.url_allowed = url_allowed
        self.auth_state = auth_state
        self.driver: Any = None
        self.navigation_count = 0
        self._lock = asyncio.Lock()
        self._cdp_hook = False
        self._suppress_dialogs = self.kind in ("chrome", "chromium", "edge")

    # -- lifecycle --------------------------------------------------------------------
    async def start(self) -> bool:
        return await asyncio.to_thread(self._start_sync)

    def _start_sync(self) -> bool:
        try:
            from selenium import webdriver  # noqa: F401
        except Exception:
            self.console.warn("Selenium is not installed - browser verification disabled (pip install selenium)")
            return False

        try:
            driver = self._create_driver()
        except Exception as exc:
            self.console.error(f"Could not start {self.kind}: {exc}")
            hint = headed_diagnostic() if not self.headless else ""
            if hint:
                self.console.warn(hint)
            return False

        self.driver = driver
        try:
            driver.set_page_load_timeout(self.page_timeout)
            driver.set_script_timeout(self.page_timeout)
        except Exception:
            pass

        if self.kind in ("chrome", "chromium", "edge"):
            try:
                driver.execute_cdp_cmd(
                    "Page.addScriptToEvaluateOnNewDocument", {"source": HOOK_JS}
                )
                self._cdp_hook = True
            except Exception:
                self._cdp_hook = False
        self.console.ok(f"{self.kind} browser ready ({'headless' if self.headless else 'headed'})", important=False)
        return True

    def _create_driver(self) -> Any:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options as ChromeOptions
        from selenium.webdriver.firefox.options import Options as FirefoxOptions

        if self.kind in ("chrome", "chromium"):
            options = ChromeOptions()
            for arg in CHROME_ARGS:
                options.add_argument(arg)
            if self.headless:
                options.add_argument("--headless=new")
            if self.user_agent:
                options.add_argument(f"--user-agent={self.user_agent}")
            if self.proxy:
                options.add_argument(f"--proxy-server={self.proxy}")
            if self.binary:
                options.binary_location = self.binary
            else:
                detected = detect_chromium_binary()
                if detected:
                    options.binary_location = detected
                    self.console.debug(f"Using detected Chromium binary: {detected}")
            if self.insecure:
                options.add_argument("--ignore-certificate-errors")
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option("useAutomationExtension", False)
            if not self.headless:
                options.add_argument("--start-maximized")
            try:
                return webdriver.Chrome(options=options)
            except Exception as first:
                self.console.debug(f"Selenium Manager failed ({first}); falling back to webdriver-manager")
                from selenium.webdriver.chrome.service import Service
                from webdriver_manager.chrome import ChromeDriverManager

                return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

        if self.kind == "edge":
            from selenium.webdriver.edge.options import Options as EdgeOptions

            options = EdgeOptions()
            for arg in CHROME_ARGS:
                options.add_argument(arg)
            if self.headless:
                options.add_argument("--headless=new")
            if self.user_agent:
                options.add_argument(f"--user-agent={self.user_agent}")
            if self.proxy:
                options.add_argument(f"--proxy-server={self.proxy}")
            return webdriver.Edge(options=options)

        # Firefox
        options = FirefoxOptions()
        if self.headless:
            options.add_argument("-headless")
        if self.binary:
            options.binary_location = self.binary
        if self.user_agent:
            options.set_preference("general.useragent.override", self.user_agent)
        if self.proxy:
            host, _, port = self.proxy.replace("http://", "").replace("https://", "").partition(":")
            options.set_preference("network.proxy.type", 1)
            options.set_preference("network.proxy.http", host)
            options.set_preference("network.proxy.http_port", int(port or 8080))
            options.set_preference("network.proxy.ssl", host)
            options.set_preference("network.proxy.ssl_port", int(port or 8080))
        options.set_preference("dom.webdriver.enabled", False)
        options.set_preference("useAutomationExtension", False)
        if self.insecure:
            options.accept_insecure_certs = True
        try:
            return webdriver.Firefox(options=options)
        except Exception as first:
            self.console.debug(f"Selenium Manager failed ({first}); falling back to webdriver-manager")
            from selenium.webdriver.firefox.service import Service
            from webdriver_manager.firefox import GeckoDriverManager

            return webdriver.Firefox(service=Service(GeckoDriverManager().install()), options=options)

    async def stop(self) -> None:
        if self.driver is None:
            return
        driver = self.driver
        self.driver = None
        try:
            await asyncio.to_thread(driver.quit)
        except Exception:
            pass

    def is_alive(self) -> bool:
        """Return True only if the driver process and session are responsive."""
        if self.driver is None:
            return False
        try:
            _ = self.driver.current_window_handle
            return True
        except Exception:
            return False

    # -- page interaction -------------------------------------------------------------
    async def navigate(self, url: str) -> str:
        if self.url_allowed is not None and not self.url_allowed(url):
            return "URL is outside the configured scan scope"
        async with self._lock:
            return await asyncio.to_thread(self._navigate_sync, url)

    def _navigate_sync(self, url: str) -> str:
        driver = self.driver
        self.navigation_count += 1
        error = ""
        try:
            driver.get(url)
        except Exception as exc:
            error = str(exc)
            self._drain_dialog_sync()
        try:
            driver.execute_script(HOOK_JS)
        except Exception:
            pass
        deadline = time.time() + min(10.0, self.page_timeout)
        while time.time() < deadline:
            try:
                if driver.execute_script("return document.readyState") == "complete":
                    break
            except Exception:
                pass
            time.sleep(0.1)
        return error

    async def collect(self) -> Dict[str, Any]:
        async with self._lock:
            return await asyncio.to_thread(self._collect_sync)

    def _collect_sync(self) -> Dict[str, Any]:
        driver = self.driver
        dialog = self._drain_dialog_sync()
        data: Dict[str, Any] = {}
        try:
            data = driver.execute_script(COLLECT_JS) or {}
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        for key in ("hits", "alerts", "sinks", "errors"):
            if not isinstance(data.get(key), list):
                data[key] = []
        if not isinstance(data.get("requests"), list):
            data["requests"] = []
        dialogs = data.get("dialogs")
        if not isinstance(dialogs, list):
            dialogs = []
        if dialog:
            dialogs.append(dialog)
        data["dialogs"] = dialogs
        try:
            data["html"] = driver.page_source[:200000]
        except Exception:
            data["html"] = ""
        return data

    def _drain_dialog_sync(self) -> Optional[str]:
        try:
            alert = self.driver.switch_to.alert
            text = alert.text
            alert.accept()
            return text
        except Exception:
            return None

    async def evaluate(self, script: str, arg: Any = None) -> Any:
        """Evaluate a function expression with one JSON-serialisable argument."""
        async with self._lock:
            return await asyncio.to_thread(self._evaluate_sync, script, arg)

    def _evaluate_sync(self, script: str, arg: Any = None) -> Any:
        driver = self.driver
        if driver is None:
            return None
        try:
            return driver.execute_script("return (" + script + ")(arguments[0]);", arg)
        except Exception as exc:
            self.console.debug(f"Browser evaluate failed: {exc}")
            return None

    async def check_token(self, token: str, timeout: float = 2.5) -> Optional[Dict[str, str]]:
        deadline = time.monotonic() + timeout
        while True:
            data = await self.collect()
            hit = self._match(data, token)
            if hit:
                return hit
            if time.monotonic() >= deadline:
                return None
            await asyncio.sleep(0.15)

    @staticmethod
    def _match(data: Dict[str, Any], token: str) -> Optional[Dict[str, str]]:
        channels: List[str] = []
        executed: bool = False
        verified: bool = False
        sink_name: str = ""
        dom_path: str = ""
        for key, label in (
            ("verifications", "oracle-verified"),
            ("hits", "js-executed"),
            ("alerts", "alert"),
            ("dialogs", "alert"),
            ("sinks", "dom-sink"),
            ("errors", "js-error"),
        ):
            for item in data.get(key) or []:
                blob = item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)
                if token not in blob:
                    continue
                channels.append(f"{label}: {_truncate(blob, 200)}")
                if key in ("verifications", "hits", "alerts", "dialogs"):
                    executed = True
                if key == "verifications":
                    verified = True
                if key == "sinks" and isinstance(item, dict):
                    if not sink_name and item.get("sink"):
                        sink_name = str(item["sink"])
                    if not dom_path and item.get("dom_path"):
                        dom_path = str(item["dom_path"])
        if not channels:
            return None
        in_dom = "yes" if token in (data.get("html") or "") else "no"
        if not dom_path and in_dom == "yes":
            # The value is in the serialized DOM even if the instrumented sink
            # that wrote it could not describe its node (e.g. document.write).
            dom_path = ""
        return {
            "evidence": " | ".join(channels[:4]),
            "executed": "yes" if executed else "no",
            "verified": "yes" if verified else "no",
            "in_dom": in_dom,
            "sink": sink_name,
            "dom_path": dom_path,
        }

    async def submit_form(self, form_index: int, field_name: str, value: str) -> Dict[str, str]:
        async with self._lock:
            self.navigation_count += 1
            return await asyncio.to_thread(self._submit_sync, form_index, field_name, value)

    def _submit_sync(self, form_index: int, field_name: str, value: str) -> Dict[str, str]:
        driver = self.driver
        result = {"fill": "error", "submit": "error"}
        try:
            result["fill"] = str(driver.execute_script(FILL_JS, form_index, field_name, value))
        except Exception as exc:
            result["fill"] = f"error: {exc}"
        time.sleep(0.15)
        try:
            result["submit"] = str(driver.execute_script(SUBMIT_JS, form_index))
        except Exception as exc:
            result["submit"] = f"error: {exc}"
        deadline = time.time() + min(10.0, self.page_timeout)
        while time.time() < deadline:
            try:
                if driver.execute_script("return document.readyState") == "complete":
                    break
            except Exception:
                pass
            time.sleep(0.1)
        self._drain_dialog_sync()
        try:
            driver.execute_script(HOOK_JS)
        except Exception:
            pass
        time.sleep(0.2)
        return result

    async def screenshot(self, path: str) -> str:
        async with self._lock:
            return await asyncio.to_thread(self._screenshot_sync, path)

    def _screenshot_sync(self, path: str) -> str:
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.driver.save_screenshot(path)
            return path
        except Exception:
            return ""


class PlaywrightEngine:
    """
    Optional Playwright backend (Chromium) with the same surface as BrowserEngine.

    Playwright boots 3-4x faster than Selenium+webdriver_manager, needs no driver
    binaries, and works well in CI containers. It is opt-in via
    ``--browser playwright``; Selenium remains the default.
    """

    def __init__(
        self,
        console: "ConsoleLike",
        kind: str = "playwright",
        headless: bool = False,
        page_timeout: float = 25.0,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        binary: Optional[str] = None,
        insecure: bool = False,
        url_allowed: Optional[Callable[[str], bool]] = None,
        auth_state: Optional[str] = None,
    ):
        self.console = console
        self.kind = kind or "playwright"
        self.headless = headless
        self.page_timeout = page_timeout
        self.user_agent = user_agent
        self.proxy = proxy
        self.binary = binary
        self.insecure = insecure
        self.url_allowed = url_allowed
        self.auth_state = auth_state
        self._lock = asyncio.Lock()
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self.page: Any = None
        self.navigation_count = 0
        self._dialogs: List[str] = []
        self._page_handler: Any = None
        self.observed_requests: List[str] = []
        self.observed_request_details: List[Dict[str, str]] = []

    async def _on_dialog(self, dialog: Any) -> None:
        try:
            self._dialogs.append(str(dialog.message))
        except Exception:
            pass
        try:
            await dialog.dismiss()
        except Exception:
            pass

    def _on_request(self, request: Any) -> None:
        """Keep a bounded list of app navigation and API request URLs."""
        try:
            if request.resource_type not in ("document", "xhr", "fetch"):
                return
            url = str(request.url)
            if url.startswith(("http://", "https://")):
                if url not in self.observed_requests and len(self.observed_requests) < 5000:
                    self.observed_requests.append(url)
                method = str(request.method or "GET").upper()
                post_data = str(request.post_data or "")[:16000]
                content_type = str(request.headers.get("content-type", ""))[:200]
                if method not in ("GET", "HEAD") and len(self.observed_request_details) < 3000:
                    detail = {"url": url, "method": method, "content_type": content_type, "post_data": post_data}
                    if detail not in self.observed_request_details:
                        self.observed_request_details.append(detail)
        except Exception:
            pass

    async def start(self) -> bool:
        try:
            from playwright.async_api import async_playwright  # type: ignore[reportMissingImports]
        except Exception:
            self.console.warn(
                "Playwright is not installed - use --browser firefox or install it "
                "(pip install playwright && playwright install chromium)"
            )
            return False

        launch: Dict[str, Any] = {
            "headless": self.headless,
            "args": list(CHROME_ARGS),
        }
        if self.binary:
            launch["executable_path"] = self.binary

        try:
            self._pw = await async_playwright().start()
        except Exception as exc:
            self.console.error(f"Could not start Playwright: {exc}")
            return False

        attempts: List[Dict[str, Any]] = [launch]
        if not self.binary:
            # Branded builds are opportunistic fallbacks; with --binary the
            # operator pinned the executable and channels are irrelevant.
            attempts += [dict(launch, channel="chrome"), dict(launch, channel="msedge")]
            detected = detect_chromium_binary()
            if detected:
                attempts.append(dict(launch, executable_path=detected))
        last_error: Optional[Exception] = None
        first_error: Optional[Exception] = None
        for attempt in attempts:
            try:
                self._browser = await self._pw.chromium.launch(**attempt)
                break
            except Exception as exc:  # try the next channel
                last_error = exc
                if first_error is None:
                    first_error = exc
        if self._browser is None:
            await self.stop()
            self._report_launch_failure(first_error or last_error)
            return False

        context_options: Dict[str, Any] = {
            "ignore_https_errors": self.insecure,
            "viewport": {"width": 1366, "height": 900},
        }
        if self.auth_state:
            state_path = Path(self.auth_state).expanduser()
            if not state_path.is_file():
                self.console.error(f"Browser auth state does not exist: {state_path}")
                await self.stop()
                return False
            context_options["storage_state"] = str(state_path)
        if self.user_agent:
            context_options["user_agent"] = self.user_agent
        if self.proxy:
            context_options["proxy"] = {"server": self.proxy}
        try:
            self._context = await self._browser.new_context(**context_options)
            await self._context.add_init_script("window.__xoxss_pw = true;\n" + HOOK_JS)
            self.page = await self._context.new_page()
            self.page.set_default_timeout(self.page_timeout * 1000)
            self.page.on("dialog", lambda dialog: asyncio.create_task(self._on_dialog(dialog)))
            self.page.on("request", self._on_request)
        except Exception as exc:
            self.console.error(f"Playwright context failed: {exc}")
            await self.stop()
            return False

        self.console.ok(
            f"playwright browser ready ({'headless' if self.headless else 'headed'})",
            important=False,
        )
        return True

    def _report_launch_failure(self, error: Optional[Exception]) -> None:
        """Turn a raw playwright launch stack into an actionable diagnosis.

        The channel-fallback chain means the *last* exception often describes an
        unrelated branded build (chrome/msedge); the primary report therefore
        focuses on why the bundled Chromium failed and keeps stack details in
        the debug channel.
        """
        text = str(error or "").strip()
        lowered = text.lower()
        missing = (
            "executable doesn't exist" in lowered
            or "not found at" in lowered
            or "no such file" in lowered
        )
        if missing:
            channel: Optional[str] = None
            match = re.search(r"distribution '([^']+)'", text)
            if match:
                channel = match.group(1)
            if channel:
                hint = (
                    f"the '{channel}' Chromium build is not installed on this machine - "
                    "run `playwright install chromium` for the bundled build, "
                    f"or install {channel} system-wide"
                )
            elif "ms-playwright" in text or "chromium" in lowered:
                # The bundled download lives under ~/.cache/ms-playwright/.
                hint = (
                    "the bundled Chromium build is not downloaded - "
                    "run `playwright install chromium`"
                )
            else:
                hint = "no usable Chromium was found - run `playwright install chromium`"
            self.console.error(f"Could not start Playwright Chromium: {hint}")
            self.console.debug(f"playwright launch error: {text}")
        else:
            base = text.splitlines()[0] if text else "unknown error"
            self.console.error(f"Could not start Playwright Chromium: {base}")
            self.console.debug(f"playwright launch error: {text}")
        hint = headed_diagnostic() if not self.headless else ""
        if hint:
            self.console.warn(hint)

    async def stop(self) -> None:
        for resource in (self._context, self._browser):
            try:
                if resource is not None:
                    await resource.close()
            except Exception:
                pass
        self._context = None
        self._browser = None
        self.page = None
        if self._pw is not None:
            try:
                await self._pw.stop()
            except Exception:
                pass
            self._pw = None

    def is_alive(self) -> bool:
        """Return True only if Playwright context and page are active."""
        if self._browser is None or self.page is None:
            return False
        try:
            return bool(self._browser.is_connected() and not self.page.is_closed())
        except Exception:
            return False

    async def navigate(self, url: str) -> str:
        if self.url_allowed is not None and not self.url_allowed(url):
            return "URL is outside the configured scan scope"
        async with self._lock:
            if self.page is None:
                return "no page"
            self.navigation_count += 1
            self._dialogs.clear()
            error = ""
            try:
                try:
                    await self.page.goto(url, wait_until="load", timeout=min(15000, self.page_timeout * 1000))
                except Exception:
                    await self.page.goto(url, wait_until="domcontentloaded", timeout=self.page_timeout * 1000)
                await self.page.wait_for_timeout(200)
            except Exception as exc:
                error = str(exc)
            try:
                await self.page.evaluate(HOOK_JS)
            except Exception:
                pass
            return error

    async def collect(self) -> Dict[str, Any]:
        async with self._lock:
            if self.page is None:
                return {"hits": [], "alerts": [], "sinks": [], "errors": [], "dialogs": [], "html": ""}
            data: Any = {}
            try:
                data = await self.page.evaluate("() => {" + COLLECT_JS + "}")
            except Exception:
                data = {}
            if not isinstance(data, dict):
                data = {}
            for key in ("hits", "alerts", "sinks", "errors"):
                if not isinstance(data.get(key), list):
                    data[key] = []
            if not isinstance(data.get("requests"), list):
                data["requests"] = []
            # Playwright's evaluate() routes through window.eval in the page,
            # so our own instrumentation/collection scripts show up as sinks.
            data["sinks"] = [
                item
                for item in data.get("sinks", [])
                if not any(
                    marker in str(item)
                    for marker in ("window.__xoxss_init", "window.__xoxss_hits || []")
                )
            ]
            data["dialogs"] = list(self._dialogs)
            data["requests"] = list(dict.fromkeys([
                *data.get("requests", []), *self.observed_requests
            ]))[:5000]
            data["request_details"] = list(self.observed_request_details)
            try:
                data["html"] = (await self.page.content())[:200000]
            except Exception:
                data["html"] = ""
            return data

    async def evaluate(self, script: str, arg: Any = None) -> Any:
        """Evaluate a function expression with one JSON-serialisable argument."""
        async with self._lock:
            if self.page is None:
                return None
            try:
                return await self.page.evaluate(script, arg)
            except Exception as exc:
                self.console.debug(f"Browser evaluate failed: {exc}")
                return None

    async def check_token(self, token: str, timeout: float = 2.5) -> Optional[Dict[str, str]]:
        deadline = time.monotonic() + timeout
        while True:
            data = await self.collect()
            hit = BrowserEngine._match(data, token)
            if hit:
                return hit
            if time.monotonic() >= deadline:
                return None
            await asyncio.sleep(0.15)

    async def submit_form(self, form_index: int, field_name: str, value: str) -> Dict[str, str]:
        async with self._lock:
            result = {"fill": "error", "submit": "error"}
            if self.page is None:
                return result
            self.navigation_count += 1
            fill_js = r"""
            ({index, name, value}) => {
              var forms = document.forms, form = forms[index];
              if (!form) {
                for (var i = 0; i < forms.length; i++) {
                  if (forms[i].elements[name]) { form = forms[i]; break; }
                }
              }
              if (!form) { return 'noform'; }
              var found = 0;
              for (var j = 0; j < form.elements.length; j++) {
                var element = form.elements[j];
                if (element.name !== name) { continue; }
                try {
                  element.value = value;
                  element.dispatchEvent(new Event('input', { bubbles: true }));
                  element.dispatchEvent(new Event('change', { bubbles: true }));
                  found++;
                } catch (e) {}
              }
              return found ? 'ok' : 'nofield';
            }
            """
            submit_js = r"""
            (index) => {
              var forms = document.forms, form = forms[index];
              if (!form) { return 'noform'; }
              var button = form.querySelector('button[type=submit],input[type=submit],button:not([type])');
              if (button) {
                try { button.click(); return 'click'; } catch (e) {}
              }
              if (form.requestSubmit) {
                try { form.requestSubmit(); return 'requestSubmit'; } catch (e) {}
              }
              try { form.submit(); return 'submit'; } catch (e) {}
              return 'failed';
            }
            """
            try:
                result["fill"] = str(
                    await self.page.evaluate(fill_js, {"index": form_index, "name": field_name, "value": value})
                )
            except Exception as exc:
                result["fill"] = f"error: {exc}"
            await asyncio.sleep(0.15)
            try:
                result["submit"] = str(await self.page.evaluate(submit_js, form_index))
            except Exception as exc:
                result["submit"] = f"error: {exc}"
            deadline = time.monotonic() + min(10.0, self.page_timeout)
            while time.monotonic() < deadline:
                try:
                    if await self.page.evaluate("document.readyState") == "complete":
                        break
                except Exception:
                    pass
                await asyncio.sleep(0.1)
            try:
                await self.page.evaluate(HOOK_JS)
            except Exception:
                pass
            return result

    async def screenshot(self, path: str) -> str:
        async with self._lock:
            if self.page is None:
                return ""
            try:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                await self.page.screenshot(path=path, full_page=False)
                return path
            except Exception:
                return ""


class BrowserPool:
    """Small pool of drivers; each driver serialises its own work."""

    MAX_CONCURRENT_WORKERS = 8

    def __init__(self, console: ConsoleLike, size: int, factory, recycle_after: int = 90):
        self.console = console
        if size > self.MAX_CONCURRENT_WORKERS:
            self.console.debug(
                f"Capping browser pool size from {size} to {self.MAX_CONCURRENT_WORKERS} "
                "to prevent excessive memory usage"
            )
            size = self.MAX_CONCURRENT_WORKERS
        self.size = max(1, size)
        self.factory = factory
        self.recycle_after = max(1, recycle_after)
        self.engines: List[BrowserEngine] = []
        self._queue: Optional[asyncio.Queue] = None

    async def start(self) -> int:
        self._queue = asyncio.Queue()
        for _ in range(self.size):
            engine = self.factory()
            if await engine.start():
                self.engines.append(engine)
                self._queue.put_nowait(engine)
            else:
                break
        if not self.engines:
            self.console.warn("No browser available - falling back to HTTP-only verification")
        elif len(self.engines) > 1:
            self.console.info(f"Browser pool: {len(self.engines)} workers")
        return len(self.engines)

    @asynccontextmanager
    async def borrow(self):
        if self._queue is None or not self.engines:
            raise RuntimeError("browser pool is not running")
        while True:
            if not self.engines:
                raise RuntimeError("browser pool has no active engines")
            try:
                engine = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                break
            except asyncio.TimeoutError:
                if not self.engines:
                    raise RuntimeError("browser pool has no active engines")
                continue
        crashed = False
        try:
            yield engine
        except Exception:
            crashed = True
            raise
        finally:
            alive = True
            if hasattr(engine, "is_alive"):
                try:
                    alive = bool(
                        await asyncio.to_thread(engine.is_alive)
                        if not inspect.iscoroutinefunction(engine.is_alive)
                        else await engine.is_alive()
                    )
                except Exception:
                    alive = False
            elif crashed:
                alive = False

            should_recycle = (engine.navigation_count >= self.recycle_after) or not alive

            if should_recycle:
                await engine.stop()
                new_engine = self.factory()
                if await new_engine.start():
                    new_engine.navigation_count = 0
                    if engine in self.engines:
                        idx = self.engines.index(engine)
                        self.engines[idx] = new_engine
                    else:
                        self.engines.append(new_engine)
                    engine = new_engine
                    if not alive:
                        self.console.debug("Crashed browser worker replaced with fresh instance")
                    else:
                        self.console.debug("Browser worker recycled after its navigation budget")
                else:
                    self.console.warn("Browser worker failed to restart and was retired")
                    if engine in self.engines:
                        self.engines.remove(engine)
                    engine = None

            is_dead_driver = (
                engine is not None and hasattr(engine, "driver") and engine.driver is None
            )
            is_dead_playwright = (
                engine is not None and hasattr(engine, "page") and engine.page is None
            )
            if engine is not None and engine in self.engines and not (is_dead_driver or is_dead_playwright):
                self._queue.put_nowait(engine)

    async def stop(self) -> None:
        for engine in self.engines:
            await engine.stop()
        self.engines = []

