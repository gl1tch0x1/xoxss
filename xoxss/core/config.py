"""
Configuration management for XOXSS scanner.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum


class ScanMode(Enum):
    """Scan operation modes."""
    CRAWL = "crawl"
    DEEP = "deep"
    TARGETED = "targeted"
    FUZZ = "fuzz"


class VerificationStrategy(Enum):
    """Browser verification strategies."""
    AUTO = "auto"
    BROWSER = "browser"
    HTTP = "http"


class BrowserType(Enum):
    """Supported browser types."""
    FIREFOX = "firefox"
    CHROME = "chrome"
    CHROMIUM = "chromium"
    EDGE = "edge"


@dataclass
class ScanConfig:
    """Comprehensive scan configuration."""
    # Target
    target: str
    target_list: Optional[str] = None

    # Discovery
    crawl: bool = False
    deep: bool = False
    crawl_depth: int = 3
    max_urls: int = 500
    allow_subdomains: bool = False
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    discover: bool = True
    discover_paths: bool = False
    endpoint_wordlist: Optional[str] = None
    js_files: int = 25
    fuzz_params: bool = False
    fuzz_param_limit: int = 10
    fuzz_paths: bool = False
    mine_params: bool = False
    subdomains: bool = False
    subdomain_brute: int = 0
    passive_urls: bool = False
    openapi: bool = False
    external_tools: bool = False

    # Injection
    payload_file: Optional[str] = None
    remote_payloads: bool = True
    payload_sources: List[str] = field(default_factory=list)
    payload_limit: int = 600
    payload_tmp_dir: Optional[str] = None
    keep_payloads: bool = False
    tamper: List[str] = field(default_factory=list)
    encoder: List[str] = field(default_factory=list)
    max_payloads: int = 6
    scan_headers: bool = False
    header_list: List[str] = field(default_factory=list)
    dom: bool = True
    stored: bool = False
    stored_pages: int = 10
    report_reflections: bool = False
    check_libs: bool = True

    # Advanced Detection
    polyglot: bool = False
    per_char_probe: bool = False
    jsonp: bool = False
    csp_analyze: bool = False
    mxss: bool = False
    proto_pollution: bool = False
    cors_analyze: bool = False
    smart_rate: bool = False
    dom_clobbering: bool = False
    trusted_types: bool = False
    graphql: bool = False
    websocket: bool = False
    file_upload: bool = False
    postmessage: bool = False
    ast_analysis: bool = False

    # Out-of-band verification
    blind: Optional[str] = None
    interactsh: Optional[str] = None
    oob_poll: Optional[str] = None
    oob_file: Optional[str] = None
    oob_interval: float = 5.0
    oob_wait: float = 0.0

    # Browser
    browser: BrowserType = BrowserType.FIREFOX
    headless: bool = False
    no_browser: bool = False
    browser_workers: int = 1
    confirm: VerificationStrategy = VerificationStrategy.AUTO
    screenshot: bool = False
    binary: Optional[str] = None
    user_agent: Optional[str] = None

    # Network
    threads: int = 10
    concurrency: int = 16
    timeout: float = 20.0
    retries: int = 2
    rate_limit: float = 0.0
    proxy: Optional[str] = None
    insecure: bool = False
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)

    # Output
    output: Optional[str] = None
    report: str = "all"
    report_dir: str = ".xoxss/reports"
    verbose: bool = False
    quiet: bool = False
    no_color: bool = False
    fail_on_findings: bool = False

    # Persistence
    state_dir: str = ".xoxss"
    no_state: bool = False
    no_resume: bool = False

    def __post_init__(self):
        """Validate and normalize configuration."""
        # Programmatic users often pass plain strings for the enum fields;
        # coerce instead of failing with a type error in deep comparisons.
        if isinstance(self.browser, str):
            try:
                self.browser = BrowserType(self.browser)
            except ValueError:
                raise ValueError(f"unknown browser type: {self.browser!r}") from None
        if isinstance(self.confirm, str):
            try:
                self.confirm = VerificationStrategy(self.confirm)
            except ValueError:
                raise ValueError(f"unknown verification strategy: {self.confirm!r}") from None
        if self.deep:
            self.crawl_depth = 5
            self.max_urls = 1500
            self.discover = True
            self.discover_paths = True
            self.fuzz_params = True

        if self.no_browser:
            self.dom = False
            self.confirm = VerificationStrategy.HTTP

        bounded_positive = {
            "crawl_depth": self.crawl_depth,
            "max_urls": self.max_urls,
            "threads": self.threads,
            "concurrency": self.concurrency,
            "browser_workers": self.browser_workers,
            "timeout": self.timeout,
        }
        invalid = [name for name, value in bounded_positive.items() if value <= 0]
        if invalid:
            raise ValueError("configuration values must be positive: " + ", ".join(invalid))
        if self.retries < 0 or self.rate_limit < 0 or self.oob_interval <= 0 or self.oob_wait < 0:
            raise ValueError("retries, rate limits, and OOB timing must be non-negative (interval must be positive)")
