# Changelog

All notable changes to XOX$$ are documented here.  The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2026-11-21

### Added

- **Dangling markup injection detection** (`xoxss/analysis/dangling.py`). A
  browser-shaped tag/attribute tokenizer walks the injected tag the way an
  HTML5 parser does (quoted values swallow `>` and `<`; an unclosed quote runs
  to end of document), then reports how much server-generated markup the
  attribute captured. Probes point at a same-page `#token` fragment, so a scan
  never exfiltrates data to a third party; the finding explains how to swap the
  fragment for an attacker URL. Enabled by default
  (`--no-dangling-markup` disables), reported as `Dangling Markup Injection`
  with `HIGH` confidence and a captured-length/preview evidence line.
- **HTTP response splitting / CRLF header injection probes**
  (`xoxss/detection/header_injection.py`). Redirect-like parameters are probed
  first with `\r\n`, bare `\n` and obsolete-fold variants; a finding requires
  the injected header to be *parsed as a header* by the HTTP client, not merely
  echoed inside an existing value. `--no-header-injection` disables,
  `--header-injection-limit` and `--header-injection-budget` bound the work.
- **CSP3 semantics**: `script-src` falls back to `default-src` correctly,
  `'strict-dynamic'` with a nonce/hash suppresses the `unsafe-inline` false
  positive, short nonces are reported as guessable, `base-uri` absence is a
  `HIGH` issue with a bypass, and `object-src`/`unsafe-eval`/`base-uri` bypass
  gating is directive-aware. Enforcement and `Content-Security-Policy-Report-Only`
  policies are both analyzed.
- **Modern DOM sinks/sources**: `setHTMLUnsafe`, `Element.setHTML`,
  `parseHTMLUnsafe`, `createContextualFragment`, `parseFromString`,
  `execCommand('insertHTML')`, `importScripts`, `Worker`, `window.open`,
  `setAttribute` attribute sinks, plus `URLSearchParams`, `location.ancestorOrigins`,
  `messageEvent.data`, `caches`, `indexedDB` and `dataset` sources.
- `tests/test_dangling.py`, `tests/test_header_injection.py`,
  `tests/test_dom_sinks.py`; CSP tests extended for the new semantics.
- `tests/test_god_mode.py`: supremacy assertions for every capability flag,
  budget ceilings, `--no-*` opt-outs, browser/AI degradation, and a drift test
  that fails when a new capability flag is added without a god-mode decision.
- Stats/summary/report rows: "Dangling markup", "Response splitting" and
  "Redirects blocked" counters (also serialized through `stats` in JSON).
- **Extended surface analyzers wired into the scan pipeline**
  (`--extended-analysis`, on by default; `--no-extended-analysis` disables).
  Template injection, HTTP parameter pollution, cookie-based XSS, WASM,
  web-component and clipboard detectors now run against the already-fetched
  landing page — no extra requests — and emit deduplicated low-confidence
  leads with explicit "not runtime verified" rationales. HPP "injection"
  results are suppressed unless duplicate parameters are actually present
  in the scanned URL.
- **CST taint analysis** alongside the AST pass when tree-sitter is
  installed, sharing the taint-flow dedupe/cap path (`source="cst"`).
- **Stored-XSS hardening**: candidate URLs carrying the token/payload are
  rejected (request reflection is not persistence), and hits are re-fetched
  once to record whether the executable reflection is stable. New
  `--stored-alt-session COOKIE_HEADER` re-checks hits under a second
  identity for cross-session stored XSS evidence.
- **mXSS and prototype-pollution detections now produce findings**
  (low-confidence static leads) instead of console-only lists, and mXSS
  payloads are delivered through HTML-body reflection points on flagged
  pages with per-attempt tokens so browser confirmation still applies.
- **DOM-clobbering payload delivery**: clobberable window properties are
  collected per page and clobbering payloads are injected through
  html-context reflections; clobbering matches emit low-confidence findings.
- **`--min-confidence LEVEL`** filters findings at the report boundary
  (JSON/Markdown/HTML/SARIF/compliance/collaboration) without affecting
  collection, stats or `--fail-on` exit codes.
- **Recon/fuzzing expansion**: ~800 directory words, ~180 fuzz extensions,
  ~850 parameter names; JS intelligence now extracts EventSource,
  sendBeacon, dynamic import, Worker, service-worker and JSONP endpoints
  plus manifest/prefetch/form-action/meta-refresh/base-href resources, and
  ~87 curated credential patterns (values masked in reports by default).
  `expand_paths` ordering fixed so extension coverage is not starved by
  wordlist size.

### Changed

- `--god` / `--yolo` is now the supreme preset.  It enables every capability,
  including CSP-bypass automation, enhanced sinks, storage XSS, service-worker
  analysis, framework bypasses, active WebSocket frames, DOM source probes,
  per-character probes, dangling markup, CRLF probing, HTTP/2 and the hybrid
  CDP + AST/DFG pipeline, and raises budgets to depth 8 / 5000 URLs / 100 JS
  files, 24 payloads per point, 64 bypass shapes, 1000 CRLF probes, a
  1500-request fuzz budget, and 32 workers × 48 concurrent requests.
  Explicit flags and `--no-*` opt-outs still win, and safety switches
  (`--insecure`, `--allow-scheme-downgrade`, `--show-secrets`,
  `--fail-on-findings`) are never flipped.  AI fallback activates only when a
  key is actually configured; browser-only stages only with a usable browser.
- `--service-worker` now gates service-worker analysis instead of being a
  no-op flag: it is on by default (matching the previous unconditional
  behaviour) and `--no-service-worker` turns it off.
- `--ai` accepts `--no-ai` so the LLM fallback can be forced off, including
  under `--god`.
- `--subdomains`, `--passive-urls`, `--openapi`, `--mine-params` and
  `--external-tools` accept `--no-*` opt-outs, so every automatic god-mode
  stage can be pinned off without dropping the preset.
- `ScanConfig` exposes analyser toggles that were CLI-only
  (`csp_bypass`, `enhanced_sinks`, `storage_xss`, `service_worker`,
  `framework_bypass`, `graphql_xss`, `browser_discovery`, `spa_crawl`).

## [2.0.1] - 2026-11-16

### Added

- `tests/` unit and integration suite (144 tests): helpers, encoder registry,
  context detection, reflection scoring, WAF fingerprinting, finding identity,
  CLI parsing, report writers, payload catalog, version contract, `HttpEngine`
  transport behaviour (retry, redirect scoping, truncation, cache) and the CLI
  application layer.
- `docs/CHANGELOG.md` and `xoxss/py.typed` (PEP 561 inline types).
- `.github/workflows/security.yml` (CodeQL + `pip-audit`) and
  `.github/dependabot.yml`.
- `xoxss/app.py`: CLI application layer (argument handling, profiles, mode
  dispatch) split out of `xoxss/scanner.py`.
- README/CONTRIBUTING: unit-test instructions and updated project tree.

### Changed

- `--ast-analysis` is now a real toggle.  AST taint analysis defaults to on and
  `--no-ast-analysis` disables it; the flag previously existed in the CLI but
  was never read by the scanner.
- `tests/` is no longer gitignored, and CI runs pytest with coverage plus the
  DOM-guard and hybrid-pipeline suites on Python 3.9–3.14 (and Windows).
- `requirements.txt` installs the project (`-e .`) instead of duplicating a
  dependency list that could drift.
- Coverage now has a floor (`fail_under = 26`, measured 28%) so it cannot
  silently regress.
- Report writer tests exercise JSON, Markdown, SARIF and HTML escaping.

### Fixed

- `--interactsh` no longer raises `TypeError` (the client was constructed
  without its required console argument).
- Optional payload families (polyglot/obfuscated/evasion) are additive instead
  of being truncated away whenever a context already had the requested count.
- `entity_encoded` no longer reports a false negative when wrapper markup such
  as `<div>` surrounds entity-encoded output.
- Encoders now preserve the empty-string contract instead of emitting
  `eval(atob(''))` scaffolding for empty input.
- Analyzer import fallbacks in `scanner.py` sat in the AI import handler, so a
  failed AI import silently disabled CSP/GraphQL/enhanced-sink/storage/framework
  analyzers.  They now live in the recon/analysis guard.
- SARIF reports use the package version instead of a hardcoded literal.
- Selenium/Playwright cleanup failures are logged at debug level instead of
  being swallowed by bare `pass` blocks.

### Removed

- Unused `xoxss/core/playwright_engine.py` shim.
- Dead `ContextType` members (`URL_PATH`, `URL_QUERY`, `URL_FRAGMENT`,
  `DATA_URI`, `SVG_DATA`, `MATHML`, `TEMPLATE_LITERAL`), the unused
  `CONTEXT_PATTERNS` table, `generate_catalog_payloads()` and
  `_CATALOG_PAYLOAD_CONTEXT`.

## [2.0.0]

Baseline release: evidence-first, context-aware XSS scanner with HTTP probing,
browser confirmation, DOM taint analysis, out-of-band verification and the
bundled 440-vector payload catalog.
