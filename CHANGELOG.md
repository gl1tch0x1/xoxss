# Changelog

All notable changes to XOX$$ are documented here.  The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Stats/summary/report rows: "Dangling markup", "Response splitting" and
  "Redirects blocked" counters (also serialized through `stats` in JSON).

## [2.0.1] - 2026-11-16

### Added

- `tests/` unit and integration suite (144 tests): helpers, encoder registry,
  context detection, reflection scoring, WAF fingerprinting, finding identity,
  CLI parsing, report writers, payload catalog, version contract, `HttpEngine`
  transport behaviour (retry, redirect scoping, truncation, cache) and the CLI
  application layer.
- `CHANGELOG.md` and `xoxss/py.typed` (PEP 561 inline types).
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
