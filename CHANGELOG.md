# Changelog

All notable changes to XOX$$ are documented here.  The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
