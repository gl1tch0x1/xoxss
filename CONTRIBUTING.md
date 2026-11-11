# Contributing to XOXSS

Thank you for your interest in contributing to **XOXSS**!

XOXSS is an advanced, context-aware, persistent cross-site scripting (XSS) scanner designed for authorized penetration testing, bug bounty assessments, and security auditing. Our primary design principles are **high detection fidelity**, **contextual awareness**, and **minimizing false positives**.

---

## Code of Conduct & Responsible Use

* **Authorized Testing Only:** XOXSS is built exclusively for authorized security assessments with explicit permission. Never use this tool against targets you do not own or lack written authorization to test.
* **Security in XOXSS:** If you identify a security flaw in the scanner itself (e.g., command injection, arbitrary file writes, SSRF), please follow our [Security Policy (SECURITY.md)](SECURITY.md) and disclose it privately via [GitHub Security Advisories](https://github.com/gl1tch0x1/xoxss/security/advisories). Do **not** open public issues for security vulnerabilities in XOXSS.

---

## Getting Started

### Prerequisites

- **Python:** 3.9 or newer (Python 3.9 through 3.14 are supported).
- **Git**
- Optional (for DOM and headless browser verification):
  - **Node.js** / **Playwright** (`pip install playwright && playwright install chromium`)
  - **Google Chrome** / **Chromium** / **Geckodriver** (for Selenium)

### Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/gl1tch0x1/xoxss.git
   cd xoxss
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv

   # On Linux/macOS:
   source .venv/bin/activate

   # On Windows (PowerShell):
   .venv\Scripts\Activate.ps1
   # On Windows (cmd.exe):
   .venv\Scripts\activate.bat
   ```

3. **Install the package in editable mode with development tools:**
   ```bash
   pip install -e ".[dev,playwright,ast,http2]"
   ```

4. **Install browser engines (optional but recommended for DOM tests):**
   ```bash
   playwright install chromium
   ```

---

## Project Structure

```text
xoxss/
├── __init__.py
├── __main__.py
├── scanner.py             # Core orchestrator, payload injection, pipeline & CLI
├── cli.py                 # Argument parsing, option validation, doctor utility
├── core/
│   ├── browser.py         # Headless browser controller (Playwright & Selenium)
│   ├── crawler.py         # Fast asynchronous web crawler & form discovery
│   ├── http.py            # HTTP transport, session pooling, HTTP/2
│   ├── payloads.py        # Context-aware payload catalog & generator
│   ├── reporter.py        # Report generators (HTML, JSON, Markdown, SARIF)
│   ├── tampers.py         # WAF evasion & character encoder filters
│   └── ...
├── analyzers/
│   ├── context.py         # Response reflection context parser (HTML, attr, script)
│   ├── dom.py             # DOM AST taint tracer and sink analyzer
│   └── ssti.py            # Polyglot template injection detector
├── benchmarks/            # Ground-truth local benchmark suite
│   ├── cases.json         # Benchmark cases & expected confidence grades
│   ├── fixture_server.py  # Self-contained local vulnerable & benign test server
│   └── run_benchmark.py   # Benchmark execution and evaluation engine
└── pyrightconfig.json     # Pyright static type checker configuration
```

---

## Code Quality Standards

We enforce strict linting, type safety, and benchmark checks on every commit.

### 1. Syntax & Compilation Check

Ensure all files compile without syntax errors:
```bash
python -m compileall xoxss xoxss.py
```

### 2. Linting & Formatting (Ruff)

We use [Ruff](https://docs.astral.sh/ruff/) for fast, modern Python linting. Configuration is maintained in `pyproject.toml` (target Python 3.9, line length 100):
```bash
ruff check xoxss benchmarks
```

To automatically fix safe lint issues:
```bash
ruff check --fix xoxss benchmarks
```

### 3. Static Type Checking (Pyright)

We use [Pyright](https://github.com/microsoft/pyright) configured via `pyrightconfig.json` in basic type checking mode targeting Python 3.9:
```bash
pyright
```

Please ensure type annotations are kept up-to-date and type check errors are resolved before submitting a PR.

---

## False Positive Prevention Principles

XOXSS is designed to avoid drowning operators in false alarms. When adding or updating detection logic, please follow these guidelines:

1. **Verify HTTP Status & Content-Type:**
   - Do not report reflections inside `4xx` or `5xx` error pages as high confidence unless they demonstrably execute HTML.
   - Non-HTML MIME types (`application/json`, `text/plain`, `application/octet-stream`) must never be marked as executable XSS.
2. **Context & Sanitization Awareness:**
   - Ensure characters are unescaped in the relevant context. For example, if `<` and `>` are entity-encoded (`&lt;` and `&gt;`), it is not an executable HTML injection.
3. **DOM Sink Verification:**
   - Static AST taint flows without browser DOM execution confirmation should be graded as `low` confidence leads or gated behind `--report-reflections`.
   - Use browser DOM token execution validation (`xoxss_canary` / alert triggers) to promote findings to `confirmed` or `high`.
4. **Stored XSS Candidates:**
   - Only flag stored XSS after verifying that the injected token actually appears in second-order view/read responses and is not neutralized.

---

## Running Benchmarks

Before opening a pull request, run the benchmark suite to verify that your changes do not introduce regressions or false positives.

### Quick Benchmark (HTTP-only)
Runs in seconds against local loopback fixtures without launching a browser:
```bash
python benchmarks/run_benchmark.py --quick
```

### Full Benchmark (includes DOM & Playwright)
Requires Playwright Chromium:
```bash
python benchmarks/run_benchmark.py
```

### Targeted Case Execution
To test a single specific case from `benchmarks/cases.json`:
```bash
python benchmarks/run_benchmark.py --only dom-location-hash
```

---

## Submitting a Pull Request

1. **Create a topic branch:**
   ```bash
   git checkout -b feat/my-new-tamper
   # or
   git checkout -b fix/reflected-attribute-fp
   ```

2. **Commit your changes:**
   Use clear, descriptive commit messages adhering to [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: add unicode escape tamper module`
   - `fix: resolve false positive in json-in-script reflections`
   - `perf: optimize aiohttp session connection reuse`
   - `docs: update troubleshooting guide for playwright on linux`

3. **Verify all checks locally:**
   ```bash
   python -m compileall xoxss xoxss.py
   ruff check xoxss benchmarks
   pyright
   python benchmarks/run_benchmark.py --quick
   ```

4. **Open a Pull Request:**
   - Push your branch to GitHub.
   - Open a PR against the `main` branch.
   - Complete the checklist provided in the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).

Thank you for helping make XOXSS faster, more accurate, and more reliable!
