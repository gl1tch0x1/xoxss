## Description

<!-- Provide a brief summary of the changes introduced in this pull request and the motivation behind them. -->

## Type of Change

<!-- Mark the appropriate option with an [x]. -->

- [ ] **Bug fix** (non-breaking change fixing an issue or unhandled exception)
- [ ] **False positive reduction** (refining detection logic / context analyzer / confidence scoring)
- [ ] **New feature** (tamper script, encoder, analyzer, reporting format, or CLI flag)
- [ ] **Performance & Refactoring** (scanner speedup, concurrency, memory reduction, code cleanup)
- [ ] **Documentation** (improvements to README, guides, or community files)
- [ ] **CI / Tooling** (GitHub Actions, benchmark fixtures, linting config)

## Related Issue

<!-- Link relevant issue(s) here, e.g. Closes #12, Fixes #34 -->
Closes #

## Changes Made

<!-- Bullet points outlining the specific modifications made in this PR -->
- 

## Verification & Quality Checklist

<!-- Please confirm all applicable checks before submitting your pull request. -->

- [ ] My code compiles cleanly: `python -m compileall xoxss xoxss.py`
- [ ] Linting and code style pass: `ruff check xoxss benchmarks`
- [ ] Static type analysis passes: `pyright`
- [ ] Built-in benchmark suite passes without regression:
  ```bash
  python benchmarks/run_benchmark.py --quick
  ```
- [ ] Detection changes do not introduce new false positives on benign reflections or non-HTML responses.
- [ ] If browser automation was touched, tested with Playwright and/or Selenium.
- [ ] Documentation and inline comments are updated where appropriate.

## Additional Context / Test Output

<!-- Paste relevant benchmark output, CLI terminal logs, or test notes below. -->
```shell

```
