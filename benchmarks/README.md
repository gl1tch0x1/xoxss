# XSS coverage benchmark corpus

This directory defines a small, stable, local-only corpus for measuring detection
coverage and false positives. It is a benchmark specification, not a claim that a
scanner finds every XSS variant. Run it only against the supplied loopback fixture
or an application you are authorized to test.

## Layout

| File | Purpose |
|---|---|
| `fixture_server.py` | Self-contained vulnerable/benign HTTP fixture bound to `127.0.0.1` (port `8765`, or `XOXSS_BENCH_PORT`). |
| `cases.json` | Schema 2 corpus: one object per case with the URL, expected evidence grade and browser requirements. |
| `run_benchmark.py` | Runs the real CLI per case and reports evidence outcomes, confusion-matrix metrics, request/payload counts, errors, browser checks, elapsed time, and coverage notes. |

## Running

```bash
python benchmarks/run_benchmark.py                         # all cases (Playwright)
python benchmarks/run_benchmark.py --quick                 # HTTP-only cases
python benchmarks/run_benchmark.py --browser none          # force HTTP-only
python benchmarks/run_benchmark.py --only dom-location-hash
python benchmarks/run_benchmark.py --json-out results.json
```

The runner starts its own fixture on a free port by default and terminates it
afterwards. Use `--base-url http://127.0.0.1:8765` to target an instance you
started manually:

```bash
python benchmarks/fixture_server.py
```

Each case runs with a fresh temporary report directory and `--no-state`. A case
passes when the strongest confidence in `findings` matches `expect`:

* `finding` requires `medium`, `high` or `confirmed` evidence.
* `none` requires no finding at or above `medium`; low informational leads are
  allowed for candidates such as a JSON echo.

The console summary and each `--json-out` case record include measured scanner
work (HTTP requests, payloads, errors, browser checks, and elapsed time). The
summary also reports TP/FP/FN/TN, precision, recall, specificity, false-positive
rate, and inconclusive cases. Timeouts and missing or unreadable reports are
inconclusive rather than being counted as false negatives. The JSON output
remains an array of per-case records.

The runner exits `1` when any case fails and `2` when no case is selected. CI runs
`--quick` on every supported Python version.

## Corpus coverage

`cases.json` covers:

* reflected HTML text, quoted attributes and JavaScript string context;
* a JSON API echo that must not be reported as executable XSS;
* DOM sources from query, hash, `localStorage`, `sessionStorage`, `window.name`
  and `postMessage` into instrumented sinks;
* stored content confirmed on a second request;
* authenticated routes reached with `--cookies`;
* negative controls: HTML-escaped reflection, a `textContent`-only DOM flow, a
  static non-reflecting page, and the JSON echo.

`authenticated-route` uses the fixture cookie `benchmark_session=authorized`.
For Playwright `storage_state` coverage, create a state file for the loopback origin
containing the same cookie and pass it with `--auth-state` to a manual scan.

## Interpreting results

The benchmark currently measures XOXSS against its bundled fixture; it is not a
cross-tool bake-off and does not establish superiority over Dalfox, XSStrike,
Burp DOM Invader, or ZAP. A fair comparison must pin tool versions and fixture
revision, align browser/authentication modes and scan budgets, report incomplete
cases, and compare false positives separately from detection. A tool that sends
more payloads or reports more candidates has not necessarily improved detection.

`--param-audit --param-batch-size 100` exercises batch-first hidden-parameter
reflection checks. `--mutation-probes` adds bounded per-endpoint encoding and
normalization observations; `--adaptive-payloads` uses those observations to pick
variants. Transform observations are reported separately and are not labeled as
vulnerabilities without reflection evidence.
