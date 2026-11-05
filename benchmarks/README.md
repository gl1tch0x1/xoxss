# XSS coverage benchmark corpus

This corpus defines a stable set of local-only cases for comparing scanner
coverage changes. It is a benchmark specification rather than a claim that any
single scanner run finds every XSS variant. Run it only against the supplied
loopback fixture or an application you are authorized to test.

`cases.json` covers reflected HTML text and attributes, script-string context,
stored content, DOM flows from query/hash/storage/message sources, encoding and
sanitization controls, authenticated routes, and negative controls. Record for
each run:

* confirmed findings by case and injection context;
* high/medium heuristic findings separately from confirmed execution;
* URLs/points failed or skipped, HTTP errors, and truncations;
* elapsed time, request count, payload count, and browser checks.

Compare confirmed detection and false positives independently. A code change is
not a detection improvement if it only increases candidate counts or payload
volume. Authenticated cases require a Playwright `storage_state` file supplied
with `--auth-state`; dynamic browser source cases require `--browser-discovery`
and `--dom --dom-source-probes`.

Start the isolated vulnerable fixture with:

```powershell
python benchmarks/fixture_server.py
```

It binds only to `127.0.0.1:8765`. Scan `http://127.0.0.1:8765/` with crawl
enabled to explore the routes. Use `--stored` for the stored-content case,
`--browser playwright --browser-discovery --dom-source-probes --headless` for the SPA/runtime cases,
and `--cookies benchmark_session=authorized` to reach the authenticated route.
For storage-state coverage, create a Playwright state file for that loopback
origin containing the same fixture cookie and pass it with `--auth-state`.

Use `--param-audit --param-batch-size 100` for batch-first hidden-parameter
reflection checks. `--mutation-probes` enables bounded per-endpoint encoding
and normalization observations; add `--adaptive-payloads` to try only the
payload variants supported by those observations. Transform observations are
reported separately and are not labeled as vulnerabilities without reflection
evidence.
