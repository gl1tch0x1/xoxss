# LazyXss payload corpus — provenance

`lazyxss.txt` in this directory is derived from the payload list published by the
LazyXss project:

- Source: https://github.com/iamunixtz/LazyXss/blob/main/payloads.txt
- Commit: `98bc213139d8ffdbca1678a38cd79ef6f450cc03`
- Retrieved: 2026-11-03
- Processing: CRLF normalised to LF, blank lines removed, duplicate entries
  collapsed, and a single 3,065-character entry was dropped by the scanner's
  2,048-character per-payload safety limit. The remaining 6,987 entries are
  otherwise preserved verbatim.

The upstream repository does **not** currently contain a `LICENSE` file even
though its README displays an MIT badge. The corpus is retained here with
attribution because it was explicitly requested for this project. If you
redistribute XOXSS, verify the upstream licensing terms first or remove this
file and use `--payload-file` / the remote SecLists corpora instead.

The file is loaded only when the bundled payload pack is enabled
(`--lazy-payloads`, the default). Disable it with `--no-lazy-payloads`.
