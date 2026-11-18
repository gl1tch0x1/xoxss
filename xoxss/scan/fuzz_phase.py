"""Post-crawl active fuzzing phase.

The crawler maps links, forms, JavaScript routes and sitemaps; it does not
enumerate paths that nothing links to, and it cannot see parameters the server
accepts but the page never renders.  This phase closes both gaps *after* the
crawl, using the crawl's own results as seeds:

1. directory/path fuzzing under crawl-discovered directories (soft-404 aware)
2. hidden-parameter mining on crawled URLs (reflection + response delta)
3. parameter-name fuzzing on endpoints that had no query string

The result is a single, bounded set of URLs that is appended to the scan queue
so the normal injection pipeline (DOM analysis + browser verification) runs
against the expanded surface.
"""

from __future__ import annotations

import asyncio
from typing import Any, List, Sequence, Set, Tuple
from urllib.parse import urlsplit, urlunsplit

from xoxss.scan.fuzzer import (
    PARAM_WORDS,
    DirFuzzer,
    ParameterMiner,
)
from xoxss.utils.urlpolicy import looks_like_dangerous, looks_like_scan_target

# Default extension set for the post-crawl phase.  The full ``FUZZ_EXTENSIONS``
# list is available through ``--fuzz-extensions`` but multiplying every word by
# 20 extensions turns a crawl into a brute-force campaign.
DEFAULT_PHASE_EXTENSIONS: Tuple[str, ...] = ("", ".html", ".php", ".json")


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _directory_root(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _directory_roots(urls: Sequence[str], limit: int) -> List[str]:
    roots: List[str] = []
    seen: Set[str] = set()
    for url in urls:
        root = _directory_root(url)
        if root in seen:
            continue
        seen.add(root)
        roots.append(root)
    # Shallow directories first: they tend to expose the application shell.
    roots.sort(key=lambda value: (value.count("/"), len(value)))
    origin = _origin(urls[0]) if urls else ""
    if origin and limit > 1:
        origin_root = origin + "/"
        if origin_root not in seen:
            roots.insert(0, origin_root)
            roots = roots[:limit]
    return roots[: max(1, limit)]


def _eligible(url: str, scope: Any) -> bool:
    if not url or not scope.in_scope(url):
        return False
    if looks_like_dangerous(url):
        return False
    return looks_like_scan_target(url, fuzz_params=True)


async def run_fuzz_phase(scanner: Any, urls: Sequence[str]) -> List[str]:
    """Fuzz the crawl-discovered surface and return new scan candidates."""
    args = scanner.args
    budget = max(1, int(getattr(args, "fuzz_budget", 400) or 400))
    directory_limit = max(1, int(getattr(args, "fuzz_targets", 8) or 8))
    word_limit = max(1, int(getattr(args, "fuzz_words", 100) or 100))
    param_targets = max(1, int(getattr(args, "fuzz_param_targets", 25) or 25))
    param_limit = max(1, int(getattr(args, "fuzz_param_limit", 10) or 10))
    timeout = max(5.0, float(getattr(args, "timeout", 15.0) or 15.0))
    concurrency = max(1, int(getattr(args, "concurrency", 16) or 16))

    candidates: List[str] = []
    seen_candidates: Set[str] = set()
    for value in [*urls, *sorted(getattr(scanner, "endpoints", set()))]:
        if value in seen_candidates or not _eligible(value, scanner.scope):
            continue
        seen_candidates.add(value)
        candidates.append(value)
    if not candidates:
        return []

    new_urls: List[str] = []
    added: Set[str] = set()

    def remember(url: str) -> None:
        if url in added or not _eligible(url, scanner.scope):
            return
        added.add(url)
        new_urls.append(url)
        scanner._record_endpoint(url, "fuzz")

    scanner.console.rule("fuzz")
    scanner.console.info(
        f"Post-crawl fuzzing: {min(len(candidates), param_targets)} parameter target(s), "
        f"{min(len(_directory_roots(candidates, directory_limit)), directory_limit)} director(ies)",
        important=False,
    )

    # -- 1. path discovery under crawl-discovered directories -----------------
    extensions = tuple(
        getattr(args, "fuzz_extensions", None) or DEFAULT_PHASE_EXTENSIONS
    )
    fuzzer = DirFuzzer(
        scanner.http,
        scanner.console,
        wordlist=getattr(args, "endpoint_wordlist", None),
        extensions=extensions,
        concurrency=min(10, concurrency),
        limit=word_limit,
        timeout=timeout,
    )
    path_hits = 0
    fuzz_results: List[Any] = []
    try:
        for root in _directory_roots(candidates, directory_limit):
            if path_hits >= budget:
                break
            hits = await fuzzer.discover(
                root,
                recursive=bool(getattr(args, "fuzz_recursive", False)),
                max_depth=max(1, int(getattr(args, "crawl_depth", 3) or 3)),
                base_path=urlsplit(root).path,
            )
            for hit in hits:
                if path_hits >= budget:
                    break
                path_hits += 1
                fuzz_results.append(hit)
                remember(hit.url)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pragma: no cover - network dependent
        scanner._record_recon_error("post-crawl path fuzzing", exc)
    if fuzz_results:
        scanner.stats.fuzzed_paths += len(fuzz_results)
        scanner.state.extra["fuzz_results"] = [
            item.to_dict() for item in fuzz_results[:2000]
        ]
        scanner.console.ok(
            f"Path fuzzing: {len(fuzz_results)} hit(s)", important=False
        )

    # -- 2. hidden-parameter mining -------------------------------------------
    names = list(dict.fromkeys([*getattr(scanner, "discovered_param_names", []), *PARAM_WORDS]))
    names = names[: max(param_limit, 1)]
    mine_targets = candidates[:param_targets]
    miner = ParameterMiner(
        scanner.http,
        scanner.console,
        marker="xoxss",
        concurrency=min(8, concurrency),
        timeout=timeout,
    )
    mined: List[Any] = []
    try:
        mined = await miner.mine(mine_targets, names, limit_per_url=len(names))
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pragma: no cover - network dependent
        scanner._record_recon_error("post-crawl parameter mining", exc)
        mined = []
    if mined:
        scanner.stats.discovered_params = max(scanner.stats.discovered_params, len(mined))
        scanner.state.extra["mined_parameters"] = [
            item.to_dict() for item in mined[:2000]
        ]
        for item in mined:
            scanner._mined_params.setdefault(item.url, []).append(item.name)
            separator = "&" if "?" in item.url else "?"
            remember(f"{item.url}{separator}{item.name}=1")
        scanner.console.ok(
            f"Parameter mining: {len(mined)} hidden parameter(s)", important=False
        )

    scanner.console.info(
        f"Fuzz phase added {len(new_urls)} candidate URL(s) to the scan queue",
        important=False,
    )
    return new_urls[:budget]


__all__ = ["DEFAULT_PHASE_EXTENSIONS", "run_fuzz_phase"]
