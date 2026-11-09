"""Path-segment injection vectors.

Amplification/rewrite features and many frameworks reflect the request path
into the rendered page (breadcrumbs, canonical links, error pages, 404
handlers).  XSSRush tests three shapes for each path:

* append a marker segment (``/a/b/[MARKER]``)
* replace the last segment (``/a/[MARKER]``)
* replace every earlier segment in turn (``/[MARKER]/b``)

The marker is kept as a literal sentinel so a single :class:`InjectionPoint`
can be rendered with different payloads, and so the final PoC URL is still a
normal, copy-pasteable request.
"""

from __future__ import annotations

from typing import List, Tuple
from urllib.parse import quote, urlsplit

PATH_MARKER = "[PATH_BASED_TESTING]"


def _origin(url: str) -> str:
    parts = urlsplit(url)
    scheme = parts.scheme or "http"
    netloc = parts.netloc
    return f"{scheme}://{netloc}" if netloc else ""


def build_path_vectors(url: str) -> List[Tuple[str, int]]:
    """Return ``(templated_url, path_index)`` pairs for one target URL.

    ``path_index`` identifies which segment carries the marker (-1 means the
    marker was appended as a new trailing segment).  Duplicate vectors are
    collapsed while keeping their first index.
    """
    origin = _origin(url)
    if not origin:
        return []
    parts = urlsplit(url)
    raw_path = parts.path.strip("/")
    segments = [segment for segment in raw_path.split("/") if segment]

    candidates: List[Tuple[str, int]] = []
    if not segments:
        candidates.append((f"{origin}/{PATH_MARKER}", 0))
    else:
        candidates.append((f"{origin}/{'/'.join(segments)}/{PATH_MARKER}", -1))
        for index in range(len(segments) - 1, -1, -1):
            mutated = list(segments)
            mutated[index] = PATH_MARKER
            candidates.append((f"{origin}/{'/'.join(mutated)}", index))

    seen = set()
    vectors: List[Tuple[str, int]] = []
    for templated, index in candidates:
        key = templated.lower()
        if key in seen:
            continue
        seen.add(key)
        vectors.append((templated, index))
    return vectors


def render_path_payload(templated_url: str, payload: str) -> str:
    """Substitute an encoded payload into a templated path vector."""
    return str(templated_url).replace(PATH_MARKER, quote(str(payload), safe=""))


def path_vector_label(index: int) -> str:
    if index < 0:
        return "PATH(appended)"
    return f"PATH[{index}]"


__all__ = [
    "PATH_MARKER",
    "build_path_vectors",
    "path_vector_label",
    "render_path_payload",
]
