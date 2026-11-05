"""Small constraint-driven mutations for context payload templates."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Set


def assemble_variants(
    templates: Sequence[str],
    surviving: Iterable[str],
    *,
    learned_unicode: Optional[Dict[str, str]] = None,
    limit: int = 24,
) -> List[str]:
    """Generate bounded syntax-preserving variants from observed constraints.

    The original templates remain the primary corpus. These variants are added
    only when the low-risk delimiter probe showed a character was transformed.
    """
    allowed: Set[str] = set(surviving)
    out: List[str] = []
    seen: Set[str] = set(templates)

    def add(value: str) -> None:
        if value and value not in seen and len(out) < max(0, limit):
            seen.add(value)
            out.append(value)

    for template in templates:
        if " " not in allowed and " " in template:
            for separator in ("\t", "\n", "/"):
                add(template.replace(" ", separator))
        if '"' not in allowed and '"' in template:
            add(template.replace('"', ""))
        if "'" not in allowed and "'" in template:
            add(template.replace("'", ""))
        if learned_unicode:
            # Mapping direction is ASCII delimiter -> observed input spelling.
            add(template.translate(str.maketrans(learned_unicode)))
        if len(out) >= limit:
            break
    return out
