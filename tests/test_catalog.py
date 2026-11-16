"""Bundled payload catalog and generator invariants."""

from __future__ import annotations

from xoxss.detection.payload import (
    CATALOG_SOURCE,
    PAYLOAD_CATALOG,
    PayloadContext,
    PayloadGenerator,
    build_blind_payloads,
    catalog_by_context,
    catalog_counts,
    catalog_total,
)


def test_catalog_total_matches_bundled_vectors() -> None:
    assert catalog_total() == len(PAYLOAD_CATALOG)
    assert catalog_total() == 440


def test_catalog_counts_sum_to_total() -> None:
    counts = catalog_counts()
    assert counts
    assert sum(counts.values()) == catalog_total()
    assert all(value >= 0 for value in counts.values())


def test_catalog_entries_are_well_formed() -> None:
    assert CATALOG_SOURCE
    for entry in PAYLOAD_CATALOG:
        assert entry.payload.strip()
        assert entry.contexts
        assert entry.category is not None
        assert isinstance(entry.auto, bool)
        assert isinstance(entry.reference, bool)


def test_catalog_index_returns_context_vectors() -> None:
    for context in ("html", "attr_double", "script", "json"):
        templates = catalog_by_context(context)
        assert templates, f"no catalog vectors for {context}"
        assert all(isinstance(template, str) and template for template in templates)


def test_generator_returns_requested_count() -> None:
    generated = PayloadGenerator().generate_payloads(PayloadContext.HTML, "MARK", count=3)
    assert len(generated) == 3
    assert all(item.marker == "MARK" for item in generated)
    assert all(item.template for item in generated)


def test_generator_includes_optional_polyglots() -> None:
    plain = PayloadGenerator().generate_payloads(PayloadContext.HTML, "MARK", count=1)
    rich = PayloadGenerator().generate_payloads(
        PayloadContext.HTML, "MARK", count=1, include_polyglots=True
    )
    assert len(rich) > len(plain)


def test_blind_payloads_embed_callback_and_marker() -> None:
    payloads = build_blind_payloads("https://oob.example.com/hit", "MARK")
    assert payloads
    assert any("oob.example.com/hit" in item.template for item in payloads)
    assert all(item.marker == "MARK" for item in payloads)


def test_blind_payloads_require_a_callback() -> None:
    assert build_blind_payloads("", "MARK") == []
