"""Deterministic mutation/evasion engine invariants."""

from __future__ import annotations

from xoxss.auto.mutations import MAX_PAYLOAD_BYTES, MutationEngine

PAYLOAD = "<script>alert('xoxss')</script>"


def test_mutations_are_deterministic() -> None:
    first = MutationEngine(seed=7).mutate(PAYLOAD, context="html", limit=30)
    second = MutationEngine(seed=7).mutate(PAYLOAD, context="html", limit=30)
    assert [item.name for item in first] == [item.name for item in second]
    assert [item.payload for item in first] == [item.payload for item in second]


def test_mutations_are_unique_and_bounded() -> None:
    mutations = MutationEngine(seed=1).mutate(PAYLOAD, context="html", limit=25)
    payloads = [item.payload for item in mutations]
    assert len(payloads) == len(set(payloads))
    assert len(mutations) <= 25
    assert all(len(item.payload.encode("utf-8")) <= MAX_PAYLOAD_BYTES for item in mutations)


def test_identity_is_not_emitted_as_a_mutation() -> None:
    mutations = MutationEngine().mutate(PAYLOAD, context="html", limit=80)
    assert PAYLOAD not in {item.payload for item in mutations}
    assert "identity" not in {item.name for item in mutations}


def test_fromcharcode_keeps_the_dialog_name() -> None:
    mutations = MutationEngine().mutate("alert('hi')", context="javascript", limit=80)
    variant = next(item for item in mutations if item.name == "fromcharcode")
    assert variant.payload.startswith("alert(String.fromCharCode(")


def test_atob_keeps_the_dialog_name() -> None:
    mutations = MutationEngine().mutate("confirm('hi')", context="javascript", limit=80)
    variant = next(item for item in mutations if item.name == "atob")
    assert variant.payload.startswith("confirm(atob(")


def test_url_encoding_changes_the_payload() -> None:
    mutations = MutationEngine().mutate(PAYLOAD, context="url", limit=80)
    variant = next(item for item in mutations if item.name == "url_encode")
    assert "%3C" in variant.payload


def test_waf_hint_is_prioritised() -> None:
    mutations = MutationEngine().mutate(
        "<script>alert(1)</script>",
        context="javascript",
        limit=10,
        waf=["cloudflare"],
    )
    assert mutations[0].name == "unicode_escape"


def test_mutate_many_deduplicates_across_seeds() -> None:
    mutations = MutationEngine().mutate_many(
        ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
        context="html",
        limit=40,
    )
    payloads = [item.payload for item in mutations]
    assert len(payloads) == len(set(payloads))


def test_empty_payload_has_no_mutations() -> None:
    assert MutationEngine().mutate("", context="html") == []


def test_names_are_stable_and_unique() -> None:
    names = MutationEngine().names
    assert len(names) == len(set(names))
    assert "tag_swap" in names
    assert "postmessage" in names
