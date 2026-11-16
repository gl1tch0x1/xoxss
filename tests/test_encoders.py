"""Encoder registry: purity, ordering, chaining and lookup contracts."""

from __future__ import annotations

import html

import pytest

from xoxss.detection.encoders import (
    Encoder,
    apply_chain,
    apply_encoder,
    describe_encoders,
    encoder_names,
    get_encoder,
    list_encoders,
    register_encoder,
)

SAMPLE = "<script>alert('x')</script>"


def test_registry_is_non_empty_and_names_are_canonical() -> None:
    names = encoder_names()
    assert len(names) >= 15
    assert names == sorted(names)
    assert all(name == name.lower().strip() for name in names)


def test_every_encoder_returns_text() -> None:
    for name in encoder_names():
        output = apply_encoder(SAMPLE, name)
        assert isinstance(output, str)
        assert output, f"{name} produced an empty string"


def test_every_encoder_handles_empty_input() -> None:
    for name in encoder_names():
        assert apply_encoder("", name) == ""


def test_encoders_are_pure() -> None:
    for name in encoder_names():
        first = apply_encoder(SAMPLE, name)
        second = apply_encoder(SAMPLE, name)
        # ``mixed_case`` is intentionally random, so only compare deterministic
        # encoders.
        if name != "mixed_case":
            assert first == second


def test_urlencode_percent_encodes_specials() -> None:
    assert apply_encoder("<", "urlencode") == "%3C"
    assert apply_encoder("a b", "urlencode") == "a%20b"


def test_chain_applies_left_to_right() -> None:
    assert apply_chain("<", ["urlencode", "double_urlencode"]) == "%25253C"
    assert apply_chain("abc", []) == "abc"
    assert apply_chain("", ["urlencode"]) == ""


def test_entity_encoders_round_trip_through_html_unescape() -> None:
    for name in ("hex_entities", "dec_entities"):
        assert html.unescape(apply_encoder("<>'\"&", name)) == "<>'\"&"


def test_get_encoder_is_case_insensitive() -> None:
    assert get_encoder("URLENCODE").name == "urlencode"
    assert get_encoder("  Urlencode  ").name == "urlencode"


def test_unknown_encoder_raises_key_error() -> None:
    with pytest.raises(KeyError):
        get_encoder("does-not-exist")


def test_duplicate_registration_is_rejected() -> None:
    with pytest.raises(ValueError):
        register_encoder(Encoder(name="urlencode", func=str, description="duplicate"))


def test_empty_encoder_name_is_rejected() -> None:
    with pytest.raises(ValueError):
        register_encoder(Encoder(name="  ", func=str, description="blank"))


def test_list_encoders_filters_by_context() -> None:
    script_names = {encoder.name for encoder in list_encoders("script")}
    assert "js_unicode" in script_names
    # ``any`` encoders stay available in every context.
    assert "lowercase" in script_names
    assert "mixed_case" not in script_names


def test_describe_encoders_lists_every_name() -> None:
    described = describe_encoders()
    for name in encoder_names():
        assert name in described
