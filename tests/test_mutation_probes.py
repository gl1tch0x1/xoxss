from xoxss.analysis.mutation_probe import (
    apply_observed_normalization,
    build_probes,
    observe,
    reverse_normalization,
)
from xoxss.analysis.payload_grammar import assemble_variants


def test_unicode_normalization_observation_drives_reverse_and_forward_mapping():
    marker = "XOXSSMARKER"
    probes = build_probes(marker, limit=14)
    probe = next(item for item in probes if item.name == "fullwidth-lt")

    observation = observe(f"{marker}<xoxssend", probe)

    assert observation is not None
    assert observation.kind == "unicode-normalization"
    assert reverse_normalization("\uff1csvg", [observation]) == "<svg"
    assert apply_observed_normalization("<svg", [observation]) == "\uff1csvg"


def test_multi_pass_decode_probe_requires_marker_and_expected_delimiter():
    marker = "XOXSSMARKER"
    probe = next(
        item for item in build_probes(marker, limit=14)
        if item.name == "double-url-decode-lt"
    )

    assert observe(f"{marker}<xoxssend", probe) is not None
    assert observe("unrelated <xoxssend", probe) is None
    assert observe(f"{marker}&lt;xoxssend", probe) is None


def test_mutation_probe_count_is_bounded():
    assert len(build_probes("M", limit=3)) == 3
    assert len(build_probes("M", limit=100)) == 22
    assert build_probes("M", limit=0) == []


def test_payload_grammar_creates_bounded_constraint_variants():
    templates = ['<svg onload="TOKEN">', "<img src=x onerror='TOKEN'>"]

    variants = assemble_variants(templates, {"<", ">", "/"}, limit=4)

    assert 1 <= len(variants) <= 4
    assert any('"' not in variant for variant in variants)
    assert any("\t" in variant or "\n" in variant or "/" in variant for variant in variants)
    assert len(set(variants)) == len(variants)
    assert all(template not in variants for template in templates)
