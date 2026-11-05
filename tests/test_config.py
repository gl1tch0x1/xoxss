import pytest

from xoxss.core.config import ScanConfig


def test_scan_config_exposes_mutation_options():
    defaults = ScanConfig(target="https://example.test")
    assert defaults.mutation_probes is False
    assert defaults.mutation_probe_limit == 12
    assert defaults.adaptive_payloads is False
    assert defaults.param_batch_size == 100

    configured = ScanConfig(
        target="https://example.test",
        mutation_probes=True,
        mutation_probe_limit=7,
        adaptive_payloads=True,
        param_batch_size=8,
    )
    assert configured.mutation_probes is True
    assert configured.mutation_probe_limit == 7
    assert configured.adaptive_payloads is True
    assert configured.param_batch_size == 8


@pytest.mark.parametrize("limit", [-1, 15])
def test_scan_config_rejects_invalid_mutation_probe_limits(limit):
    with pytest.raises(ValueError, match="mutation_probe_limit"):
        ScanConfig(target="https://example.test", mutation_probe_limit=limit)


@pytest.mark.parametrize("limit", [0, 101])
def test_scan_config_rejects_invalid_parameter_batch_sizes(limit):
    with pytest.raises(ValueError, match="param_batch_size"):
        ScanConfig(target="https://example.test", param_batch_size=limit)
