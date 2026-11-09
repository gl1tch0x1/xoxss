"""CLI presentation, briefing, and strict finding-policy contracts."""

import xoxss.utils.ui as ui
from xoxss.cli import build_parser as cli_parser
from xoxss.scanner import (
    Finding,
    briefing_rows,
    enforce_finding_policy,
)


def _parser():
    return cli_parser("XOXSS", "2.0.0", ".xoxss", "test-agent", ["all", "hex"])


def _finding(**overrides):
    values = {
        "kind": "Reflected XSS",
        "url": "https://target.test/?q=x",
        "parameter": "q",
        "method": "GET",
        "payload": "<script>alert(1)</script>",
        "confidence": "confirmed",
    }
    values.update(overrides)
    return Finding(**values)


# --------------------------------------------------------------------------------------
# Help output
# --------------------------------------------------------------------------------------


def test_help_is_grouped_and_documents_the_evidence_policy():
    text = _parser().format_help()
    assert "usage:" in text
    assert "discovery:" in text
    assert "injection:" in text
    assert "out-of-band:" in text
    assert "evidence policy:" in text
    assert "--report-reflections" in text


def test_help_styling_preserves_option_columns(monkeypatch):
    plain = _parser().format_help()
    monkeypatch.setattr(ui, "_ENABLE", True)
    styled = _parser().format_help()

    assert "\x1b[" in styled
    visible = {ui.strip_ansi(line) for line in styled.splitlines()}
    headings = {
        line
        for line in plain.splitlines()
        if line.endswith(":") and not line.startswith(" ")
    }
    missing = [
        line
        for line in plain.splitlines()
        if line not in headings and line not in visible
    ]
    assert missing == []


# --------------------------------------------------------------------------------------
# Operation briefing
# --------------------------------------------------------------------------------------


def test_briefing_reflects_operator_flags():
    args = _parser().parse_args(
        [
            "https://target.test",
            "--scan-headers",
            "--blind",
            "https://oob.test",
            "--report",
            "json",
        ]
    )
    rows = dict(briefing_rows(args, "https://target.test"))

    assert rows["TARGET"] == "https://target.test"
    assert "headers" in rows["VECTORS"]
    assert "blind-xss" in rows["VECTORS"]
    assert rows["EVIDENCE"].startswith("executable")
    assert rows["OOB"] == "https://oob.test"


def test_briefing_marks_reflection_opt_in():
    args = _parser().parse_args(["https://target.test", "--report-reflections"])
    rows = dict(briefing_rows(args, "https://target.test"))
    assert "inert reflections" in rows["EVIDENCE"]


# --------------------------------------------------------------------------------------
# Strict finding policy
# --------------------------------------------------------------------------------------


def test_confirmed_claim_without_evidence_is_downgraded():
    finding = _finding()

    assert enforce_finding_policy(finding) is True
    assert finding.confidence == "high"
    assert "Downgraded from confirmed" in finding.confidence_rationale


def test_confirmed_claim_with_evidence_is_preserved():
    finding = _finding(
        evidence="the marker reached an instrumented sink",
        screenshot="screenshots/hit.png",
    )

    assert enforce_finding_policy(finding) is True
    assert finding.confidence == "confirmed"


def test_high_claim_without_evidence_is_downgraded():
    finding = _finding(confidence="high")

    assert enforce_finding_policy(finding) is True
    assert finding.confidence == "medium"


def test_unknown_confidence_normalises_to_low():
    finding = _finding(confidence="urgent", evidence="something was observed")

    assert enforce_finding_policy(finding) is True
    assert finding.confidence == "low"


def test_finding_without_identity_is_rejected():
    assert enforce_finding_policy(_finding(url="")) is False
    assert enforce_finding_policy(_finding(kind="")) is False
