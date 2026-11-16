"""Report escaping: attacker-controlled data must never become markup."""

from __future__ import annotations

import json

from xoxss.reports.common import APP_NAME, VERSION
from xoxss.reports.html import _card


def test_card_escapes_labels_and_values() -> None:
    card = _card("<script>alert(1)</script>", "<img src=x onerror=alert(1)>")
    assert "<script>" not in card
    assert "<img" not in card
    assert "&lt;script&gt;" in card
    assert "&lt;img" in card


def test_card_coerces_non_string_values() -> None:
    assert ">7<" in _card("count", 7)


def test_report_header_constants_are_serialisable() -> None:
    # The HTML/JSON/SARIF writers interpolate these into every report.
    payload = json.dumps({"app": APP_NAME, "version": VERSION})
    assert "XOX$$" in payload
    assert VERSION in payload
