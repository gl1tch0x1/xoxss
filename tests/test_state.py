"""Checkpoint persistence: resume state, schema guards and finding dedupe."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from xoxss.core.state import StateStore


class SilentConsole:
    def __init__(self) -> None:
        self.warnings: list[str] = []

    def warn(self, message: str, *_args: Any, **_kwargs: Any) -> None:
        self.warnings.append(str(message))


def _store(tmp_path: Path, target: str = "https://target.test/app") -> StateStore:
    return StateStore(target, str(tmp_path), console=SilentConsole())


def test_state_roundtrips_scanned_urls_and_findings(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.mark_scanned("https://target.test/app?b=2&a=1")
    store.add_finding(SimpleNamespace(to_dict=lambda: {"finding_id": "abc", "kind": "xss"}))
    store.mark_url_status("https://target.test/fail", "failed", "timeout")
    store.save(force=True)

    restored = _store(tmp_path)
    assert restored.load() is True
    assert restored.is_scanned("https://target.test/app?b=2&a=1")
    assert [item["finding_id"] for item in restored.findings] == ["abc"]
    assert restored.url_status["https://target.test/fail"]["status"] == "failed"
    assert restored.url_status["https://target.test/fail"]["error"] == "timeout"


def test_disabled_store_never_writes(tmp_path: Path) -> None:
    store = StateStore("https://target.test", str(tmp_path), enabled=False)
    store.mark_scanned("https://target.test/")
    store.save(force=True)
    assert not store.path.exists()
    assert store.load() is False


def test_load_rejects_a_different_target(tmp_path: Path) -> None:
    original = _store(tmp_path)
    original.mark_scanned("https://target.test/")
    original.save(force=True)

    other = StateStore("https://other.test/", str(tmp_path), console=SilentConsole())
    assert other.load() is False


def test_load_rejects_schema_and_type_mismatches(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)

    store.path.write_text(
        json.dumps({"target": store.target, "schema": 99}), encoding="utf-8"
    )
    assert store.load() is False

    store.path.write_text(
        json.dumps(
            {
                "target": store.target,
                "schema": StateStore.SCHEMA,
                "scanned": "not-a-list",
            }
        ),
        encoding="utf-8",
    )
    assert store.load() is False

    store.path.write_text(
        json.dumps(
            {
                "target": store.target,
                "schema": StateStore.SCHEMA,
                "scanned": [1, 2],
                "findings": [],
                "waf": [],
                "extra": {},
            }
        ),
        encoding="utf-8",
    )
    assert store.load() is False


def test_load_ignores_unreadable_checkpoint(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("{not json", encoding="utf-8")
    assert store.load() is False


def test_failed_status_removes_url_from_resume_set(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.mark_scanned("https://target.test/a")
    assert store.is_scanned("https://target.test/a")

    store.mark_url_status("https://target.test/a", "running")
    assert not store.is_scanned("https://target.test/a")


def test_save_is_debounced_but_force_writes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.min_save_interval = 3600.0
    store._last_save = time.monotonic()
    store.save()
    assert not store.path.exists()
    store.save(force=True)
    assert store.path.exists()


def test_replace_finding_updates_matching_entry(tmp_path: Path) -> None:
    store = _store(tmp_path)
    old = SimpleNamespace(to_dict=lambda: {"finding_id": "dup", "confidence": "low"})
    store.add_finding(old)
    store.replace_finding(
        old, SimpleNamespace(to_dict=lambda: {"finding_id": "dup", "confidence": "high"})
    )
    assert len(store.findings) == 1
    assert store.findings[0]["confidence"] == "high"

    store.replace_finding(
        {"finding_id": "missing"},
        SimpleNamespace(to_dict=lambda: {"finding_id": "new"}),
    )
    assert [item["finding_id"] for item in store.findings] == ["dup", "new"]


def test_reset_clears_the_checkpoint_file(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.mark_scanned("https://target.test/a")
    store.add_finding(SimpleNamespace(to_dict=lambda: {"finding_id": "x"}))
    store.save(force=True)
    store.reset()

    assert store.scanned == set()
    assert store.findings == []
    assert not store.path.exists()
