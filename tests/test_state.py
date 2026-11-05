"""Checkpoint/resume state: crash safety, schema guards and URL lifecycle."""

import json

from xoxss.core.state import StateStore


def _store(tmp_path, target="https://example.test/"):
    return StateStore(target, str(tmp_path), enabled=True)


class _Finding:
    def to_dict(self):
        return {
            "kind": "Reflected XSS",
            "url": "https://example.test/?q=1",
            "parameter": "q",
            "method": "GET",
            "payload": "<script>alert(1)</script>",
        }


def test_state_roundtrip_preserves_findings_and_lifecycle(tmp_path):
    store = _store(tmp_path)
    store.mark_scanned("https://example.test/a")
    store.mark_url_status("https://example.test/b", "failed", error="timeout")
    store.add_finding(_Finding())
    store.waf = ["Cloudflare"]
    store.save(force=True)

    resumed = _store(tmp_path)
    assert resumed.load() is True
    assert resumed.findings == [_Finding().to_dict()]
    assert resumed.waf == ["Cloudflare"]
    assert "https://example.test/a" in resumed.scanned
    # A failed URL is tracked but never skipped on resume.
    assert resumed.url_status["https://example.test/b"]["status"] == "failed"
    assert "https://example.test/b" not in resumed.scanned


def test_state_rejects_checkpoint_with_mismatched_target(tmp_path):
    store = _store(tmp_path)
    store.save(force=True)
    data = json.loads(store.path.read_text(encoding="utf-8"))
    data["target"] = "https://other.test/"
    store.path.write_text(json.dumps(data), encoding="utf-8")

    assert _store(tmp_path).load() is False


def test_state_ignores_corrupt_or_wrong_schema_checkpoints(tmp_path):
    store = _store(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("{not json", encoding="utf-8")
    assert _store(tmp_path).load() is False

    store.path.write_text(
        json.dumps({"schema": 999, "target": store.target}), encoding="utf-8"
    )
    assert _store(tmp_path).load() is False


def test_state_reset_removes_checkpoint(tmp_path):
    store = _store(tmp_path)
    store.mark_scanned("https://example.test/a")
    store.save(force=True)
    assert store.path.exists()

    store.reset()
    assert not store.path.exists()
    assert store.scanned == set()
    assert store.findings == []


def test_state_debounces_periodic_saves_but_honours_force(tmp_path):
    store = _store(tmp_path)
    store.min_save_interval = 60.0
    store.mark_scanned("https://example.test/a")
    store.save()  # first save always writes
    assert store.path.exists()
    first = store.path.read_text(encoding="utf-8")

    store.scanned.add("https://example.test/b")
    store.save()  # debounced: unchanged on disk
    assert store.path.read_text(encoding="utf-8") == first

    store.save(force=True)
    assert "https://example.test/b" in store.path.read_text(encoding="utf-8")


def test_state_survives_unwritable_directory(tmp_path, monkeypatch):
    store = _store(tmp_path)

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("xoxss.core.state.os.replace", boom)
    store.save(force=True)  # must never raise
