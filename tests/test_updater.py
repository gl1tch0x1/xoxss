"""Tests for safe updater handling of local work."""

import subprocess

import pytest

import updater


def _git(root, *args):
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def _repo(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.name", "XOXSS tests")
    _git(tmp_path, "config", "user.email", "tests@example.invalid")
    (tmp_path / "source.txt").write_text("base\n", encoding="utf-8")
    _git(tmp_path, "add", "source.txt")
    _git(tmp_path, "commit", "-m", "base")
    monkeypatch.setattr(updater, "ROOT", tmp_path)


def test_updater_stashes_and_restores_tracked_and_untracked_changes(tmp_path, monkeypatch):
    _repo(tmp_path, monkeypatch)
    (tmp_path / "source.txt").write_text("local edit\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("untracked work\n", encoding="utf-8")

    stash = updater.stash_if_needed()
    assert stash
    assert not updater.is_dirty()

    assert updater.restore_stash(stash)
    assert (tmp_path / "source.txt").read_text(encoding="utf-8") == "local edit\n"
    assert (tmp_path / "notes.txt").read_text(encoding="utf-8") == "untracked work\n"
    assert not updater.out(updater.git(["stash", "list"]))


def test_updater_preserves_stash_when_local_changes_conflict(tmp_path, monkeypatch):
    _repo(tmp_path, monkeypatch)
    (tmp_path / "source.txt").write_text("local edit\n", encoding="utf-8")
    stash = updater.stash_if_needed()
    assert stash

    (tmp_path / "source.txt").write_text("upstream edit\n", encoding="utf-8")
    _git(tmp_path, "add", "source.txt")
    _git(tmp_path, "commit", "-m", "upstream change")

    assert not updater.restore_stash(stash)
    assert stash in updater.out(updater.git(["stash", "list", "--format=%H"]))
    assert "<<<<<<<" in (tmp_path / "source.txt").read_text(encoding="utf-8")


def test_updater_can_refuse_to_stash_when_requested(tmp_path, monkeypatch):
    _repo(tmp_path, monkeypatch)
    (tmp_path / "source.txt").write_text("local edit\n", encoding="utf-8")

    with pytest.raises(SystemExit):
        updater.stash_if_needed(auto_stash=False)
    assert updater.is_dirty()
