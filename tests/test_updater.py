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


def test_updater_handles_multiple_remotes(tmp_path, monkeypatch):
    _repo(tmp_path, monkeypatch)
    _git(tmp_path, "remote", "add", "origin", "https://github.com/gl1tch0x1/xoxss.git")
    _git(tmp_path, "remote", "add", "upstream", "https://github.com/fork/xoxss.git")

    branch = updater.ensure_repo()
    assert branch == "main"


def test_updater_tracking_branch_resolution(tmp_path, monkeypatch):
    _repo(tmp_path, monkeypatch)
    # No origin tracking ref exists in local tmp repo, so fallback to origin/main
    target = updater.resolve_tracking_branch("feature-branch")
    assert target == "origin/main"


def test_installer_launcher_generation_and_venv_lookup(tmp_path, monkeypatch):
    import installer
    monkeypatch.setattr(installer, "ROOT", tmp_path)

    venv_dir = tmp_path / ".venv"
    scripts_dir = venv_dir / ("Scripts" if installer.os.name == "nt" else "bin")
    scripts_dir.mkdir(parents=True, exist_ok=True)
    fake_python = scripts_dir / ("python.exe" if installer.os.name == "nt" else "python")
    fake_python.write_text("", encoding="utf-8")

    found_py = installer.find_venv_python(venv_dir)
    assert found_py is not None
    assert found_py.exists()

    installer.create_launcher_scripts(venv_dir)
    assert (tmp_path / "xoxss.bat").exists()
    assert (tmp_path / "xoxss").exists()
    assert ".venv" in (tmp_path / "xoxss.bat").read_text(encoding="ascii")

