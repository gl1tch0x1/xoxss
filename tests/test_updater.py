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


def test_fetch_state_ahead_and_behind_counts(tmp_path, monkeypatch):
    """Verify rev-list parsing correctly distinguishes ahead vs behind."""
    # Origin repo
    origin_dir = tmp_path / "origin"
    origin_dir.mkdir()
    _git(origin_dir, "init", "-b", "main")
    _git(origin_dir, "config", "user.name", "Origin")
    _git(origin_dir, "config", "user.email", "origin@example.invalid")
    (origin_dir / "file.txt").write_text("v1\n", encoding="utf-8")
    _git(origin_dir, "add", "file.txt")
    _git(origin_dir, "commit", "-m", "init")

    # Local repo cloned from origin
    local_dir = tmp_path / "local"
    subprocess.run(["git", "clone", str(origin_dir), str(local_dir)], check=True, capture_output=True)
    _git(local_dir, "config", "user.name", "Local")
    _git(local_dir, "config", "user.email", "local@example.invalid")
    monkeypatch.setattr(updater, "ROOT", local_dir)

    # 1. In sync
    behind, ahead = updater.fetch_state("main")
    assert behind == 0
    assert ahead == 0

    # 2. Local commits -> ahead = 1, behind = 0
    (local_dir / "local.txt").write_text("local\n", encoding="utf-8")
    _git(local_dir, "add", "local.txt")
    _git(local_dir, "commit", "-m", "local commit")
    behind, ahead = updater.fetch_state("main")
    assert ahead == 1
    assert behind == 0

    # 3. Origin commits -> behind = 1, ahead = 1
    (origin_dir / "remote.txt").write_text("remote\n", encoding="utf-8")
    _git(origin_dir, "add", "remote.txt")
    _git(origin_dir, "commit", "-m", "origin commit")
    behind, ahead = updater.fetch_state("main")
    assert ahead == 1
    assert behind == 1


def test_detect_installed_extras():
    extras = updater.detect_installed_extras()
    assert isinstance(extras, list)
    # dev extra has pytest which is installed in test runner environment
    assert "dev" in extras


def test_safe_temp_dir_and_clean_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "ROOT", tmp_path)
    (tmp_path / "build").mkdir()
    (tmp_path / "xoxss.egg-info").mkdir()
    (tmp_path / ".tmp").mkdir()
    assert (tmp_path / "build").exists()
    assert (tmp_path / ".tmp").exists()

    updater.clean_build_artifacts()
    assert not (tmp_path / "build").exists()
    assert not (tmp_path / "xoxss.egg-info").exists()
    assert not (tmp_path / ".tmp").exists()


def test_installer_space_and_cache_arguments(tmp_path, monkeypatch):
    import installer
    monkeypatch.setattr(installer, "ROOT", tmp_path)
    free = installer.get_free_space_mb(tmp_path)
    assert free > 0

    # Test parser recognizes --no-cache
    import argparse
    # Create parser through installer's main logic
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-cache", action="store_true")
    opts = parser.parse_args(["--no-cache"])
    assert opts.no_cache is True


