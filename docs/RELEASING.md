# Releasing XOXSS

This document describes the recommended process for building packages and publishing releases for XOXSS.

## Versioning

- XOXSS uses semantic versioning (`MAJOR.MINOR.PATCH`).
- Keep the package version in sync:
  - `pyproject.toml` (`[project].version`)
  - `xoxss/__init__.py` (`__version__`)
- Update `CHANGELOG.md` before creating a release tag:
  - Move relevant entries from `Unreleased` into a new version section.
  - Add the release date and compare/release links.

## Pre-release checks

Run the standard quality checks locally before tagging:

```bash
python -m pip install --upgrade pip build twine
python -m pip install -e ".[dev]"
python -m compileall -q xoxss xoxss.py tests
ruff check xoxss tests benchmarks
pyright
pytest
python benchmarks/test_dom_guards.py
python benchmarks/test_hybrid_pipeline.py
python benchmarks/run_benchmark.py --quick
```

Build and validate distribution artifacts:

```bash
python -m build
python -m twine check dist/*
```

## Creating a release

1. Commit the version/changelog/docs updates on the release branch and merge to `main`.
2. Create and push a version tag matching the package version:

   ```bash
   git tag v2.0.1
   git push origin v2.0.1
   ```

3. The `Release` GitHub Actions workflow (`.github/workflows/release.yml`) will:
   - build source and wheel distributions,
   - validate package metadata with `twine check`,
   - build standalone binaries for Windows (x86_64), Linux (x86_64) and
     macOS (arm64 + x86_64) via PyInstaller (`packaging/xoxss.spec`),
   - upload build artifacts to the workflow run,
   - create a GitHub Release for the tag and attach the distributions and
     binaries,
   - publish to PyPI when trusted publishing is configured.

### Standalone binaries

Each release attaches single-file executables built with PyInstaller:

| Asset | Platform |
| --- | --- |
| `xoxss-x86_64-pc-windows-msvc.exe` | Windows x86_64 |
| `xoxss-x86_64-unknown-linux-gnu` | Linux x86_64 |
| `xoxss-aarch64-apple-darwin` | macOS Apple Silicon |
| `xoxss-x86_64-apple-darwin` | macOS Intel |

Binaries bundle the core dependencies only; optional extras (browser
drivers, Interactsh crypto, HTTP/2) degrade gracefully, matching the
pip-installed behaviour. To rebuild locally:

```bash
pip install -e . pyinstaller
python -m PyInstaller packaging/xoxss.spec --noconfirm --distpath dist-bin --workpath build
```

## PyPI publishing prerequisites

The release workflow is configured to publish with PyPI trusted publishing (OIDC). To enable publishing:

1. Create/configure the `xoxss` project on PyPI.
2. In PyPI, add a trusted publisher for this GitHub repository, workflow file `.github/workflows/release.yml`, and the appropriate environment (recommended: `pypi`).
3. In the GitHub repository settings, create a deployment environment named `pypi` (optionally with required reviewers/protection rules).

If PyPI trusted publishing is not configured, the package build and GitHub Release steps can still be used, but the publish job will fail until publishing access is set up.

## Post-release

- Verify the GitHub Release assets and generated notes.
- Verify the package page and installation from PyPI (if published):

  ```bash
  python -m pip install xoxss==<version>
  xoxss --version
  ```

- Add a new empty `Unreleased` section to `CHANGELOG.md` for future changes.
