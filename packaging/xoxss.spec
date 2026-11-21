# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for standalone XOXSS binaries.

Build from the repository root::

    pyinstaller packaging/xoxss.spec --noconfirm \
        --distpath dist-bin --workpath build

Produces a single-file console executable.  Optional extras (browser
drivers, interactsh crypto, http2) are not bundled — the scanner degrades
gracefully when they are absent, matching the pip-installed behaviour.
"""

import os

from PyInstaller.utils.hooks import collect_data_files

_spec_dir = SPECPATH if os.path.isdir(SPECPATH) else os.path.dirname(SPECPATH)
ROOT = os.path.dirname(os.path.abspath(_spec_dir))

datas = collect_data_files("xoxss")

# Heavy/optional integrations stay out of the binary; every use site is
# guarded by find_spec/import checks and reports a clean degradation.
excludes = [
    "selenium",
    "webdriver_manager",
    "playwright",
    "tkinter",
    "pytest",
    "IPython",
    "notebook",
    "jupyter",
    "jupyterlab",
    "sphinx",
    "numpydoc",
]

a = Analysis(
    [os.path.join(ROOT, "xoxss.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="xoxss",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
