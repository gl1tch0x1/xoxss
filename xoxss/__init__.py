"""
XOXSS - Advanced XSS Scanner Package

A professional, aggressive XSS security scanner for authorized testing.
"""

__version__ = "2.0.0"
__author__ = "Security Research"
__license__ = "MIT"

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from xoxss.scanner import main

# The scanner implementation lives in xoxss.scanner (moved out of the root
# xoxss.py so the package and the console script share one code path).
# ``main`` is exposed lazily to keep ``import xoxss`` cheap.
_SCANNER_EXPORTS = {"main": "xoxss.scanner"}

__all__ = ["main", "__version__"]


def __getattr__(name: str):
    module_name = _SCANNER_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
