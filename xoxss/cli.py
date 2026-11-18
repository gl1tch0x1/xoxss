"""Backward-compatible CLI parser entry point.

The argparse surface moved to :mod:`xoxss.cli_parser` when it grew past 700
lines; this module re-exports the public names so existing imports and
``xoxss.cli.build_parser`` callers keep working unchanged.
"""

from xoxss.cli_parser import EXAMPLES, XoxssHelpFormatter, build_parser

__all__ = ["EXAMPLES", "XoxssHelpFormatter", "build_parser"]
