#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XOX$$ entry point.

The implementation now lives in :mod:`xoxss.scanner` (inside the package) so
that ``pip install .`` and ``python -m xoxss`` expose the same code.  This file
only exists for backwards compatibility::

    python xoxss.py <target>

Authorised testing only. You are responsible for the targets you scan.
"""

from __future__ import annotations

import sys

from xoxss.scanner import main

if __name__ == "__main__":
    sys.exit(main())
