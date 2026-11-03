"""Allow ``python -m xoxss`` to run the scanner."""

import sys

from xoxss.scanner import main

if __name__ == "__main__":
    sys.exit(main())
