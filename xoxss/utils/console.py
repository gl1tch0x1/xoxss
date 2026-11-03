"""
Console output utility with color support.
"""

import sys
from typing import Optional


class bcolors:
    """ANSI color codes."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    GREY = '\033[90m'


class Console:
    """Console output handler with color support."""

    def __init__(self, quiet: bool = False, verbose: bool = False, no_color: bool = False):
        self.quiet = quiet
        self.verbose = verbose
        self.no_color = no_color

    def _colorize(self, text: str, color: str, bold: bool = False) -> str:
        """Apply color to text if colors are enabled."""
        if self.no_color or not sys.stdout.isatty():
            return text
        prefix = bcolors.BOLD if bold else ""
        return f"{prefix}{color}{text}{bcolors.ENDC}"

    def info(self, message: str, important: bool = False) -> None:
        """Print an info message; ``important`` keeps CompatConsole parity."""
        if not self.quiet:
            print(self._colorize(f"[*] {message}", bcolors.OKBLUE, bold=important))

    def ok(self, message: str, important: bool = False) -> None:
        """Alias of :meth:`success` with CompatConsole-compatible keyword."""
        self.success(message)

    def rule(self, text: str = "") -> None:
        """Print a horizontal rule (CompatConsole parity)."""
        if not self.quiet:
            width = 72
            print(f"-- {text} ".ljust(width, "-") if text else "-" * width)

    def success(self, message: str, important: bool = False) -> None:
        """Print a success message."""
        if not self.quiet:
            print(self._colorize(f"[+] {message}", bcolors.OKGREEN, bold=important))

    def warn(self, message: str, important: bool = False) -> None:
        """Print a warning message."""
        if not self.quiet:
            print(self._colorize(f"[!] {message}", bcolors.WARNING, bold=important))

    def error(self, message: str) -> None:
        """Print an error message."""
        print(self._colorize(f"[-] {message}", bcolors.FAIL), file=sys.stderr)

    def debug(self, message: str) -> None:
        """Print a debug message."""
        if self.verbose:
            print(self._colorize(f"[D] {message}", bcolors.GREY))

    def raw(self, message: str) -> None:
        """Print a raw message without prefix."""
        if not self.quiet:
            print(message)

    def banner(self) -> None:
        """Print the tool banner."""
        banner = f"""
{bcolors.BOLD}{bcolors.OKCYAN}
XOX$$ v2.0.0 - Advanced XSS Scanner
====================================
{bcolors.ENDC}
"""
        print(banner)
