"""
Shared terminal UI engine for XOXSS (scanner, installer, updater).

Design contract:

* Zero third-party dependencies - installer.py and updater.py import this
  module through the repository checkout *before* the package is installed,
  so it must only ever use the standard library.
* Colours auto-disable on: NO_COLOR, TERM=dumb, non-tty output, encoding
  that cannot represent the glyphs used, or an explicit :func:`disable`.
* Only 256-colour ANSI codes are emitted (supported by Windows 10+ conhost,
  Windows Terminal, every xterm-compatible emulator) - no truecolor probe.
* Aggressive but professional: brand-red accents, dim metadata, generous
  whitespace.  No rainbow, no ASCII noise.
"""

from __future__ import annotations

import os
import sys
from typing import Iterable, List, Optional, Sequence

__all__ = [
    "enabled", "disable", "enable_for", "paint", "rule", "panel", "bar",
    "glyphs", "SPINNER", "paint_ramp", "strip_ansi", "safe_width",
]

#--------------------------------------------------------------------------------------
# Colour state
#--------------------------------------------------------------------------------------

_ENABLE = os.environ.get("NO_COLOR") is None \
    and os.environ.get("TERM", "") != "dumb" \
    and sys.stdout is not None and getattr(sys.stdout, "isatty", lambda: False)()


def enabled() -> bool:
    """True when ANSI styling is currently allowed."""
    return _ENABLE


def disable() -> None:
    """Force plain output (used by --no-color / NO_COLOR)."""
    global _ENABLE
    _ENABLE = False


def enable_for(stream=sys.stdout) -> None:
    """Re-evaluate colours for a specific stream (dropdown of stdout)."""
    global _ENABLE
    if os.environ.get("NO_COLOR") or os.environ.get("TERM", "") == "dumb":
        _ENABLE = False
        return
    _ENABLE = bool(getattr(stream, "isatty", lambda: False)())


#--------------------------------------------------------------------------------------
# Building blocks
#--------------------------------------------------------------------------------------

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

BRAND = "\033[38;5;196m"      # XOX$$ red
BRAND_DEEP = "\033[38;5;124m"
BRAND_BRIGHT = "\033[38;5;203m"
CYAN = "\033[38;5;51m"
GREEN = "\033[38;5;114m"
YELLOW = "\033[38;5;220m"
GREY = "\033[38;5;245m"
GREY_DARK = "\033[38;5;238m"
WHITE = "\033[38;5;252m"
PINK = "\033[38;5;218m"

# white -> brand-red ramp used for the banner gradient (top to bottom)
BANNER_RAMP = (231, 218, 203, 196, 160, 124, 88)


def paint(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes when colours are enabled."""
    if not _ENABLE or not codes:
        return text
    return "".join(codes) + text + RESET


def strip_ansi(text: str) -> str:
    out = []
    i = 0
    while i < len(text):
        if text[i] == "\033":
            j = text.find("m", i)
            i = j + 1 if j != -1 else len(text)
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def safe_width() -> int:
    try:
        return max(58, os.get_terminal_size().columns)
    except Exception:
        return 100


def _glyph(fallback: str, unicode_glyph: str) -> str:
    if not _ENABLE:
        return fallback
    encoding = (getattr(sys.stdout, "encoding", "") or "ascii").lower()
    try:
        unicode_glyph.encode(encoding, errors="strict")
        return unicode_glyph
    except (UnicodeEncodeError, LookupError):
        return fallback


#--------------------------------------------------------------------------------------
# Composable widgets
#--------------------------------------------------------------------------------------

def glyphs() -> dict:
    """Unicode arrows/bars with a per-encoding ASCII fallback."""
    return {
        "arrow": _glyph("->", "\u25b8"),          # ▸
        "bullet": _glyph("*", "\u00bb"),          # »
        "bar_full": _glyph("#", "\u25b0"),        # ▰
        "bar_empty": _glyph("-", "\u25b1"),       # ▱
        "tick": _glyph("ok", "\u2713"),           # ✓
        "cross": _glyph("X", "\u2717"),           # ✗
        "warn": _glyph("!", "!"),
        "diamond": _glyph("+", "\u25c6"),         # ◆
        "line": _glyph("-", "\u2500"),            # ─
        "dline": _glyph("=", "\u2550"),           # ═
    }


SPINNER = ["\u280b", "\u2819", "\u2839", "\u2838", "\u283c", "\u2834",
           "\u2826", "\u2827", "\u2807", "\u280f"]


def rule(title: str = "", *, width: int = 0, color: str = GREY_DARK,
         title_color: str = BOLD, thick: bool = False) -> str:
    """`── TITLE ─────────────` section header; empty title = full rule."""
    g = glyphs()
    line_char = g["dline"] if thick else g["line"]
    width = width or safe_width() - 1
    if not title:
        return paint(line_char * max(4, width), color, DIM)
    label = f" {title.upper()} "
    padding = max(3, width - len(label) - 2)
    return (
        paint(f"{line_char * 2}{label}", color, DIM)
        + paint(line_char * padding, color, DIM)
    )


def bar(fraction: float, width: int = 20) -> str:
    """▰▰▰▱▱▱ progress bar with percentage."""
    g = glyphs()
    fraction = min(1.0, max(0.0, fraction))
    filled = round(fraction * width)
    full = paint(g["bar_full"] * filled, BRAND)
    empty = paint(g["bar_empty"] * (width - filled), GREY_DARK)
    pct = paint(f"{int(fraction * 100):>3}%", DIM)
    return f"{full}{empty} {pct}"


def panel(title: str, lines: Sequence[str], *, width: int = 0,
          accent: str = BRAND, pad: int = 0, style: str = "badge") -> str:
    """Boxed block used for headers, summaries, briefings, and commit lists.

    Guarantees 100% mathematical column alignment across every row,
    preventing right-border zig-zags and terminal wrapping glitches.
    Falls back to plain text (no box) on ASCII-only encodings.
    """
    lines = list(lines)
    box_on = _glyph("|", "\u2502") != "|"
    if not box_on:
        body = "\n".join(lines)
        return (paint(f"== {title} ==", BOLD) + "\n" + body) if title else body

    term_w = safe_width()
    title_raw = strip_ansi(title)
    max_line_len = max([len(title_raw)] + [len(strip_ansi(line)) for line in lines] + [40])

    if width:
        outer = min(width, term_w - 2)
    else:
        outer = min(max_line_len + 6 + pad * 2, term_w - 2)
    outer = max(outer, 44)
    inner = outer - 2

    tl, tr = "\u256d", "\u256e"  # ╭ ╮
    bl, br = "\u2570", "\u256f"  # ╰ ╯
    h, v = "\u2500", "\u2502"    # ─ │
    sep_l, sep_r = "\u251c", "\u2524"  # ├ ┤

    side = paint(v, accent)
    out = []

    badge_raw = f" [ {title_raw.upper()} ] "
    can_use_badge = style == "badge" and title and (len(badge_raw) + 6 <= inner)

    if can_use_badge:
        badge = f" [ {paint(title.upper(), WHITE, BOLD)} ] "
        dashes_left = 3
        dashes_right = max(1, inner - dashes_left - len(badge_raw))
        top_str = (
            paint(tl + (h * dashes_left), accent)
            + badge
            + paint((h * dashes_right) + tr, accent)
        )
        out.append(top_str)
        out.append(f"{side}{' ' * inner}{side}")
    else:
        out.append(paint(tl + (h * inner) + tr, accent))
        if title:
            avail = inner - 2 - pad * 2
            gap = max(0, avail - len(title_raw))
            out.append(f"{side} {' ' * pad}{paint(title, BOLD)}{' ' * (gap + pad)} {side}")
            out.append(paint(sep_l + (h * inner) + sep_r, accent))

    for line in lines:
        raw_len = len(strip_ansi(line))
        avail = inner - 2 - pad * 2
        gap = max(0, avail - raw_len)
        out.append(f"{side} {' ' * pad}{line}{' ' * (gap + pad)} {side}")

    if can_use_badge:
        out.append(f"{side}{' ' * inner}{side}")

    out.append(paint(bl + (h * inner) + br, accent))
    return "\n".join(out)


def paint_ramp(art: str, *, ramp: Sequence[int] = BANNER_RAMP) -> Optional[str]:
    """Apply a top-to-bottom colour ramp to non-empty banner lines.

    Returns ``None`` when the request cannot be honoured (colours disabled or
    the output encoding cannot represent the artwork) so callers can fall back
    to their plain/legacy rendering.
    """
    if not _ENABLE:
        return None
    rows: List[str] = [row for row in art.split("\n")]
    content = [row for row in rows if row.strip()]
    if not content:
        return None
    encoding = (getattr(sys.stdout, "encoding", "") or "ascii").lower()
    try:
        content[0].encode(encoding, errors="strict")
    except (UnicodeEncodeError, LookupError):
        return None
    n = len(content)
    ramp_len = len(ramp)
    colors = [ramp[min(ramp_len - 1, i * (ramp_len - 1) // max(1, n - 1))] for i in range(n)]

    def decorate() -> Iterable[str]:
        idx = 0
        for row in rows:
            if row.strip():
                yield f"\033[38;5;{colors[idx]}m{row}{RESET}"
                idx += 1
            else:
                yield row
    return "\n".join(decorate())
