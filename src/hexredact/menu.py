"""Arrow-key menus with no dependencies.

Keys come from ``msvcrt`` on Windows and ``termios``/``tty`` elsewhere. Drawing
uses plain ANSI cursor movement on stderr. Callers check :func:`available`
first and fall back to numbered prompts when input is not a real terminal.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import TYPE_CHECKING, List, Optional, Sequence, Set

if TYPE_CHECKING:
    from .ui import Term

UP, DOWN, LEFT, RIGHT, ENTER, SPACE, ESC, HOME, END, PGUP, PGDN = (
    "up", "down", "left", "right", "enter", "space", "esc", "home", "end", "pgup", "pgdn")


class Aborted(KeyboardInterrupt):
    pass


# --------------------------------------------------------------------------
# key input
# --------------------------------------------------------------------------

if os.name == "nt":
    import msvcrt

    _WIN = {"H": UP, "P": DOWN, "K": LEFT, "M": RIGHT, "G": HOME, "O": END, "I": PGUP, "Q": PGDN}

    def read_key() -> str:
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            return _WIN.get(msvcrt.getwch(), "")
        return _plain(ch)

    class _Raw:
        def __enter__(self): return self
        def __exit__(self, *a): return False

else:
    import termios
    import tty

    _CSI = {"A": UP, "B": DOWN, "D": LEFT, "C": RIGHT, "H": HOME, "F": END}
    _TILDE = {"1": HOME, "7": HOME, "4": END, "8": END, "5": PGUP, "6": PGDN}

    class _Raw:
        """cbreak mode for the duration of a widget; always restored."""

        def __enter__(self):
            self.fd = sys.stdin.fileno()
            self.old = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)
            # cbreak keeps ISIG; turn it off so Ctrl-C arrives as \x03 and we restore cleanly
            attrs = termios.tcgetattr(self.fd)
            attrs[3] &= ~termios.ISIG
            termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
            return self

        def __exit__(self, *a):
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)
            return False

    def _getc() -> str:
        return os.read(sys.stdin.fileno(), 1).decode("utf-8", "replace")

    def read_key() -> str:
        ch = _getc()
        if ch != "\x1b":
            return _plain(ch)
        import select
        if not select.select([sys.stdin], [], [], 0.05)[0]:
            return ESC
        nxt = _getc()
        if nxt not in ("[", "O"):
            return ESC
        seq = _getc()
        if seq in _CSI:
            return _CSI[seq]
        if seq.isdigit():
            rest = _getc()
            while rest not in ("~", "") and not rest.isalpha():
                rest = _getc()
            return _TILDE.get(seq, "")
        return ""


def _plain(ch: str) -> str:
    if ch in ("\r", "\n"):
        return ENTER
    if ch == " ":
        return SPACE
    if ch == "\x1b":
        return ESC
    if ch == "\x03":
        raise Aborted()
    if ch == "\x04":
        raise EOFError()
    return ch


def available(term: "Term") -> bool:
    if os.environ.get("HEXREDACT_NO_MENU"):
        return False
    try:
        return sys.stdin.isatty() and term.out.isatty() and os.environ.get("TERM") != "dumb" and term.vt
    except (AttributeError, ValueError):
        return False


# --------------------------------------------------------------------------
# drawing
# --------------------------------------------------------------------------

class _Canvas:
    """Redraws a block of lines in place."""

    def __init__(self, term: "Term"):
        self.t, self.h = term, 0

    def draw(self, lines: List[str]) -> None:
        out = self.t.out
        if self.h:
            out.write(f"\033[{self.h}A")
        cols = shutil.get_terminal_size((80, 24)).columns
        for ln in lines:
            out.write("\r\033[K" + _clip(ln, cols - 1) + "\n")
        for _ in range(self.h - len(lines)):          # block shrank: blank the leftovers
            out.write("\r\033[K\n")
        if self.h > len(lines):
            out.write(f"\033[{self.h - len(lines)}A")
        self.h = len(lines)
        out.flush()

    def close(self, summary: Optional[str] = None) -> None:
        """Collapse the widget to a single answered line."""
        out = self.t.out
        if self.h:
            out.write(f"\033[{self.h}A")
            for _ in range(self.h):
                out.write("\r\033[K\n")
            out.write(f"\033[{self.h}A")
        if summary is not None:
            out.write("\r\033[K" + summary + "\n")
        out.flush()
        self.h = 0


def _clip(s: str, width: int) -> str:
    """Truncate to `width` visible characters, ignoring ANSI escapes."""
    out, vis, i = [], 0, 0
    while i < len(s):
        if s[i] == "\033":
            j = s.find("m", i)
            if j == -1:
                break
            out.append(s[i:j + 1])
            i = j + 1
            continue
        if vis >= width:
            break
        out.append(s[i])
        vis += 1
        i += 1
    return "".join(out) + ("\033[0m" if "\033" in s else "")


def _hide(term): term.out.write("\033[?25l")
def _show(term): term.out.write("\033[?25h"); term.out.flush()


def _window(n: int, cur: int, top: int, height: int) -> int:
    if cur < top:
        return cur
    if cur >= top + height:
        return cur - height + 1
    return max(0, min(top, n - height))


def _move(key: str, cur: int, n: int, page: int) -> int:
    if key in (UP, "k"):
        return (cur - 1) % n
    if key in (DOWN, "j"):
        return (cur + 1) % n
    if key == HOME:
        return 0
    if key == END:
        return n - 1
    if key == PGUP:
        return max(0, cur - page)
    if key == PGDN:
        return min(n - 1, cur + page)
    return cur


# --------------------------------------------------------------------------
# widgets
# --------------------------------------------------------------------------

def select(term: "Term", prompt: str, options: Sequence[str], default: int = 0,
           hints: Optional[Sequence[str]] = None) -> int:
    """Single choice. Returns a 0-based index."""
    t, n = term, len(options)
    cur = max(0, min(default, n - 1))
    canvas = _Canvas(t)
    ptr = t.g("›", ">")
    help_ = t.dim("↑/↓ move  enter select  1-9 jump" if t.uni else "up/down move  enter select  1-9 jump")
    _hide(t)
    try:
        with _Raw():
            while True:
                lines = [f"{t.cyan('?')} {t.bold(prompt)}  {help_}"]
                for i, o in enumerate(options):
                    if i == cur:
                        line = f"  {t.cyan(ptr)} {t.bold(o)}"
                        if hints and hints[i]:
                            line += "  " + t.dim(hints[i])
                    else:
                        line = f"    {t.dim(o) if t.color else o}"
                    lines.append(line)
                canvas.draw(lines)
                k = read_key()
                if k == ENTER:
                    break
                if k == ESC:
                    raise Aborted()
                if k.isdigit() and 1 <= int(k) <= n:
                    cur = int(k) - 1
                    break
                cur = _move(k, cur, n, 5)
    finally:
        _show(t)
    canvas.close(f"{t.green(t.g('✓', '+'))} {prompt}  {t.cyan(options[cur])}")
    return cur


def checklist(term: "Term", prompt: str, items: Sequence[str], checked: Set[int],
              details: Optional[Sequence[str]] = None) -> Set[int]:
    """Multi-select. Space toggles, a = all, n = none. Returns 0-based indices."""
    t, n = term, len(items)
    sel = set(checked)
    cur, top = 0, 0
    nag = False
    rows = shutil.get_terminal_size((80, 24)).lines
    height = max(5, min(n, rows - 5))
    canvas = _Canvas(t)
    on, off = (t.green("◉"), t.dim("○")) if t.uni else (t.green("[x]"), t.dim("[ ]"))
    ptr = t.g("›", ">")
    keys = "↑/↓ move  space toggle  a all  n none  enter done" if t.uni else \
        "up/down move  space toggle  a all  n none  enter done"
    _hide(t)
    try:
        with _Raw():
            while True:
                top = _window(n, cur, top, height)
                lines = [f"{t.cyan('?')} {t.bold(prompt)}  {t.dim(f'{len(sel)}/{n} on')}",
                         "  " + t.dim(keys)]
                for i in range(top, min(n, top + height)):
                    mark = on if i in sel else off
                    label = items[i] if i == cur else (items[i] if i in sel else t.dim(items[i]))
                    line = f"  {t.cyan(ptr) if i == cur else ' '} {mark} {t.bold(label) if i == cur else label}"
                    if i == cur and details and details[i]:
                        line += "  " + t.dim(details[i])
                    lines.append(line)
                more = []
                if top > 0:
                    more.append(f"{top} above")
                if top + height < n:
                    more.append(f"{n - top - height} below")
                tail = "  " + t.dim("  ".join(more)) if more else ""
                if nag:
                    tail = (tail + "   " if tail else "  ") + t.red("select at least one")
                lines.append(tail)
                canvas.draw(lines)
                k = read_key()
                nag = False
                if k == ENTER:
                    if sel:
                        break
                    nag = True                    # refuse to finish with nothing selected
                    continue
                if k == ESC:
                    raise Aborted()
                if k == SPACE:
                    sel ^= {cur}
                elif k == "a":
                    sel = set(range(n))
                elif k == "n":
                    sel = set()
                else:
                    cur = _move(k, cur, n, height)
    finally:
        _show(t)
    canvas.close(f"{t.green(t.g('✓', '+'))} {prompt}  {t.cyan(f'{len(sel)} of {n} on')}")
    return sel


def confirm(term: "Term", prompt: str, default: bool = True) -> bool:
    """Inline yes/no: left/right or y/n, enter to accept."""
    t = term
    val = default
    canvas = _Canvas(t)
    _hide(t)
    try:
        with _Raw():
            while True:
                yes = t.cyan(t.bold("Yes")) if val else t.dim("Yes")
                no = t.cyan(t.bold("No")) if not val else t.dim("No")
                canvas.draw([f"{t.cyan('?')} {prompt}  {yes} {t.dim('/')} {no}"])
                k = read_key()
                if k == ENTER:
                    break
                if k == ESC:
                    raise Aborted()
                if k in (LEFT, RIGHT, UP, DOWN, SPACE, "h", "l"):
                    val = not val
                elif k.lower() == "y":
                    val = True
                    break
                elif k.lower() == "n":
                    val = False
                    break
    finally:
        _show(t)
    canvas.close(f"{t.green(t.g('✓', '+'))} {prompt}  {t.cyan('Yes' if val else 'No')}")
    return val
