"""Terminal output: colour, prompts, progress. Stdlib only, Windows-aware."""

from __future__ import annotations

import os
import shutil
import sys
import time
from typing import List, Optional, Sequence, Set


def _enable_windows_vt() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32  # type: ignore[attr-defined]
        h = k.GetStdHandle(-12)     # stderr
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x0004)
        h = k.GetStdHandle(-11)     # stdout
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x0004)
        return True
    except Exception:
        return False


class Term:
    def __init__(self, stream=None, color: Optional[bool] = None, quiet: bool = False):
        self.out = stream or sys.stderr          # UI goes to stderr; stdout stays clean for pipes
        self.quiet = quiet
        if color is None:
            color = (self.out.isatty() and "NO_COLOR" not in os.environ
                     and os.environ.get("TERM") != "dumb")
        try:
            tty_out = self.out.isatty()
        except (AttributeError, ValueError):
            tty_out = False
        self.vt = tty_out and _enable_windows_vt()      # ANSI cursor control available
        self.color = bool(color) and (self.vt or not tty_out)
        try:
            "█░✓›…".encode(getattr(self.out, "encoding", None) or "ascii")
            self.uni = True
        except (UnicodeEncodeError, LookupError):
            self.uni = False                     # e.g. legacy Windows code page

    def g(self, fancy: str, plain: str) -> str:
        return fancy if self.uni else plain

    # ---- styling ---------------------------------------------------------
    def _c(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.color else s

    def bold(self, s): return self._c("1", s)
    def dim(self, s): return self._c("2", s)
    def red(self, s): return self._c("31", s)
    def green(self, s): return self._c("32", s)
    def yellow(self, s): return self._c("33", s)
    def cyan(self, s): return self._c("36", s)
    def accent(self, s): return self._c("1;35", s)

    # ---- output ----------------------------------------------------------
    def say(self, *parts: str, force: bool = False) -> None:
        if not self.quiet or force:
            print(*parts, file=self.out)

    def warn(self, msg: str) -> None:
        print(self.yellow("warning: ") + msg, file=self.out)

    def error(self, msg: str) -> None:
        print(self.red("error: ") + msg, file=self.out)

    def banner(self, version: str) -> None:
        self.say("")
        self.say("  " + self.accent("hexredact") + " " + self.dim(f"v{version}"))
        self.say("  " + self.dim("heavy, reversible log redaction"))
        self.say("")

    def section(self, title: str) -> None:
        self.say("\n" + self.bold(title))

    def kv(self, rows: Sequence[Sequence[str]], indent: int = 3) -> None:
        if not rows:
            return
        w = max(len(k) for k, _ in rows)
        for k, v in rows:
            self.say(" " * indent + self.dim(k.ljust(w)) + "  " + v)

    def table(self, rows: List[Sequence[str]], header: Sequence[str], indent: int = 3) -> None:
        cols = list(zip(header, *rows)) if rows else [(h,) for h in header]
        widths = [max(len(str(x)) for x in c) for c in cols]
        line = " " * indent + "  ".join(h.ljust(w) for h, w in zip(header, widths))
        self.say(self.dim(line))
        for r in rows:
            self.say(" " * indent + "  ".join(str(x).ljust(w) for x, w in zip(r, widths)))

    # ---- prompts ---------------------------------------------------------
    def ask(self, prompt: str, default: Optional[str] = None) -> str:
        suffix = self.dim(f" [{default}]") if default not in (None, "") else ""
        self.out.write(f"{self.cyan('?')} {prompt}{suffix}: ")
        self.out.flush()
        v = sys.stdin.readline()
        if not v:
            raise EOFError
        v = v.strip()
        return v if v else (default or "")

    def ask_yn(self, prompt: str, default: bool = True) -> bool:
        d = "Y/n" if default else "y/N"
        while True:
            v = self.ask(f"{prompt} {self.dim('(' + d + ')')}").lower()
            if not v:
                return default
            if v in ("y", "yes"):
                return True
            if v in ("n", "no"):
                return False

    def ask_choice(self, prompt: str, options: Sequence[str], default: int = 1) -> int:
        for i, o in enumerate(options, 1):
            mark = self.cyan(self.g("›", ">")) if i == default else " "
            self.say(f"  {mark} {self.bold(str(i))}  {o}")
        while True:
            v = self.ask(prompt, str(default))
            if v.isdigit() and 1 <= int(v) <= len(options):
                return int(v)

    # ---- arrow-key widgets with numbered fallbacks ------------------------
    def choose(self, prompt: str, options: Sequence[str], default: int = 1,
               hints: Optional[Sequence[str]] = None) -> int:
        """1-based choice. Arrow keys on a real terminal, numbered prompt otherwise."""
        from . import menu
        if menu.available(self):
            return menu.select(self, prompt, options, default - 1, hints) + 1
        labels = [o + (self.dim("  " + hints[i]) if hints and hints[i] else "") for i, o in enumerate(options)]
        self.say(self.bold(prompt))
        return self.ask_choice("Choose", labels, default)

    def pick_many(self, prompt: str, items: Sequence[str], checked: Set[int],
                  details: Optional[Sequence[str]] = None) -> Set[int]:
        """0-based multi-select. Checklist on a real terminal, number toggles otherwise."""
        from . import menu
        if menu.available(self):
            return menu.checklist(self, prompt, items, checked, details)
        sel = set(checked)
        while True:
            self.say(self.bold(prompt))
            for i, it in enumerate(items):
                mark = self.green("[x]") if i in sel else self.dim("[ ]")
                self.say(f"   {mark} {i + 1:>2}  {it}")
            v = self.ask("Toggle numbers, or Enter to accept")
            if not v:
                if sel:
                    return sel
                self.say(self.red("   select at least one"))
                continue
            for tok in v.replace(",", " ").split():
                if tok.isdigit() and 1 <= int(tok) <= len(items):
                    sel ^= {int(tok) - 1}

    def yes(self, prompt: str, default: bool = True) -> bool:
        from . import menu
        if menu.available(self):
            return menu.confirm(self, prompt, default)
        return self.ask_yn(prompt, default)

    def ask_secret(self, prompt: str, confirm: bool = True, min_len: int = 8) -> str:
        import getpass
        while True:
            a = getpass.getpass(f"{self.cyan('?')} {prompt}: ", stream=self.out)
            if len(a) < min_len:
                self.say(self.red(f"  minimum {min_len} characters"))
                continue
            if confirm and a != getpass.getpass(f"{self.cyan('?')} confirm: ", stream=self.out):
                self.say(self.red("  did not match"))
                continue
            return a


class Progress:
    """Single-line progress bar on a TTY; plain per-item lines otherwise."""

    def __init__(self, term: Term, total: int, label: str):
        self.t, self.total, self.label = term, max(total, 1), label
        self.n = 0
        self.live = term.out.isatty() and not term.quiet
        self.start = time.monotonic()

    def step(self, item: str, detail: str = "") -> None:
        self.n += 1
        if self.t.quiet:
            return
        if not self.live:
            self.t.say(f"   [{self.n}/{self.total}] {item} {detail}".rstrip())
            return
        cols = shutil.get_terminal_size((80, 20)).columns
        width = max(10, min(30, cols - 50))
        filled = int(width * self.n / self.total)
        bar = self.t.cyan(self.t.g("█", "#") * filled) + self.t.dim(self.t.g("░", ".") * (width - filled))
        name = item if len(item) <= 28 else self.t.g("…", "~") + item[-27:]
        self.t.out.write(f"\r\033[K   {self.label} {bar} {self.n}/{self.total}  {self.t.dim(name)}")
        self.t.out.flush()

    def done(self) -> None:
        if self.live:
            self.t.out.write("\r\033[K")
            self.t.out.flush()
        took = time.monotonic() - self.start
        self.t.say(f"   {self.t.green(self.t.g('✓', 'ok'))} {self.label} {self.total} file(s) "
                   + self.t.dim(f"in {took:.1f}s"))
