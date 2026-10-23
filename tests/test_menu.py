import io
import os
import shutil
import sys
import time
from pathlib import Path

import pytest

from hexredact import menu
from hexredact.ui import Term

SAMPLE = Path(__file__).parent.parent / "examples" / "sample.log"


# ---- pure logic ----------------------------------------------------------

def test_clip_ignores_ansi_width():
    s = "\033[1mhello\033[0m world"
    out = menu._clip(s, 5)
    assert out.replace("\033[1m", "").replace("\033[0m", "") == "hello"


def test_move_wraps_and_pages():
    assert menu._move(menu.UP, 0, 5, 3) == 4
    assert menu._move(menu.DOWN, 4, 5, 3) == 0
    assert menu._move("j", 1, 5, 3) == 2
    assert menu._move(menu.PGDN, 1, 10, 4) == 5
    assert menu._move(menu.END, 1, 10, 4) == 9


def test_window_keeps_cursor_visible():
    assert menu._window(31, 0, 0, 10) == 0
    assert menu._window(31, 12, 0, 10) == 3
    assert menu._window(31, 2, 5, 10) == 2


def test_plain_keys():
    assert menu._plain("\r") == menu.ENTER
    assert menu._plain(" ") == menu.SPACE
    with pytest.raises(KeyboardInterrupt):
        menu._plain("\x03")


# ---- fallbacks when not a terminal --------------------------------------

def _term_with_input(monkeypatch, text):
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    return Term(stream=io.StringIO(), color=False)


def test_choose_falls_back_to_numbers(monkeypatch):
    t = _term_with_input(monkeypatch, "2\n")
    assert not menu.available(t)
    assert t.choose("Mode", ["a", "b", "c"]) == 2


def test_pick_many_fallback_toggles_and_refuses_empty(monkeypatch):
    t = _term_with_input(monkeypatch, "1 2 3\n\n2\n\n")
    # all three toggled off -> empty -> refused -> toggle 2 back on -> accept
    assert t.pick_many("D", ["x", "y", "z"], {0, 1, 2}) == {1}


def test_yes_fallback(monkeypatch):
    t = _term_with_input(monkeypatch, "n\n")
    assert t.yes("ok?", True) is False


# ---- real keystrokes through a pseudo-terminal --------------------------

UP, DOWN, ENTER = "\x1b[A", "\x1b[B", "\r"


@pytest.mark.skipif(os.name != "posix", reason="pty is POSIX-only; Windows runs the fallback tests")
def test_arrow_key_wizard_end_to_end(tmp_path):
    import pty
    import select

    shutil.copy(SAMPLE, tmp_path / "app.log")
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.chdir(tmp_path)
        os.environ["TERM"] = "xterm"
        os.environ.pop("HEXREDACT_NO_MENU", None)
        src = str(Path(__file__).parent.parent / "src")
        os.environ["PYTHONPATH"] = src + os.pathsep + os.environ.get("PYTHONPATH", "")
        os.execvp(sys.executable, [sys.executable, "-m", "hexredact", "wizard", "app.log"])

    buf = bytearray()

    def expect(text, timeout=10.0):
        end = time.time() + timeout
        while time.time() < end:
            if text.encode() in buf:
                return
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    buf.extend(os.read(fd, 65536))
                except OSError:
                    break
        raise AssertionError(f"never saw {text!r}; tail: {bytes(buf[-600:])!r}")

    def send(keys, then=None):
        os.write(fd, keys.encode())
        if then:
            expect(then)

    try:
        expect("What do you want to do")
        send(ENTER, then="Mode")                      # Redact
        send(DOWN + ENTER, then="Detectors")          # Mask
        send("n" + ENTER, then="select at least one")  # empty is refused
        send("a" + DOWN + " " + ENTER, then="Extra terms")   # all on, then untick jwt
        send("Acme Ltd\r", then="hostname")
        send("n", then="Never redact")
        send("\r", then="loopback")
        send(ENTER, then="Write redacted output")
        send("y", then="residual scan")
    finally:
        _, status = os.waitpid(pid, 0)
        os.close(fd)

    assert os.waitstatus_to_exitcode(status) == 0
    out = (tmp_path / "app_redacted.log").read_text()
    assert "[REDACTED:IPV4_PRIV]" in out
    assert "127.0.0.1" in out                         # loopback kept (answered Yes)
    assert not (tmp_path / "app_redaction_map.json").exists()   # mask mode: no map
    assert b"30 of 31 on" in buf
