"""File discovery, layout planning and safe IO."""

from __future__ import annotations

import gzip
import os
import re
import stat
from pathlib import Path
from typing import IO, Iterable, Iterator, List, NamedTuple

DEFAULT_EXTS = [".log", ".txt", ".out", ".err", ".json", ".jsonl", ".csv", ".trace"]
ROTATED = re.compile(r"\.(?:log|txt|out|err)(?:[.-]\d+|[.-]\d{8})?(?:\.gz)?$", re.I)
OWN_OUTPUT = re.compile(r"_(?:original|redacted|restored)\b|redaction_(?:map|report)", re.I)
CHUNK_LINES = 2000


class Layout(NamedTuple):
    is_dir: bool
    original: Path
    redacted: Path
    map_path: Path
    report_path: Path


def plan_paths(src: Path) -> Layout:
    """dir  logs/   -> logs_original/ (+ map), logs_redacted/ (+ report)
    file app.log -> app_original.log, app_redacted.log, app_redaction_map.json"""
    if src.is_dir():
        orig = src.with_name(src.name + "_original")
        red = src.with_name(src.name + "_redacted")
        return Layout(True, orig, red, orig / "redaction_map.json", red / "redaction_report.txt")
    name = src.name
    for multi in (".log.gz", ".txt.gz"):
        if name.lower().endswith(multi):
            stem, suf = name[: -len(multi)], name[-len(multi):]
            break
    else:
        stem, suf = src.stem, src.suffix
    return Layout(False,
                  src.with_name(f"{stem}_original{suf}"),
                  src.with_name(f"{stem}_redacted{suf}"),
                  src.with_name(f"{stem}_redaction_map.json"),
                  src.with_name(f"{stem}_redaction_report.txt"))


def normalise_exts(exts: Iterable[str]) -> List[str]:
    out = []
    for e in exts:
        e = e.strip().lower()
        if e:
            out.append(e if e.startswith(".") else "." + e)
    return out


def is_target(p: Path, exts: List[str]) -> bool:
    name = p.name.lower()
    base = name[:-3] if name.endswith(".gz") else name
    return any(base.endswith(e) for e in exts) or bool(ROTATED.search(name))


def collect(src: Path, exts: List[str]) -> List[Path]:
    if src.is_file():
        return [src]
    return [p for p in sorted(src.rglob("*"))
            if p.is_file() and not p.is_symlink() and is_target(p, exts)
            and not OWN_OUTPUT.search(p.name)]


def _opener(p: Path):
    return gzip.open if p.suffix.lower() == ".gz" else open


def looks_binary(p: Path) -> bool:
    try:
        with _opener(p)(p, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return True


def read_lines(p: Path) -> Iterator[str]:
    # surrogateescape: undecodable bytes survive the round trip untouched
    with _opener(p)(p, "rt", encoding="utf-8", errors="surrogateescape", newline="") as f:
        yield from f


def open_out(p: Path) -> IO[str]:
    p.parent.mkdir(parents=True, exist_ok=True)
    return _opener(p)(p, "wt", encoding="utf-8", errors="surrogateescape", newline="")


def secure_write(p: Path, data: bytes) -> None:
    """Write with 0600 from creation (no window where the file is world-readable)."""
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    try:
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def chunks(lines: Iterable[str], size: int = CHUNK_LINES) -> Iterator[str]:
    buf: List[str] = []
    for line in lines:
        buf.append(line)
        if len(buf) >= size:
            yield "".join(buf)
            buf = []
    if buf:
        yield "".join(buf)
