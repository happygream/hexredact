"""Redaction jobs: discovery, learning pass, redaction pass, report."""

from __future__ import annotations

import datetime as _dt
import json
import shutil
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__
from .engine import Redactor, strip_pem
from .files import Layout, chunks, collect, looks_binary, open_out, plan_paths, read_lines
from .mapfile import build_map, write_map
from .ui import Progress, Term


class JobError(Exception):
    pass


@dataclass
class JobResult:
    layout: Optional[Layout]
    files: List[Path]
    skipped: List[Path]
    totals: Counter
    per_file: Dict[str, Counter]
    residual: Counter
    learned: int
    map_written: bool = False
    map_encrypted: bool = False
    extra: Dict = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.totals.values())

    def to_dict(self) -> Dict:
        lay = self.layout
        return {
            "tool": f"hexredact {__version__}",
            "files": len(self.files), "skipped_binary": [str(p) for p in self.skipped],
            "learned_terms": self.learned,
            "totals": dict(self.totals.most_common()),
            "per_file": {k: dict(v) for k, v in self.per_file.items()},
            "residual": dict(self.residual),
            "outputs": None if lay is None else {
                "original": str(lay.original), "redacted": str(lay.redacted),
                "map": str(lay.map_path) if self.map_written else None,
                "report": str(lay.report_path)},
        }


def discover(src: Path, exts: List[str]):
    files = collect(src, exts)
    skipped = [f for f in files if looks_binary(f)]
    return [f for f in files if f not in skipped], skipped


def learn(files: List[Path], r: Redactor, term: Term) -> int:
    p = Progress(term, len(files), "learning ")
    for f in files:
        for chunk in chunks(read_lines(f)):
            r.learn(chunk)
        p.step(f.name)
    p.done()
    return len(r.terms)


def _rel(f: Path, src: Path) -> str:
    return str(f.relative_to(src)) if src.is_dir() else f.name


def scan(src: Path, r: Redactor, exts: List[str], term: Term) -> JobResult:
    """Dry run: learn + redact in memory, write nothing."""
    files, skipped = discover(src, exts)
    if not files:
        raise JobError("no matching text files found")
    n = learn(files, r, term)
    per_file: Dict[str, Counter] = {}
    p = Progress(term, len(files), "scanning ")
    for f in files:
        before = Counter(r.counts)
        for chunk in chunks(strip_pem(read_lines(f))):
            r.redact(chunk)
        per_file[_rel(f, src)] = r.counts - before
        p.step(f.name)
    p.done()
    return JobResult(None, files, skipped, Counter(r.counts), per_file, Counter(), n)


def preview_lines(src: Path, r: Redactor, exts: List[str], limit: int = 12):
    """(before, after) pairs for the first lines that change. Resets token state after."""
    out = []
    files, _ = discover(src, exts)
    for f in files:
        for line in strip_pem(read_lines(f)):
            after = r.redact(line)
            if after != line:
                out.append((line.rstrip("\r\n"), after.rstrip("\r\n")))
                if len(out) >= limit:
                    break
        if len(out) >= limit:
            break
    r.reset_state()
    return out


def redact(src: Path, r: Redactor, exts: List[str], term: Term, *,
           overwrite: bool = False, move: bool = False, map_passphrase: Optional[str] = None,
           meta: Optional[Dict] = None, already_learned: bool = False) -> JobResult:
    layout = plan_paths(src)
    files, skipped = discover(src, exts)
    if not files:
        raise JobError("no matching text files found")
    for p in (layout.original, layout.redacted):
        if p.exists() and not overwrite:
            raise JobError(f"{p} already exists (use --overwrite)")

    n = len(r.terms) if already_learned else learn(files, r, term)

    for p in (layout.original, layout.redacted):
        if p.exists():
            shutil.rmtree(p) if p.is_dir() else p.unlink()

    # Preserve the untouched source first: if anything below fails, nothing is lost.
    # With --move the source is renamed (cheap on the same filesystem) and read from there.
    if move:
        src.rename(layout.original)
        read_root = layout.original
    else:
        if layout.is_dir:
            shutil.copytree(src, layout.original, symlinks=True)
        else:
            shutil.copy2(src, layout.original)
        read_root = src
    term.say(f"   {term.green(term.g('✓', 'ok'))} original preserved  " + term.dim(str(layout.original)))

    per_file: Dict[str, Counter] = {}
    residual: Counter = Counter()
    p = Progress(term, len(files), "redacting")
    for f in files:
        rel = f.relative_to(src) if layout.is_dir else None
        reading = (read_root / rel) if rel is not None else (layout.original if move else f)
        out = (layout.redacted / rel) if rel is not None else layout.redacted
        before = Counter(r.counts)
        with open_out(out) as w:
            for chunk in chunks(strip_pem(read_lines(reading))):
                red = r.redact(chunk)
                residual += r.scan_residual(red)
                w.write(red)
        try:
            shutil.copystat(reading, out)
        except OSError:
            pass
        c = r.counts - before
        per_file[_rel(f, src)] = c
        p.step(f.name, term.dim(f"{sum(c.values())} redactions"))
    p.done()

    res = JobResult(layout, files, skipped, Counter(r.counts), per_file, residual, n)

    if r.mode == "token":
        doc = build_map(r, str(src.resolve()), meta or {})
        write_map(layout.map_path, doc, map_passphrase)
        res.map_written, res.map_encrypted = True, bool(map_passphrase)

    write_report(res, r.mode)
    return res


def write_report(res: JobResult, mode: str) -> None:
    lay = res.layout
    assert lay is not None
    lines = [f"hexredact {__version__} report - {_dt.datetime.now().isoformat(timespec='seconds')}",
             f"mode: {mode}", f"files: {len(res.files)}  skipped(binary): {len(res.skipped)}",
             f"learned terms: {res.learned}", "", "totals:"]
    lines += [f"  {k:<14}{v}" for k, v in res.totals.most_common()]
    lines += ["", "per file:"]
    for fn, c in res.per_file.items():
        lines.append(f"  {fn}: " + (", ".join(f"{k}={v}" for k, v in sorted(c.items())) or "-"))
    lines += ["", "residual scan (should be empty):"]
    lines += [f"  {k}: {v}" for k, v in res.residual.items()] or ["  none"]
    if res.skipped:
        lines += ["", "skipped (binary):"] + [f"  {s.name}" for s in res.skipped]
    lay.report_path.parent.mkdir(parents=True, exist_ok=True)
    lay.report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    lay.report_path.with_suffix(".json").write_text(json.dumps(res.to_dict(), indent=2),
                                                     encoding="utf-8")
