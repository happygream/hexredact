"""Command-line interface."""

from __future__ import annotations

import argparse
import getpass
import io
import json
import os
import re
import socket
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import __version__
from .engine import Redactor, strip_pem
from .files import DEFAULT_EXTS, collect, normalise_exts, plan_paths
from .job import JobError, JobResult, preview_lines, redact as run_redact, scan as run_scan
from .mapfile import (MapError, have_crypto, key_from_passphrase, load_map, lookup,
                      random_key, restore, write_map, build_map)
from .patterns import DETECTOR_NAMES, DETECTORS

EXIT_OK, EXIT_ERR, EXIT_USAGE, EXIT_RESIDUAL = 0, 1, 2, 3

# Unix permission bits mean nothing on Windows; describe what actually protects the file.
PROTECTED = "owner-only 0600" if os.name == "posix" else "keep private"


def _prog() -> str:
    """How the user launched us, so printed hints can be pasted back verbatim."""
    argv0 = Path(sys.argv[0]).name.lower() if sys.argv and sys.argv[0] else ""
    return "python -m hexredact" if argv0 in ("__main__.py", "-m", "-c", "") else "hexredact"


def _q(p) -> str:
    return f'"{p}"' if " " in str(p) or os.name == "nt" else str(p)


def _term(args):
    from .ui import Term
    color = False if getattr(args, "no_color", False) else None
    return Term(color=color, quiet=getattr(args, "quiet", False))


# --------------------------------------------------------------------------
# option groups
# --------------------------------------------------------------------------

def _split(v: Optional[str]) -> List[str]:
    return [x.strip() for x in re.split(r",", v or "") if x.strip()]


def _add_detection_opts(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("detection")
    g.add_argument("--only", metavar="NAMES", help="comma-separated detectors to enable (see `hexredact detectors`)")
    g.add_argument("--disable", metavar="NAMES", help="comma-separated detectors to disable")
    g.add_argument("--terms", metavar="LIST", help="extra terms to redact everywhere (names, company, hosts)")
    g.add_argument("--terms-file", metavar="FILE", help="file with one extra term per line")
    g.add_argument("--allow", metavar="LIST", help="values never to redact")
    g.add_argument("--exts", metavar="LIST", default=",".join(DEFAULT_EXTS),
                   help="extensions to process in directories (default: %(default)s; rotated .log.N/.gz always)")
    g.add_argument("--no-auto-terms", action="store_true",
                   help="don't add this machine's hostname and current username to the terms")
    g.add_argument("--redact-loopback", action="store_true",
                   help="also tokenise 127.0.0.1, ::1, 0.0.0.0 (kept readable by default)")


def _add_key_opts(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("tokens")
    g.add_argument("--mode", choices=["token", "mask"], default="token",
                   help="token: keyed HMAC pseudonyms + reverse map (default); mask: [REDACTED:TYPE], irreversible")
    x = g.add_mutually_exclusive_group()
    x.add_argument("--passphrase-env", metavar="VAR", help="derive the token key from this env var (stable tokens across runs)")
    x.add_argument("--passphrase-file", metavar="FILE", help="derive the token key from this file's first line")
    x.add_argument("--ask-passphrase", action="store_true", help="prompt for the token passphrase")


def _add_output_opts(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("output")
    g.add_argument("--overwrite", action="store_true", help="replace existing *_original / *_redacted outputs")
    g.add_argument("--move", action="store_true", help="move the source to *_original instead of copying it")
    g.add_argument("--map", metavar="FILE", help="reverse-map path (required when reading stdin in token mode)")
    m = g.add_mutually_exclusive_group()
    m.add_argument("--encrypt-map", action="store_true", help="prompt for a passphrase and encrypt the map (needs [crypto] extra)")
    m.add_argument("--map-passphrase-env", metavar="VAR", help="encrypt the map with the passphrase in this env var")
    g.add_argument("--strict", action="store_true", help=f"exit {EXIT_RESIDUAL} if the residual scan finds anything")
    g.add_argument("--json", action="store_true", help="print the result as JSON on stdout")


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("-q", "--quiet", action="store_true", help="only print errors and the final summary")
    p.add_argument("--no-color", action="store_true", help="disable colour (NO_COLOR is honoured too)")


# --------------------------------------------------------------------------
# building a Redactor from options
# --------------------------------------------------------------------------

def _enabled(args) -> Set[str]:
    only, disable = _split(args.only), _split(args.disable)
    bad = [n for n in only + disable if n not in DETECTOR_NAMES]
    if bad:
        raise SystemExit(f"error: unknown detector(s): {', '.join(bad)} (see `hexredact detectors`)")
    enabled = set(only) if only else set(DETECTOR_NAMES)
    return enabled - set(disable)


def _resolve_key(args, term) -> Tuple[Optional[bytes], Dict]:
    if args.mode == "mask":
        return None, {"key_source": None}
    if args.passphrase_env:
        pp = os.environ.get(args.passphrase_env)
        if not pp:
            raise SystemExit(f"error: env var {args.passphrase_env} is empty or unset")
        return key_from_passphrase(pp), {"key_source": "passphrase-pbkdf2"}
    if args.passphrase_file:
        pp = Path(args.passphrase_file).read_text(encoding="utf-8").splitlines()[0]
        return key_from_passphrase(pp), {"key_source": "passphrase-pbkdf2"}
    if args.ask_passphrase:
        return key_from_passphrase(term.ask_secret("token passphrase")), {"key_source": "passphrase-pbkdf2"}
    return random_key(), {"key_source": "random"}


def _map_passphrase(args, term) -> Optional[str]:
    if getattr(args, "map_passphrase_env", None):
        pp = os.environ.get(args.map_passphrase_env)
        if not pp:
            raise SystemExit(f"error: env var {args.map_passphrase_env} is empty or unset")
    elif getattr(args, "encrypt_map", False):
        pp = None
    else:
        return None
    if args.mode != "token":
        return None
    if not have_crypto():
        raise SystemExit("error: map encryption needs the crypto extra: pip install 'hexredact[crypto]'")
    return pp or term.ask_secret("map passphrase")


def _auto_terms() -> Tuple[List[str], List[str]]:
    hosts = [h for h in {socket.gethostname(), socket.getfqdn()} if h]
    try:
        users = [getpass.getuser()]
    except Exception:
        users = []
    return hosts, users


def _build(args, term, key: Optional[bytes]) -> Redactor:
    r = Redactor(args.mode, key, _enabled(args),
                 keep_trivial_ips=not args.redact_loopback, allow=set(_split(args.allow)))
    terms = _split(args.terms)
    if args.terms_file:
        terms += [ln.strip() for ln in Path(args.terms_file).read_text(encoding="utf-8").splitlines()
                  if ln.strip() and not ln.lstrip().startswith("#")]
    r.add_terms(terms, "TERM")
    if not args.no_auto_terms:
        hosts, users = _auto_terms()
        r.add_terms(hosts, "HOST")
        r.add_terms(users, "USER")
    return r


# --------------------------------------------------------------------------
# summaries
# --------------------------------------------------------------------------

def _print_totals(term, res: JobResult) -> None:
    if not res.totals:
        term.say("   " + term.dim("nothing detected"))
        return
    rows = [(k, str(v)) for k, v in res.totals.most_common()]
    term.table(rows, ("category", "count"))


def _print_result(term, res: JobResult, mode: str) -> None:
    lay = res.layout
    term.section("Result")
    rows = [("redacted", str(lay.redacted)), ("original", str(lay.original))]
    if res.map_written:
        state = "encrypted" if res.map_encrypted else term.yellow(f"plaintext, {PROTECTED} - treat as sensitive")
        rows.append(("map", f"{lay.map_path}  {term.dim('(')}{state}{term.dim(')')}"))
    rows.append(("report", str(lay.report_path)))
    term.kv(rows)
    term.section(f"Redactions  {term.dim(str(res.total) + ' total, ' + str(res.learned) + ' learned terms')}")
    _print_totals(term, res)
    if res.skipped:
        term.warn(f"skipped {len(res.skipped)} binary file(s): " + ", ".join(p.name for p in res.skipped[:5]))
    if res.residual:
        term.say("\n   " + term.yellow(f"residual scan flagged {sum(res.residual.values())} item(s): "
                                       f"{dict(res.residual)} - review the output"), force=True)
    else:
        term.say("\n   " + term.green("residual scan: clean"))
    if mode == "token":
        term.say(term.dim(f"\n   look up a token:  {_prog()} lookup {_q(lay.map_path)} '<TOKEN>'"))


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_detectors(args) -> int:
    from .ui import Term
    term = Term(stream=sys.stdout, color=False if args.no_color else None)
    if args.json:
        print(json.dumps([{"name": d.name, "category": d.cat, "description": d.desc}
                          for d in DETECTORS], indent=2))
        return EXIT_OK
    term.section("Detectors " + term.dim("(applied in this order; all enabled by default)"))
    term.table([(str(i), d.name, d.cat, d.desc) for i, d in enumerate(DETECTORS, 1)],
               ("#", "name", "category", "description"))
    term.say(term.dim("\n   enable a subset with --only a,b   disable with --disable a,b"))
    return EXIT_OK


def _redact_stdin(args, term) -> int:
    key, meta = _resolve_key(args, term)
    if args.mode == "token" and not args.map:
        term.error("reading stdin in token mode needs --map FILE for the reverse map (or use --mode mask)")
        return EXIT_USAGE
    r = _build(args, term, key)
    data = sys.stdin.buffer.read().decode("utf-8", "surrogateescape")
    r.learn(data)
    text = "".join(strip_pem(io.StringIO(data, newline="")))
    out = r.redact(text)
    sys.stdout.buffer.write(out.encode("utf-8", "surrogateescape"))
    sys.stdout.flush()
    if args.mode == "token":
        write_map(Path(args.map), build_map(r, "<stdin>", meta), _map_passphrase(args, term))
    residual = r.scan_residual(out)
    if residual:
        term.warn(f"residual scan flagged {dict(residual)}")
        if args.strict:
            return EXIT_RESIDUAL
    return EXIT_OK


def cmd_redact(args) -> int:
    term = _term(args)
    if args.path == "-":
        return _redact_stdin(args, term)
    src = Path(args.path).expanduser().resolve()
    if not src.exists():
        term.error(f"{src} not found")
        return EXIT_ERR
    if args.map:
        term.warn("--map is only used with stdin input; the map goes next to the *_original output")
    key, meta = _resolve_key(args, term)
    map_pp = _map_passphrase(args, term)
    r = _build(args, term, key)
    if not args.quiet and not args.json:
        term.banner(__version__)
    try:
        res = run_redact(src, r, normalise_exts(_split(args.exts)), term, overwrite=args.overwrite,
                         move=args.move, map_passphrase=map_pp, meta=meta)
    except JobError as e:
        term.error(str(e))
        return EXIT_ERR
    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        _print_result(term, res, args.mode)
    return EXIT_RESIDUAL if (args.strict and res.residual) else EXIT_OK


def cmd_scan(args) -> int:
    term = _term(args)
    src = Path(args.path).expanduser().resolve()
    if not src.exists():
        term.error(f"{src} not found")
        return EXIT_ERR
    args.mode = "token"
    r = _build(args, term, random_key())
    exts = normalise_exts(_split(args.exts))
    try:
        res = run_scan(src, r, exts, term)
    except JobError as e:
        term.error(str(e))
        return EXIT_ERR
    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
        return EXIT_OK
    term.section(f"Would redact  {term.dim(str(res.total) + ' item(s) in ' + str(len(res.files)) + ' file(s)')}")
    _print_totals(term, res)
    if args.show:
        r.reset_state()
        term.section("Sample " + term.dim("(original lines are shown - local terminal only)"))
        for before, after in preview_lines(src, r, exts, args.show):
            term.say("  " + term.red("-") + " " + before[:200])
            term.say("  " + term.green("+") + " " + after[:200])
    term.say(term.dim(f"\n   nothing was written. run `{_prog()} redact {_q(args.path)}` to apply."))
    return EXIT_OK


def _load_entries(args) -> Dict:
    pp = os.environ.get(args.map_passphrase_env) if args.map_passphrase_env else None
    return load_map(Path(args.map), pp)["entries"]


def cmd_lookup(args) -> int:
    term = _term(args)
    try:
        entries = _load_entries(args)
    except MapError as e:
        term.error(str(e))
        return EXIT_ERR
    toks = list(args.tokens)
    if not toks and not sys.stdin.isatty():
        toks = re.findall(r"<[A-Z][A-Z0-9_]*_[0-9a-f]{10,16}>", sys.stdin.read())
    rows = lookup(entries, toks)
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return EXIT_OK if all(r["value"] is not None for r in rows) else EXIT_ERR
    missing = 0
    for r in rows:
        if r["value"] is None:
            missing += 1
            print(f"{r['token']}\t" + term.red("not in map"))
        else:
            extra = f"  (also: {', '.join(r['variants'])})" if r.get("variants") else ""
            print(f"{r['token']}\t{r['value']}\t{term.dim(r['category'] + ', seen ' + str(r['count']) + 'x' + extra)}")
    return EXIT_ERR if missing else EXIT_OK


def cmd_restore(args) -> int:
    term = _term(args)
    try:
        entries = _load_entries(args)
    except MapError as e:
        term.error(str(e))
        return EXIT_ERR
    src = Path(args.path).expanduser().resolve()
    if not src.exists():
        term.error(f"{src} not found")
        return EXIT_ERR
    out = restore(entries, src, Path(args.output).resolve() if args.output else None)
    term.say(f"{term.green('restored')} -> {out} " + term.dim(f"({PROTECTED}; contains the original values)"), force=True)
    return EXIT_OK


# --------------------------------------------------------------------------
# interactive wizard
# --------------------------------------------------------------------------

def cmd_wizard(args) -> int:
    from .ui import Term
    term = Term(color=False if getattr(args, "no_color", False) else None)
    term.banner(__version__)
    try:
        rc = _wizard(term, getattr(args, "path", None))
    except (KeyboardInterrupt, EOFError):
        term.say("\n" + term.dim("aborted"))
        rc = EXIT_ERR
    except Exception as e:                 # never let a double-clicked window vanish on a traceback
        if not getattr(args, "pause", False):
            raise
        term.error(f"{type(e).__name__}: {e}")
        rc = EXIT_ERR
    if getattr(args, "pause", False):
        try:
            term.out.write("\n" + term.dim("press Enter to close") + " ")
            term.out.flush()
            sys.stdin.readline()
        except (KeyboardInterrupt, EOFError):
            pass
    return rc


def _clean_path(raw: str) -> Path:
    """Paths dragged into a terminal arrive quoted (Windows) or backslash-escaped (macOS)."""
    raw = raw.strip().strip('"\'')
    if os.name != "nt":
        raw = re.sub(r"\\(.)", r"\1", raw)
    return Path(raw).expanduser().resolve()


def _ask_path(term, prompt: str, must_exist: bool = True, default: Optional[str] = None) -> Path:
    while True:
        p = _clean_path(term.ask(prompt + term.dim("  (drag a file or folder here)"), default))
        if p.exists() or not must_exist:
            return p
        term.say(term.red("   not found: ") + str(p))


def _wizard(term, pre_path: Optional[str]) -> int:
    pre = _clean_path(pre_path) if pre_path else None
    if pre is not None and not pre.exists():
        term.warn(f"{pre} not found")
        pre = None

    action = term.choose("What do you want to do", [
        "Redact",
        "Scan only",
        "Look up a token",
        "Restore",
    ], hints=[
        "write a redacted copy, keep the original and a reverse map",
        "dry run: show what would be redacted, write nothing",
        "turn <TOKEN> back into the original value",
        "rehydrate a redacted file or folder from its map",
    ])

    if action in (3, 4):
        map_path = _ask_path(term, "Map file")
        try:
            entries = load_map(map_path)["entries"]
        except MapError as e:
            term.error(str(e))
            return EXIT_ERR
        if action == 3:
            while True:
                raw = term.ask("Token(s)  " + term.dim("Enter on its own to finish"))
                toks = re.findall(r"<?[A-Z][A-Z0-9_]*_[0-9a-f]{10,16}>?", raw)
                if not toks:
                    return EXIT_OK
                for r in lookup(entries, toks):
                    val = r["value"] if r["value"] is not None else term.red("not in map")
                    term.say(f"   {term.dim(r['token'])}  {val}", force=True)
        out = restore(entries, _ask_path(term, "Redacted file or folder"))
        term.say(f"   {term.green('restored')} -> {out}  " + term.dim(f"({PROTECTED}; contains the original values)"), force=True)
        return EXIT_OK

    if pre is not None:
        src = pre
        term.say(f"{term.green(term.g('✓', '+'))} Path  {term.cyan(str(src))}")
    else:
        src = _ask_path(term, "Path to a log file or folder")
    exts = DEFAULT_EXTS
    if src.is_dir():
        exts = normalise_exts(_split(term.ask("Extensions", ",".join(DEFAULT_EXTS))))
        n = len(collect(src, exts))
        term.say(term.dim(f"   {n} matching file(s); rotated .log.N and .gz included"))
        if not n:
            term.error("no matching files in that folder")
            return EXIT_ERR

    ns = argparse.Namespace(only=None, disable=None, terms=None, terms_file=None, allow=None,
                            no_auto_terms=False, redact_loopback=False, mode="token",
                            passphrase_env=None, passphrase_file=None, ask_passphrase=False,
                            encrypt_map=False, map_passphrase_env=None)
    key, meta, map_pp = None, {"key_source": None}, None

    if action == 1:
        ns.mode = "token" if term.choose("Mode", ["Tokenise", "Mask"], hints=[
            "keyed pseudonyms + reverse map, so you can look values up later (recommended)",
            "[REDACTED:TYPE] labels, irreversible, no map",
        ]) == 1 else "mask"
        if ns.mode == "token":
            if term.choose("Token key", ["Random", "Passphrase"], hints=[
                "tokens unique to this job",
                "same passphrase gives the same tokens across jobs",
            ]) == 1:
                key, meta = random_key(), {"key_source": "random"}
            else:
                key, meta = key_from_passphrase(term.ask_secret("token passphrase")), {"key_source": "passphrase-pbkdf2"}
            if have_crypto():
                if term.yes("Encrypt the reverse map", True):
                    map_pp = term.ask_secret("map passphrase")
            else:
                term.say(term.yellow(f"   reverse map will be plaintext ({PROTECTED}). ")
                         + term.dim("pip install 'hexredact[crypto]' to encrypt it"))

    picked = term.pick_many("Detectors", [d.desc for d in DETECTORS], set(range(len(DETECTORS))),
                            details=[f"{d.name} -> {d.cat}" for d in DETECTORS])
    ns.only = ",".join(DETECTORS[i].name for i in sorted(picked))

    ns.terms = term.ask("Extra terms to redact everywhere " + term.dim("(names, company, hosts; comma-separated, optional)"))
    ns.no_auto_terms = not term.yes("Also redact this machine's hostname and your username", True)
    ns.allow = term.ask("Never redact " + term.dim("(comma-separated, optional)"))
    ns.redact_loopback = not term.yes("Keep loopback IPs (127.0.0.1, ::1, 0.0.0.0) readable", True)

    r = _build(ns, term, key or random_key())
    if action == 2:
        res = run_scan(src, r, exts, term)
        term.section(f"Would redact  {term.dim(str(res.total) + ' item(s)')}")
        _print_totals(term, res)
        r.reset_state()
        pairs = preview_lines(src, r, exts)
        if pairs:
            term.section("Sample " + term.dim("(original lines shown - local terminal only)"))
            for before, after in pairs:
                term.say("  " + term.red("-") + " " + before[:160])
                term.say("  " + term.green("+") + " " + after[:160])
        term.say(term.dim("\n   nothing was written"))
        return EXIT_OK

    term.section("Learning")
    from .job import discover, learn
    files, _ = discover(src, exts)
    if not files:
        term.error("no matching text files found")
        return EXIT_ERR
    learn(files, r, term)

    term.section("Preview " + term.dim("(first changed lines)"))
    pairs = preview_lines(src, r, exts)
    for before, after in pairs:
        term.say("  " + term.red("-") + " " + before[:160])
        term.say("  " + term.green("+") + " " + after[:160])
    if not pairs:
        term.say("   " + term.dim("nothing detected in the sample"))
    term.say("")

    lay = plan_paths(src)
    exists = lay.original.exists() or lay.redacted.exists()
    if exists:
        term.warn(f"{lay.original.name} / {lay.redacted.name} already exist")
    if not term.yes("Write redacted output" + (" and OVERWRITE" if exists else ""), not exists):
        term.say(term.dim("aborted"))
        return EXIT_ERR
    term.say("")
    try:
        res = run_redact(src, r, exts, term, overwrite=exists, map_passphrase=map_pp,
                         meta=meta, already_learned=True)
    except JobError as e:
        term.error(str(e))
        return EXIT_ERR
    _print_result(term, res, ns.mode)
    return EXIT_OK


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

EPILOG = """examples:
  hexredact                                   interactive wizard
  hexredact scan /var/log/nginx --show 10     dry run with a before/after sample
  hexredact redact /var/log/nginx             -> nginx_original/ + nginx_redacted/
  hexredact redact app.log --mode mask        irreversible labels, no map
  P=secret hexredact redact logs/ --passphrase-env P   stable tokens across runs
  journalctl -b | hexredact redact - --map boot.map.json > boot.redacted.log
  hexredact lookup logs_original/redaction_map.json '<IPV4_PRIV_3f9a2c1b07>'
  hexredact restore logs_original/redaction_map.json logs_redacted/
"""


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hexredact", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Heavy, reversible redaction of PII, secrets and infrastructure identifiers in logs.",
        epilog=EPILOG)
    ap.add_argument("-V", "--version", action="version", version=f"hexredact {__version__}")
    sub = ap.add_subparsers(dest="cmd", metavar="COMMAND")

    p = sub.add_parser("redact", help="redact a file, directory or stdin ('-')",
                       formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG)
    p.add_argument("path", help="file, directory, or - for stdin")
    _add_key_opts(p); _add_detection_opts(p); _add_output_opts(p); _add_common(p)
    p.set_defaults(func=cmd_redact)

    p = sub.add_parser("scan", help="dry run: report what would be redacted, write nothing")
    p.add_argument("path")
    p.add_argument("--show", type=int, default=0, metavar="N", help="print N before/after sample lines")
    p.add_argument("--json", action="store_true")
    _add_detection_opts(p); _add_common(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("lookup", help="resolve tokens via a reverse map (tokens may also be piped in)")
    p.add_argument("map")
    p.add_argument("tokens", nargs="*")
    p.add_argument("--map-passphrase-env", metavar="VAR")
    p.add_argument("--json", action="store_true")
    _add_common(p)
    p.set_defaults(func=cmd_lookup)

    p = sub.add_parser("restore", help="rehydrate a redacted file or directory from its map")
    p.add_argument("map")
    p.add_argument("path")
    p.add_argument("-o", "--output", metavar="PATH")
    p.add_argument("--map-passphrase-env", metavar="VAR")
    _add_common(p)
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("detectors", help="list detectors in the order they run")
    p.add_argument("--json", action="store_true")
    _add_common(p)
    p.set_defaults(func=cmd_detectors)

    p = sub.add_parser("wizard", help="interactive mode (the default with no arguments)")
    p.add_argument("path", nargs="?")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--pause", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_wizard)
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = build_parser()
    if not argv:
        return cmd_wizard(argparse.Namespace(path=None))
    args = ap.parse_args(argv)
    if not getattr(args, "cmd", None):
        ap.print_help()
        return EXIT_USAGE
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return EXIT_OK
