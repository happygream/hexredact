"""Token keys, the reverse map (token -> original), lookup and restore."""

from __future__ import annotations

import datetime as _dt
import getpass
import hashlib
import json
import secrets
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from . import __version__
from .engine import TOKEN_RE, Redactor
from .files import collect, open_out, read_lines, secure_write
from .seal import SealError, is_sealed, seal, unseal

KDF_SALT = b"hexredact/v1/token-key"
KDF_ITERS = 400_000


class MapError(Exception):
    pass


# ---- token keys ----------------------------------------------------------

def random_key() -> bytes:
    return secrets.token_bytes(32)


def key_from_passphrase(pp: str) -> bytes:
    """Deterministic: the same passphrase yields the same tokens across runs."""
    return hashlib.pbkdf2_hmac("sha256", pp.encode("utf-8"), KDF_SALT, KDF_ITERS)


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(b"fp" + key).hexdigest()[:16]


# ---- encryption (stdlib, see seal.py) ----------------------------------

def encrypt_blob(data: bytes, passphrase: str) -> bytes:
    return json.dumps(seal(data, passphrase), indent=2).encode("ascii")


# ---- write / load -------------------------------------------------------

def build_map(r: Redactor, source: str, meta: Dict) -> Dict:
    return {
        "tool": f"hexredact {__version__}",
        "created": _dt.datetime.now().isoformat(timespec="seconds"),
        "source": source,
        "key_fingerprint": key_fingerprint(r.key) if r.key else None,
        **meta,
        "entries": {t: {k: v for k, v in e.items() if k != "canon"}
                    for t, e in sorted(r.map.items())},
    }


def write_map(path: Path, doc: Dict, passphrase: Optional[str] = None) -> None:
    data = json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8", "surrogateescape")
    if passphrase:
        data = encrypt_blob(data, passphrase)
    secure_write(path, data)


def is_encrypted(path: Path) -> bool:
    try:
        return is_sealed(json.loads(path.read_bytes()))
    except (OSError, ValueError):
        return False


def load_map(path: Path, passphrase: Optional[str] = None) -> Dict:
    try:
        raw = json.loads(path.read_bytes())
    except (OSError, ValueError) as e:
        raise MapError(f"cannot read map {path}: {e}") from e
    if is_sealed(raw):
        if passphrase is None:
            passphrase = getpass.getpass("Map passphrase: ")
        try:
            raw = json.loads(unseal(raw, passphrase).decode("utf-8", "surrogateescape"))
        except SealError as e:
            raise MapError(str(e)) from e
    if "entries" not in raw:
        raise MapError(f"{path} is not a hexredact map")
    return raw


# ---- lookup / restore ---------------------------------------------------

def lookup(entries: Dict, tokens: Iterable[str]) -> List[Dict]:
    out = []
    for t in tokens:
        t = t.strip()
        if not t:
            continue
        if not t.startswith("<"):
            t = f"<{t}>"
        e = entries.get(t)
        out.append({"token": t, **e} if e else {"token": t, "value": None})
    return out


def _restore_file(entries: Dict, src: Path, dst: Path) -> int:
    n = 0

    def sub(m):
        nonlocal n
        e = entries.get(m.group(0))
        if e:
            n += 1
            return e["value"]
        return m.group(0)

    with open_out(dst) as w:
        for line in read_lines(src):
            w.write(TOKEN_RE.sub(sub, line))
    try:
        dst.chmod(0o600)
    except OSError:
        pass
    return n


def restore(entries: Dict, src: Path, out: Optional[Path] = None) -> Path:
    """Rehydrate a redacted file or a whole *_redacted directory.

    Values that appeared in several surface forms (e.g. the same phone number
    written two ways) come back in their first-seen form; the map lists the
    other forms under "variants".
    """
    if out is None:
        name = src.name.replace("_redacted", "_restored") if "_redacted" in src.name else (
            src.name + "_restored" if src.is_dir() else f"{src.stem}_restored{src.suffix}")
        out = src.with_name(name)
    if src.is_dir():
        for f in collect(src, [""]):
            if f.name == "redaction_report.txt":
                continue
            _restore_file(entries, f, out / f.relative_to(src))
    else:
        _restore_file(entries, src, out)
    return out
