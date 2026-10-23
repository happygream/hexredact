"""Token keys, the reverse map (token -> original), lookup and restore."""

from __future__ import annotations

import base64
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


# ---- optional encryption ------------------------------------------------

def have_crypto() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def _scrypt(pp: str, salt: bytes) -> bytes:
    return hashlib.scrypt(pp.encode("utf-8"), salt=salt, n=2 ** 15, r=8, p=1,
                          maxmem=64 * 2 ** 20, dklen=32)


def encrypt_blob(data: bytes, passphrase: str) -> bytes:
    from cryptography.fernet import Fernet
    salt = secrets.token_bytes(16)
    token = Fernet(base64.urlsafe_b64encode(_scrypt(passphrase, salt))).encrypt(data)
    return json.dumps({"hexredact_encrypted": 1, "kdf": "scrypt-n32768-r8-p1",
                       "cipher": "fernet", "salt": base64.b64encode(salt).decode(),
                       "data": token.decode()}).encode()


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
        return bool(json.loads(path.read_bytes()).get("hexredact_encrypted"))
    except (OSError, ValueError, AttributeError):
        return False


def load_map(path: Path, passphrase: Optional[str] = None) -> Dict:
    try:
        raw = json.loads(path.read_bytes())
    except (OSError, ValueError) as e:
        raise MapError(f"cannot read map {path}: {e}") from e
    if raw.get("hexredact_encrypted"):
        if not have_crypto():
            raise MapError("map is encrypted; install the extra: pip install 'hexredact[crypto]'")
        from cryptography.fernet import Fernet, InvalidToken
        if passphrase is None:
            passphrase = getpass.getpass("Map passphrase: ")
        key = _scrypt(passphrase, base64.b64decode(raw["salt"]))
        try:
            raw = json.loads(Fernet(base64.urlsafe_b64encode(key)).decrypt(raw["data"].encode()))
        except InvalidToken as e:
            raise MapError("wrong map passphrase") from e
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
