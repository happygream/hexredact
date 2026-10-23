"""Passphrase encryption for reverse maps, standard library only.

Construction (envelope version 2):

    dk       = scrypt(passphrase, salt, N=2^15, r=8, p=1, dklen=64)
               (PBKDF2-HMAC-SHA256, 600k iterations, if this Python lacks scrypt)
    enc_key  = dk[:32]          mac_key = dk[32:]
    stream   = HMAC-SHA256(enc_key, LABEL || nonce || ctr_be64) for ctr = 0, 1, ...
    ct       = plaintext XOR stream
    tag      = HMAC-SHA256(mac_key, canonical_json(header) || ct)

A keyed PRF in counter mode (as in NIST SP 800-108) with a fresh 128-bit random
nonce per message, then encrypt-then-MAC over everything that affects
decryption. The tag is checked in constant time before any decryption, and KDF
parameters read from a file are bounded so a hostile map cannot exhaust memory.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from typing import Dict, Tuple

VERSION = 2
LABEL = b"hexredact/v2/keystream"
SCRYPT = {"name": "scrypt", "n": 2 ** 15, "r": 8, "p": 1}
PBKDF2 = {"name": "pbkdf2-sha256", "iterations": 600_000}
_MAXMEM = 128 * 2 ** 20


class SealError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as e:
        raise SealError("malformed encrypted map") from e


def _derive(passphrase: str, salt: bytes, kdf: Dict) -> Tuple[bytes, bytes]:
    pw = passphrase.encode("utf-8")
    if kdf.get("name") == "scrypt":
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
        if not (2 ** 14 <= n <= 2 ** 20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4):
            raise SealError("refusing unsafe or unreasonable scrypt parameters")
        if not hasattr(hashlib, "scrypt"):
            raise SealError("this map needs scrypt, which this Python build lacks")
        dk = hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, maxmem=_MAXMEM, dklen=64)
    elif kdf.get("name") == "pbkdf2-sha256":
        it = int(kdf["iterations"])
        if not 100_000 <= it <= 10_000_000:
            raise SealError("refusing unreasonable PBKDF2 iteration count")
        dk = hashlib.pbkdf2_hmac("sha256", pw, salt, it, dklen=64)
    else:
        raise SealError(f"unknown KDF {kdf.get('name')!r}")
    return dk[:32], dk[32:]


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    base = hmac.new(key, LABEL + nonce, hashlib.sha256)
    out = bytearray()
    ctr = 0
    while len(out) < n:
        h = base.copy()
        h.update(ctr.to_bytes(8, "big"))
        out += h.digest()
        ctr += 1
    return bytes(out[:n])


def _xor(a: bytes, b: bytes) -> bytes:
    if not a:
        return b""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _canonical(header: Dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _header_of(env: Dict) -> Dict:
    return {k: v for k, v in env.items() if k not in ("data", "tag")}


def seal(plaintext: bytes, passphrase: str) -> Dict:
    if not passphrase:
        raise SealError("empty passphrase")
    kdf = dict(SCRYPT) if hasattr(hashlib, "scrypt") else dict(PBKDF2)
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(16)
    enc_key, mac_key = _derive(passphrase, salt, kdf)
    ct = _xor(plaintext, _keystream(enc_key, nonce, len(plaintext)))
    header = {"hexredact_encrypted": VERSION, "kdf": kdf, "cipher": "hmac-sha256-ctr",
              "mac": "hmac-sha256", "salt": _b64(salt), "nonce": _b64(nonce)}
    tag = hmac.new(mac_key, _canonical(header) + ct, hashlib.sha256).digest()
    return {**header, "data": _b64(ct), "tag": _b64(tag)}


def unseal(env: Dict, passphrase: str) -> bytes:
    if env.get("hexredact_encrypted") != VERSION:
        raise SealError("this map was encrypted by an older pre-release build; re-run the redaction to recreate it")
    if env.get("cipher") != "hmac-sha256-ctr" or env.get("mac") != "hmac-sha256":
        raise SealError("unknown cipher in encrypted map")
    try:
        salt, nonce = _unb64(env["salt"]), _unb64(env["nonce"])
        ct, tag = _unb64(env["data"]), _unb64(env["tag"])
        kdf = env["kdf"]
    except KeyError as e:
        raise SealError("malformed encrypted map") from e
    if len(salt) != 16 or len(nonce) != 16 or len(tag) != 32:
        raise SealError("malformed encrypted map")
    enc_key, mac_key = _derive(passphrase, salt, kdf)
    want = hmac.new(mac_key, _canonical(_header_of(env)) + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(want, tag):
        raise SealError("wrong passphrase, or the map has been modified")
    return _xor(ct, _keystream(enc_key, nonce, len(ct)))


def is_sealed(obj) -> bool:
    return isinstance(obj, dict) and "hexredact_encrypted" in obj
