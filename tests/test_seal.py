import base64
import json
import os

import pytest

from hexredact import seal as S


def roundtrip(data, pp="correct horse battery"):
    return S.unseal(json.loads(json.dumps(S.seal(data, pp))), pp)


@pytest.mark.parametrize("n", [0, 1, 31, 32, 33, 1000, 250_000])
def test_roundtrip_sizes(n):
    data = os.urandom(n)
    assert roundtrip(data) == data


def test_leading_zero_bytes_survive():
    data = b"\x00\x00\x00abc\x00"
    assert roundtrip(data) == data


def test_fresh_salt_and_nonce_each_time():
    a, b = S.seal(b"same", "pw-pw-pw-pw"), S.seal(b"same", "pw-pw-pw-pw")
    assert a["salt"] != b["salt"] and a["nonce"] != b["nonce"] and a["data"] != b["data"]


def test_ciphertext_hides_plaintext():
    env = S.seal(b"10.26.190.67 alice@example.com", "pw-pw-pw-pw")
    assert b"alice" not in base64.b64decode(env["data"])


def test_wrong_passphrase():
    env = S.seal(b"secret", "right-passphrase")
    with pytest.raises(S.SealError, match="wrong passphrase"):
        S.unseal(env, "wrong-passphrase")


@pytest.mark.parametrize("field", ["data", "salt", "nonce", "tag"])
def test_tamper_detected(field):
    env = S.seal(b"secret value here", "pw-pw-pw-pw")
    raw = bytearray(base64.b64decode(env[field]))
    raw[0] ^= 1
    env[field] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(S.SealError):
        S.unseal(env, "pw-pw-pw-pw")


def test_header_change_breaks_tag():
    env = S.seal(b"secret", "pw-pw-pw-pw")
    env["kdf"] = dict(env["kdf"], n=2 ** 15, r=9)    # valid params, but not what was signed
    with pytest.raises(S.SealError):
        S.unseal(env, "pw-pw-pw-pw")


@pytest.mark.parametrize("kdf", [
    {"name": "scrypt", "n": 2 ** 30, "r": 8, "p": 1},       # memory bomb
    {"name": "scrypt", "n": 3000, "r": 8, "p": 1},          # not a power of two
    {"name": "pbkdf2-sha256", "iterations": 10 ** 9},       # cpu bomb
    {"name": "md5"},
])
def test_hostile_kdf_params_rejected_before_work(kdf):
    env = S.seal(b"x", "pw-pw-pw-pw")
    env["kdf"] = kdf
    with pytest.raises(S.SealError):
        S.unseal(env, "pw-pw-pw-pw")


def test_old_prerelease_format_gets_clear_error():
    with pytest.raises(S.SealError, match="older pre-release"):
        S.unseal({"hexredact_encrypted": 1, "cipher": "fernet"}, "x")


def test_pbkdf2_fallback_roundtrip(monkeypatch):
    monkeypatch.delattr(S.hashlib, "scrypt")
    env = S.seal(b"no scrypt here", "pw-pw-pw-pw")
    assert env["kdf"]["name"] == "pbkdf2-sha256"
    assert S.unseal(env, "pw-pw-pw-pw") == b"no scrypt here"
