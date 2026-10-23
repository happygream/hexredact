import re

import pytest

from hexredact.engine import TOKEN_RE, Redactor
from hexredact.patterns import DETECTOR_NAMES


def make(mode="token", **kw):
    return Redactor(mode, b"k" * 32, set(DETECTOR_NAMES), **kw)


def cats(text, **kw):
    r = make(**kw)
    r.learn(text)
    out = r.redact(text)
    return out, [m.group(1) for m in TOKEN_RE.finditer(out)]


# ---- phones vs IPs: the core guarantee ---------------------------------

@pytest.mark.parametrize("ip", ["10.26.190.67", "10.0.0.12", "8.8.8.8", "172.16.4.4", "203.0.113.77"])
def test_ipv4_is_never_a_phone(ip):
    out, c = cats(f"from {ip} port 22")
    assert len(c) == 1 and c[0].startswith("IPV4_")
    assert "PHONE" not in out


@pytest.mark.parametrize("phone", ["+44 20 7946 0958", "07700 900123", "020 7946 0958",
                                   "(555) 123-4567", "555-123-4567", "+1 555 123 4567"])
def test_phone_is_never_an_ip(phone):
    out, c = cats(f"call {phone} now")
    assert c == ["PHONE"], (phone, out)


def test_ip_and_phone_adjacent():
    out, c = cats("ip 10.1.2.3 phone 020 7946 0958 ip 8.8.4.4")
    assert c == ["IPV4_PRIV", "PHONE", "IPV4_PUB"]


def test_ip_scopes():
    _, c = cats("a 10.0.0.1 b 8.8.8.8 c 203.0.113.9 d fe80::1 e 2001:4860:4860::8888")
    assert c == ["IPV4_PRIV", "IPV4_PUB", "IPV4_RSVD", "IPV6_PRIV", "IPV6_PUB"]


def test_port_and_cidr_kept():
    out, _ = cats("listen 10.0.0.5:8443 net 10.20.0.0/16")
    assert ":8443" in out and "/16" in out


def test_loopback_kept_by_default_and_optional():
    assert "127.0.0.1" in cats("hc 127.0.0.1")[0]
    assert "127.0.0.1" not in cats("hc 127.0.0.1", keep_trivial_ips=False)[0]


# ---- false positives that must survive --------------------------------

@pytest.mark.parametrize("line", [
    "version 1.2.3 build 20261023",
    "epoch 1729700000 pid 004512",
    "elapsed 00:12:33.456 date 2026-10-23",
    "time 12:34:56",
    "java.lang.NullPointerException at com.example.App.main(App.java:42)",
    "logger.info file.name obj.id",
    "took 3ms status 200 bytes 51234",
])
def test_not_redacted(line):
    out, c = cats(line)
    assert c == [], (line, out)


# ---- coverage ----------------------------------------------------------

@pytest.mark.parametrize("text,cat", [
    ("mail alice.smith@example.com", "EMAIL"),
    ("card 4111 1111 1111 1111", "CARD"),
    ("ni AB 12 34 56 C", "NINO"),
    ("ssn 123-45-6789", "SSN"),
    ("iban GB82 WEST 1234 5698 7654 32", "IBAN"),
    ("mac aa:bb:cc:dd:ee:ff", "MAC"),
    ("id 3f2504e0-4f89-11d3-9a0c-0305e82c3301", "UUID"),
    ("key AKIAIOSFODNN7EXAMPLE", "APIKEY"),
    ("host db-primary.corp.example.co.uk up", "HOST"),
    ("sid S-1-5-21-1004336348-1177238915-682003330-512", "SID"),
    ("at 51.5074, -0.1278", "GEO"),
    ("office SW1A 1AA", "POSTCODE"),
])
def test_detects(text, cat):
    _, c = cats(text)
    assert cat in c, (text, c)


def test_secrets():
    out, c = cats('password="S3cr3t!" token=abc123def Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl')
    assert "S3cr3t" not in out and "abc123def" not in out and "eyJ" not in out


def test_url_credentials_and_host():
    out, c = cats("GET https://admin:hunter2@api.internal.lan/v1?id=7")
    assert "hunter2" not in out and "admin" not in out and "api.internal.lan" not in out


def test_luhn_rejects_random_digits():
    _, c = cats("ref 4111 1111 1111 1112")
    assert "CARD" not in c


# ---- learning ----------------------------------------------------------

def test_syslog_host_learned_and_propagated():
    text = "Oct 23 10:15:02 web01 sshd[1]: started\nlater: web01 restarted\n"
    out, c = cats(text)
    assert "web01" not in out
    toks = re.findall(r"<HOST_[0-9a-f]+>", out)
    assert len(toks) == 2 and toks[0] == toks[1]


def test_user_learned_from_sshd():
    out, _ = cats("Accepted publickey for alice from 10.0.0.1\nPWD=/home/alice\nalice logged out")
    assert "alice" not in out


def test_stop_terms_not_propagated():
    out, _ = cats("Failed password for root from 10.0.0.1\nthe root cause was disk")
    assert "root cause" in out


def test_custom_terms():
    r = make()
    r.add_terms(["Acme Ltd"], "TERM")
    assert "Acme" not in r.redact("invoice for acme ltd sent")


def test_allowlist():
    r = make(allow={"8.8.8.8"})
    assert "8.8.8.8" in r.redact("dns 8.8.8.8")


# ---- tokens ------------------------------------------------------------

def test_tokens_consistent_and_keyed():
    a, b = make(), Redactor("token", b"x" * 32, set(DETECTOR_NAMES))
    t1 = a.redact("ip 10.0.0.9")
    assert a.redact("again 10.0.0.9").split()[-1] == t1.split()[-1]
    assert b.redact("ip 10.0.0.9") != t1


def test_phone_formats_share_token_and_record_variants():
    r = make()
    out = r.redact("x (555) 123-4567 y 555-123-4567")
    toks = TOKEN_RE.findall(out)
    assert toks[0] == toks[1]
    entry = next(iter(r.map.values()))
    assert entry["variants"] == ["555-123-4567"]


def test_mask_mode():
    r = Redactor("mask", None, set(DETECTOR_NAMES))
    assert r.redact("ip 10.0.0.1") == "ip [REDACTED:IPV4_PRIV]"
    assert r.map == {}


def test_no_double_redaction_inside_tokens():
    r = make()
    r.add_terms(["cafe", "beef"], "TERM")
    out = r.redact("10.0.0.1 " * 50)
    assert all(t.startswith("IPV4") for t, _ in TOKEN_RE.findall(out))


def test_residual_scan_clean():
    r = make()
    text = open(__file__.replace("test_detection.py", "../examples/sample.log")).read()
    r.learn(text)
    assert sum(r.scan_residual(r.redact(text)).values()) == 0
