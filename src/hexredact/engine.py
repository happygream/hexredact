"""Redaction engine: placeholder protection, keyed tokens, term learning."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple

from .patterns import (CONTEXT_DETECTORS, DETECTORS, LEARN_SOURCES, STOP_TERMS, Det,
                       _RFC1918, _ULA, _ip_is_trivial)

TOKEN_HEX = 10
TOKEN_RE = re.compile(r"<([A-Z][A-Z0-9_]*)_([0-9a-f]{10,16})>")

# Every detection is swapped for a private-use-area placeholder immediately,
# so later detectors can never re-match (or partially match) something that
# has already been redacted. Placeholders become final tokens at the very end.
_PH_OPEN, _PH_CLOSE, _PH_BASE = "\ue000", "\ue001", 0xE100
_PH_RE = re.compile(f"{_PH_OPEN}([\ue100-\ue1ff]+){_PH_CLOSE}")


def _ph_encode(i: int) -> str:
    out = []
    while True:
        out.append(chr(_PH_BASE + (i & 0xFF)))
        i >>= 8
        if not i:
            break
    return _PH_OPEN + "".join(out) + _PH_CLOSE


def _ph_decode(s: str) -> int:
    i = 0
    for n, ch in enumerate(s):
        i |= (ord(ch) - _PH_BASE) << (8 * n)
    return i


class Redactor:
    def __init__(self, mode: str, key: Optional[bytes], enabled: Set[str],
                 keep_trivial_ips: bool = True, allow: Optional[Set[str]] = None):
        self.mode, self.key = mode, key
        self.enabled = enabled
        self.keep_trivial_ips = keep_trivial_ips
        self.allow = {a.lower() for a in (allow or set())}
        self.dets = [d for d in DETECTORS if d.name in enabled]
        self.terms: Dict[str, str] = {}          # lower(term) -> category
        self.term_rx: Optional["re.Pattern[str]"] = None
        self.map: Dict[str, dict] = {}           # token -> {cat, value, count}
        self._tok_by_key: Dict[Tuple[str, str], str] = {}
        self.counts: Counter = Counter()
        self._slots: List[str] = []

    def reset_state(self) -> None:
        """Forget tokens and counts (keeps key, detectors and learned terms)."""
        self.map.clear()
        self._tok_by_key.clear()
        self.counts.clear()

    # ---- terms ---------------------------------------------------------
    def add_terms(self, terms, cat: str):
        for t in terms:
            t = t.strip()
            if len(t) >= 3 and t.lower() not in STOP_TERMS and t.lower() not in self.allow \
                    and not _PH_RE.search(t):
                self.terms.setdefault(t.lower(), cat)
                # first label of a learned FQDN is useful on its own (bare hostname)
                if cat == "HOST" and t.count(".") >= 2:   # web01.corp.tld -> web01
                    first = t.split(".", 1)[0]
                    if len(first) >= 3 and first.lower() not in STOP_TERMS and not first.isdigit():
                        self.terms.setdefault(first.lower(), "HOST")
        self._compile_terms()

    def _compile_terms(self):
        if not self.terms:
            self.term_rx = None
            return
        alts = sorted(self.terms, key=len, reverse=True)
        self.term_rx = re.compile(
            r"(?<![\w.-])(?:" + "|".join(re.escape(a) for a in alts) + r")(?![\w-]|\.\w)", re.I)

    def learn(self, text: str):
        """Pass 1: harvest hostnames/usernames from strong contexts."""
        for d in self.dets:
            if d.name not in LEARN_SOURCES and d.name != "fqdn":
                continue
            for m in d.rx.finditer(text):
                for g in d.groups:
                    v = m.group(g)
                    if v and not self._is_ipish(v):
                        self.add_terms([v.rstrip(".")], d.cat)

    @staticmethod
    def _is_ipish(v: str) -> bool:
        try:
            ipaddress.ip_address(v.split("%")[0])
            return True
        except ValueError:
            return bool(re.fullmatch(r"[\d.:]+", v))

    # ---- tokens --------------------------------------------------------
    def _token(self, cat: str, value: str, canon: str) -> str:
        if self.mode == "mask":
            return f"[REDACTED:{cat}]"
        k = (cat, canon)
        tok = self._tok_by_key.get(k)
        if tok:
            e = self.map[tok]
            e["count"] += 1
            if value != e["value"] and value not in e.setdefault("variants", []):
                e["variants"].append(value)      # other surface forms of the same value
            return tok
        digest = hmac.new(self.key, f"{cat}\x00{canon}".encode("utf-8", "surrogateescape"),
                          hashlib.sha256).hexdigest()
        n = TOKEN_HEX
        tok = f"<{cat}_{digest[:n]}>"
        while tok in self.map and self.map[tok]["canon"] != canon:   # collision guard
            n += 2
            tok = f"<{cat}_{digest[:n]}>"
        self.map[tok] = {"category": cat, "value": value, "canon": canon, "count": 1}
        self._tok_by_key[k] = tok
        return tok

    def _slot(self, final: str) -> str:
        self._slots.append(final)
        return _ph_encode(len(self._slots) - 1)

    # ---- classification ------------------------------------------------
    def _classify(self, d: Det, v: str):
        """Return (category, canonical) or None to leave untouched."""
        if v.lower() in self.allow:
            return None
        if d.name in LEARN_SOURCES and v.lower() in STOP_TERMS:
            return None
        if d.name in ("ipv4", "ipv6"):
            try:
                ip = ipaddress.ip_address(v.split("%")[0])
            except ValueError:
                return None
            if self.keep_trivial_ips and _ip_is_trivial(ip):
                return None
            if ip.is_loopback or ip.is_unspecified:
                scope = "LOOP"
            elif ip.is_global:
                scope = "PUB"
            elif ip.is_link_local or (ip.version == 4 and any(ip in n for n in _RFC1918)) or \
                    (ip.version == 6 and ip in _ULA):
                scope = "PRIV"
            else:
                scope = "RSVD"      # doc/test/CGNAT/multicast/reserved ranges
            return f"{d.cat}_{scope}", ip.compressed
        if d.name == "fqdn" and v.lower().rstrip(".") in ("localhost", "localhost.localdomain"):
            return None
        if d.validate and not d.validate(v):
            return None
        return d.cat, (d.canon(v) if d.canon else v)

    def _apply(self, d: Det, text: str) -> str:
        def repl(m: re.Match) -> str:
            if d.groups == (0,):
                v = m.group(0)
                cls = self._classify(d, v)
                if not cls:
                    return v
                self.counts[cls[0]] += 1
                return self._slot(self._token(cls[0], v, cls[1]))
            # rebuild the match, swapping only the listed groups
            out, pos = [], m.start(0)
            for g in d.groups:
                if m.group(g) is None or _PH_RE.fullmatch(m.group(g) or ""):
                    continue
                gs, ge = m.span(g)
                v = m.group(g)
                cls = self._classify(d, v)
                out.append(m.string[pos:gs])
                if cls:
                    self.counts[cls[0]] += 1
                    out.append(self._slot(self._token(cls[0], v, cls[1])))
                else:
                    out.append(v)
                pos = ge
            out.append(m.string[pos:m.end(0)])
            return "".join(out)
        return d.rx.sub(repl, text)

    def _apply_terms(self, text: str) -> str:
        if not self.term_rx:
            return text

        def repl(m):
            v = m.group(0)
            cat = self.terms[v.lower()]
            self.counts[cat] += 1
            return self._slot(self._token(cat, v, v.lower()))
        return self.term_rx.sub(repl, text)

    # ---- main ----------------------------------------------------------
    def redact(self, text: str) -> str:
        self._slots = []
        for d in self.dets:
            text = self._apply(d, text)
            if d.name == "path_user":          # learned/custom terms slot in here
                text = self._apply_terms(text)
        if "path_user" not in self.enabled:
            text = self._apply_terms(text)
        return _PH_RE.sub(lambda m: self._slots[_ph_decode(m.group(1))], text)

    def scan_residual(self, text: str) -> Counter:
        """Verification: what would still be caught in already-redacted text."""
        c = Counter()
        masked = TOKEN_RE.sub(" ", text).replace("[REDACTED:", " [")
        for d in self.dets:
            if d.name in CONTEXT_DETECTORS:
                continue           # context detectors legitimately match around tokens
            for m in d.rx.finditer(masked):
                v = m.group(d.groups[0]) if d.groups != (0,) else m.group(0)
                if v and self._classify(d, v):
                    c[d.cat] += 1
        if self.term_rx:
            c["TERM"] += len(self.term_rx.findall(masked))
        return c



# --------------------------------------------------------------------------
# PEM / multi-line secret blocks (handled line-wise before the engine)
# --------------------------------------------------------------------------

PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|CERTIFICATE|PGP [A-Z ]+)-----")
PEM_END = re.compile(r"-----END [A-Z0-9 ]*(?:PRIVATE KEY|CERTIFICATE|PGP [A-Z ]+)-----")


def strip_pem(lines):
    inside = False
    for line in lines:
        if inside:
            e = PEM_END.search(line)
            if e:
                inside = False
                tail = line[e.end():]
                if tail.strip():
                    yield tail
            continue
        m = PEM_BEGIN.search(line)
        if m:
            e = PEM_END.search(line, m.end())
            if e:
                yield line[:m.start()] + "[REDACTED:PEM_BLOCK]" + line[e.end():]
            else:
                inside = True
                yield line[:m.start()] + "[REDACTED:PEM_BLOCK]\n"
            continue
        yield line


