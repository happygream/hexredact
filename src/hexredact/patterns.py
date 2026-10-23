"""Detector definitions and validators.

Order in DETECTORS matters: most specific / highest-risk first. Every hit is
replaced by an opaque placeholder immediately, so later detectors (phones are
last) can never see digits that an earlier detector (IPs, cards...) claimed.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Callable, List, Optional, Sequence

NON_IDENTIFYING_IPS = {
    "0.0.0.0", "255.255.255.255", "::", "::1",
}


_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_ULA = ipaddress.ip_network("fc00::/7")


def _ip_is_trivial(ip) -> bool:
    return str(ip) in NON_IDENTIFYING_IPS or ip.is_loopback or ip.is_unspecified


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def card_ok(raw: str) -> bool:
    d = re.sub(r"\D", "", raw)
    if not 13 <= len(d) <= 19 or not luhn_ok(d):
        return False
    # issuer prefixes only (Visa, MC, Amex, Discover, JCB, Diners, Maestro).
    # UK/intl phones start 0 or +, so they can never be classed as cards.
    return bool(re.match(r"4|5[1-5]|2[2-7]|3[47]|3[0689]|6(?:011|5|4[4-9])|35|5[06-9]|6", d))


def iban_ok(raw: str) -> bool:
    s = re.sub(r"\s", "", raw).upper()
    if not 15 <= len(s) <= 34:
        return False
    s = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in s)
    return int(num) % 97 == 1


def ssn_ok(raw: str) -> bool:
    a, b, c = raw.split("-")
    return a not in ("000", "666") and not a.startswith("9") and b != "00" and c != "0000"


def phone_ok(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if not 9 <= len(digits) <= 15:
        return False
    # belt and braces: never accept anything shaped like a dotted quad or a date
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", raw.strip()):
        return False
    if re.fullmatch(r"\d{4}[-/.]\d{2}[-/.]\d{2}", raw.strip()):
        return False
    if len(set(digits)) == 1:
        return False
    if raw.lstrip("(").startswith("00"):        # zero-padded counters, not phones
        return False
    return True


def blob_ok(raw: str) -> bool:
    if raw.count("/") > len(raw) // 10:          # looks like a path
        return False
    return (any(c.isdigit() for c in raw) and any(c.isupper() for c in raw)
            and any(c.islower() for c in raw))


# Deliberately excluded because they collide with file extensions or attribute
# access in stack traces (obj.id, logger.info, file.name, user.home, x.sh, x.pl):
# id in is it no to me my at int info name home host sh pl py md rs
TLDS = (
    # internal / infra
    "local|lan|internal|intranet|intra|corp|localdomain|priv|private|arpa|ad|"
    # generic
    "com|net|org|edu|gov|mil|biz|pro|io|co|ai|app|dev|cloud|tech|online|site|xyz|"
    "tv|gg|ly|ws|"
    # country
    "uk|us|ca|au|nz|ie|de|fr|nl|be|es|ch|se|dk|fi|pt|cz|sk|hu|ro|bg|gr|tr|ru|ua|"
    "cn|jp|kr|sg|hk|tw|th|vn|ph|br|mx|ar|cl|za|ng|ke|ae|sa|il|eu"
)


class Det:
    """A detector. ``groups`` = which capture groups get redacted (0 = whole match)."""

    def __init__(self, name: str, cat: str, pattern: str, flags: int = 0,
                 groups: Sequence[int] = (0,),
                 validate: Optional[Callable[[str], bool]] = None,
                 canon: Optional[Callable[[str], str]] = None, desc: str = ""):
        self.name, self.cat, self.desc = name, cat, desc
        self.rx = re.compile(pattern, flags)
        self.groups, self.validate, self.canon = groups, validate, canon


def _canon_lower(v): return v.lower()
def _canon_digits(v): return re.sub(r"\D", "", v)
def _canon_mac(v): return re.sub(r"[^0-9a-f]", "", v.lower())


# Order matters. Most specific / highest-risk first; phones are near the end and
# only see text that every IP / card / IBAN / ID detector has already claimed.
DETECTORS: List[Det] = [
    # ---- secrets -------------------------------------------------------
    Det("auth_header", "SECRET",
        r"(?i)\b(?:authorization|proxy-authorization|x-api-key|x-auth-token|cookie|set-cookie)\s*[:=]\s*(.+?)\s*$",
        flags=re.M, groups=(1,), desc="Authorization / Cookie header values"),
    Det("jwt", "JWT", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        desc="JSON Web Tokens"),
    Det("cloud_key", "APIKEY",
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b"
        r"|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b"
        r"|\bxox[abprs]-[A-Za-z0-9-]{10,}\b|\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"
        r"|\bAIza[0-9A-Za-z_-]{35}\b|\bglpat-[A-Za-z0-9_-]{20,}\b"
        r"|\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b|\bnpm_[A-Za-z0-9]{36}\b",
        desc="AWS/GitHub/Slack/Stripe/Google/GitLab/OpenAI/Anthropic/npm keys"),
    Det("bearer", "SECRET", r"(?i)\b(?:bearer|basic|token)\s+([A-Za-z0-9._~+/=-]{12,})",
        groups=(1,), desc="Bearer/Basic tokens"),
    Det("kv_secret", "SECRET",
        r"(?i)\b(?:pass(?:word|wd|phrase)?|pwd(?!\s*=\s*/)|secret|client_secret|api[_-]?key|apikey|"
        r"access[_-]?key|secret[_-]?key|private[_-]?key|token|access_token|refresh_token|"
        r"id_token|auth|session(?:id)?|sid|csrf(?:token)?|otp|pin|signature|sig|salt|"
        r"credential|creds?)\s*[\"']?\s*[:=]\s*[\"']?([^\s\"',;&}]{1,})",
        groups=(1,), desc="key=value secrets (password=, token=, api_key= ...)"),
    Det("url_creds", "CREDS", r"(?<=://)([^/\s:@]+):([^/\s@]+)@", groups=(1, 2),
        desc="user:pass@ in URLs"),
    # ---- personal identifiers -----------------------------------------
    Det("email", "EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b",
        canon=_canon_lower, desc="Email addresses"),
    Det("iban", "IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b",
        validate=iban_ok, canon=lambda v: re.sub(r"\s", "", v).upper(), desc="IBANs (mod-97 checked)"),
    Det("card", "CARD", r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])",
        validate=card_ok, canon=_canon_digits, desc="Payment cards (Luhn + issuer checked)"),
    Det("ssn", "SSN", r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])", validate=ssn_ok, desc="US SSNs"),
    Det("nino", "NINO", r"\b[A-CEGHJ-PR-TW-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b",
        canon=lambda v: v.replace(" ", ""), desc="UK National Insurance numbers"),
    # ---- network identifiers ------------------------------------------
    Det("mac", "MAC",
        r"(?<![\w:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![\w:-])"
        r"|(?<![\w.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![\w.])",
        canon=_canon_mac, desc="MAC addresses"),
    Det("ipv6", "IPV6",
        r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3})?(?:%[\w.-]+)?(?![\w:])",
        desc="IPv6 addresses (validated)"),
    Det("ipv4", "IPV4",
        r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w]|\.\d)",
        desc="IPv4 addresses (octet-validated; ports/CIDR kept)"),
    Det("arn_acct", "AWS_ACCT", r"(?<=:)(\d{12})(?=:)", desc="AWS account IDs in ARNs"),
    Det("win_sid", "SID", r"\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b", desc="Windows SIDs"),
    Det("uuid", "UUID",
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        canon=_canon_lower, desc="UUIDs / GUIDs (device, session, request IDs)"),
    # ---- names --------------------------------------------------------
    Det("fqdn", "HOST",
        rf"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?\.)+(?:{TLDS})(?![\w-]|\.[A-Za-z0-9])",
        flags=re.I, canon=_canon_lower, desc="FQDNs / domains"),
    Det("unc", "HOST", r"(?<=\\\\)([A-Za-z0-9][\w.-]{0,62})(?=\\)", groups=(1,),
        canon=_canon_lower, desc="UNC \\\\SERVER\\share hosts"),
    Det("win_user", "USER", r"(?<![\\:/\w])([A-Z][A-Z0-9-]{1,14})\\([A-Za-z][\w.$-]{0,63})\b", groups=(1, 2),
        canon=_canon_lower, desc="DOMAIN\\user"),
    Det("path_user", "USER",
        r"(?:(?<=/home/)|(?<=/Users/)|(?<=\\Users\\)|(?<=/var/mail/))([A-Za-z0-9._-]+)",
        canon=_canon_lower, desc="Usernames in home paths"),
    # learned + custom terms are injected here at runtime
    Det("kv_host", "HOST",
        r"(?i)\b(?:host|hostname|host_name|server|servername|computer|computername|machine|"
        r"workstation|node|nodename|device|devicename|fqdn|shost|dhost|src_host|dst_host|"
        r"client|peer)\s*[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9][\w.-]{1,252})",
        groups=(1,), canon=_canon_lower, desc="host=/server=/computer= values"),
    Det("kv_user", "USER",
        r"(?i)\b(?:user|username|user_name|uname|login|logname|account|acct|owner|suser|duser|"
        r"principal|upn|samaccountname|actor|author)\s*[\"']?\s*[:=]\s*[\"']?([\w.@$\\-]{2,})",
        groups=(1,), canon=_canon_lower, desc="user=/account= values"),
    Det("auth_user", "USER",
        r"(?i)(?:\bfor (?:invalid |illegal )?user |\bsession opened for user |\bsession closed for user |"
        r"\bAccepted \w+ for |\bFailed \w+ for (?:invalid user )?|\bsudo:\s+)"
        r"([A-Za-z_][\w.-]{0,31})", groups=(1,), canon=_canon_lower,
        desc="sshd/sudo/PAM usernames"),
    Det("syslog_host", "HOST",
        r"^(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)\s+([A-Za-z0-9][\w.-]*)\s+(?=\S+?(?:\[\d+\])?:)",
        flags=re.M, groups=(1,), canon=_canon_lower, desc="syslog header hostname"),
    # ---- misc PII -----------------------------------------------------
    Det("query", "QUERY", r"[?&][\w.\[\]-]+=([^&\s\"'#<>]+)", groups=(1,),
        desc="All URL query-string values"),
    Det("geo", "GEO", r"(?<![\d.])-?\d{1,2}\.\d{4,},\s*-?\d{1,3}\.\d{4,}(?![\d.])",
        desc="lat,long coordinates"),
    Det("postcode", "POSTCODE", r"\b(?:[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}|GIR ?0AA)\b",
        canon=lambda v: v.replace(" ", ""), desc="UK postcodes"),
    Det("hexblob", "HASH", r"(?<![\w/+=-])[A-Fa-f0-9]{32,}(?![\w])", canon=_canon_lower,
        desc="Long hex strings (hashes, session IDs)"),
    Det("b64blob", "BLOB", r"(?<![\w/+=-])[A-Za-z0-9+/]{40,}={0,2}(?![\w/+=])", validate=blob_ok,
        desc="Long base64 blobs"),
    # ---- phones: last, strict shapes only -----------------------------
    Det("phone", "PHONE",
        r"(?<![\w.:/+-])(?:"
        r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}"        # +44 20 7946 0958
        r"|\(?0\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}"                    # 020 7946 0958, 07700 900123
        r"|\(\d{3}\)\s?\d{3}[\s-]\d{4}"                                 # (555) 123-4567
        r"|\d{3}-\d{3}-\d{4}"                                           # 555-123-4567
        r")(?![\w.:/-]|\.\d)",
        validate=phone_ok, canon=_canon_digits, desc="Phone numbers (strict shapes, never dotted quads)"),
]

LEARN_SOURCES = {"kv_host", "kv_user", "auth_user", "syslog_host", "path_user", "win_user", "unc"}

STOP_TERMS = {
    "root", "admin", "administrator", "nobody", "daemon", "system", "localhost", "unknown",
    "null", "none", "true", "false", "anonymous", "guest", "user", "users", "default",
    "www", "mail", "api", "app", "web", "cdn", "smtp", "imap", "ns1", "ns2", "static",
    "login", "auth", "the", "and", "for", "from", "with", "invalid", "service", "server",
    "client", "local", "host", "kernel", "systemd", "cron", "sshd", "sudo", "info",
    "error", "warn", "debug", "localdomain", "domain", "test", "dev", "prod",
    "authority", "builtin", "workgroup", "nt", "https", "http", "windows",
}


DETECTOR_NAMES = [d.name for d in DETECTORS]
CONTEXT_DETECTORS = {"query", "kv_host", "kv_user", "auth_user", "kv_secret", "auth_header",
                     "bearer", "syslog_host", "path_user", "win_user", "unc", "url_creds",
                     "arn_acct"}
