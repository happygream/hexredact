# Security policy

## Reporting

Report vulnerabilities privately through GitHub's **Report a vulnerability** button on the Security tab of this repository. Do not open a public issue.

Missed detections are in scope: a log line that leaks PII or a secret through `hexredact` with default settings. Include a **synthetic** reproduction. Never send real data.

## Threat model

- **Redacted output** (`*_redacted`) is meant to be shared.
- **Original output and the reverse map** (`*_original`, `redaction_map.json`) contain the real values and must stay with the data owner. Maps are written `0600` on POSIX (on Windows they inherit the folder ACL) and can be encrypted with `--encrypt-map`.
- **Tokens** are `HMAC-SHA256(key, category || canonical value)`, truncated to 40 bits, with collision checks within a run. Without the key they cannot be reversed or brute-forced offline, as long as you use a random key or a strong passphrase. A weak passphrase lets an attacker test guesses for low-entropy values such as IPv4 addresses.
- **Map encryption** uses the standard library only. Envelope version 2:
  - `scrypt(N=2^15, r=8, p=1)` derives 64 bytes, split into an encryption key and a MAC key. PBKDF2-SHA256 with 600k iterations is used only on Python builds without scrypt.
  - The keystream is `HMAC-SHA256(enc_key, label || nonce || counter)`, a PRF in counter mode as in NIST SP 800-108, with a fresh 128-bit random nonce per file.
  - The tag is `HMAC-SHA256(mac_key, header || ciphertext)`, encrypt-then-MAC. It covers the KDF parameters, salt and nonce.
  - The tag is checked in constant time before anything is decrypted, and KDF parameters read from a file are bounded.
  - These are standard primitives in a standard composition, but it is not AES-GCM. If you need a FIPS-validated cipher, leave the map unencrypted and protect it with your own tooling, such as full-disk encryption or `age`.
- **Mask mode** keeps nothing and cannot be reversed.
- **Frequency and structure leak in token mode.** Which values repeat, and where, stays visible. That is intentional for analysis. Use mask mode when it matters.
