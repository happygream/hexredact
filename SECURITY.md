# Security policy

## Reporting

Report vulnerabilities privately through GitHub's **Report a vulnerability** button on the Security tab of this repository. Do not open a public issue.

Missed detections are in scope: a log line that leaks PII or a secret through `hexredact` with default settings. Include a **synthetic** reproduction. Never send real data.

## Threat model

- **Redacted output** (`*_redacted`) is meant to be shared.
- **Original output and the reverse map** (`*_original`, `redaction_map.json`) contain the real values and must stay with the data owner. Maps are written `0600` on POSIX (on Windows they inherit the folder ACL) and can be encrypted with `--encrypt-map`.
- **Tokens** are `HMAC-SHA256(key, category || canonical value)`, truncated to 40 bits, with collision checks within a run. Without the key they cannot be reversed or brute-forced offline, as long as you use a random key or a strong passphrase. A weak passphrase lets an attacker test guesses for low-entropy values such as IPv4 addresses.
- **Mask mode** keeps nothing and cannot be reversed.
- **Frequency and structure leak in token mode.** Which values repeat, and where, stays visible. That is intentional for analysis. Use mask mode when it matters.
