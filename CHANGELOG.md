# Changelog

## 1.0.0 - 2026-10-23

First public release.

- Commands: `redact`, `scan`, `lookup`, `restore` and `detectors`, plus an interactive wizard that runs with no arguments.
- 31 detectors covering secrets, personal identifiers, network identifiers and IDs.
- Phones are kept apart from IPs: detectors run in a fixed order and each hit is replaced by a placeholder that later detectors cannot match.
- Learning pass: hostnames and usernames seen in strong contexts are redacted everywhere they appear.
- Token mode with keyed HMAC pseudonyms (random key or passphrase) and a reverse map. Mask mode for irreversible output.
- Optional encryption of the reverse map with scrypt + Fernet.
- `_original` / `_redacted` output layout, gzip and rotated logs, stdin to stdout pipe mode, residual verification scan, `--strict` for CI.
