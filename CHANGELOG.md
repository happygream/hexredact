# Changelog

## Unreleased

- Interactive mode uses arrow-key menus, a space-to-toggle detector checklist, and inline yes/no questions. No dependencies: `msvcrt` on Windows, `termios` elsewhere. Falls back to numbered prompts when input isn't a terminal.
- `hexredact.bat` for Windows: double-click to open the wizard, or drag a file or folder onto it.
- Paths dragged into the wizard have their quotes or escapes stripped.
- Loopback and unspecified addresses get their own `LOOP` scope when `--redact-loopback` is on.
- Map-protection wording is accurate on Windows. Hints print the command you actually launched with.

## 1.0.0 - 2026-10-23

First public release.

- Commands: `redact`, `scan`, `lookup`, `restore` and `detectors`, plus an interactive wizard that runs with no arguments.
- 31 detectors covering secrets, personal identifiers, network identifiers and IDs.
- Phones are kept apart from IPs: detectors run in a fixed order and each hit is replaced by a placeholder that later detectors cannot match.
- Learning pass: hostnames and usernames seen in strong contexts are redacted everywhere they appear.
- Token mode with keyed HMAC pseudonyms (random key or passphrase) and a reverse map. Mask mode for irreversible output.
- Optional encryption of the reverse map with scrypt + Fernet.
- `_original` / `_redacted` output layout, gzip and rotated logs, stdin to stdout pipe mode, residual verification scan, `--strict` for CI.
