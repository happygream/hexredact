import gzip
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from hexredact.cli import main

SAMPLE = Path(__file__).parent.parent / "examples" / "sample.log"


@pytest.fixture
def logs(tmp_path):
    d = tmp_path / "logs"
    (d / "sub").mkdir(parents=True)
    shutil.copy(SAMPLE, d / "auth.log")
    with gzip.open(d / "sub" / "kern.log.1.gz", "wt") as f:
        f.write("Oct 23 11:00:00 web01 kernel: link up 10.0.0.12\n")
    (d / "sub" / "notes.txt").write_text("host=nas02.lan\n")
    (d / "image.bin").write_bytes(b"\x00\x01")
    return d


def run(*args):
    return main([*args, "--no-auto-terms", "-q"] if args[0] in ("redact", "scan") else list(args))


def test_redact_directory_layout(logs):
    assert run("redact", str(logs)) == 0
    orig, red = logs.with_name("logs_original"), logs.with_name("logs_redacted")
    assert (orig / "auth.log").read_text() == SAMPLE.read_text()
    assert (orig / "redaction_map.json").exists()
    assert (red / "auth.log").exists() and (red / "sub" / "kern.log.1.gz").exists()
    assert (red / "redaction_report.txt").exists() and (red / "redaction_report.json").exists()
    out = (red / "auth.log").read_text()
    for s in ("10.26.190.67", "alice", "web01", "hunter2", "07700 900123", "4111"):
        assert s not in out
    with gzip.open(red / "sub" / "kern.log.1.gz", "rt") as f:
        assert "10.0.0.12" not in f.read()
    if os.name == "posix":
        assert oct((orig / "redaction_map.json").stat().st_mode & 0o777) == "0o600"


def test_refuses_to_overwrite(logs):
    assert run("redact", str(logs)) == 0
    assert run("redact", str(logs)) == 1
    assert run("redact", str(logs), "--overwrite") == 0


def test_single_file_layout(tmp_path):
    f = tmp_path / "app.log"
    shutil.copy(SAMPLE, f)
    assert run("redact", str(f)) == 0
    for n in ("app_original.log", "app_redacted.log", "app_redaction_map.json", "app_redaction_report.txt"):
        assert (tmp_path / n).exists(), n


def test_move(tmp_path):
    f = tmp_path / "app.log"
    shutil.copy(SAMPLE, f)
    assert run("redact", str(f), "--move") == 0
    assert not f.exists() and (tmp_path / "app_original.log").exists()


def test_roundtrip_restore(logs, capsys):
    assert run("redact", str(logs)) == 0
    m = logs.with_name("logs_original") / "redaction_map.json"
    red = logs.with_name("logs_redacted")
    assert main(["restore", str(m), str(red / "auth.log")]) == 0
    restored = (red / "auth_restored.log").read_text().splitlines()
    original = SAMPLE.read_text().splitlines()
    assert restored == original


def test_lookup(logs, capsys):
    assert run("redact", str(logs)) == 0
    m = json.loads((logs.with_name("logs_original") / "redaction_map.json").read_text())
    tok, entry = next((t, e) for t, e in m["entries"].items() if e["value"] == "8.8.8.8")
    capsys.readouterr()
    assert main(["lookup", str(logs.with_name("logs_original") / "redaction_map.json"), tok, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["value"] == "8.8.8.8"


def test_passphrase_gives_stable_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("HXP", "correct horse battery")
    outs = []
    for i in range(2):
        d = tmp_path / f"r{i}"
        d.mkdir()
        shutil.copy(SAMPLE, d / "a.log")
        assert run("redact", str(d / "a.log"), "--passphrase-env", "HXP") == 0
        outs.append((d / "a_redacted.log").read_text())
    assert outs[0] == outs[1]


def test_mask_mode_writes_no_map(tmp_path):
    f = tmp_path / "a.log"
    shutil.copy(SAMPLE, f)
    assert run("redact", str(f), "--mode", "mask") == 0
    assert not (tmp_path / "a_redaction_map.json").exists()
    assert "[REDACTED:IPV4_PRIV]" in (tmp_path / "a_redacted.log").read_text()


def test_scan_writes_nothing(logs):
    before = sorted(p.name for p in logs.parent.iterdir())
    assert run("scan", str(logs)) == 0
    assert sorted(p.name for p in logs.parent.iterdir()) == before


def test_only_and_disable(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("ip 10.0.0.1 mail a@b.com\n")
    assert run("redact", str(f), "--only", "ipv4") == 0
    out = (tmp_path / "a_redacted.log").read_text()
    assert "10.0.0.1" not in out and "a@b.com" in out


def test_unknown_detector_errors(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("x\n")
    with pytest.raises(SystemExit):
        run("redact", str(f), "--only", "nope")


def test_stdin_pipe(tmp_path):
    m = tmp_path / "m.json"
    p = subprocess.run([sys.executable, "-m", "hexredact", "redact", "-", "--map", str(m), "--no-auto-terms"],
                       input=SAMPLE.read_bytes(), capture_output=True, check=True)
    assert b"10.26.190.67" not in p.stdout and b"<IPV4_PRIV_" in p.stdout
    assert m.exists()


def test_stdin_token_mode_requires_map():
    p = subprocess.run([sys.executable, "-m", "hexredact", "redact", "-"], input=b"x", capture_output=True)
    assert p.returncode == 2


def test_encrypted_map(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("MP", "map passphrase!")
    f = tmp_path / "a.log"
    shutil.copy(SAMPLE, f)
    assert run("redact", str(f), "--map-passphrase-env", "MP") == 0
    raw = json.loads((tmp_path / "a_redaction_map.json").read_text())
    assert raw["hexredact_encrypted"] == 1 and "8.8.8.8" not in json.dumps(raw)
    assert main(["restore", str(tmp_path / "a_redaction_map.json"), str(tmp_path / "a_redacted.log"),
                 "--map-passphrase-env", "MP"]) == 0
    assert (tmp_path / "a_restored.log").read_text().splitlines() == SAMPLE.read_text().splitlines()


def test_detectors_lists(capsys):
    assert main(["detectors", "--json"]) == 0
    names = [d["name"] for d in json.loads(capsys.readouterr().out)]
    assert names[-1] == "phone" and "ipv4" in names


def test_wizard_end_to_end(logs, monkeypatch, capsys):
    import io
    answers = "\n".join(["1", str(logs), "", "2", "", "Acme", "n", "", "y", "y"]) + "\n"
    monkeypatch.setattr("sys.stdin", io.StringIO(answers))
    assert main(["wizard"]) == 0
    assert (logs.with_name("logs_redacted") / "auth.log").exists()
