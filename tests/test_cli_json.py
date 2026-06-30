"""End-to-end tests for --json stdout output and the verify verdict exit codes.

These run the script as a subprocess so we can assert that stdout is pure JSON
(logs go to stderr) and that exit codes are correct.
"""
import json
import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parent.parent / "rednb-verify.py")


def _run(*args):
    return subprocess.run([sys.executable, TOOL, *args], capture_output=True, text=True)


def _journal(tmp_path):
    nb = tmp_path / "j"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    (nb / "2026-02.txt").write_text("beta")
    return nb


def test_create_json_stdout_is_pure_json(tmp_path):
    nb = _journal(tmp_path)
    r = _run(str(nb), "--no-sign", "-o", str(tmp_path), "--json")
    assert r.returncode == 0
    doc = json.loads(r.stdout)            # stdout must parse as JSON
    assert doc["tool"] == "rednb-verify"
    assert "content_root" in doc
    assert "[OK]" not in r.stdout          # logs are on stderr, not stdout


def test_verify_json_clean_exit_zero(tmp_path):
    nb = _journal(tmp_path)
    _run(str(nb), "--no-sign", "-o", str(tmp_path))
    r = _run(str(nb), "--verify", str(tmp_path), "--no-sign", "--json")
    assert r.returncode == 0
    doc = json.loads(r.stdout)
    assert doc["content_root_status"] == ["match"]
    assert "Verification successful" in r.stderr


def test_verify_moved_exits_one_with_messages(tmp_path):
    nb = _journal(tmp_path)
    _run(str(nb), "--no-sign", "-o", str(tmp_path))
    (nb / "2026-01.txt").rename(nb / "moved.txt")
    r = _run(str(nb), "--verify", str(tmp_path), "--no-sign")
    assert r.returncode == 1
    assert "All files present" in r.stdout
    assert "Files moved" in r.stdout


def test_verify_tamper_exits_one(tmp_path):
    nb = _journal(tmp_path)
    _run(str(nb), "--no-sign", "-o", str(tmp_path))
    (nb / "2026-01.txt").write_text("tampered")
    r = _run(str(nb), "--verify", str(tmp_path), "--no-sign")
    assert r.returncode == 1
    assert "Modified" in r.stdout
