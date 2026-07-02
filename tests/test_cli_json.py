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


def test_verify_output_without_report_errors(tmp_path):
    # -o has no effect on --verify unless a report is generated; using it alone
    # is a usage error (exit 2) rather than silently doing nothing.
    nb = _journal(tmp_path)
    _run(str(nb), "--no-sign", "-o", str(tmp_path))
    reports = tmp_path / "reports"
    r = _run(str(nb), "--verify", str(tmp_path), "--no-sign", "-o", str(reports))
    assert r.returncode == 2
    assert "only sets where a report is written" in r.stderr


def test_verify_no_report_writes_no_file(tmp_path):
    nb = _journal(tmp_path)
    _run(str(nb), "--no-sign", "-o", str(tmp_path))
    before = set(tmp_path.glob("report-*"))
    r = _run(str(nb), "--verify", str(tmp_path), "--no-sign")
    assert r.returncode == 0
    assert set(tmp_path.glob("report-*")) == before    # no new report file


def test_noninteractive_create_skips_signing(tmp_path):
    # Piped/non-interactive stdin: no signing menu, default to skip-signing,
    # exit 0 with the manifest written (no prompt, no traceback).
    nb = _journal(tmp_path)
    r = subprocess.run([sys.executable, TOOL, str(nb), "-o", str(tmp_path)],
                       capture_output=True, text=True, input="")
    assert r.returncode == 0
    assert "skipping signing" in r.stdout
    assert "How would you like to sign" not in r.stdout
    assert "Traceback" not in r.stderr


def test_verify_report_to_output_dir(tmp_path):
    nb = _journal(tmp_path)
    _run(str(nb), "--no-sign", "-o", str(tmp_path))
    reports = tmp_path / "reports"
    r = _run(str(nb), "--verify", str(tmp_path), "--no-sign", "-o", str(reports), "--report", "json")
    assert r.returncode == 0
    assert list(reports.glob("report-*.json"))
