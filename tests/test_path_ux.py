"""Path-argument UX: a missing notebook_dir must error (not silently produce an
empty manifest), and a garbled path (e.g. from the Windows trailing-backslash-
before-closing-quote shell quirk) gets a specific, actionable hint.
"""
import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parent.parent / "rednb-verify.py")


def _run(*args, **kw):
    return subprocess.run([sys.executable, TOOL, *args],
                          capture_output=True, text=True, input="", **kw)


def test_bad_path_hint_detects_embedded_quote(tool):
    assert "backslash before the closing quote" in tool._bad_path_hint('C:\\x" --verify')


def test_bad_path_hint_detects_swallowed_flag(tool):
    assert "backslash before the closing quote" in tool._bad_path_hint("C:\\x -o output")


def test_bad_path_hint_silent_for_normal_path(tool):
    assert tool._bad_path_hint("C:\\Users\\uriel\\journal") == ""
    assert tool._bad_path_hint("/home/user/journal") == ""


def test_create_errors_on_missing_notebook_dir(tmp_path):
    missing = tmp_path / "nope"
    r = _run(str(missing), "--no-sign", "-o", str(tmp_path))
    assert r.returncode == 2
    assert "Notebook directory not found" in r.stderr
    assert not list(tmp_path.glob("hashes-*"))          # no manifest silently written


def test_create_errors_with_hint_on_garbled_path(tmp_path):
    garbled = str(tmp_path / "nope") + '" --verify foo'
    r = _run(garbled, "--no-sign", "-o", str(tmp_path))
    assert r.returncode == 2
    assert "backslash before the closing quote" in r.stderr


def test_verify_errors_on_missing_notebook_dir(tmp_path):
    nb = tmp_path / "j"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("a")
    _run(str(nb), "--no-sign", "-o", str(tmp_path))
    missing = tmp_path / "nope"
    r = _run(str(missing), "--verify", str(tmp_path), "--no-sign")
    assert r.returncode == 2
    assert "Notebook directory not found" in r.stderr
