"""Tests for the hashing progress bar (normal-mode only, --jobs default).

The bar itself only activates on a real TTY (see _progress_active), which
pytest's captured subprocess/StringIO streams never are -- so the "is it
actually drawn" behavior is exercised directly here rather than via the CLI,
and confirmed live by the user in a real terminal (out of scope for this
suite, same as the TSA live round-trip).
"""
import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parent.parent / "rednb-verify.py")


def _run(*args, **kw):
    return subprocess.run([sys.executable, TOOL, *args],
                          capture_output=True, text=True, **kw)


# ---- elapsed-time formatting ----

def test_format_elapsed_milliseconds_under_one_second(tool):
    assert tool._format_elapsed(0.034) == "34ms"
    assert tool._format_elapsed(0.999) == "999ms"
    assert tool._format_elapsed(0.0) == "0ms"


def test_format_elapsed_seconds_at_and_above_one(tool):
    assert tool._format_elapsed(1.0) == "1.0s"
    assert tool._format_elapsed(4.2) == "4.2s"
    assert tool._format_elapsed(63.45) == "63.4s" or tool._format_elapsed(63.45) == "63.5s"


# ---- spinner encoding fallback (the actual bug found: cp1252 crashes on
# the braille glyphs used in the design-gallery-chosen "minimal spinner"
# style) ----
#
# sys.stdout.encoding is read-only on the real stream (and on pytest's
# capture object), so a fake stream stands in wherever the encoding itself
# needs to vary.

class _FakeStdout:
    def __init__(self, encoding, is_tty=True):
        self.encoding = encoding
        self._is_tty = is_tty
        self.written = []

    def isatty(self):
        return self._is_tty

    def write(self, text):
        self.written.append(text.encode(self.encoding))  # raises like a real stream would

    def flush(self):
        pass


def test_spinner_uses_braille_when_encoding_supports_it(tool, monkeypatch):
    tool._spinner_frames_cache = None
    monkeypatch.setattr(tool.sys, "stdout", _FakeStdout("utf-8"))
    assert tool._spinner_frames() == tool._SPINNER_FRAMES_BRAILLE
    tool._spinner_frames_cache = None  # don't leak into other tests


def test_spinner_falls_back_to_ascii_on_cp1252(tool, monkeypatch):
    tool._spinner_frames_cache = None
    monkeypatch.setattr(tool.sys, "stdout", _FakeStdout("cp1252"))
    assert tool._spinner_frames() == tool._SPINNER_FRAMES_ASCII
    # every frame must be safely encodable in cp1252 -- this is the actual
    # property that matters, not just "which list did we pick"
    for frame in tool._spinner_frames():
        frame.encode("cp1252")
    tool._spinner_frames_cache = None


def test_spinner_frames_are_cached(tool, monkeypatch):
    tool._spinner_frames_cache = None
    monkeypatch.setattr(tool.sys, "stdout", _FakeStdout("utf-8"))
    first = tool._spinner_frames()
    monkeypatch.setattr(tool.sys, "stdout", _FakeStdout("cp1252"))
    second = tool._spinner_frames()  # encoding changed, but cache should not re-check
    assert first is second
    tool._spinner_frames_cache = None


def test_progress_tick_never_raises_unicode_error_on_cp1252(tool, monkeypatch):
    # End-to-end guard for the actual crash: force cp1252 AND force the bar
    # active, then tick -- must not raise, regardless of terminal capability.
    tool._spinner_frames_cache = None
    fake = _FakeStdout("cp1252")
    monkeypatch.setattr(tool.sys, "stdout", fake)
    monkeypatch.setattr(tool, "_progress_active", lambda: True)
    import time
    tool._progress_tick(3, 9, time.perf_counter() - 0.34)  # must not raise
    tool._progress_clear()
    tool._spinner_frames_cache = None
    assert fake.written  # confirms it actually wrote something, not a silent no-op


# ---- activation gating: quiet / verbose / json / non-TTY all disable it ----

def test_progress_active_false_when_quiet(tool, monkeypatch):
    monkeypatch.setattr(tool, "_quiet", True)
    monkeypatch.setattr(tool, "_verbose", False)
    monkeypatch.setattr(tool, "_json_mode", False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert tool._progress_active() is False


def test_progress_active_false_when_verbose(tool, monkeypatch):
    monkeypatch.setattr(tool, "_quiet", False)
    monkeypatch.setattr(tool, "_verbose", True)
    monkeypatch.setattr(tool, "_json_mode", False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert tool._progress_active() is False


def test_progress_active_false_when_json_mode(tool, monkeypatch):
    monkeypatch.setattr(tool, "_quiet", False)
    monkeypatch.setattr(tool, "_verbose", False)
    monkeypatch.setattr(tool, "_json_mode", True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert tool._progress_active() is False


def test_progress_active_false_when_not_a_tty(tool, monkeypatch):
    monkeypatch.setattr(tool, "_quiet", False)
    monkeypatch.setattr(tool, "_verbose", False)
    monkeypatch.setattr(tool, "_json_mode", False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    assert tool._progress_active() is False


def test_progress_active_true_in_plain_normal_mode_on_a_tty(tool, monkeypatch):
    monkeypatch.setattr(tool, "_quiet", False)
    monkeypatch.setattr(tool, "_verbose", False)
    monkeypatch.setattr(tool, "_json_mode", False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert tool._progress_active() is True


# ---- counting-phase status lines (not TTY-gated -- ordinary _info/_ok) ----

def test_cli_create_prints_counting_phase_messages(tmp_path):
    nb = tmp_path / "j"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("a")
    (nb / "2026-02.txt").write_text("b")
    r = _run(str(nb), "--no-sign", "-o", str(tmp_path))
    assert "Counting files..." in r.stdout
    assert "2 files to hash" in r.stdout
    assert r.stdout.index("Counting files...") < r.stdout.index("2 files to hash")


def test_cli_quiet_suppresses_counting_phase_messages(tmp_path):
    nb = tmp_path / "j"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("a")
    r = _run(str(nb), "--no-sign", "--quiet", "-o", str(tmp_path))
    assert "Counting files" not in r.stdout
    assert "files to hash" not in r.stdout


# ---- --jobs default: cores-2, floored at 1 ----

def test_default_jobs_is_cores_minus_two_floored_at_one(tool):
    import os
    expected = max(1, (os.cpu_count() or 1) - 2)
    assert tool.DEFAULT_JOBS == expected
    assert tool.DEFAULT_JOBS >= 1


def test_cli_help_shows_computed_default_jobs():
    r = _run("--help")
    import re
    m = re.search(r"cores-2\) = (\d+) on this machine", r.stdout)
    assert m is not None
    import os
    assert int(m.group(1)) == max(1, (os.cpu_count() or 1) - 2)
