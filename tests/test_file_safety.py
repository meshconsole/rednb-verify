"""File Safety: verify must never modify the files it monitors, and --lock
must actually mark this run's own output read-only (defense-in-depth, not
true WORM -- see README 'File Safety')."""
import subprocess
import sys
from pathlib import Path

import pytest

TOOL = str(Path(__file__).resolve().parent.parent / "rednb-verify.py")


def _run(*args, **kw):
    return subprocess.run([sys.executable, TOOL, *args],
                          capture_output=True, text=True, input="", **kw)


def _nb(tmp_path, files):
    nb = tmp_path / "nb"
    nb.mkdir(parents=True)
    for name, content in files.items():
        (nb / name).write_text(content)
    return nb


def _snapshot(nb: Path) -> dict:
    """path -> (bytes, mtime_ns) for every file under nb, recursively."""
    out = {}
    for p in sorted(nb.rglob("*")):
        if p.is_file():
            st = p.stat()
            out[str(p.relative_to(nb))] = (p.read_bytes(), st.st_mtime_ns)
    return out


# ---- verify never writes to the monitored directory ----

def test_verify_manifest_leaves_files_byte_identical(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "alpha", "2026-02.txt": "beta"})
    before = _snapshot(nb)
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    tool.verify_manifest(m, nb)
    after = _snapshot(nb)
    assert before == after, "verify_manifest() must not touch monitored files"


def test_verify_manifest_creates_no_new_files_in_notebook(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "alpha"})
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    before = {p.name for p in nb.iterdir()}
    tool.verify_manifest(m, nb)
    after = {p.name for p in nb.iterdir()}
    assert before == after, "verify_manifest() must not create files in the notebook dir"


def test_cli_verify_leaves_notebook_untouched(tmp_path):
    # End-to-end (subprocess) version of the same guarantee, including a
    # tampered/mismatched case -- even a FAILING verify must not write back.
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out))
    assert r.returncode == 0
    manifest = next(out.glob("hashes-*.txt"))

    before = _snapshot(nb)
    r = _run(str(nb), "--verify", str(manifest), "--no-sign")
    assert r.returncode == 0
    assert _snapshot(nb) == before

    # Now make it fail (modify a file) and confirm verify STILL doesn't write.
    (nb / "2026-01.txt").write_text("tampered")
    before = _snapshot(nb)
    r = _run(str(nb), "--verify", str(manifest), "--no-sign")
    assert r.returncode == 1
    assert _snapshot(nb) == before


# ---- --lock ----

def test_lock_file_readonly_sets_permissions(tool, tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("data")
    assert tool._lock_file_readonly(f) is True
    assert not (f.stat().st_mode & 0o222)          # no write bits for anyone


def test_lock_file_readonly_blocks_overwrite(tool, tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("data")
    tool._lock_file_readonly(f)
    with pytest.raises(PermissionError):
        f.write_text("tampered")
    assert f.read_text() == "data"


def test_lock_file_readonly_missing_file_returns_false(tool, tmp_path):
    assert tool._lock_file_readonly(tmp_path / "nope.txt") is False


def test_cli_lock_locks_manifest(tmp_path):
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "--lock", "-o", str(out))
    assert r.returncode == 0
    assert "Locked read-only" in r.stdout
    manifest = next(out.glob("hashes-*.txt"))
    assert not (manifest.stat().st_mode & 0o222)


_DEAD_TSA = "http://127.0.0.1:1"     # closed port -> immediate ECONNREFUSED, no live network


def test_cli_lock_only_locks_files_actually_written(tmp_path):
    # A failed TSA request means no .tsr is ever created -- --lock must not
    # choke trying to lock a file that doesn't exist, and must still lock the
    # manifest that WAS written.
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "--tsa", _DEAD_TSA, "--lock",
             "-o", str(out), "-y")
    manifests = list(out.glob("hashes-*.txt"))
    assert len(manifests) == 1
    assert not (manifests[0].stat().st_mode & 0o222)
    assert not list(out.glob("*.tsr"))               # nothing to lock; no crash
    assert "Locked read-only" in r.stdout


def test_cli_without_lock_manifest_stays_writable(tmp_path):
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out))
    assert r.returncode == 0
    manifest = next(out.glob("hashes-*.txt"))
    assert manifest.stat().st_mode & 0o200          # owner-writable, unlocked
    manifest.write_text("still writable")            # must not raise
