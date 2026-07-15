"""--files-only: during --verify, skip checks that aren't about the files
themselves -- signatures, TSA timestamps, and manifest chain history --
shorthand for --ignore-sig --ignore-tsa --ignore-chain together. Symlinks ARE
a monitored filesystem entry, so they stay checked (--ignore-symlinks is a
separate, deliberate opt-out); the actual file hash comparison is of course
never skipped either."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

TOOL = str(Path(__file__).resolve().parent.parent / "rednb-verify.py")


def _run(*args, **kw):
    return subprocess.run([sys.executable, TOOL, *args],
                          capture_output=True, text=True, input="", **kw)


def _nb(tmp_path, files=None):
    nb = tmp_path / "nb"
    nb.mkdir(parents=True, exist_ok=True)
    for fname, content in (files or {"2026-01.txt": "alpha"}).items():
        (nb / fname).write_text(content)
    return nb


def _symlink_or_skip(link: Path, target: str):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks not permitted in this environment: {exc}")


def test_files_only_skips_unresolved_signature_requirement(tool, tmp_path):
    # A manifest built directly via generate_manifest() (bypassing the CLI
    # create flow) carries no WARN_UNSIGNED marker and no signed_by, so it
    # implies a signature that was never actually made -- normally a blocking
    # "issue". --files-only must let it pass anyway.
    nb = _nb(tmp_path)
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    mf = tmp_path / "hashes-unsigned-implied.json"
    mf.write_text(json.dumps(m))

    r = _run(str(nb), "--verify", str(mf), "--no-sign")
    assert r.returncode == 1
    assert "manifest implies a signature" in r.stdout

    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--files-only")
    assert r.returncode == 0
    assert "[PASS]" in r.stdout
    assert "Flag --ignore-sig in use" in r.stdout


def test_files_only_skips_broken_tsa_and_chain(tmp_path):
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json")
    assert r.returncode == 0
    mf = next(out.glob("hashes-*.json"))

    doc = json.loads(mf.read_text())
    doc["tsa_stamp"] = {"tsa": "http://x", "time": "t", "token_b64": "Zm9v"}
    doc["prev"] = {"file": "hashes-does-not-exist.json", "created": "20260101T000000Z",
                   "height": 1, "hashes": {"sha256": "deadbeef"}}
    mf.write_text(json.dumps(doc))

    # Without --files-only: both the fake TSA stamp and the broken chain
    # link surface as blocking issues.
    r = _run(str(nb), "--verify", str(mf), "--no-sign")
    assert r.returncode == 1
    assert "TSA timestamp could not be verified" in r.stdout
    assert "manifest chain incomplete" in r.stdout

    # With --files-only: both are skipped, clean pass.
    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--files-only")
    assert r.returncode == 0
    assert "[PASS]" in r.stdout
    assert "Flag --ignore-tsa in use" in r.stdout
    assert "Flag --ignore-chain in use" in r.stdout


def test_files_only_still_checks_symlinks(tmp_path):
    # Symlinks are a monitored filesystem entry, not a provenance/metadata
    # check like sig/TSA/chain -- --files-only must NOT silently skip them.
    # --ignore-symlinks remains the separate, deliberate opt-out for that.
    ext = tmp_path / "ext.txt"
    ext.write_text("data")
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    _symlink_or_skip(nb / "link.txt", str(ext))

    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json",
             "--symlink-targets", "hash:sha256")
    assert r.returncode == 0
    mf = next(out.glob("hashes-*.json"))

    # Replace the symlink with a regular file of the SAME content -- content
    # hashes stay identical, only the symlink table comparison catches this.
    (nb / "link.txt").unlink()
    (nb / "link.txt").write_text("data")

    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--files-only")
    assert r.returncode == 1
    assert "Symlinks" in r.stdout
    assert "Flag --ignore-symlinks in use" not in r.stdout


def test_files_only_still_catches_real_tampering(tmp_path):
    # The one thing --files-only must NEVER skip: actual file content changes.
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json")
    mf = next(out.glob("hashes-*.json"))

    (nb / "2026-01.txt").write_text("TAMPERED")

    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--files-only")
    assert r.returncode == 1
    assert "Modified" in r.stdout
    assert "[PASS]" not in r.stdout


def test_files_only_still_catches_missing_and_new_files(tmp_path):
    nb = _nb(tmp_path, {"a.txt": "alpha", "b.txt": "beta"})
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json")
    mf = next(out.glob("hashes-*.json"))

    (nb / "a.txt").unlink()
    (nb / "c.txt").write_text("new")

    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--files-only")
    assert r.returncode == 1
    assert "Missing" in r.stdout


def test_files_only_clean_manifest_still_passes(tmp_path):
    # Sanity: --files-only on an untouched, unsigned (--no-sign) manifest
    # with no TSA/chain/symlinks is just a normal clean pass.
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json")
    mf = next(out.glob("hashes-*.json"))

    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--files-only")
    assert r.returncode == 0
    assert "[PASS]" in r.stdout
