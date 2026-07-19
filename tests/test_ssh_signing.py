"""SSH sign/verify, including the directory-form --verify path resolution bug:
ssh_sign_manifest()/ssh_verify_manifest() run ssh-keygen with cwd set to the
manifest's own directory, so any path argument that's still relative gets
re-interpreted against that NEW cwd instead of the caller's -- silently
doubling the directory prefix. This previously broke any --verify <DIR>
(directory auto-select, which never resolved to absolute) combined with SSH
signature checking, whether the .sshsig was auto-detected or passed via
--sig. No hardware/FIDO key is needed to reproduce or guard this -- a
throwaway ssh-ed25519 key exercises the exact same code path.
"""
import subprocess
import sys
from pathlib import Path

import pytest


class _FakeStdout:
    """A minimal, writable stdout stand-in (print() only needs .write(), and
    optionally .flush()) with a freely-settable .encoding, so
    _confirm_sign's encodability check can be exercised without touching the
    real console. Not a StringIO subclass: io.TextIOBase's own .encoding is a
    read-only C-level property, so it can't be overridden that way. Also
    avoids relying on capsys, which watches the REAL sys.stdout/stderr and
    would see nothing once sys.stdout itself has been swapped out."""

    def __init__(self, encoding: str):
        self.encoding = encoding
        self._buf = []

    def write(self, s):
        self._buf.append(s)
        return len(s)

    def flush(self):
        pass

    def getvalue(self):
        return "".join(self._buf)

TOOL = str(Path(__file__).resolve().parent.parent / "rednb-verify.py")


def _run(*args, **kw):
    kw.setdefault("input", "")
    return subprocess.run([sys.executable, TOOL, *args],
                          capture_output=True, text=True, **kw)


def _nb(tmp_path, files=None):
    nb = tmp_path / "nb"
    nb.mkdir(parents=True, exist_ok=True)
    for fname, content in (files or {"2026-01.txt": "alpha"}).items():
        (nb / fname).write_text(content)
    return nb


def _throwaway_ssh_key(tmp_path, name="testkey"):
    """A plain (non-hardware) ssh-ed25519 keypair -- signs without any tap,
    exercising the identical ssh-keygen -Y sign/verify code path a FIDO2
    sk-* key would, so this doesn't need real hardware to catch the bug."""
    if not shutil_which("ssh-keygen"):
        pytest.skip("ssh-keygen not available")
    key_path = tmp_path / name
    r = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "test@example.com",
         "-f", str(key_path), "-q"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        pytest.skip(f"could not generate a throwaway ssh key: {r.stderr}")
    return key_path, key_path.with_suffix(".pub")


def shutil_which(name):
    import shutil
    return shutil.which(name)


def _create_and_sign(tmp_path, nb, out, pub_path, manifest_type="txt"):
    r = _run(str(nb), "--ssh", str(pub_path), "-o", str(out),
             "--manifest-type", manifest_type, input="y\n")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SSH signature created" in r.stdout
    ext = ".json" if manifest_type == "json" else ".txt"
    manifest = next(out.glob(f"hashes-*{ext}"))
    sig = manifest.with_suffix(manifest.suffix + ".sshsig")
    assert sig.exists()
    return manifest, sig


# ---- the reported bug: directory-form --verify + SSH signature checking ----

def test_verify_directory_form_auto_detected_sig(tmp_path):
    priv, pub = _throwaway_ssh_key(tmp_path)
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    _create_and_sign(tmp_path, nb, out, pub)

    # --verify <DIRECTORY> (not the explicit file) is what triggered the bug:
    # the auto-selected manifest path was left relative, so the auto-detected
    # .sshsig path derived from it was ALSO relative, and ssh-keygen -Y verify
    # (run with cwd changed to the manifest's directory) looked for it in a
    # doubled, nonexistent path.
    r = _run(str(nb), "--verify", str(out), "--ssh", str(pub), "--ssh-verify")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SSH signature verified" in r.stdout
    assert "[PASS]" in r.stdout


def test_verify_directory_form_explicit_relative_sig(tmp_path, monkeypatch):
    priv, pub = _throwaway_ssh_key(tmp_path)
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    manifest, sig = _create_and_sign(tmp_path, nb, out, pub)

    # Exact shape of the user's originally-reported failing command: a
    # directory passed to --verify, AND an explicitly-typed --sig path that
    # is itself relative to the invocation directory.
    monkeypatch.chdir(tmp_path)
    rel_out = str(out.relative_to(tmp_path))
    rel_sig = str(sig.relative_to(tmp_path))
    r = subprocess.run(
        [sys.executable, TOOL, str(nb.relative_to(tmp_path)), "--verify", rel_out,
         "--ssh", str(pub), "--ssh-verify", "--sig", rel_sig],
        capture_output=True, text=True, input="",
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SSH signature verified" in r.stdout
    assert "[PASS]" in r.stdout
    # An explicit --sig is the documented, fully-supported way to point at a
    # signature file -- it must not be flagged as if something were wrong.
    assert "non-standard filename" not in r.stdout


def test_verify_explicit_file_form_still_works(tmp_path):
    # The explicit-file branch already resolved to absolute before this fix;
    # confirm it still does (no regression from touching the shared helper).
    priv, pub = _throwaway_ssh_key(tmp_path)
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    manifest, sig = _create_and_sign(tmp_path, nb, out, pub)

    r = _run(str(nb), "--verify", str(manifest), "--ssh", str(pub),
             "--ssh-verify", "--sig", str(sig))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SSH signature verified" in r.stdout
    assert "non-standard filename" not in r.stdout


def test_verify_json_manifest_directory_form(tmp_path):
    # Same bug class, JSON manifest format.
    priv, pub = _throwaway_ssh_key(tmp_path)
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    _create_and_sign(tmp_path, nb, out, pub, manifest_type="json")

    r = _run(str(nb), "--verify", str(out), "--ssh", str(pub), "--ssh-verify")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SSH signature verified" in r.stdout


# ---- must not mask real problems ----

def test_verify_detects_tampered_notebook_file(tmp_path):
    priv, pub = _throwaway_ssh_key(tmp_path)
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    _create_and_sign(tmp_path, nb, out, pub)

    (nb / "2026-01.txt").write_text("TAMPERED")

    r = _run(str(nb), "--verify", str(out), "--ssh", str(pub), "--ssh-verify")
    assert r.returncode == 1
    # Signature (of the manifest file) is still genuinely valid; it's the
    # notebook content that no longer matches -- these are independent checks.
    assert "SSH signature verified" in r.stdout
    assert "Modified" in r.stdout
    assert "[PASS]" not in r.stdout


def test_verify_detects_tampered_manifest_and_surfaces_reason(tmp_path):
    priv, pub = _throwaway_ssh_key(tmp_path)
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    manifest, sig = _create_and_sign(tmp_path, nb, out, pub)

    manifest.write_text(manifest.read_text() + "\ntampered\n")

    r = _run(str(nb), "--verify", str(out), "--ssh", str(pub), "--ssh-verify")
    assert r.returncode == 1
    assert "Manifest failed Signature" in r.stdout
    # The failure reason must be surfaced, not silently swallowed -- this was
    # the second half of what made the original bug hard to diagnose.
    assert "SSH signature verification failed" in (r.stdout + r.stderr)


def test_wrong_key_fails_verification(tmp_path):
    priv1, pub1 = _throwaway_ssh_key(tmp_path, "key1")
    priv2, pub2 = _throwaway_ssh_key(tmp_path, "key2")
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    _create_and_sign(tmp_path, nb, out, pub1)

    r = _run(str(nb), "--verify", str(out), "--ssh", str(pub2), "--ssh-verify")
    assert r.returncode == 1
    assert "Manifest failed Signature" in r.stdout


# ---- unit-level: the resolved-path guarantee itself ----

def test_ssh_verify_manifest_accepts_relative_sig_path(tool, tmp_path, monkeypatch):
    priv, pub = _throwaway_ssh_key(tmp_path)
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    manifest, sig = _create_and_sign(tmp_path, nb, out, pub)

    monkeypatch.chdir(tmp_path)
    rel_manifest = manifest.relative_to(tmp_path)
    rel_sig = sig.relative_to(tmp_path)
    assert not rel_manifest.is_absolute()
    assert not rel_sig.is_absolute()

    result = tool.ssh_verify_manifest(
        rel_manifest, rel_sig, pub, multiple_signatures=False,
    )
    assert result.status == "OK"


def test_resolve_manifest_path_directory_branch_returns_absolute(tool, tmp_path, monkeypatch):
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out))
    assert r.returncode == 0

    monkeypatch.chdir(tmp_path)
    resolved = tool._resolve_manifest_path(str(out.relative_to(tmp_path)), out)
    assert resolved.is_absolute()


# ---- Unicode-safe signing warning (cp1252 console crash guard) ----

def test_confirm_sign_falls_back_when_encoding_cannot_render_box(tool, monkeypatch):
    fake = _FakeStdout("cp1252")
    monkeypatch.setattr(tool.sys, "stdout", fake)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    # Real assertion is that this does NOT raise UnicodeEncodeError (it would
    # have, unconditionally printing the box-drawing version on a cp1252
    # stream) -- then confirm the plain fallback, not the fancy box, was what
    # actually got written.
    assert tool._confirm_sign(
        tool.SSH_NON_REPUDIATION_WARNING, tool.SSH_NON_REPUDIATION_WARNING_PLAIN,
        "prompt: ", False,
    ) is True
    out = fake.getvalue()
    assert "SSH Non-Repudiation Warning" in out
    assert "╔" not in out            # the box-drawing corner character


def test_confirm_sign_uses_fancy_box_when_encoding_supports_it(tool, monkeypatch):
    fake = _FakeStdout("utf-8")
    monkeypatch.setattr(tool.sys, "stdout", fake)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    tool._confirm_sign(
        tool.SSH_NON_REPUDIATION_WARNING, tool.SSH_NON_REPUDIATION_WARNING_PLAIN,
        "prompt: ", False,
    )
    out = fake.getvalue()
    assert "╔" in out                 # the box-drawing corner character
