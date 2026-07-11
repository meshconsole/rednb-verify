"""Tests for RFC 3161 timestamping (--tsa and friends).

Everything here is OFFLINE: network calls are monkeypatched. The one test that
touches openssl (query generation) skips when openssl isn't installed.
"""
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

TOOL = str(Path(__file__).resolve().parent.parent / "rednb-verify.py")


def _run(*args, **kw):
    return subprocess.run([sys.executable, TOOL, *args],
                          capture_output=True, text=True, **kw)


def _journal(tmp_path):
    nb = tmp_path / "j"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    (nb / "2026-02.txt").write_text("beta")
    return nb


def _fake_net(tool, monkeypatch, token=b"FAKE-TSR"):
    """Stub the network + token-time so embed logic runs without a TSA."""
    calls = []

    def fake_request(data: bytes, url: str, label: str = ""):
        calls.append((data, url))
        return token

    monkeypatch.setattr(tool, "tsa_timestamp_data", fake_request)
    monkeypatch.setattr(tool, "tsa_token_time", lambda tsr: "Jul 3 00:00:00 2026 GMT")
    return calls


# ---- flag plumbing (subprocess; no network possible: they exit before) ----

def test_tsa_list_prints_registry_and_exits():
    r = _run("--tsa-list")
    assert r.returncode == 0
    assert "digicert" in r.stdout and "http://timestamp.digicert.com" in r.stdout


def test_offline_refuses_tsa(tmp_path):
    nb = _journal(tmp_path)
    r = _run(str(nb), "--no-sign", "--offline", "--tsa", "digicert")
    assert r.returncode == 2
    assert "--offline forbids" in r.stderr


def test_offline_alone_is_fine(tmp_path):
    nb = _journal(tmp_path)
    r = _run(str(nb), "--no-sign", "-o", str(tmp_path), "--offline")
    assert r.returncode == 0


def test_embed_flags_require_tsa(tmp_path):
    nb = _journal(tmp_path)
    r = _run(str(nb), "--no-sign", "--tsa-embed")
    assert r.returncode == 2
    assert "require --tsa" in r.stderr


def test_embed_modes_mutually_exclusive(tmp_path):
    nb = _journal(tmp_path)
    r = _run(str(nb), "--no-sign", "--tsa", "digicert",
             "--tsa-embed", "--tsa-embed-separate")
    assert r.returncode == 2
    assert "mutually exclusive" in r.stderr


def test_tsa_is_create_only(tmp_path):
    nb = _journal(tmp_path)
    r = _run(str(nb), "--verify", str(tmp_path), "--tsa", "digicert")
    assert r.returncode == 2
    assert "create-time flag" in r.stderr


# ---- registry resolution ----

def test_resolve_tsa_name_and_url(tool):
    assert tool.resolve_tsa("digicert") == "http://timestamp.digicert.com"
    assert tool.resolve_tsa("DigiCert") == "http://timestamp.digicert.com"
    assert tool.resolve_tsa("https://my.tsa.example/tsr") == "https://my.tsa.example/tsr"


def test_resolve_tsa_unknown_exits(tool):
    with pytest.raises(SystemExit) as e:
        tool.resolve_tsa("bogus-authority")
    assert e.value.code == 2


# ---- embed logic (mocked network) ----

def _manifest(tool, tmp_path, algos=("sha256",)):
    nb = tmp_path / "nb"
    nb.mkdir(parents=True, exist_ok=True)
    (nb / "2026-01.txt").write_text("alpha")
    (nb / "2026-02.txt").write_text("beta")
    return tool.generate_manifest(nb, False, list(algos), "sha256")


def test_embed_single_covers_merkle_root(tool, tmp_path, monkeypatch):
    m = _manifest(tool, tmp_path)
    calls = _fake_net(tool, monkeypatch)
    assert tool.tsa_embed_into_manifest(m, "http://tsa.example", separate=False)
    assert len(calls) == 1                                   # ONE network call
    assert calls[0][0] == m["merkle_root"].encode()          # covers the root
    entry = m["tsa_stamp"]
    assert entry["tsa"] == "http://tsa.example"
    assert base64.b64decode(entry["token_b64"]) == b"FAKE-TSR"
    assert "tsa_merkle" not in m and "tsa_content" not in m


def test_embed_separate_two_stamps_single_hash(tool, tmp_path, monkeypatch):
    m = _manifest(tool, tmp_path)
    calls = _fake_net(tool, monkeypatch)
    assert tool.tsa_embed_into_manifest(m, "http://tsa.example", separate=True)
    assert len(calls) == 2                                   # TWO network calls
    assert m["tsa_merkle"] and m["tsa_content"]
    assert "tsa_stamp" not in m
    covered = {c[0].decode() for c in calls}
    assert m["merkle_root"] in covered and m["content_root"] in covered


def test_embed_separate_multi_hash_uses_concat(tool, tmp_path, monkeypatch):
    m = _manifest(tool, tmp_path, algos=("sha256", "blake2b"))
    assert "merkle_root_concat" not in m                     # not requested at create
    calls = _fake_net(tool, monkeypatch)
    assert tool.tsa_embed_into_manifest(m, "http://tsa.example", separate=True)
    # concat root auto-computed AND stored so verify can recheck it
    assert "merkle_root_concat" in m
    assert m["tsa_concat"] and m["tsa_content"]
    concat_root = next(iter(m["merkle_root_concat"].values()))
    covered = {c[0].decode() for c in calls}
    assert concat_root in covered
    # content value is the alphabetical algo:root join
    crs = m["content_roots"]
    assert ",".join(f"{a}:{crs[a]}" for a in sorted(crs)) in covered


def test_embed_failure_returns_false(tool, tmp_path, monkeypatch):
    m = _manifest(tool, tmp_path)
    monkeypatch.setattr(tool, "tsa_timestamp_data", lambda data, url, label="": None)
    assert not tool.tsa_embed_into_manifest(m, "http://tsa.example", separate=False)


# ---- stamped-value recovery (verify side) ----

def test_stamped_value_mapping(tool, tmp_path, monkeypatch):
    m = _manifest(tool, tmp_path)
    assert tool._tsa_stamped_value(m, "tsa_stamp") == m["merkle_root"]
    assert tool._tsa_stamped_value(m, "tsa_merkle") == m["merkle_root"]
    assert tool._tsa_stamped_value(m, "tsa_content") == m["content_root"]
    mm = _manifest(tool, tmp_path / "multi", algos=("sha256", "blake2b"))
    _fake_net(tool, monkeypatch)
    tool.tsa_embed_into_manifest(mm, "http://tsa.example", separate=True)
    concat_root = next(iter(mm["merkle_root_concat"].values()))
    assert tool._tsa_stamped_value(mm, "tsa_concat") == concat_root


# ---- text round-trip + schema ----

def test_text_roundtrip_preserves_tsa_fields(tool, tmp_path, monkeypatch):
    m = _manifest(tool, tmp_path)
    _fake_net(tool, monkeypatch)
    tool.tsa_embed_into_manifest(m, "http://tsa.example", separate=True)
    parsed = tool._parse_text_manifest(tool._write_text_manifest(m))
    assert parsed["tsa_merkle"] == m["tsa_merkle"]
    assert parsed["tsa_content"] == m["tsa_content"]


def test_schema_accepts_and_rejects_tsa_entries(tool, tmp_path, monkeypatch):
    pytest.importorskip("jsonschema")
    m = _manifest(tool, tmp_path)
    _fake_net(tool, monkeypatch)
    tool.tsa_embed_into_manifest(m, "http://tsa.example", separate=False)
    assert tool.validate_manifest_schema(m) == []
    m["tsa_stamp"] = {"tsa": "http://x"}                     # token_b64 missing
    assert tool.validate_manifest_schema(m)


# ---- verify-side handling (subprocess, no cert / ignore) ----

def _create_with_fake_stamp(tmp_path):
    """Create a real unsigned manifest, then inject a fake embedded stamp
    (text format tolerates appended header lines only via rewrite, so use
    the JSON manifest and edit it)."""
    nb = _journal(tmp_path)
    r = _run(str(nb), "--no-sign", "-o", str(tmp_path), "--manifest-type", "json")
    assert r.returncode == 0
    mf = sorted(tmp_path.glob("hashes-*.json"))[-1]
    doc = json.loads(mf.read_text())
    doc["tsa_stamp"] = {"tsa": "http://tsa.example", "time": "t",
                        "token_b64": base64.b64encode(b"FAKE").decode()}
    mf.write_text(json.dumps(doc))
    return nb, mf


def test_verify_warns_without_tsa_cert(tmp_path):
    # With no --tsa-cert the tool now tries the system trust store rather than
    # refusing outright; a fake/unverifiable token still can't confirm, so the
    # unconfirmed TSA claim must still block PASS.
    nb, mf = _create_with_fake_stamp(tmp_path)
    r = _run(str(nb), "--verify", str(mf), "--no-sign")
    out = r.stdout + r.stderr
    assert r.returncode == 1                                  # unconfirmed TSA claim blocks PASS
    assert "system trust store" in out
    assert "Verification completed with issues" in r.stdout


def test_verify_ignore_tsa_skips(tmp_path):
    nb, mf = _create_with_fake_stamp(tmp_path)
    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--ignore-tsa")
    out = r.stdout + r.stderr
    assert r.returncode == 0
    assert "--ignore-tsa in use" in out
    assert "system trust store" not in out


# ---- openssl query generation (skips when openssl absent) ----

def test_query_bytes_with_real_openssl(tool, tmp_path):
    if not tool.openssl_available():
        pytest.skip("openssl not installed")
    f = tmp_path / "data.txt"
    f.write_text("hello")
    tsq = tool._tsa_query_bytes(f)
    assert tsq and tsq[0] == 0x30                             # DER SEQUENCE


# ---- backend selection (openssl preferred, rfc3161ng fallback) ----

def test_backend_available_reflects_openssl_or_lib(tool, monkeypatch):
    monkeypatch.setattr(tool, "openssl_available", lambda: False)
    monkeypatch.setattr(tool, "_tsa_lib_available", lambda: False)
    assert not tool.tsa_backend_available()
    monkeypatch.setattr(tool, "_tsa_lib_available", lambda: True)
    assert tool.tsa_backend_available()


def test_request_prefers_openssl(tool, monkeypatch):
    monkeypatch.setattr(tool, "openssl_available", lambda: True)
    monkeypatch.setattr(tool, "_tsa_query_bytes", lambda p: b"QUERY")
    monkeypatch.setattr(tool, "_tsa_http_post", lambda url, q, timeout=30: b"TSR")
    monkeypatch.setattr(tool, "_lib_request", lambda d, u: (_ for _ in ()).throw(AssertionError))
    assert tool._tsa_request_bytes(b"data", "http://x") == b"TSR"


def test_request_falls_back_to_lib_without_openssl(tool, monkeypatch):
    monkeypatch.setattr(tool, "openssl_available", lambda: False)
    monkeypatch.setattr(tool, "_tsa_lib_available", lambda: True)
    monkeypatch.setattr(tool, "_lib_request", lambda data, url: b"LIBTSR")
    assert tool._tsa_request_bytes(b"data", "http://x") == b"LIBTSR"


def test_request_no_backend_returns_none(tool, monkeypatch):
    monkeypatch.setattr(tool, "openssl_available", lambda: False)
    monkeypatch.setattr(tool, "_tsa_lib_available", lambda: False)
    assert tool._tsa_request_bytes(b"data", "http://x") is None


def test_verify_no_backend_is_none(tool, tmp_path, monkeypatch):
    monkeypatch.setattr(tool, "openssl_available", lambda: False)
    monkeypatch.setattr(tool, "_tsa_lib_available", lambda: False)
    assert tool.tsa_verify_data(b"d", b"t", tmp_path / "ca.pem") is None




# ---- failure handling: preserve the hashing, mark 'failed' ----

def test_embed_failure_marks_failed(tool, tmp_path, monkeypatch):
    m = _manifest(tool, tmp_path)
    monkeypatch.setattr(tool, "tsa_timestamp_data", lambda data, url, label="": None)
    assert tool.tsa_embed_into_manifest(m, "http://x", separate=False) is False
    assert m["tsa_stamp"] == "failed"


def test_embed_separate_partial_failure_keeps_success(tool, tmp_path, monkeypatch):
    calls = []

    def fake(data, url, label=""):
        calls.append(data)
        return b"TSR" if len(calls) == 1 else None   # placement ok, content fails

    monkeypatch.setattr(tool, "tsa_timestamp_data", fake)
    monkeypatch.setattr(tool, "tsa_token_time", lambda t: "t")
    m = _manifest(tool, tmp_path)
    assert tool.tsa_embed_into_manifest(m, "http://x", separate=True) is False
    assert isinstance(m["tsa_merkle"], dict)             # first stamp preserved
    assert m["tsa_content"] == "failed"                  # second marked failed


def test_schema_accepts_failed_marker(tool, tmp_path):
    pytest.importorskip("jsonschema")
    m = _manifest(tool, tmp_path)
    m["tsa_stamp"] = "failed"
    assert tool.validate_manifest_schema(m) == []


def test_text_roundtrip_failed_marker(tool, tmp_path):
    m = _manifest(tool, tmp_path)
    m["tsa_content"] = "failed"
    m["tsa_merkle"] = "failed"
    parsed = tool._parse_text_manifest(tool._write_text_manifest(m))
    assert parsed["tsa_content"] == "failed" and parsed["tsa_merkle"] == "failed"


# ---- CLI failure paths (loopback refused connection; no external network) ----

_DEAD_TSA = "http://127.0.0.1:1"     # closed port -> immediate ECONNREFUSED


def test_cli_embed_failure_writes_manifest_with_marker(tmp_path):
    nb = _journal(tmp_path)
    r = _run(str(nb), "--no-sign", "--tsa", _DEAD_TSA, "--tsa-embed",
             "--manifest-type", "json", "-o", str(tmp_path), input="")
    assert r.returncode == 0                              # hashing preserved
    doc = json.loads(sorted(tmp_path.glob("hashes-*.json"))[-1].read_text())
    assert doc.get("tsa_stamp") == "failed"


def test_cli_detached_failure_noninteractive_continues(tmp_path):
    nb = _journal(tmp_path)
    r = _run(str(nb), "--no-sign", "--tsa", _DEAD_TSA, "-o", str(tmp_path), input="")
    assert r.returncode == 0                              # non-interactive -> continue
    assert sorted(tmp_path.glob("hashes-*.txt"))          # manifest written
    assert not list(tmp_path.glob("hashes-*.tsr"))        # but no token
    assert "Timestamping failed" in r.stdout + r.stderr


def test_cli_verify_failed_marker_warns_not_fail(tmp_path):
    nb = _journal(tmp_path)
    _run(str(nb), "--no-sign", "-o", str(tmp_path), "--manifest-type", "json")
    mf = sorted(tmp_path.glob("hashes-*.json"))[-1]
    doc = json.loads(mf.read_text())
    doc["tsa_stamp"] = "failed"
    mf.write_text(json.dumps(doc))
    r = _run(str(nb), "--verify", str(mf), "--no-sign")
    assert r.returncode == 0
    assert "not applied" in (r.stdout + r.stderr)


# ---- duplicate "Requesting timestamp" log line (bug found in live testing) ----
# Mocking tsa_timestamp_data directly would replace the very code whose
# _info() call these tests check, so the single-request case is tested at the
# CLI level (subprocess, real code path, a dead TSA fails fast on request 1).
# The two-request case needs two SUCCESSFUL round trips -- a dead TSA stops
# after the first failure -- so that one mocks only the network primitive
# (_tsa_http_post), leaving the real _tsa_request_bytes/_info() path intact.

def test_cli_embed_single_prints_exactly_one_request_line(tmp_path):
    # End-to-end reproduction of the exact bug: --tsa-embed used to print BOTH
    # a "Requesting N timestamp(s)" summary AND a per-request "Requesting
    # timestamp" line for the same single request.
    nb = _journal(tmp_path)
    r = _run(str(nb), "--no-sign", "--tsa", _DEAD_TSA, "--tsa-embed",
             "-o", str(tmp_path), input="")
    lines = [l for l in (r.stdout + r.stderr).splitlines() if "Requesting timestamp" in l]
    assert len(lines) == 1


def test_embed_separate_prints_two_distinct_labeled_lines(tool, tmp_path, monkeypatch, capsys):
    # _DEAD_TSA can't cover this: the embed loop correctly stops after the
    # FIRST failed request rather than attempting the second against a TSA
    # that just refused the connection, so it never gets to a second label.
    # Testing two REQUESTS requires two SUCCESSFUL round trips; mock only the
    # actual network primitive (_tsa_http_post) so the real _tsa_request_bytes
    # -- including its _info() call -- still runs for both attempts.
    m = _manifest(tool, tmp_path)
    monkeypatch.setattr(tool, "_tsa_http_post", lambda url, tsq, timeout=30: b"FAKE-TSR")
    monkeypatch.setattr(tool, "openssl_available", lambda: True)
    monkeypatch.setattr(tool, "_tsa_query_bytes", lambda data_path: b"FAKE-QUERY")
    monkeypatch.setattr(tool, "tsa_token_time", lambda tsr: "t")
    capsys.readouterr()
    assert tool.tsa_embed_into_manifest(m, "http://tsa.example", separate=True)
    lines = [l for l in capsys.readouterr().out.splitlines() if "Requesting timestamp" in l]
    assert len(lines) == 2
    assert "(1/2)" in lines[0] and "(2/2)" in lines[1]


# ---- verdict: an explicitly-requested TSA check that can't be confirmed must
# not still report [PASS] (bug found in live testing against a real TSA) ----
#
# The subprocess is run with a PATH that excludes openssl, forcing the library
# (rfc3161ng) backend regardless of what happens to be installed on the machine
# running these tests -- this matters because openssl's -verify always returns
# a clean True/False, never inconclusive; only the library path can produce
# None, and that's specifically the case this test needs to exercise.

def _env_without_openssl():
    # A machine can have more than one openssl on PATH (e.g. Git for Windows
    # ships one under both mingw64\bin and usr\bin) -- shutil.which() only
    # finds the first, so scan every PATH entry directly instead.
    env = dict(os.environ)
    dirs_with_openssl = {
        p for p in env.get("PATH", "").split(os.pathsep)
        if any((Path(p) / name).is_file() for name in ("openssl", "openssl.exe"))
    }
    env["PATH"] = os.pathsep.join(
        p for p in env.get("PATH", "").split(os.pathsep) if p not in dirs_with_openssl
    )
    return env


def test_verify_tsa_inconclusive_with_cert_blocks_pass(tmp_path):
    pytest.importorskip("rfc3161ng")
    nb = _journal(tmp_path)
    _run(str(nb), "--no-sign", "-o", str(tmp_path), "--manifest-type", "json")
    mf = sorted(tmp_path.glob("hashes-*.json"))[-1]
    doc = json.loads(mf.read_text())
    doc["tsa_stamp"] = {"tsa": "http://x", "time": "t", "token_b64": "Zm9v"}
    mf.write_text(json.dumps(doc))
    ca = tmp_path / "ca.pem"
    ca.write_text("dummy")  # not a real cert -> decode fails -> inconclusive

    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--tsa-cert", str(ca),
             env=_env_without_openssl())
    out = r.stdout + r.stderr
    assert r.returncode == 1
    assert "[PASS]" not in out
    assert "Verification completed with issues" in out
    assert "TSA timestamp" in out


def test_verify_tsa_no_cert_given_also_blocks_pass(tmp_path):
    # A TSA claim exists in the manifest and wasn't ignored (--ignore-tsa) --
    # leaving it silently unconfirmed just because --tsa-cert happened to be
    # omitted would let verification read as a clean pass even though part of
    # what the manifest asserts was never checked. Only --ignore-tsa (or a
    # confirmed match) produces a clean [PASS] when a TSA stamp is present.
    nb = _journal(tmp_path)
    _run(str(nb), "--no-sign", "-o", str(tmp_path), "--manifest-type", "json")
    mf = sorted(tmp_path.glob("hashes-*.json"))[-1]
    doc = json.loads(mf.read_text())
    doc["tsa_stamp"] = {"tsa": "http://x", "time": "t", "token_b64": "Zm9v"}
    mf.write_text(json.dumps(doc))

    r = _run(str(nb), "--verify", str(mf), "--no-sign")
    out = r.stdout + r.stderr
    assert r.returncode == 1
    assert "[PASS]" not in r.stdout
    assert "Verification completed with issues" in r.stdout
    # The tool tried the system trust store but couldn't confirm this token.
    assert "system trust store" in out
    assert "could not be verified" in r.stdout


def test_verify_tsa_ignore_tsa_still_passes(tmp_path):
    # --ignore-tsa is the one way to get a clean PASS with an unconfirmed
    # TSA stamp present -- an explicit, deliberate opt-out.
    nb = _journal(tmp_path)
    _run(str(nb), "--no-sign", "-o", str(tmp_path), "--manifest-type", "json")
    mf = sorted(tmp_path.glob("hashes-*.json"))[-1]
    doc = json.loads(mf.read_text())
    doc["tsa_stamp"] = {"tsa": "http://x", "time": "t", "token_b64": "Zm9v"}
    mf.write_text(json.dumps(doc))

    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--ignore-tsa")
    assert r.returncode == 0
    assert "[PASS]" in r.stdout


# ---- _lib_verify exception routing (the actual bug: certificate= misuse and
# check_timestamp's own broken None-vs-b"" default). Uses a real self-signed
# cert (offline, no network) so _lib_verify's CA-load step succeeds, then
# monkeypatches rfc3161ng.check_timestamp to force each exception path. ----

def _throwaway_pem_cert(tmp_path):
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as _dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
        .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "throwaway-ca.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def test_lib_verify_ec_typeerror_is_inconclusive_not_false(tool, tmp_path, monkeypatch):
    pytest.importorskip("rfc3161ng")
    import rfc3161ng

    class _Tst:
        content = object()

    class _Resp:
        time_stamp_token = _Tst()

    monkeypatch.setattr(rfc3161ng, "decode_timestamp_response", lambda tsr: _Resp())

    def _raise_ec(tst, certificate=None, data=None, hashname=None):
        raise TypeError("ECPublicKey.verify() takes 3 positional arguments but 4 were given")

    monkeypatch.setattr(rfc3161ng, "check_timestamp", _raise_ec)
    ca_file = _throwaway_pem_cert(tmp_path)
    assert tool._lib_verify(b"root-value", b"fake-tsr-bytes", ca_file) is None


def test_lib_verify_message_imprint_mismatch_is_false_not_none(tool, tmp_path, monkeypatch):
    # This is the library's own tamper-detection signal (data given doesn't
    # match what the token certifies) -- a real failure, not a tooling gap.
    pytest.importorskip("rfc3161ng")
    import rfc3161ng

    class _Tst:
        content = object()

    class _Resp:
        time_stamp_token = _Tst()

    monkeypatch.setattr(rfc3161ng, "decode_timestamp_response", lambda tsr: _Resp())

    def _raise_mismatch(tst, certificate=None, data=None, hashname=None):
        raise ValueError("Message imprint mismatch")

    monkeypatch.setattr(rfc3161ng, "check_timestamp", _raise_mismatch)
    ca_file = _throwaway_pem_cert(tmp_path)
    assert tool._lib_verify(b"tampered-value", b"fake-tsr-bytes", ca_file) is False


def test_lib_verify_passes_certificate_bstring_not_none(tool, tmp_path, monkeypatch):
    # Regression guard for the check_timestamp(certificate=None) bug: its OWN
    # default is None, but load_certificate's "auto-extract from token" sentinel
    # is b"" -- passing None crashes inside load_certificate. _lib_verify must
    # always pass certificate=b"" explicitly for step 1.
    pytest.importorskip("rfc3161ng")
    import rfc3161ng

    class _Tst:
        content = object()

    class _Resp:
        time_stamp_token = _Tst()

    monkeypatch.setattr(rfc3161ng, "decode_timestamp_response", lambda tsr: _Resp())
    seen = {}

    def _capture(tst, certificate=None, data=None, hashname=None):
        seen["certificate"] = certificate
        return True

    monkeypatch.setattr(rfc3161ng, "check_timestamp", _capture)
    ca_file = _throwaway_pem_cert(tmp_path)
    tool._lib_verify(b"root-value", b"fake-tsr-bytes", ca_file)
    assert seen["certificate"] == b""


# ---- --tsa marked experimental (two live testing rounds found real, if
# narrow, reliability gaps in the rfc3161ng fallback backend) ----

def test_cli_create_tsa_prints_experimental_warning(tmp_path):
    nb = _journal(tmp_path)
    r = _run(str(nb), "--no-sign", "--tsa", _DEAD_TSA, "-o", str(tmp_path), input="")
    assert "EXPERIMENTAL" in r.stdout


def test_cli_verify_tsa_check_prints_experimental_warning_without_openssl(tmp_path):
    nb, mf = _create_with_fake_stamp(tmp_path)
    ca = _throwaway_pem_cert(tmp_path)
    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--tsa-cert", str(ca),
             env=_env_without_openssl())
    assert "EXPERIMENTAL" in r.stdout


def test_verify_experimental_warning_skipped_when_openssl_available(tool, tmp_path):
    if not tool.openssl_available():
        pytest.skip("openssl not installed")
    # Only the rfc3161ng fallback has shown issues -- don't alarm users who
    # have openssl, which has no known problems in testing so far. Run
    # WITHOUT stripping PATH so openssl (present on this dev machine) is used.
    nb, mf = _create_with_fake_stamp(tmp_path)
    ca = _throwaway_pem_cert(tmp_path)
    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--tsa-cert", str(ca))
    assert "EXPERIMENTAL" not in r.stdout


# ---- root-first certificate ordering (real Apple + Sectigo tokens found the
# certificates[0]-is-the-signer assumption in rfc3161ng.api.load_certificate
# is wrong when a TSA sends its `certificates` SET root-first rather than
# leaf-first -- both orderings are legal per RFC 5652, the SET has no defined
# order. That mis-selection made _lib_verify fail real, untampered tokens
# with InvalidSignature. _find_signer_certificate_der fixes this by matching
# signerInfo's issuerAndSerialNumber instead of guessing index 0.) ----

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tsa"


@pytest.mark.parametrize("name", ["apple", "sectigo"])
def test_find_signer_certificate_der_picks_non_zero_index(tool, name):
    # Both fixtures are real captured tokens whose certificates SET is
    # root-first: the actual signer is at index [2], not [0].
    pytest.importorskip("rfc3161ng")
    pytest.importorskip("pyasn1")
    pytest.importorskip("cryptography")
    import rfc3161ng
    from pyasn1.codec.der import encoder as der_encoder
    from cryptography import x509

    tsr = (_FIXTURES / f"{name}.tsr").read_bytes()
    tst = rfc3161ng.decode_timestamp_response(tsr).time_stamp_token
    signed_data = tst.content
    certs = signed_data["certificates"]

    signer_der = tool._find_signer_certificate_der(signed_data)
    assert signer_der is not None

    index_zero_der = der_encoder.encode(certs[0][0])
    assert signer_der != index_zero_der, (
        "fixture no longer exercises the root-first ordering this test guards"
    )

    signer_cert = x509.load_der_x509_certificate(signer_der)
    assert "Signer" in signer_cert.subject.rfc4514_string()


@pytest.mark.parametrize("name", ["apple", "sectigo"])
def test_lib_verify_step1_passes_for_root_first_cert_order(tool, name):
    # Before the fix, both of these raised InvalidSignature in _lib_verify's
    # step 1 (checked against the wrong -- root/intermediate -- certificate)
    # despite being real, untampered, independently-valid tokens.
    pytest.importorskip("rfc3161ng")
    import rfc3161ng
    from cryptography.exceptions import InvalidSignature

    data = (_FIXTURES / f"{name}-data.txt").read_bytes()
    tsr = (_FIXTURES / f"{name}.tsr").read_bytes()
    tst = rfc3161ng.decode_timestamp_response(tsr).time_stamp_token
    signer_der = tool._find_signer_certificate_der(tst.content)
    assert signer_der is not None

    try:
        rfc3161ng.check_timestamp(tst, certificate=signer_der, data=data, hashname="sha256")
    except InvalidSignature:
        pytest.fail(f"{name}: signature check failed even with the correct signer cert")


# ---- chain-building: --tsa-cert can be the ROOT, not just the direct issuer
# (a 3-level chain signer<-intermediate<-root must verify when any ancestor,
# including the root, is the pinned anchor -- matching openssl -CAfile) ----

def _embedded_cert_pem(tsr_bytes, needle):
    import rfc3161ng
    from pyasn1.codec.der import encoder
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    tst = rfc3161ng.decode_timestamp_response(tsr_bytes).time_stamp_token
    certs = tst.content["certificates"]
    for i in range(len(certs)):
        der = encoder.encode(certs[i][0])
        c = x509.load_der_x509_certificate(der)
        if needle in c.subject.rfc4514_string():
            return c.public_bytes(Encoding.PEM)
    return None


@pytest.mark.parametrize("anchor", ["Root", "CA R41", "Signer"])
def test_lib_verify_chains_to_any_anchor_level(tool, tmp_path, anchor):
    # Sectigo sends signer<-CA R41<-Root R46; pinning ANY of the three as
    # --tsa-cert must verify the token.
    pytest.importorskip("rfc3161ng")
    pytest.importorskip("cryptography")
    data = (_FIXTURES / "sectigo-data.txt").read_bytes()
    tsr = (_FIXTURES / "sectigo.tsr").read_bytes()
    pem = _embedded_cert_pem(tsr, anchor)
    assert pem is not None, f"no embedded cert matching {anchor!r}"
    ca = tmp_path / "anchor.pem"
    ca.write_bytes(pem)
    assert tool._lib_verify(data, tsr, ca) is True


def test_lib_verify_wrong_pinned_ca_is_false(tool, tmp_path):
    # An Apple token pinned against Sectigo's ROOT does not chain to it, so a
    # PINNED-cert mismatch is a real failure (False), as openssl -CAfile reports.
    pytest.importorskip("rfc3161ng")
    a_data = (_FIXTURES / "apple-data.txt").read_bytes()
    a_tsr = (_FIXTURES / "apple.tsr").read_bytes()
    s_tsr = (_FIXTURES / "sectigo.tsr").read_bytes()
    pem = _embedded_cert_pem(s_tsr, "Root")
    ca = tmp_path / "sectigo-root.pem"
    ca.write_bytes(pem)
    assert tool._lib_verify(a_data, a_tsr, ca) is False


def test_lib_verify_system_store_unknown_ca_is_none_not_false(tool, tmp_path, monkeypatch):
    # CRITICAL false-tamper safety: in the system-store path (no pinned CA), a
    # signer whose root isn't a trusted anchor must be INCONCLUSIVE (None), never
    # a failure (False) -- an untrusted-but-legitimate TSA is not tampering.
    pytest.importorskip("rfc3161ng")
    from cryptography import x509
    unrelated = x509.load_pem_x509_certificate(_throwaway_pem_cert(tmp_path).read_bytes())
    monkeypatch.setattr(tool, "_system_trust_anchors", lambda: [unrelated])
    data = (_FIXTURES / "sectigo-data.txt").read_bytes()
    tsr = (_FIXTURES / "sectigo.tsr").read_bytes()
    assert tool._lib_verify(data, tsr, None, system_store=True) is None


def test_lib_verify_system_store_ec_is_none_not_false(tool, monkeypatch):
    # An EC token in the system-store path must also be inconclusive, not a
    # false tamper report.
    pytest.importorskip("rfc3161ng")
    from cryptography import x509
    # A non-empty anchor set (some unrelated real cert) so we exercise the step-1
    # EC path rather than the empty-store guard.
    root_pem = _embedded_cert_pem((_FIXTURES / "sectigo.tsr").read_bytes(), "Root")
    anchor = x509.load_pem_x509_certificate(root_pem)
    monkeypatch.setattr(tool, "_system_trust_anchors", lambda: [anchor])
    data = (_FIXTURES / "freetsa-ec-data.txt").read_bytes()
    tsr = (_FIXTURES / "freetsa-ec.tsr").read_bytes()
    assert tool._lib_verify(data, tsr, None, system_store=True) is None


def test_build_and_verify_chain_empty_anchors_is_false(tool):
    # No anchors -> cannot establish trust -> False (the caller maps this to
    # None in the system-store path; here we assert the primitive itself).
    pytest.importorskip("cryptography")
    from cryptography import x509
    leaf = x509.load_pem_x509_certificate(
        _embedded_cert_pem((_FIXTURES / "sectigo.tsr").read_bytes(), "Signer"))
    assert tool._build_and_verify_chain(leaf, [], []) is False


# ---- --tsa-list carries CA pointers and marks EC hosts ----

def test_tsa_list_shows_ca_pointers_and_ec_mark():
    r = _run("--tsa-list")
    assert r.returncode == 0
    assert "CA certs:" in r.stdout                      # pointer URLs present
    assert "sectigo.com" in r.stdout
    assert "[EC" in r.stdout                            # freetsa flagged EC
    # RSA hosts are not flagged EC
    for line in r.stdout.splitlines():
        if line.strip().startswith("digicert"):
            assert "[EC" not in line


# ---- create-time RSA/EC signer notice ----

def test_keytype_confirm_rsa_keeps_and_announces(tool, capsys):
    pytest.importorskip("rfc3161ng")
    tsr = (_FIXTURES / "sectigo.tsr").read_bytes()
    assert tool._tsa_keytype_confirm(tsr, assume_yes=False, quiet=False) is True
    cap = capsys.readouterr()
    assert "RSA" in (cap.out + cap.err)


def test_keytype_confirm_ec_without_openssl_warns_but_autokeeps(tool, capsys, monkeypatch):
    # Non-interactive stdin (pytest) => auto-keep, but the EC warning must fire so
    # the record isn't silently lost.
    pytest.importorskip("rfc3161ng")
    monkeypatch.setattr(tool, "openssl_available", lambda: False)
    tsr = (_FIXTURES / "freetsa-ec.tsr").read_bytes()
    assert tool._tsa_keytype_confirm(tsr, assume_yes=True, quiet=False) is True
    cap = capsys.readouterr()
    assert "EC" in (cap.out + cap.err)


def test_keytype_confirm_ec_no_openssl_piped_stdin_autokeeps(tool, monkeypatch):
    # A piped/non-tty stdin (the common case: input isn't a real terminal) must
    # also auto-keep without blocking on input() -- assume_yes=False here, so
    # this specifically exercises the "not sys.stdin.isatty()" branch, not the
    # assume_yes shortcut.
    pytest.importorskip("rfc3161ng")
    monkeypatch.setattr(tool, "openssl_available", lambda: False)
    monkeypatch.setattr(tool.sys.stdin, "isatty", lambda: False)
    tsr = (_FIXTURES / "freetsa-ec.tsr").read_bytes()
    assert tool._tsa_keytype_confirm(tsr, assume_yes=False, quiet=False) is True


def test_keytype_confirm_ec_no_openssl_real_tty_declines_when_user_says_no(tool, monkeypatch):
    # On a genuine TTY with no openssl, the user is asked, and "n" must
    # actually decline (return False) -- the one branch that can drop data,
    # so it needs its own direct check beyond the auto-keep paths above.
    pytest.importorskip("rfc3161ng")
    monkeypatch.setattr(tool, "openssl_available", lambda: False)
    monkeypatch.setattr(tool.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    tsr = (_FIXTURES / "freetsa-ec.tsr").read_bytes()
    assert tool._tsa_keytype_confirm(tsr, assume_yes=False, quiet=False) is False


def test_keytype_confirm_ec_no_openssl_real_tty_keeps_when_user_says_yes(tool, monkeypatch):
    pytest.importorskip("rfc3161ng")
    monkeypatch.setattr(tool, "openssl_available", lambda: False)
    monkeypatch.setattr(tool.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    tsr = (_FIXTURES / "freetsa-ec.tsr").read_bytes()
    assert tool._tsa_keytype_confirm(tsr, assume_yes=False, quiet=False) is True
