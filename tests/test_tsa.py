"""Tests for RFC 3161 timestamping (--tsa and friends).

Everything here is OFFLINE: network calls are monkeypatched. The one test that
touches openssl (query generation) skips when openssl isn't installed.
"""
import base64
import json
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

    def fake_request(data: bytes, url: str):
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
    monkeypatch.setattr(tool, "tsa_timestamp_data", lambda data, url: None)
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
    nb, mf = _create_with_fake_stamp(tmp_path)
    r = _run(str(nb), "--verify", str(mf), "--no-sign")
    assert r.returncode == 0                                  # warn, don't fail
    assert "no --tsa-cert" in r.stdout + r.stderr


def test_verify_ignore_tsa_skips(tmp_path):
    nb, mf = _create_with_fake_stamp(tmp_path)
    r = _run(str(nb), "--verify", str(mf), "--no-sign", "--ignore-tsa")
    out = r.stdout + r.stderr
    assert r.returncode == 0
    assert "--ignore-tsa in use" in out
    assert "no --tsa-cert" not in out


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
    monkeypatch.setattr(tool, "tsa_timestamp_data", lambda data, url: None)
    assert tool.tsa_embed_into_manifest(m, "http://x", separate=False) is False
    assert m["tsa_stamp"] == "failed"


def test_embed_separate_partial_failure_keeps_success(tool, tmp_path, monkeypatch):
    calls = []

    def fake(data, url):
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
