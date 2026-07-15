"""Manifest chaining: --prev-manifest / --prev-hash link a manifest to the
previous one by hash of its raw file bytes, and --verify walks the chain back
to genesis, distinguishing a genuinely broken link (tampering) from one that's
merely missing (inconclusive, e.g. a pruned old manifest)."""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

# Manifest filenames are timestamp-based with 1-second resolution
# (hashes-<created>.ext); two creates in the same second collide/overwrite.
_TICK = 1.1

TOOL = str(Path(__file__).resolve().parent.parent / "rednb-verify.py")


def _run(*args, **kw):
    return subprocess.run([sys.executable, TOOL, *args],
                          capture_output=True, text=True, input="", **kw)


def _nb(tmp_path, name="nb", files=None):
    nb = tmp_path / name
    nb.mkdir(parents=True, exist_ok=True)
    for fname, content in (files or {"2026-01.txt": "alpha"}).items():
        (nb / fname).write_text(content)
    return nb


# ---- compute_prev_link (create-time helper) ----

def test_compute_prev_link_genesis(tool, tmp_path):
    nb = _nb(tmp_path)
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    genesis = tmp_path / "hashes-genesis.json"
    genesis.write_text(json.dumps(m))

    link = tool.compute_prev_link(genesis, ["sha256"])
    assert link["file"] == "hashes-genesis.json"
    assert link["created"] == m["created"]
    assert link["height"] == 1                      # first link after genesis
    assert set(link["hashes"]) == {"sha256"}
    assert link["hashes"]["sha256"] == tool.hash_file(genesis, "sha256")


def test_compute_prev_link_increments_height(tool, tmp_path):
    nb = _nb(tmp_path)
    m1 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    f1 = tmp_path / "hashes-1.json"
    f1.write_text(json.dumps(m1))

    link1 = tool.compute_prev_link(f1, ["sha256"])
    m2 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    m2["prev"] = link1
    f2 = tmp_path / "hashes-2.json"
    f2.write_text(json.dumps(m2))

    link2 = tool.compute_prev_link(f2, ["sha256"])
    assert link2["height"] == 2


def test_compute_prev_link_multi_hash(tool, tmp_path):
    nb = _nb(tmp_path)
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    genesis = tmp_path / "hashes-genesis.json"
    genesis.write_text(json.dumps(m))

    link = tool.compute_prev_link(genesis, ["sha256", "blake2b"])
    assert set(link["hashes"]) == {"sha256", "blake2b"}
    assert link["hashes"]["sha256"] != link["hashes"]["blake2b"]


# ---- verify_chain (verify-time walker) ----

def test_verify_chain_no_chain(tool, tmp_path):
    nb = _nb(tmp_path)
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    p = tmp_path / "hashes-genesis.json"
    p.write_text(json.dumps(m))
    status, _ = tool.verify_chain(p, m)
    assert status == "no-chain"


def test_verify_chain_ok_single_link(tool, tmp_path):
    nb = _nb(tmp_path)
    m1 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    f1 = tmp_path / "hashes-1.json"
    f1.write_text(json.dumps(m1))

    m2 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    m2["prev"] = tool.compute_prev_link(f1, ["sha256"])
    f2 = tmp_path / "hashes-2.json"
    f2.write_text(json.dumps(m2))

    status, detail = tool.verify_chain(f2, m2)
    assert status == "ok"
    assert "1 link" in detail


def test_verify_chain_ok_multi_link(tool, tmp_path):
    nb = _nb(tmp_path)
    m1 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    f1 = tmp_path / "hashes-1.json"
    f1.write_text(json.dumps(m1))

    m2 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    m2["prev"] = tool.compute_prev_link(f1, ["sha256"])
    f2 = tmp_path / "hashes-2.json"
    f2.write_text(json.dumps(m2))

    m3 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    m3["prev"] = tool.compute_prev_link(f2, ["sha256"])
    f3 = tmp_path / "hashes-3.json"
    f3.write_text(json.dumps(m3))

    status, detail = tool.verify_chain(f3, m3)
    assert status == "ok"
    assert "2 link" in detail


def test_verify_chain_broken_on_tamper(tool, tmp_path):
    nb = _nb(tmp_path)
    m1 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    f1 = tmp_path / "hashes-1.json"
    f1.write_text(json.dumps(m1))

    m2 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    m2["prev"] = tool.compute_prev_link(f1, ["sha256"])
    f2 = tmp_path / "hashes-2.json"
    f2.write_text(json.dumps(m2))

    # Tamper the PREVIOUS manifest after the link was made.
    tampered = json.loads(f1.read_text())
    tampered["warnings"] = tampered.get("warnings", []) + ["TAMPERED"]
    f1.write_text(json.dumps(tampered))

    status, detail = tool.verify_chain(f2, m2)
    assert status == "broken"
    assert "hashes-1.json" in detail


def test_verify_chain_missing_when_prev_file_gone(tool, tmp_path):
    nb = _nb(tmp_path)
    m1 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    f1 = tmp_path / "hashes-1.json"
    f1.write_text(json.dumps(m1))

    m2 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    m2["prev"] = tool.compute_prev_link(f1, ["sha256"])
    f2 = tmp_path / "hashes-2.json"
    f2.write_text(json.dumps(m2))

    f1.unlink()
    status, detail = tool.verify_chain(f2, m2)
    assert status == "missing"
    assert "hashes-1.json" in detail


# ---- schema ----

def test_prev_field_in_schema(tool):
    assert "prev" in tool.MANIFEST_SCHEMA["properties"]


def test_chained_manifest_is_schema_valid(tool, tmp_path):
    pytest.importorskip("jsonschema")
    nb = _nb(tmp_path)
    m1 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    f1 = tmp_path / "hashes-1.json"
    f1.write_text(json.dumps(m1))
    m2 = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    m2["prev"] = tool.compute_prev_link(f1, ["sha256"])
    errors = tool.validate_against_schema(m2, "manifest", required=True)
    assert errors == []


# ---- CLI: flag validation ----

def test_cli_prev_hash_without_prev_manifest_errors(tmp_path):
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "--prev-hash", "sha256", "-o", str(out))
    assert r.returncode == 2
    assert "--prev-hash requires --prev-manifest" in r.stderr


def test_cli_prev_manifest_with_resign_errors(tmp_path):
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out))
    manifest = next(out.glob("hashes-*.txt"))
    r = _run("--resign", str(manifest), "--gpg", "--prev-manifest", str(out))
    assert r.returncode == 2
    assert "--prev-manifest cannot be combined with --resign" in r.stderr


def test_cli_prev_hash_bad_algo_errors(tmp_path):
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out))
    genesis = next(out.glob("hashes-*.txt"))
    r = _run(str(nb), "--no-sign", "-o", str(out), "--prev-manifest", str(genesis),
             "--prev-hash", "not-a-real-algo")
    assert r.returncode == 2


# ---- CLI: end-to-end create + verify ----

def test_cli_chain_end_to_end_json(tmp_path):
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json")
    assert r.returncode == 0
    genesis = next(out.glob("hashes-*.json"))
    time.sleep(_TICK)

    r = _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json",
             "--prev-manifest", str(genesis), "--prev-hash", "sha256,blake2b")
    assert r.returncode == 0
    assert "Linked to previous manifest" in r.stdout
    chained = [p for p in out.glob("hashes-*.json") if p != genesis][0]
    doc = json.loads(chained.read_text())
    assert doc["prev"]["file"] == genesis.name
    assert doc["prev"]["height"] == 1
    assert set(doc["prev"]["hashes"]) == {"sha256", "blake2b"}

    r = _run(str(nb), "--verify", str(chained), "--no-sign")
    assert r.returncode == 0
    assert "Manifest chain verified" in r.stdout
    assert "[PASS]" in r.stdout


def test_cli_chain_end_to_end_text_round_trip(tmp_path):
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "txt")
    genesis = next(out.glob("hashes-*.txt"))
    time.sleep(_TICK)

    r = _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "txt",
             "--prev-manifest", str(genesis))
    assert r.returncode == 0
    chained = [p for p in out.glob("hashes-*.txt") if p != genesis][0]
    text = chained.read_text()
    assert text.splitlines()[0] == "rednb-verify manifest"
    prev_line = next(l for l in text.splitlines() if l.startswith("prev: "))
    assert json.loads(prev_line[len("prev: "):])["file"] == genesis.name

    r = _run(str(nb), "--verify", str(chained), "--no-sign")
    assert r.returncode == 0
    assert "Manifest chain verified" in r.stdout


def test_cli_prev_manifest_directory_auto_selects_latest(tmp_path):
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json")
    time.sleep(_TICK)
    _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json")
    latest = sorted(out.glob("hashes-*.json"))[-1]

    r = _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json",
             "--prev-manifest", str(out))
    assert r.returncode == 0
    assert "Using latest previous manifest" in r.stdout
    assert latest.name in r.stdout


def test_cli_chain_broken_blocks_pass_as_hard_fail(tmp_path):
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json")
    genesis = next(out.glob("hashes-*.json"))
    time.sleep(_TICK)
    _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json",
         "--prev-manifest", str(genesis))
    chained = [p for p in out.glob("hashes-*.json") if p != genesis][0]

    # Tamper the genesis manifest after chaining.
    doc = json.loads(genesis.read_text())
    doc["warnings"] = doc.get("warnings", []) + ["TAMPERED"]
    genesis.write_text(json.dumps(doc))

    r = _run(str(nb), "--verify", str(chained), "--no-sign")
    assert r.returncode == 1
    assert "Manifest chain broken" in r.stdout
    assert "[PASS]" not in r.stdout


def test_cli_chain_missing_link_is_soft_issue_not_hard_fail_wording(tmp_path):
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json")
    genesis = next(out.glob("hashes-*.json"))
    time.sleep(_TICK)
    _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json",
         "--prev-manifest", str(genesis))
    chained = [p for p in out.glob("hashes-*.json") if p != genesis][0]

    genesis.unlink()                                  # pruned, not tampered

    r = _run(str(nb), "--verify", str(chained), "--no-sign")
    assert r.returncode == 1
    assert "Verification completed with issues" in r.stdout
    assert "chain incomplete" in r.stdout
    assert "Manifest chain broken" not in r.stdout      # must not read as tampering


def test_cli_ignore_chain_skips_check(tmp_path):
    nb = _nb(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json")
    genesis = next(out.glob("hashes-*.json"))
    time.sleep(_TICK)
    _run(str(nb), "--no-sign", "-o", str(out), "--manifest-type", "json",
         "--prev-manifest", str(genesis))
    chained = [p for p in out.glob("hashes-*.json") if p != genesis][0]

    genesis.unlink()

    r = _run(str(nb), "--verify", str(chained), "--no-sign", "--ignore-chain")
    assert r.returncode == 0
    assert "--ignore-chain in use" in r.stdout
    assert "[PASS]" in r.stdout
