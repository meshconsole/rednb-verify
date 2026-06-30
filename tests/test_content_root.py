"""Tests for the move-invariant content root and verify-time move detection (v3)."""


def _nb(tmp_path, files):
    nb = tmp_path / "nb"
    nb.mkdir(parents=True)
    for name, content in files.items():
        (nb / name).write_text(content)
    return nb


def test_manifest_has_content_root(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "alpha", "2026-02.txt": "beta"})
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    assert m["schema_version"] == 3
    assert "content_root" in m


def test_multi_hash_has_content_roots(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "alpha"})
    m = tool.generate_manifest(nb, False, ["sha256", "blake2b"], "sha256")
    assert set(m["content_roots"]) == {"sha256", "blake2b"}


def test_content_root_is_move_invariant_but_merkle_is_not(tool, tmp_path):
    # Same content SET, different path->content assignment. The path-ordered
    # Merkle root must differ; the move-invariant content root must match.
    nb1 = _nb(tmp_path / "one", {"a.txt": "yyy", "b.txt": "xxx"})
    nb2 = _nb(tmp_path / "two", {"a.txt": "xxx", "b.txt": "yyy"})
    m1 = tool.generate_manifest(nb1, False, ["sha256"], "sha256")
    m2 = tool.generate_manifest(nb2, False, ["sha256"], "sha256")
    assert m1["content_root"] == m2["content_root"]
    assert m1["merkle_root"] != m2["merkle_root"]


def test_verify_clean_matches(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "alpha", "2026-02.txt": "beta"})
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    r = tool.verify_manifest(m, nb)
    assert r["content_root_status"] == ["match"]
    assert r["moved"] == []
    assert r["missing"] == [] and r["new"] == []


def test_verify_detects_move_as_content_intact(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "alpha", "2026-02.txt": "beta"})
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    (nb / "2026-01.txt").rename(nb / "renamed.txt")
    r = tool.verify_manifest(m, nb)
    assert r["content_root_status"] == ["match"]      # content all present
    assert r["modified"] == []                         # nothing tampered
    assert r["moved"] == ["2026-01.txt -> renamed.txt"]


def test_verify_detects_real_tamper_as_mismatch(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "alpha"})
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    (nb / "2026-01.txt").write_text("ALPHA-changed")
    r = tool.verify_manifest(m, nb)
    assert r["content_root_status"] == ["mismatch"]
    assert "2026-01.txt" in r["modified"]


def test_old_manifest_without_content_root_skips(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "alpha"})
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    del m["content_root"]            # simulate a pre-v3 manifest
    r = tool.verify_manifest(m, nb)
    assert r["content_root_status"] == []   # gracefully skipped


def test_text_roundtrip_preserves_content_root(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "alpha", "2026-02.txt": "beta"})
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    parsed = tool._parse_text_manifest(tool._write_text_manifest(m))
    assert parsed["content_root"] == m["content_root"]


def test_text_roundtrip_preserves_content_roots_multi(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "alpha"})
    m = tool.generate_manifest(nb, False, ["sha256", "blake2b"], "sha256")
    parsed = tool._parse_text_manifest(tool._write_text_manifest(m))
    assert parsed["content_roots"] == m["content_roots"]
