"""Symlink logic tests that don't need OS-level symlink privilege.

These cover the parts most likely to harbour bugs — the policy resolver, the
table builder, and the verify-time comparison — by driving them with controlled
inputs (the comparison's filesystem read is monkeypatched). This keeps the logic
covered even on platforms where os.symlink is unavailable.
"""
import types


def _ns(**kw):
    base = dict(no_symlink_table=False, privacy=False, symlink_targets="hash")
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_resolve_policy_defaults_to_sha256(tool):
    assert tool._resolve_symlink_policy(_ns()) == "hash:sha256"


def test_resolve_policy_variants(tool):
    assert tool._resolve_symlink_policy(_ns(symlink_targets="full")) == "full"
    assert tool._resolve_symlink_policy(_ns(symlink_targets="none")) == "none"
    assert tool._resolve_symlink_policy(_ns(symlink_targets="hash:blake2b")) == "hash:blake2b"


def test_resolve_policy_aliases_map_to_none(tool):
    assert tool._resolve_symlink_policy(_ns(no_symlink_table=True)) == "none"
    assert tool._resolve_symlink_policy(_ns(privacy=True)) == "none"
    # Aliases win even if --symlink-targets says otherwise.
    assert tool._resolve_symlink_policy(_ns(privacy=True, symlink_targets="full")) == "none"


def test_hash_target_is_deterministic_and_opaque(tool):
    a = tool._hash_target("/home/user/secret.txt", "sha256")
    b = tool._hash_target("/home/user/secret.txt", "sha256")
    assert a == b
    assert "/home/user/secret.txt" not in a


def test_build_table_full_vs_hash(tool):
    links = {"l.txt": "/x/y"}
    full = tool._build_symlink_table(links, "full")
    assert full == [{"path": "l.txt", "target": "/x/y"}]
    hashed = tool._build_symlink_table(links, "hash:sha256")
    assert hashed[0]["target_hash"] == tool._hash_target("/x/y", "sha256")
    assert "target" not in hashed[0]


def test_verify_symlink_comparison_hash_policy(tool, tmp_path, monkeypatch):
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="hash:sha256")
    h = lambda t: tool._hash_target(t, "sha256")
    m["symlinks"] = [
        {"path": "keep.txt", "target_hash": h("/a")},
        {"path": "gone.txt", "target_hash": h("/b")},
        {"path": "moved.txt", "target_hash": h("/c")},
    ]
    current = {"keep.txt": "/a", "moved.txt": "/CHANGED", "extra.txt": "/d"}
    monkeypatch.setattr(tool, "collect_symlinks", lambda base, exclude=None: current)

    r = tool.verify_manifest(m, nb)
    assert r["symlink_ok"] == ["keep.txt"]
    assert r["symlink_changed"] == ["moved.txt"]
    assert r["symlink_missing"] == ["gone.txt"]
    assert r["symlink_new"] == ["extra.txt"]


def test_verify_symlink_comparison_full_policy(tool, tmp_path, monkeypatch):
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="full")
    m["symlinks"] = [{"path": "l.txt", "target": "/a"}]
    monkeypatch.setattr(tool, "collect_symlinks", lambda base, exclude=None: {"l.txt": "/b"})

    r = tool.verify_manifest(m, nb)
    assert r["symlink_changed"] == ["l.txt"]


def test_verify_empty_recorded_flags_new_symlink(tool, tmp_path, monkeypatch):
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="hash:sha256")
    assert m["symlinks"] == []
    monkeypatch.setattr(tool, "collect_symlinks", lambda base, exclude=None: {"new.txt": "/z"})

    r = tool.verify_manifest(m, nb)
    assert r["symlink_new"] == ["new.txt"]


def test_verify_none_policy_skips_symlink_checks(tool, tmp_path, monkeypatch):
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="none")
    # Even if links exist on disk, a 'none' manifest commits to nothing.
    monkeypatch.setattr(tool, "collect_symlinks", lambda base, exclude=None: {"x.txt": "/z"})

    r = tool.verify_manifest(m, nb)
    assert r["symlink_new"] == []
    assert r["symlink_changed"] == []
