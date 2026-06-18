"""Tests for symlink recording and verification.

Symlink creation needs privilege on Windows (and isn't available everywhere),
so each test that creates one skips cleanly when the OS refuses.
"""
import json
import os
from pathlib import Path

import pytest


def _symlink_or_skip(link: Path, target: str):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks not permitted in this environment: {exc}")


def _nb_with_link(tmp_path, target_name="ext.txt", content="payload"):
    """Build a notebook dir with one month file and a symlink to an external file."""
    ext = tmp_path / target_name
    ext.write_text(content)
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    _symlink_or_skip(nb / "link.txt", str(ext))
    return nb, ext


def test_collect_symlinks_reports_links_only(tool, tmp_path):
    nb, ext = _nb_with_link(tmp_path)
    links = tool.collect_symlinks(nb)
    assert links == {"link.txt": str(ext)}


def test_hash_policy_does_not_leak_target(tool, tmp_path):
    nb, ext = _nb_with_link(tmp_path)
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="hash:sha256")
    assert m["symlink_targets"] == "hash:sha256"
    entry = next(e for e in m["symlinks"] if e["path"] == "link.txt")
    assert "target" not in entry
    assert entry["target_hash"] == tool._hash_target(str(ext), "sha256")
    # The cleartext target path must appear nowhere in the manifest.
    assert str(ext) not in json.dumps(m)


def test_full_policy_records_cleartext_target(tool, tmp_path):
    nb, ext = _nb_with_link(tmp_path)
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="full")
    entry = next(e for e in m["symlinks"] if e["path"] == "link.txt")
    assert entry["target"] == str(ext)


def test_none_policy_omits_table(tool, tmp_path):
    nb, ext = _nb_with_link(tmp_path)
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="none")
    assert "symlinks" not in m
    assert "symlink_targets" not in m


def test_empty_table_recorded_when_no_symlinks(tool, tmp_path):
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="hash:sha256")
    assert m["symlinks"] == []
    assert m["symlink_targets"] == "hash:sha256"


def test_verify_detects_identical_content_target_swap(tool, tmp_path):
    # Two external files with IDENTICAL content: a content hash alone cannot
    # tell them apart, so only the symlink table catches the repoint.
    a = tmp_path / "a.txt"
    a.write_text("same")
    b = tmp_path / "b.txt"
    b.write_text("same")
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    _symlink_or_skip(nb / "link.txt", str(a))
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="hash:sha256")

    (nb / "link.txt").unlink()
    os.symlink(str(b), nb / "link.txt")
    results = tool.verify_manifest(m, nb)
    assert "link.txt" in results["symlink_changed"]
    assert "link.txt" not in results["modified"]  # content is identical


def test_verify_detects_symlink_replaced_by_file(tool, tmp_path):
    nb, ext = _nb_with_link(tmp_path, content="data")
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="hash:sha256")
    # Replace the symlink with a regular file of the SAME content.
    (nb / "link.txt").unlink()
    (nb / "link.txt").write_text("data")
    results = tool.verify_manifest(m, nb)
    assert "link.txt" in results["symlink_missing"]


def test_verify_detects_new_symlink(tool, tmp_path):
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    ext = tmp_path / "ext.txt"
    ext.write_text("x")
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="hash:sha256")
    _symlink_or_skip(nb / "sneaky.txt", str(ext))
    results = tool.verify_manifest(m, nb)
    assert "sneaky.txt" in results["symlink_new"]


def test_text_roundtrip_preserves_symlinks(tool, tmp_path):
    nb, ext = _nb_with_link(tmp_path)
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="hash:sha256")
    text = tool._write_text_manifest(m)
    parsed = tool._parse_text_manifest(text)
    assert parsed["symlink_targets"] == "hash:sha256"
    assert parsed["symlinks"] == m["symlinks"]


def test_text_roundtrip_preserves_empty_table(tool, tmp_path):
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256", symlink_policy="hash:sha256")
    parsed = tool._parse_text_manifest(tool._write_text_manifest(m))
    assert parsed["symlinks"] == []
    assert parsed["symlink_targets"] == "hash:sha256"
