"""Tests for JSON-schema validation (--validate).

The 'jsonschema' package is an optional dependency; these tests skip when it is
not installed.
"""
import pytest

pytest.importorskip("jsonschema")


def _make_manifest(tool, tmp_path):
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    (nb / "2026-02.txt").write_text("beta")
    return tool.generate_manifest(nb, False, ["sha256"], "sha256")


def test_generated_manifest_is_valid(tool, tmp_path):
    m = _make_manifest(tool, tmp_path)
    assert tool.validate_manifest_schema(m) == []


def test_multi_hash_manifest_is_valid(tool, tmp_path):
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    m = tool.generate_manifest(nb, False, ["sha256", "blake2b"], "sha256")
    assert tool.validate_manifest_schema(m) == []


def test_missing_required_field_is_caught(tool, tmp_path):
    m = _make_manifest(tool, tmp_path)
    del m["created"]
    errors = tool.validate_manifest_schema(m)
    assert any("created" in e for e in errors)


def test_wrong_tool_const_is_caught(tool, tmp_path):
    m = _make_manifest(tool, tmp_path)
    m["tool"] = "not-rednb-verify"
    errors = tool.validate_manifest_schema(m)
    assert errors


def test_bad_schema_version_type_is_caught(tool, tmp_path):
    m = _make_manifest(tool, tmp_path)
    m["schema_version"] = "two"
    errors = tool.validate_manifest_schema(m)
    assert errors


def test_symlink_entry_requires_target_or_hash(tool, tmp_path):
    m = _make_manifest(tool, tmp_path)
    m["symlink_targets"] = "hash:sha256"
    m["symlinks"] = [{"path": "link.txt"}]  # neither target nor target_hash
    errors = tool.validate_manifest_schema(m)
    assert errors
