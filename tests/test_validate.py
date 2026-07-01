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


def test_report_schema_validates_clean_report(tool, tmp_path):
    m = _make_manifest(tool, tmp_path)
    nb = tmp_path / "nb"
    r = tool.verify_manifest(m, nb)
    errors = tool.validate_against_schema(r, "report", required=True)
    assert errors == []


def test_schema_for_picks_manifest_vs_report(tool, tmp_path):
    from pathlib import Path
    m = _make_manifest(tool, tmp_path)
    assert tool._schema_for(m, Path("hashes-x.json")).startswith("manifest")
    report = {"ok": [], "missing": [], "modified": [], "new": []}
    assert tool._schema_for(report, Path("report-x.json")).startswith("report")


def test_validate_not_required_returns_none_without_jsonschema(tool, tmp_path, monkeypatch):
    # Simulate jsonschema being unavailable: best-effort call returns None.
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "jsonschema":
            raise ImportError("simulated")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    m = _make_manifest(tool, tmp_path)
    assert tool.validate_manifest_schema(m, required=False) is None
