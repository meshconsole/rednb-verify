"""The embedded schemas are the source of truth; the shipped schema/*.json files
are exports. These tests keep them from drifting and check --dump-schema.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = str(ROOT / "rednb-verify.py")


def test_manifest_json_matches_embedded(tool):
    on_disk = json.loads((ROOT / "schema" / "manifest-v3.schema.json").read_text())
    assert on_disk == tool.MANIFEST_SCHEMA


def test_report_json_matches_embedded(tool):
    on_disk = json.loads((ROOT / "schema" / "report-v1.schema.json").read_text())
    assert on_disk == tool.REPORT_SCHEMA


def test_dump_schema_manifest_stdout(tool):
    r = subprocess.run([sys.executable, TOOL, "--dump-schema", "manifest"],
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert json.loads(r.stdout) == tool.MANIFEST_SCHEMA


def test_dump_schema_report_stdout(tool):
    r = subprocess.run([sys.executable, TOOL, "--dump-schema", "report"],
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert json.loads(r.stdout) == tool.REPORT_SCHEMA


def test_dump_schema_bad_name_errors(tool):
    r = subprocess.run([sys.executable, TOOL, "--dump-schema", "bogus"],
                       capture_output=True, text=True)
    assert r.returncode == 2


def test_validate_is_self_contained_without_schema_dir(tool, tmp_path, monkeypatch):
    # Validation must not depend on the schema/ folder being present next to the
    # script — copy just the script elsewhere and validate a manifest there.
    import shutil
    solo = tmp_path / "solo"
    solo.mkdir()
    shutil.copy(TOOL, solo / "rednb-verify.py")
    nb = tmp_path / "nb"
    nb.mkdir()
    (nb / "2026-01.txt").write_text("alpha")
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    manifest_file = solo / "hashes-20260101T000000Z.json"
    manifest_file.write_text(json.dumps(m))
    r = subprocess.run([sys.executable, str(solo / "rednb-verify.py"),
                        "--validate", str(manifest_file)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "schema-valid" in r.stdout
