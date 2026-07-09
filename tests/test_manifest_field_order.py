"""'files' should be the last key in a JSON manifest, so every summary/verdict
field (roots, warnings, symlinks, TSA stamps) is visible before the per-file
detail. generate_manifest() puts it last on its own; _manifest_files_last()
re-asserts that after later steps (signing, TSA embedding) add more keys.
"""


def _nb(tmp_path, files):
    nb = tmp_path / "nb"
    nb.mkdir()
    for name, content in files.items():
        (nb / name).write_text(content)
    return nb


def test_files_last_single_hash(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "a"})
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    assert list(m.keys())[-1] == "files"


def test_files_last_multi_hash(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "a"})
    m = tool.generate_manifest(nb, False, ["sha256", "blake2b"], "sha256")
    assert list(m.keys())[-1] == "files"


def test_manifest_files_last_reasserts_after_new_keys(tool, tmp_path):
    nb = _nb(tmp_path, {"2026-01.txt": "a"})
    m = tool.generate_manifest(nb, False, ["sha256"], "sha256")
    assert list(m.keys())[-1] == "files"
    m["signed_by"] = {"gpg": "ABC"}          # simulates signing adding a key
    m["tsa_stamp"] = {"tsa": "x", "token_b64": "y"}  # simulates TSA embedding
    assert list(m.keys())[-1] != "files"     # now displaced, as expected
    tool._manifest_files_last(m)
    assert list(m.keys())[-1] == "files"
    assert m["signed_by"] == {"gpg": "ABC"}  # content untouched, only order changed


def test_manifest_files_last_noop_without_files_key(tool):
    m = {"a": 1, "b": 2}
    tool._manifest_files_last(m)  # must not raise
    assert m == {"a": 1, "b": 2}
