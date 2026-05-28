#!/usr/bin/env python3
"""
rednb-verify
Version: 0.5.0

RedNotebook integrity verification tool.
Creates and verifies cryptographic manifests for notebook directories.

CLI/Commands:
rednb-verify.py [options] [notebook_directory]
"-m", "--month-only" : Hashes only month files
"-o", "--output": Set output path of manifest, default is outside of notebook directory
"--verify" : Set to verification mode
"--manifest": Set manifest file to compare against
"--report": Optional, Creates report of comparison between manifest and notebook
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

VERSION = "0.5.0"
HASH_ALGO = "sha256"


# ---------- Utilities ----------

def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def is_month_file(path: Path) -> bool:
    if path.suffix != ".txt":
        return False

    stem = path.stem
    return (
        len(stem) == 7  # y10k bug
        and stem[4] == "-"
        and stem[0:4].isnumeric()
        and stem[5:7].isnumeric()
        and 1 <= int(stem[5:7]) <= 12
    )


# ---------- Merkle ----------

def merkle_root(hashes: List[str]) -> str:
    if not hashes:
        return ""

    level = [bytes.fromhex(h) for h in hashes]

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            h = hashlib.sha256(left + right).digest()
            next_level.append(h)
        level = next_level

    return level[0].hex()


# ---------- GPG ----------

def gpg_available() -> bool:
    try:
        subprocess.run(
            ["gpg", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except Exception:
        return False


def gpg_has_secret_keys() -> bool:
    try:
        result = subprocess.run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
            check=True,
        )
        return any(line.startswith("sec:") for line in result.stdout.splitlines())
    except Exception:
        return False


def gpg_detach_sign(manifest_path: Path) -> bool:
    try:
        subprocess.run(
            ["gpg", "--detach-sign", "--armor", manifest_path.name],
            cwd=manifest_path.parent,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def gpg_verify(manifest: Path, signature: Path) -> bool:
    try:
        subprocess.run(
            ["gpg", "--verify", signature.name, manifest.name],
            cwd=manifest.parent,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


# ---------- Manifest ----------

def collect_files(base: Path, month_only: bool) -> Dict[str, str]:
    files = {}
    for root, _, filenames in os.walk(base):
        for name in filenames:
            path = Path(root) / name
            rel = path.relative_to(base)
            if month_only and not is_month_file(path):
                continue
            files[rel.as_posix()] = sha256_file(path)
    return dict(sorted(files.items()))


def generate_manifest(notebook: Path, month_only: bool) -> Dict:
    files = collect_files(notebook, month_only)
    hashes = list(files.values())

    created = utc_timestamp()
    return {
        "tool": "rednb-verify",
        "version": VERSION,
        "created": created,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "hash_algorithm": HASH_ALGO,
        "merkle_hash": "sha256",
        "mode": "month-files" if month_only else "full-tree",
        "files": [
            {"path": p, HASH_ALGO: h} for p, h in files.items()
        ],
        "merkle_root": merkle_root(hashes),
    }


# ---------- Verification ----------

def verify_manifest(manifest: Dict, notebook: Path) -> Dict[str, List[str]]:
    results = {
        "ok": [],
        "missing": [],
        "modified": [],
        "new": [],
    }

    algo = manifest.get("hash_algorithm", "sha256")
    expected = {f["path"]: f[algo] for f in manifest["files"]}
    actual = collect_files(notebook, manifest["mode"] == "month-files")

    for path, h in expected.items():
        if path not in actual:
            results["missing"].append(path)
        elif actual[path] != h:
            results["modified"].append(path)
        else:
            results["ok"].append(path)

    for path in actual:
        if path not in expected:
            results["new"].append(path)

    return results


# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser(
        description="Verify RedNotebook integrity"
    )
    parser.add_argument("notebook_dir", type=Path)
    parser.add_argument("-m", "--month-only", action="store_true",
                        help="Hash only YYYY-MM.txt files")
    parser.add_argument("-o", "--output", type=Path,
                        help="Output directory (default: cwd)")
    parser.add_argument("--verify", action="store_true",
                        help="Verify an existing manifest")
    parser.add_argument("--manifest", type=Path,
                        help="Manifest file to verify")
    parser.add_argument("--report", type=Path,
                        help="Verification report file")

    args = parser.parse_args()

    out_dir = args.output or Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.verify:
        if not args.manifest:
            print("[ERROR] --verify requires --manifest")
            sys.exit(2)

        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        results = verify_manifest(manifest, args.notebook_dir)

        report_path = args.report or out_dir / f"report-{utc_timestamp()}.json"
        report_path.write_text(
            json.dumps(results, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        sig = args.manifest.with_suffix(args.manifest.suffix + ".asc")
        if sig.exists() and gpg_available():
            if gpg_verify(args.manifest, sig):
                print("[OK] GPG signature verified.")
            else:
                print("[WARN] GPG signature invalid.")
        else:
            print("[WARN] Manifest not signed.")

        if any(k != "ok" and results[k] for k in results):
            print("Verification completed with issues.")
            sys.exit(1)

        print("[OK] Verification successful.")
        return

    manifest = generate_manifest(args.notebook_dir, args.month_only)
    manifest_name = f"hashes-{manifest['created']}.json"
    manifest_path = out_dir / manifest_name

    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if gpg_available():
        if not gpg_has_secret_keys():
            print("[WARN] GPG available but no secret keys found — not signing.")
        elif gpg_detach_sign(manifest_path):
            print("[OK] Manifest signed with GPG.")
        else:
            print("[WARN] GPG signing failed.")
    else:
        print("[INFO] GPG not available — manifest not signed.")

    print(f"Manifest created: {manifest_path}")


if __name__ == "__main__":
    main()
