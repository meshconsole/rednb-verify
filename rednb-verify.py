#!/usr/bin/env python3
"""
rednb-verify
Version: 0.5.1

RedNotebook integrity verification tool.
Creates and verifies cryptographic manifests for notebook directories.

CLI/Commands:
rednb-verify.py [options] [notebook_directory]
"-m", "--month-only"    : Hashes only month files
"-o", "--output"        : Set output path of manifest, default is outside of notebook directory
"--verify"              : Set to verification mode
"--manifest"            : Set manifest file to compare against
"--report"              : Optional, creates report of comparison between manifest and notebook
"--hash"                : Hash algorithm for files (default: sha256), e.g. sha512, blake2b
"--hash-merkle"         : Hash algorithm for Merkle tree (default: same as --hash)
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

VERSION = "0.5.2"
HASH_ALGO = "sha256"


# ---------- Utilities ----------

def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def hash_file(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
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

def merkle_root(hashes: List[str], algo: str) -> str:
    if not hashes:
        return ""

    level = [bytes.fromhex(h) for h in hashes]

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            h = hashlib.new(algo, left + right).digest()
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


def list_secret_keys() -> List[Dict]:
    result = subprocess.run(
        ["gpg", "--list-secret-keys", "--with-colons"],
        capture_output=True,
        text=True,
        check=True,
    )

    keys = []
    current = None

    for line in result.stdout.splitlines():
        parts = line.split(":")

        if parts[0] == "sec":
            expires = parts[6]
            current = {
                "fingerprint": None,
                "uid": "",
                "expires": (
                    datetime.fromtimestamp(int(expires), tz=timezone.utc).strftime("%Y-%m-%d")
                    if expires.isdigit() and int(expires) > 0
                    else "never"
                ),
            }
            keys.append(current)

        elif parts[0] == "fpr" and current and current["fingerprint"] is None:
            current["fingerprint"] = parts[9].upper()

        elif parts[0] == "uid" and current and not current["uid"]:
            current["uid"] = parts[9]

    return [k for k in keys if k["fingerprint"] and k["uid"]]


def choose_key(keys: List[Dict]) -> str | None:
    print("\nAvailable signing keys:\n")
    for idx, key in enumerate(keys):
        print(f"  [{idx:02d}] {key['uid']}")
        print(f"        FPR: {key['fingerprint']}")
        print(f"        Expires: {key['expires']}")

    choice = input("\nSelect key index (or Enter to cancel): ").strip()
    if not choice:
        return None
    if not choice.isdigit():
        print("[ERROR] Invalid selection.")
        return None
    idx = int(choice)
    if idx < 0 or idx >= len(keys):
        print("[ERROR] Selection out of range.")
        return None
    return keys[idx]["fingerprint"]


def gpg_detach_sign(manifest_path: Path, key_fpr: str | None) -> bool:
    cmd = ["gpg", "--detach-sign", "--armor"]
    if key_fpr:
        cmd.extend(["--local-user", key_fpr])
    cmd.append(manifest_path.name)
    try:
        subprocess.run(cmd, cwd=manifest_path.parent, check=True)
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

def collect_files(base: Path, month_only: bool, algo: str) -> Dict[str, str]:
    files = {}
    for root, _, filenames in os.walk(base):
        for name in filenames:
            path = Path(root) / name
            rel = path.relative_to(base)
            if month_only and not is_month_file(path):
                continue
            files[rel.as_posix()] = hash_file(path, algo)
    return dict(sorted(files.items()))


def generate_manifest(notebook: Path, month_only: bool, algo: str, merkle_algo: str) -> Dict:
    files = collect_files(notebook, month_only, algo)
    hashes = list(files.values())

    created = utc_timestamp()
    return {
        "tool": "rednb-verify",
        "version": VERSION,
        "created": created,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "hash_algorithm": algo,
        "merkle_hash": merkle_algo,
        "mode": "month-files" if month_only else "full-tree",
        "files": [
            {"path": p, algo: h} for p, h in files.items()
        ],
        "merkle_root": merkle_root(hashes, merkle_algo),
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
    actual = collect_files(notebook, manifest["mode"] == "month-files", algo)

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

NON_REPUDIATION_WARNING = """
╔══════════════════════════════════════════════════╗
║          Non-Repudiation Warning                 ║
║                                                  ║
║ Signing a manifest is a serious cryptographic    ║
║ act. By signing, you assert that:                ║
║                                                  ║
║  - These files existed                           ║
║  - In this exact form                            ║
║  - At or before the signing time                 ║
║                                                  ║
║ Anyone with your public key can verify this.     ║
╚══════════════════════════════════════════════════╝
"""


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
    parser.add_argument("--hash", default=HASH_ALGO, dest="hash_algo",
                        help="Hash algorithm for files (default: sha256)")
    parser.add_argument("--hash-merkle", default=None, dest="merkle_algo",
                        help="Hash algorithm for Merkle tree (default: same as --hash)")

    args = parser.parse_args()
    args.merkle_algo = args.merkle_algo or args.hash_algo

    for label, algo in [("--hash", args.hash_algo), ("--hash-merkle", args.merkle_algo)]:
        try:
            hashlib.new(algo)
        except ValueError:
            print(f"[ERROR] Unsupported algorithm for {label}: {algo}")
            sys.exit(2)

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

    manifest = generate_manifest(args.notebook_dir, args.month_only, args.hash_algo, args.merkle_algo)
    manifest_name = f"hashes-{manifest['created']}.json"
    manifest_path = out_dir / manifest_name

    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if not gpg_available():
        print("[INFO] GPG not available — manifest not signed.")
    else:
        keys = list_secret_keys()
        if not keys:
            print("[WARN] GPG available but no secret keys found — not signing.")
        else:
            print(NON_REPUDIATION_WARNING)
            confirm = input("Sign this manifest? [y/N]: ").strip().lower()
            if confirm != "y":
                print("[INFO] Manifest left unsigned.")
            else:
                key_fpr = choose_key(keys)
                if key_fpr is None:
                    print("[INFO] Signing cancelled.")
                elif gpg_detach_sign(manifest_path, key_fpr):
                    print("[OK] Manifest signed with GPG.")
                else:
                    print("[WARN] GPG signing failed.")

    print(f"Manifest created: {manifest_path}")


if __name__ == "__main__":
    main()
