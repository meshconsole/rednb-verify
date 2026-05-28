#!/usr/bin/env python3
"""
rednb-verify
Version: 0.5.3

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
"--ssh-sign"            : Sign manifest with an SSH key
"--ssh-verify"          : Verify an SSH signature during --verify
"--ssh-sig"             : Path to SSH signature file (default: <manifest>.sshsig)
"--ssh-kl"              : Directory to scan for SSH keys (default: ~/.ssh)
"--ssh-fido"            : Prefer FIDO2/hardware-backed SSH keys; optional key name filter
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

VERSION = "0.5.3"
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


# ---------- SSH ----------

SSH_NAMESPACE = "rednotebook-manifest"
SSH_SIGNER_IDENTITY = "rednb-verify"


@dataclass(frozen=True)
class SshKeyCandidate:
    pub_path: Path
    priv_path: Optional[Path]
    key_type: str
    comment: str
    filename: str
    is_fido: bool


@dataclass(frozen=True)
class SshVerifyResult:
    status: str
    message: str
    warnings: List[str]


def ssh_keygen_available() -> bool:
    return shutil.which("ssh-keygen") is not None


def _parse_pubkey_line(line: str) -> Optional[tuple]:
    parts = line.strip().split()
    if len(parts) < 2:
        return None
    key_type = parts[0]
    comment = parts[2] if len(parts) > 2 else ""
    return key_type, comment


def scan_ssh_keys(directory: Path, require_private: bool) -> List[SshKeyCandidate]:
    candidates = []
    if not directory.exists():
        return candidates
    for pub_path in sorted(directory.glob("*.pub")):
        try:
            line = pub_path.read_text(encoding="utf-8").splitlines()[0]
        except (OSError, IndexError):
            continue
        parsed = _parse_pubkey_line(line)
        if not parsed:
            continue
        key_type, comment = parsed
        is_fido = "sk-" in key_type
        priv_path = pub_path.with_suffix("")
        if require_private and not priv_path.exists():
            continue
        candidates.append(SshKeyCandidate(
            pub_path=pub_path,
            priv_path=priv_path if priv_path.exists() else None,
            key_type=key_type,
            comment=comment,
            filename=pub_path.name,
            is_fido=is_fido,
        ))
    return candidates


def _filter_ssh_candidates(
    candidates: Iterable[SshKeyCandidate],
    prefer_fido: bool,
    keyname: Optional[str],
) -> List[SshKeyCandidate]:
    filtered = list(candidates)
    if keyname:
        kl = keyname.lower()
        filtered = [
            c for c in filtered
            if kl in c.pub_path.stem.lower() or kl in c.comment.lower()
        ]
    if prefer_fido:
        fido = [c for c in filtered if c.is_fido]
        if fido:
            filtered = fido
    return filtered


def choose_ssh_key(candidates: List[SshKeyCandidate]) -> Optional[SshKeyCandidate]:
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    print("\nAvailable SSH keys:\n")
    for idx, key in enumerate(candidates):
        fido_tag = " [FIDO2]" if key.is_fido else ""
        print(f"  [{idx:02d}] {key.filename}{fido_tag}")
        print(f"        Type: {key.key_type}")
        if key.comment:
            print(f"        Comment: {key.comment}")
    choice = input("\nSelect key index (or Enter to cancel): ").strip()
    if not choice:
        return None
    if not choice.isdigit():
        print("[ERROR] Invalid selection.")
        return None
    idx = int(choice)
    if idx < 0 or idx >= len(candidates):
        print("[ERROR] Selection out of range.")
        return None
    return candidates[idx]


def select_ssh_key(
    directory: Path,
    require_private: bool,
    prefer_fido: bool,
    keyname: Optional[str],
) -> Optional[SshKeyCandidate]:
    candidates = scan_ssh_keys(directory, require_private=require_private)
    candidates = _filter_ssh_candidates(candidates, prefer_fido=prefer_fido, keyname=keyname)
    return choose_ssh_key(candidates)


def _normalize_ssh_sig_path(sig_path: Path) -> Path:
    if sig_path.suffix == ".sshsig":
        return sig_path
    return Path(f"{sig_path}.sshsig")


def _detect_ssh_sig_candidates(manifest_path: Path) -> List[Path]:
    return sorted(manifest_path.parent.glob(f"{manifest_path.name}*.sshsig"))


def ssh_sign_manifest(manifest_path: Path, key_path: Path, sig_path: Path) -> bool:
    # ssh-keygen writes <manifest>.sig; we rename to our target path
    default_sig = manifest_path.with_suffix(manifest_path.suffix + ".sig")
    appended_sig = manifest_path.parent / f"{manifest_path.name}.sig"
    for candidate in (default_sig, appended_sig):
        if candidate.exists():
            candidate.unlink()
    try:
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key_path),
             "-n", SSH_NAMESPACE, str(manifest_path)],
            cwd=manifest_path.parent,
            check=True,
        )
    except subprocess.CalledProcessError:
        return False
    generated = next(
        (c for c in (default_sig, appended_sig) if c.exists()), None
    )
    if generated is None:
        return False
    sig_path.parent.mkdir(parents=True, exist_ok=True)
    generated.replace(sig_path)
    return True


def _write_allowed_signers(pub_path: Path) -> Path:
    line = pub_path.read_text(encoding="utf-8").splitlines()[0].strip()
    tmp = tempfile.NamedTemporaryFile("w", suffix=".signers", delete=False)
    tmp.write(f"{SSH_SIGNER_IDENTITY} {line}\n")
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


def ssh_verify_manifest(
    manifest_path: Path,
    sig_path: Path,
    pub_path: Path,
    multiple_signatures: bool,
    nonstandard_sig: bool,
) -> SshVerifyResult:
    warnings: List[str] = []
    if multiple_signatures:
        warnings.append(
            "Multiple SSH signatures found; only the selected signature was verified."
        )
    if nonstandard_sig:
        warnings.append("SSH signature verified using a non-standard filename.")

    allowed_path = _write_allowed_signers(pub_path)
    try:
        subprocess.run(
            ["ssh-keygen", "-Y", "verify",
             "-f", str(allowed_path),
             "-I", SSH_SIGNER_IDENTITY,
             "-n", SSH_NAMESPACE,
             "-s", str(sig_path),
             str(manifest_path)],
            cwd=manifest_path.parent,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        return SshVerifyResult(status="FAIL", message="SSH signature verification failed.", warnings=warnings)
    finally:
        Path(allowed_path).unlink(missing_ok=True)

    return SshVerifyResult(status="OK", message="SSH signature verified.", warnings=warnings)


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
║             Non-Repudiation Warning              ║
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

SSH_NON_REPUDIATION_WARNING = """
╔═════════════════════════════════════════════════════╗
║             SSH Non-Repudiation Warning             ║
║                                                     ║
║ Signing with an SSH key binds your identity to      ║
║ this manifest. By signing, you assert that:         ║
║                                                     ║
║  - These files existed                              ║
║  - In this exact form                               ║
║  - At or before the signing time                    ║
║                                                     ║
║ Anyone with your public key can verify this.        ║
║ FIDO2/hardware keys are kept offline in the device. ║
╚═════════════════════════════════════════════════════╝
"""


def main():
    parser = argparse.ArgumentParser(
        description="rednb-verify — RedNotebook integrity and tamper detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Create a manifest
  rednb-verify.py ~/journal

  # Month files only, save manifest inside the journal directory
  rednb-verify.py ~/journal --month-only --output ~/journal

  # Verify and write a report
  rednb-verify.py ~/journal --verify --manifest hashes-....json --report report.json

  # Use blake2b for files, sha256 for the Merkle tree
  rednb-verify.py ~/journal --hash blake2b --hash-merkle sha256

  # Create manifest and sign with SSH (FIDO2 hardware key preferred)
  rednb-verify.py ~/journal --ssh-sign --ssh-fido

  # Verify with both GPG and SSH signature checks
  rednb-verify.py ~/journal --verify --manifest hashes-....json --ssh-verify

supported hash algorithms (python hashlib):
  sha256, sha512, sha3_256, sha3_512, blake2b, blake2s, and others
  run: python -c "import hashlib; print(hashlib.algorithms_guaranteed)"
"""
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
    parser.add_argument("--ssh-sign", action="store_true",
                        help="Sign manifest with an SSH key after creation")
    parser.add_argument("--ssh-verify", action="store_true",
                        help="Verify SSH signature during --verify")
    parser.add_argument("--ssh-sig", type=Path,
                        help="Path to SSH signature file (default: <manifest>.sshsig)")
    parser.add_argument("--ssh-kl", type=Path, default=Path("~/.ssh"),
                        help="Directory to scan for SSH keys (default: ~/.ssh)")
    parser.add_argument("--ssh-fido", nargs="?", const="", metavar="KEYNAME",
                        help="Prefer FIDO2 hardware keys; optional name filter")

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
            print("[WARN] Manifest not GPG-signed.")

        ssh_dir = Path(os.path.expanduser(str(args.ssh_kl)))
        ssh_sig_path = (
            _normalize_ssh_sig_path(args.ssh_sig)
            if args.ssh_sig
            else args.manifest.with_suffix(args.manifest.suffix + ".sshsig")
        )
        sig_candidates = _detect_ssh_sig_candidates(args.manifest)

        if args.ssh_verify or ssh_sig_path.exists():
            if not ssh_keygen_available():
                print("[WARN] ssh-keygen not available — SSH verification skipped.")
            elif not ssh_sig_path.exists():
                print("[WARN] SSH signature file not found.")
            else:
                prefer_fido = args.ssh_fido is not None
                keyname = args.ssh_fido or None
                signer = select_ssh_key(
                    ssh_dir, require_private=False,
                    prefer_fido=prefer_fido, keyname=keyname,
                )
                if signer is None:
                    print("[WARN] No suitable SSH key found for verification.")
                else:
                    result = ssh_verify_manifest(
                        args.manifest, ssh_sig_path, signer.pub_path,
                        multiple_signatures=len(sig_candidates) > 1 and args.ssh_sig is None,
                        nonstandard_sig=ssh_sig_path != args.manifest.with_suffix(
                            args.manifest.suffix + ".sshsig"
                        ),
                    )
                    label = "[OK]" if result.status == "OK" else f"[{result.status}]"
                    print(f"{label} {result.message}")
                    for w in result.warnings:
                        print(f"[WARN] {w}")

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

    if args.ssh_sign:
        if not ssh_keygen_available():
            print("[WARN] ssh-keygen not available — SSH signing skipped.")
        else:
            ssh_dir = Path(os.path.expanduser(str(args.ssh_kl)))
            prefer_fido = args.ssh_fido is not None
            keyname = args.ssh_fido or None
            signer = select_ssh_key(
                ssh_dir, require_private=True,
                prefer_fido=prefer_fido, keyname=keyname,
            )
            if signer is None or signer.priv_path is None:
                print("[WARN] No suitable SSH key found for signing.")
            else:
                print(SSH_NON_REPUDIATION_WARNING)
                confirm = input("Sign this manifest with SSH? [y/N]: ").strip().lower()
                if confirm != "y":
                    print("[INFO] SSH signing cancelled.")
                else:
                    sig_path = (
                        _normalize_ssh_sig_path(args.ssh_sig)
                        if args.ssh_sig
                        else manifest_path.with_suffix(manifest_path.suffix + ".sshsig")
                    )
                    if ssh_sign_manifest(manifest_path, signer.priv_path, sig_path):
                        print(f"[OK] SSH signature created: {sig_path.name}")
                    else:
                        print("[WARN] SSH signing failed.")


if __name__ == "__main__":
    main()
