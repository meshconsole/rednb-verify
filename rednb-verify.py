#!/usr/bin/env python3
"""
rednb-verify
Version: 0.5.4

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
"--ssh-sign"            : Sign manifest with an SSH key (skips signing menu)
"--ssh-verify"          : Force SSH signature check during --verify
"--sig"                 : Signature file(s) — comma-separated, .asc=GPG .sshsig=SSH
"--ssh-kl"              : SSH key file (.pub) or directory to scan (default: ~/.ssh)
"--ssh-fido"            : Prefer FIDO2/hardware-backed SSH keys; optional key name filter
"--no-sign"             : Skip all signing prompts (GPG and SSH)
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

VERSION = "0.5.4"
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
            ["gpg", "--verify", str(signature.resolve()), str(manifest.resolve())],
            check=True,
            capture_output=True,
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
    ssh_kl: Path,
    require_private: bool,
    prefer_fido: bool,
    keyname: Optional[str],
) -> Optional[SshKeyCandidate]:
    """Resolve an SSH key from a direct .pub file path or a directory to scan."""
    if ssh_kl.is_file():
        # Direct public key file — use it immediately without scanning
        pub_path = ssh_kl
        try:
            line = pub_path.read_text(encoding="utf-8").splitlines()[0]
        except (OSError, IndexError):
            print(f"[WARN] Could not read public key: {pub_path}")
            return None
        parsed = _parse_pubkey_line(line)
        if not parsed:
            print(f"[WARN] Could not parse public key: {pub_path}")
            return None
        key_type, comment = parsed
        is_fido = "sk-" in key_type
        priv_path = pub_path.with_suffix("")
        if require_private and not priv_path.exists():
            print(f"[WARN] Private key not found alongside {pub_path.name}")
            return None
        return SshKeyCandidate(
            pub_path=pub_path,
            priv_path=priv_path if priv_path.exists() else None,
            key_type=key_type,
            comment=comment,
            filename=pub_path.name,
            is_fido=is_fido,
        )
    # Directory: scan and optionally prompt for selection
    candidates = scan_ssh_keys(ssh_kl, require_private=require_private)
    candidates = _filter_ssh_candidates(candidates, prefer_fido=prefer_fido, keyname=keyname)
    return choose_ssh_key(candidates)


def _normalize_ssh_sig_path(sig_path: Path) -> Path:
    if sig_path.suffix == ".sshsig":
        return sig_path
    return Path(f"{sig_path}.sshsig")


def _detect_ssh_sig_candidates(manifest_path: Path) -> List[Path]:
    return sorted(manifest_path.parent.glob(f"{manifest_path.name}*.sshsig"))


def ssh_sign_manifest(manifest_path: Path, key_path: Path, sig_path: Path) -> bool:
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
║ FIDO2/hardware keys are kept offline on the device. ║
╚═════════════════════════════════════════════════════╝
"""


def _prompt_signing_menu() -> int:
    """Ask user how to sign the manifest. Returns 1=GPG, 2=SSH, 3=Both, 4=None."""
    print("""
How would you like to sign this manifest?

  [1] Sign with GPG
  [2] Sign with SSH
  [3] Sign with both GPG and SSH
  [4] Manifest only (skip signing)
""")
    choice = input("Option: ").strip()
    if not choice or choice == "4":
        return 4
    if choice in ("1", "2", "3"):
        return int(choice)
    print("[WARN] Invalid selection — skipping signing.")
    return 4


def _sign_with_gpg(manifest_path: Path) -> None:
    if not gpg_available():
        print("[WARN] GPG not available — GPG signing skipped.")
        return
    keys = list_secret_keys()
    if not keys:
        print("[WARN] No GPG secret keys found — GPG signing skipped.")
        return
    print(NON_REPUDIATION_WARNING)
    confirm = input("Sign this manifest with GPG? [y/N]: ").strip().lower()
    if confirm != "y":
        print("[INFO] GPG signing cancelled.")
        return
    key_fpr = choose_key(keys)
    if key_fpr is None:
        print("[INFO] GPG signing cancelled.")
        return
    if gpg_detach_sign(manifest_path, key_fpr):
        print("[OK] Manifest signed with GPG.")
    else:
        print("[WARN] GPG signing failed.")


def _sign_with_ssh(
    manifest_path: Path,
    sig_path: Path,
    ssh_kl_path: Path,
    prefer_fido: bool,
    keyname: Optional[str],
) -> None:
    if not ssh_keygen_available():
        print("[WARN] ssh-keygen not available — SSH signing skipped.")
        return
    signer = select_ssh_key(
        ssh_kl_path, require_private=True,
        prefer_fido=prefer_fido, keyname=keyname,
    )
    if signer is None or signer.priv_path is None:
        print("[WARN] No suitable SSH key found for signing.")
        return
    print(SSH_NON_REPUDIATION_WARNING)
    confirm = input("Sign this manifest with SSH? [y/N]: ").strip().lower()
    if confirm != "y":
        print("[INFO] SSH signing cancelled.")
        return
    if ssh_sign_manifest(manifest_path, signer.priv_path, sig_path):
        print(f"[OK] SSH signature created: {sig_path.name}")
    else:
        print("[WARN] SSH signing failed.")


def main():
    parser = argparse.ArgumentParser(
        description="rednb-verify — RedNotebook integrity and tamper detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Create a manifest (signing menu appears)
  rednb-verify.py ~/journal

  # Month files only, save manifest inside the journal directory
  rednb-verify.py ~/journal --month-only --output ~/journal

  # Create and skip signing
  rednb-verify.py ~/journal --no-sign

  # Create and sign with SSH directly (skips menu)
  rednb-verify.py ~/journal --ssh-sign

  # Create and sign with a FIDO2 hardware key
  rednb-verify.py ~/journal --ssh-sign --ssh-fido

  # Use a specific SSH public key file directly
  rednb-verify.py ~/journal --ssh-sign --ssh-kl ~/.ssh/id_ed25519.pub

  # Use blake2b for files, sha256 for the Merkle tree
  rednb-verify.py ~/journal --hash blake2b --hash-merkle sha256

  # Verify and write a report
  rednb-verify.py ~/journal --verify --manifest hashes-....json --report report.json

  # Verify with explicit signature files (GPG and SSH at the same time)
  rednb-verify.py ~/journal --verify --manifest hashes-....json \\
    --sig hashes-....json.asc,hashes-....json.sshsig

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
                        help="Verification report output path")
    parser.add_argument("--hash", default=HASH_ALGO, dest="hash_algo",
                        help="Hash algorithm for files (default: sha256)")
    parser.add_argument("--hash-merkle", default=None, dest="merkle_algo",
                        help="Hash algorithm for Merkle tree (default: same as --hash)")
    parser.add_argument("--ssh-sign", action="store_true",
                        help="Sign manifest with an SSH key (skips signing menu)")
    parser.add_argument("--ssh-verify", action="store_true",
                        help="Force SSH signature check during --verify")
    parser.add_argument("--sig", type=str, default=None,
                        metavar="FILE[,FILE]",
                        help="Signature file(s), comma-separated (.asc=GPG, .sshsig=SSH)")
    parser.add_argument("--ssh-kl", type=Path, default=Path("~/.ssh"),
                        metavar="FILE_OR_DIR",
                        help="SSH key .pub file (used directly) or directory to scan (default: ~/.ssh)")
    parser.add_argument("--ssh-fido", nargs="?", const="", metavar="KEYNAME",
                        help="Prefer FIDO2 hardware keys; optional name filter")
    parser.add_argument("--no-sign", action="store_true",
                        help="Skip all signing prompts (GPG and SSH)")

    args = parser.parse_args()
    args.merkle_algo = args.merkle_algo or args.hash_algo

    for label, algo in [("--hash", args.hash_algo), ("--hash-merkle", args.merkle_algo)]:
        try:
            hashlib.new(algo)
        except ValueError:
            print(f"[ERROR] Unsupported algorithm for {label}: {algo}")
            sys.exit(2)

    # Resolve SSH key location (file used directly, directory scanned)
    ssh_kl_path = Path(os.path.expanduser(str(args.ssh_kl)))

    # Parse --sig into a list of Paths
    sig_paths: List[Path] = []
    if args.sig:
        sig_paths = [Path(s.strip()) for s in args.sig.split(",") if s.strip()]

    prefer_fido = args.ssh_fido is not None
    keyname = args.ssh_fido or None

    out_dir = args.output or Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- Verify mode ----
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
        print(f"Verification report: {report_path}")

        # Resolve which signature files to check
        if sig_paths:
            gpg_sigs = [p for p in sig_paths if p.suffix == ".asc"]
            ssh_sigs = [p for p in sig_paths if p.suffix == ".sshsig"]
            unknown = [p for p in sig_paths if p.suffix not in (".asc", ".sshsig")]
            for p in unknown:
                print(f"[WARN] Unknown signature type for '{p.name}' — skipped (expected .asc or .sshsig).")
        else:
            # Auto-detect from manifest location
            auto_asc = args.manifest.with_suffix(args.manifest.suffix + ".asc")
            gpg_sigs = [auto_asc] if auto_asc.exists() else []
            auto_sshsig = args.manifest.with_suffix(args.manifest.suffix + ".sshsig")
            ssh_sigs = [auto_sshsig] if (auto_sshsig.exists() or args.ssh_verify) else []

        # GPG verification
        if not gpg_sigs:
            print("[WARN] Manifest not GPG-signed.")
        else:
            for gpg_sig in gpg_sigs:
                if not gpg_sig.exists():
                    print(f"[WARN] GPG signature file not found: {gpg_sig.name}")
                elif not gpg_available():
                    print("[WARN] GPG not available — GPG verification skipped.")
                else:
                    if gpg_verify(args.manifest, gpg_sig):
                        print(f"[OK] GPG signature verified: {gpg_sig.name}")
                    else:
                        print(f"[WARN] GPG signature invalid: {gpg_sig.name}")

        # SSH verification
        for ssh_sig in ssh_sigs:
            if not ssh_keygen_available():
                print("[WARN] ssh-keygen not available — SSH verification skipped.")
                break
            if not ssh_sig.exists():
                print(f"[WARN] SSH signature file not found: {ssh_sig.name}")
                continue
            signer = select_ssh_key(
                ssh_kl_path, require_private=False,
                prefer_fido=prefer_fido, keyname=keyname,
            )
            if signer is None:
                print("[WARN] No suitable SSH key found for verification.")
                continue
            result = ssh_verify_manifest(
                args.manifest, ssh_sig, signer.pub_path,
                multiple_signatures=len(ssh_sigs) > 1,
                nonstandard_sig=ssh_sig != args.manifest.with_suffix(
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

    # ---- Create mode ----
    manifest = generate_manifest(
        args.notebook_dir, args.month_only, args.hash_algo, args.merkle_algo
    )
    manifest_name = f"hashes-{manifest['created']}.json"
    manifest_path = out_dir / manifest_name

    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Manifest created: {manifest_path}")

    # Resolve SSH sig output path: from --sig if a .sshsig path given, else default
    ssh_sig_out = next(
        (p for p in sig_paths if p.suffix == ".sshsig"),
        manifest_path.with_suffix(manifest_path.suffix + ".sshsig"),
    )

    # ---- Signing ----
    if args.no_sign:
        print("[INFO] Signing skipped (--no-sign).")

    elif args.ssh_sign:
        # Explicit SSH flag — skip menu, sign with SSH only
        _sign_with_ssh(manifest_path, ssh_sig_out, ssh_kl_path, prefer_fido, keyname)

    else:
        # No explicit method — show interactive signing menu
        sign_choice = _prompt_signing_menu()
        if sign_choice in (1, 3):
            _sign_with_gpg(manifest_path)
        if sign_choice in (2, 3):
            _sign_with_ssh(manifest_path, ssh_sig_out, ssh_kl_path, prefer_fido, keyname)


if __name__ == "__main__":
    main()
