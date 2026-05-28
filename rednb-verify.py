#!/usr/bin/env python3
"""
rednb-verify
Version: 0.5.5

RedNotebook integrity verification tool.
Creates and verifies cryptographic manifests for notebook directories.

CLI/Commands:
rednb-verify.py [options] [notebook_directory]
"-m", "--month-only"    : Hashes only month files
"-o", "--output"        : Output directory for manifest (default: cwd)
"--verify"              : Verification mode
"--manifest"            : Manifest file to verify against
"--report txt|json"     : Report format during --verify (default: txt)
"--hash ALGO"           : Hash algorithm for files (default: sha256)
"--hash-list"           : Print available hash algorithms and exit
"--hash-merkle"         : Hash algorithm for Merkle tree (default: same as --hash)
"--gpg [FINGERPRINT]"   : Sign with GPG; optional fingerprint pre-selects key (skips menu)
"--gpg-k FILE"          : GPG armored key file; implies --gpg
"--ssh-sign"            : Sign with SSH key (skips menu)
"--ssh-verify"          : Force SSH signature check during --verify
"--sig FILE[,FILE]"     : Signature file(s) comma-separated (.asc=GPG, .sshsig=SSH)
"--ssh-kl FILE|DIR"     : SSH .pub key file (used directly) or directory to scan; implies --ssh-sign
"--ssh-fido [NAME]"     : Prefer FIDO2/hardware-backed SSH keys; optional name filter
"--no-sign"             : Skip all signing
"--quiet"               : Suppress non-error output; implies --no-sign unless signing is explicit
"--exclude PATTERN"     : Exclude files matching glob (repeatable)
"""

import argparse
import fnmatch
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

VERSION = "0.5.5"
HASH_ALGO = "sha256"
CONFIG_PATH = Path(os.path.expanduser("~/.config/rednb-verify/config.json"))

# Set by main() before any output; suppresses _qprint calls
_quiet: bool = False


def _qprint(msg: str) -> None:
    """Print only when not in quiet mode."""
    if not _quiet:
        print(msg)


# ---------- Config ----------

def load_config() -> Dict:
    """Load ~/.config/rednb-verify/config.json if present."""
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] Could not load config {CONFIG_PATH}: {exc}", file=sys.stderr)
    return {}


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
        len(stem) == 7
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
        capture_output=True, text=True, check=True,
    )
    keys: List[Dict] = []
    current: Optional[Dict] = None
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


def choose_gpg_key(keys: List[Dict]) -> Optional[str]:
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


def gpg_detach_sign(manifest_path: Path, key_fpr: str) -> bool:
    cmd = ["gpg", "--detach-sign", "--armor", "--local-user", key_fpr, manifest_path.name]
    try:
        subprocess.run(cmd, cwd=manifest_path.parent, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def gpg_verify(manifest: Path, signature: Path) -> bool:
    try:
        subprocess.run(
            ["gpg", "--verify", str(signature.resolve()), str(manifest.resolve())],
            check=True, capture_output=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _gpg_sign_with_keyfile(manifest_path: Path, key_file: Path) -> bool:
    """Sign using an armored GPG key export file via a temporary homedir."""
    tmp_home = Path(tempfile.mkdtemp(prefix="rednb-gpg-"))
    try:
        os.chmod(tmp_home, 0o700)
        subprocess.run(
            ["gpg", "--homedir", str(tmp_home), "--import", str(key_file.resolve())],
            check=True, capture_output=True,
        )
        result = subprocess.run(
            ["gpg", "--homedir", str(tmp_home), "--list-secret-keys", "--with-colons"],
            check=True, capture_output=True, text=True,
        )
        fpr = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "fpr":
                fpr = parts[9].upper()
                break
        if not fpr:
            return False
        subprocess.run(
            ["gpg", "--homedir", str(tmp_home),
             "--detach-sign", "--armor", "--local-user", fpr,
             manifest_path.name],
            cwd=manifest_path.parent, check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False
    finally:
        shutil.rmtree(tmp_home, ignore_errors=True)


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
    return parts[0], (parts[2] if len(parts) > 2 else "")


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
        priv_path = pub_path.with_suffix("")
        if require_private and not priv_path.exists():
            continue
        candidates.append(SshKeyCandidate(
            pub_path=pub_path,
            priv_path=priv_path if priv_path.exists() else None,
            key_type=key_type,
            comment=comment,
            filename=pub_path.name,
            is_fido="sk-" in key_type,
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
        filtered = [c for c in filtered if kl in c.pub_path.stem.lower() or kl in c.comment.lower()]
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
    """Resolve an SSH key from a direct .pub file or a directory to scan."""
    if ssh_kl.is_file():
        try:
            line = ssh_kl.read_text(encoding="utf-8").splitlines()[0]
        except (OSError, IndexError):
            print(f"[WARN] Could not read public key: {ssh_kl}")
            return None
        parsed = _parse_pubkey_line(line)
        if not parsed:
            print(f"[WARN] Could not parse public key: {ssh_kl}")
            return None
        key_type, comment = parsed
        priv_path = ssh_kl.with_suffix("")
        if require_private and not priv_path.exists():
            print(f"[WARN] Private key not found alongside {ssh_kl.name}")
            return None
        return SshKeyCandidate(
            pub_path=ssh_kl,
            priv_path=priv_path if priv_path.exists() else None,
            key_type=key_type,
            comment=comment,
            filename=ssh_kl.name,
            is_fido="sk-" in key_type,
        )
    candidates = scan_ssh_keys(ssh_kl, require_private=require_private)
    candidates = _filter_ssh_candidates(candidates, prefer_fido=prefer_fido, keyname=keyname)
    return choose_ssh_key(candidates)


def ssh_sign_manifest(manifest_path: Path, key_path: Path, sig_path: Path) -> bool:
    default_sig = manifest_path.with_suffix(manifest_path.suffix + ".sig")
    appended_sig = manifest_path.parent / f"{manifest_path.name}.sig"
    for c in (default_sig, appended_sig):
        if c.exists():
            c.unlink()
    try:
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key_path),
             "-n", SSH_NAMESPACE, str(manifest_path)],
            cwd=manifest_path.parent, check=True,
        )
    except subprocess.CalledProcessError:
        return False
    generated = next((c for c in (default_sig, appended_sig) if c.exists()), None)
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
        warnings.append("Multiple SSH signatures found; only the selected signature was verified.")
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
            cwd=manifest_path.parent, check=True,
            capture_output=True, text=True,
        )
    except subprocess.CalledProcessError:
        return SshVerifyResult("FAIL", "SSH signature verification failed.", warnings)
    finally:
        Path(allowed_path).unlink(missing_ok=True)
    return SshVerifyResult("OK", "SSH signature verified.", warnings)


# ---------- Manifest ----------

def collect_files(
    base: Path,
    month_only: bool,
    algo: str,
    exclude: Optional[List[str]] = None,
) -> Dict[str, str]:
    files: Dict[str, str] = {}
    exclude = exclude or []
    for root, _, filenames in os.walk(base):
        for name in filenames:
            path = Path(root) / name
            rel = path.relative_to(base)
            rel_str = rel.as_posix()
            if month_only and not is_month_file(path):
                continue
            if any(fnmatch.fnmatch(path.name, pat) or fnmatch.fnmatch(rel_str, pat) for pat in exclude):
                continue
            files[rel_str] = hash_file(path, algo)
    return dict(sorted(files.items()))


def generate_manifest(
    notebook: Path,
    month_only: bool,
    algo: str,
    merkle_algo: str,
    exclude: Optional[List[str]] = None,
) -> Dict:
    files = collect_files(notebook, month_only, algo, exclude=exclude)
    hashes = list(files.values())
    manifest: Dict = {
        "tool": "rednb-verify",
        "version": VERSION,
        "created": utc_timestamp(),
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "hash_algorithm": algo,
        "merkle_hash": merkle_algo,
        "mode": "month-files" if month_only else "full-tree",
        "files": [{"path": p, algo: h} for p, h in files.items()],
        "merkle_root": merkle_root(hashes, merkle_algo),
    }
    if exclude:
        manifest["exclude"] = exclude
    return manifest


# ---------- Verification ----------

def verify_manifest(
    manifest: Dict,
    notebook: Path,
    extra_exclude: Optional[List[str]] = None,
) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {"ok": [], "missing": [], "modified": [], "new": []}
    algo = manifest.get("hash_algorithm", "sha256")
    expected = {f["path"]: f[algo] for f in manifest["files"]}
    exclude = list(manifest.get("exclude", []))
    if extra_exclude:
        exclude.extend(extra_exclude)
    actual = collect_files(notebook, manifest["mode"] == "month-files", algo, exclude=exclude)
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


def write_report(results: Dict[str, List[str]], report_path: Path, manifest_path: Path) -> None:
    """Write JSON if path ends in .json, otherwise human-readable text."""
    if report_path.suffix.lower() == ".json":
        report_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        return
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        f"rednb-verify report — {now}",
        f"Manifest: {manifest_path.name}",
        "",
        f"{'OK:':<10} {len(results['ok'])}",
        f"{'New:':<10} {len(results['new'])}",
        f"{'Missing:':<10} {len(results['missing'])}",
        f"{'Modified:':<10} {len(results['modified'])}",
    ]
    for label, key in [("OK", "ok"), ("NEW", "new"), ("MISSING", "missing"), ("MODIFIED", "modified")]:
        if results[key]:
            lines += ["", f"--- {label} ---"] + [f"  {f}" for f in sorted(results[key])]
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
    """Returns 1=GPG, 2=SSH, 3=Both, 4=None."""
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


def _sign_with_gpg(
    manifest_path: Path,
    key_fpr: Optional[str],
    key_file: Optional[Path],
) -> None:
    """Sign with GPG. key_file uses armored export; key_fpr pre-selects keyring key."""
    if not gpg_available():
        print("[WARN] GPG not available — GPG signing skipped.")
        return

    # --- Key file path (temp homedir, no keyring pollution) ---
    if key_file:
        if not _quiet:
            print(NON_REPUDIATION_WARNING)
            if input("Sign with GPG key file? [y/N]: ").strip().lower() != "y":
                _qprint("[INFO] GPG signing cancelled.")
                return
        if _gpg_sign_with_keyfile(manifest_path, key_file):
            _qprint("[OK] Manifest signed with GPG.")
        else:
            print("[WARN] GPG signing failed.")
        return

    # --- Keyring path ---
    try:
        keys = list_secret_keys()
    except subprocess.CalledProcessError:
        print("[WARN] Could not list GPG keys.")
        return
    if not keys:
        print("[WARN] No GPG secret keys found — GPG signing skipped.")
        return

    if key_fpr:
        # Pre-selected fingerprint — still ask unless quiet
        fpr = key_fpr
        if not _quiet:
            print(NON_REPUDIATION_WARNING)
            if input("Sign this manifest with GPG? [y/N]: ").strip().lower() != "y":
                _qprint("[INFO] GPG signing cancelled.")
                return
    elif _quiet:
        # Non-interactive: require exactly one key
        if len(keys) == 1:
            fpr = keys[0]["fingerprint"]
        else:
            print("[ERROR] --quiet with --gpg requires a fingerprint when multiple keys exist.")
            print(f"        Use: --gpg {keys[0]['fingerprint']}")
            sys.exit(2)
    else:
        print(NON_REPUDIATION_WARNING)
        if input("Sign this manifest with GPG? [y/N]: ").strip().lower() != "y":
            _qprint("[INFO] GPG signing cancelled.")
            return
        fpr = choose_gpg_key(keys)
        if fpr is None:
            _qprint("[INFO] GPG signing cancelled.")
            return

    if gpg_detach_sign(manifest_path, fpr):
        _qprint("[OK] Manifest signed with GPG.")
    else:
        print("[WARN] GPG signing failed.")


def _sign_with_ssh(
    manifest_path: Path,
    sig_path: Path,
    ssh_kl_path: Path,
    prefer_fido: bool,
    keyname: Optional[str],
) -> None:
    """Sign manifest with SSH."""
    if not ssh_keygen_available():
        print("[WARN] ssh-keygen not available — SSH signing skipped.")
        return
    signer = select_ssh_key(ssh_kl_path, require_private=True, prefer_fido=prefer_fido, keyname=keyname)
    if signer is None or signer.priv_path is None:
        print("[WARN] No suitable SSH key found for signing.")
        return
    if not _quiet:
        print(SSH_NON_REPUDIATION_WARNING)
        if input("Sign this manifest with SSH? [y/N]: ").strip().lower() != "y":
            _qprint("[INFO] SSH signing cancelled.")
            return
    if ssh_sign_manifest(manifest_path, signer.priv_path, sig_path):
        _qprint(f"[OK] SSH signature created: {sig_path.name}")
    else:
        print("[WARN] SSH signing failed.")


def main():
    global _quiet

    config = load_config()

    parser = argparse.ArgumentParser(
        description="rednb-verify — RedNotebook integrity and tamper detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Create manifest — signing menu appears
  rednb-verify.py ~/journal

  # Skip signing
  rednb-verify.py ~/journal --no-sign

  # Sign with GPG (interactive key selection)
  rednb-verify.py ~/journal --gpg

  # Sign with GPG, pre-select key
  rednb-verify.py ~/journal --gpg ABCDEF1234567890

  # Sign with GPG key file
  rednb-verify.py ~/journal --gpg-k ~/backup-key.asc

  # Sign with SSH (skips menu)
  rednb-verify.py ~/journal --ssh-sign

  # Sign with both GPG and SSH (no menu)
  rednb-verify.py ~/journal --gpg --ssh-sign

  # Use specific SSH public key file (implies --ssh-sign)
  rednb-verify.py ~/journal --ssh-kl ~/.ssh/id_ed25519.pub

  # Show available hash algorithms
  rednb-verify.py . --hash-list

  # Exclude editor lock files
  rednb-verify.py ~/journal --exclude "*.tmp" --exclude ".~lock.*"

  # Non-interactive / cron use
  rednb-verify.py ~/journal --quiet --gpg ABCDEF1234567890

  # Verify — human-readable report saved next to journal (default)
  rednb-verify.py ~/journal --verify --manifest hashes-....json

  # Verify with JSON report
  rednb-verify.py ~/journal --verify --manifest hashes-....json --report json

  # Verify GPG + SSH signatures in one run
  rednb-verify.py ~/journal --verify --manifest hashes-....json \\
    --sig hashes-....json.asc,hashes-....json.sshsig

supported hash algorithms:
  sha256 (default), sha512, sha3_256, sha3_512, blake2b, blake2s ...
  use --hash-list to see all available algorithms
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
    parser.add_argument("--report", nargs="?", const="txt", default="txt",
                        metavar="txt|json",
                        help="Report format during --verify: txt (default) or json")
    parser.add_argument("--hash", default=HASH_ALGO, dest="hash_algo", metavar="ALGO",
                        help="Hash algorithm for files (default: sha256)")
    parser.add_argument("--hash-list", action="store_true",
                        help="Print available hash algorithms and exit")
    parser.add_argument("--hash-merkle", default=None, dest="merkle_algo",
                        help="Hash algorithm for Merkle tree (default: same as --hash)")
    parser.add_argument("--gpg", nargs="?", const="", default=None, metavar="FINGERPRINT",
                        help="Sign with GPG; optionally specify key fingerprint (skips menu)")
    parser.add_argument("--gpg-k", type=Path, default=None, metavar="FILE",
                        help="GPG armored key file to sign with; implies --gpg")
    parser.add_argument("--ssh-sign", action="store_true",
                        help="Sign with SSH key (skips menu)")
    parser.add_argument("--ssh-verify", action="store_true",
                        help="Force SSH signature check during --verify")
    parser.add_argument("--sig", type=str, default=None, metavar="FILE[,FILE]",
                        help="Signature file(s), comma-separated (.asc=GPG, .sshsig=SSH)")
    parser.add_argument("--ssh-kl", type=Path, default=None, metavar="FILE_OR_DIR",
                        help="SSH .pub file (used directly) or directory to scan; implies --ssh-sign")
    parser.add_argument("--ssh-fido", nargs="?", const="", metavar="KEYNAME",
                        help="Prefer FIDO2 hardware keys; optional name filter")
    parser.add_argument("--no-sign", action="store_true",
                        help="Skip all signing")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress non-error output; implies --no-sign unless signing is explicit")
    parser.add_argument("--exclude", action="append", metavar="PATTERN",
                        help="Exclude files matching glob pattern (repeatable)")

    # Apply config file as default layer (CLI args override)
    cfg: Dict = {}
    if "hash" in config:
        cfg["hash_algo"] = config["hash"]
    if config.get("hash_merkle"):
        cfg["merkle_algo"] = config["hash_merkle"]
    if config.get("quiet"):
        cfg["quiet"] = True
    if config.get("no_sign"):
        cfg["no_sign"] = True
    if config.get("gpg_key"):
        cfg["gpg"] = config["gpg_key"]
    if config.get("ssh_kl"):
        cfg["ssh_kl"] = Path(os.path.expanduser(config["ssh_kl"]))
    if config.get("exclude"):
        cfg["exclude"] = list(config["exclude"])
    if cfg:
        parser.set_defaults(**cfg)

    args = parser.parse_args()

    # Activate quiet mode before any output
    _quiet = args.quiet

    # Validate --report format
    if args.report not in ("txt", "json"):
        print(f"[ERROR] --report must be 'txt' or 'json', got: {args.report!r}")
        sys.exit(2)

    # --gpg-k implies --gpg
    if args.gpg_k is not None and args.gpg is None:
        args.gpg = ""

    # --ssh-kl (explicit) implies --ssh-sign
    if args.ssh_kl is not None and not args.ssh_sign:
        args.ssh_sign = True

    # --quiet implies --no-sign unless an explicit signing method was given
    if args.quiet and args.gpg is None and not args.ssh_sign:
        args.no_sign = True

    # Resolve SSH key location (None → default ~/.ssh)
    ssh_kl_path = (
        Path(os.path.expanduser(str(args.ssh_kl)))
        if args.ssh_kl is not None
        else Path(os.path.expanduser("~/.ssh"))
    )

    # --hash-list: print available algorithms and exit
    if args.hash_list:
        print("Available hash algorithms:")
        for algo in sorted(hashlib.algorithms_guaranteed):
            print(f"  {algo}")
        sys.exit(0)

    args.merkle_algo = args.merkle_algo or args.hash_algo

    for label, algo in [("--hash", args.hash_algo), ("--hash-merkle", args.merkle_algo)]:
        try:
            hashlib.new(algo)
        except ValueError:
            print(f"[ERROR] Unsupported algorithm for {label}: {algo}")
            sys.exit(2)

    # Parse --sig
    sig_paths: List[Path] = (
        [Path(s.strip()) for s in args.sig.split(",") if s.strip()]
        if args.sig else []
    )

    prefer_fido = args.ssh_fido is not None
    keyname = args.ssh_fido or None
    exclude: List[str] = args.exclude or []

    # Default output: parent of the journal directory
    notebook_path = args.notebook_dir.resolve()
    out_dir = (args.output or notebook_path.parent).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Verify mode                                                         #
    # ------------------------------------------------------------------ #
    if args.verify:
        if not args.manifest:
            print("[ERROR] --verify requires --manifest")
            sys.exit(2)

        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        results = verify_manifest(manifest, args.notebook_dir, extra_exclude=exclude)

        report_path = out_dir / f"report-{utc_timestamp()}.{args.report}"
        write_report(results, report_path, args.manifest)
        _qprint(f"Verification report: {report_path}")

        # Resolve signature files
        if sig_paths:
            gpg_sigs = [p for p in sig_paths if p.suffix == ".asc"]
            ssh_sigs = [p for p in sig_paths if p.suffix == ".sshsig"]
            for p in sig_paths:
                if p.suffix not in (".asc", ".sshsig"):
                    print(f"[WARN] Unknown signature type '{p.name}' — skipped (expected .asc or .sshsig).")
        else:
            auto_asc = args.manifest.with_suffix(args.manifest.suffix + ".asc")
            gpg_sigs = [auto_asc] if auto_asc.exists() else []
            auto_ssh = args.manifest.with_suffix(args.manifest.suffix + ".sshsig")
            ssh_sigs = [auto_ssh] if (auto_ssh.exists() or args.ssh_verify) else []

        # GPG verification
        if not gpg_sigs:
            _qprint("[WARN] Manifest not GPG-signed.")
        else:
            for gpg_sig in gpg_sigs:
                if not gpg_sig.exists():
                    print(f"[WARN] GPG signature not found: {gpg_sig.name}")
                elif not gpg_available():
                    print("[WARN] GPG not available — GPG verification skipped.")
                else:
                    if gpg_verify(args.manifest, gpg_sig):
                        _qprint(f"[OK] GPG signature verified: {gpg_sig.name}")
                    else:
                        print(f"[WARN] GPG signature invalid: {gpg_sig.name}")

        # SSH verification
        for ssh_sig in ssh_sigs:
            if not ssh_keygen_available():
                print("[WARN] ssh-keygen not available — SSH verification skipped.")
                break
            if not ssh_sig.exists():
                print(f"[WARN] SSH signature not found: {ssh_sig.name}")
                continue
            signer = select_ssh_key(ssh_kl_path, require_private=False,
                                    prefer_fido=prefer_fido, keyname=keyname)
            if signer is None:
                print("[WARN] No suitable SSH key found for verification.")
                continue
            result = ssh_verify_manifest(
                args.manifest, ssh_sig, signer.pub_path,
                multiple_signatures=len(ssh_sigs) > 1,
                nonstandard_sig=ssh_sig != args.manifest.with_suffix(
                    args.manifest.suffix + ".sshsig"),
            )
            label = "[OK]" if result.status == "OK" else f"[{result.status}]"
            _qprint(f"{label} {result.message}")
            for w in result.warnings:
                print(f"[WARN] {w}")

        if any(k != "ok" and results[k] for k in results):
            _qprint("Verification completed with issues.")
            sys.exit(1)

        _qprint("[OK] Verification successful.")
        return

    # ------------------------------------------------------------------ #
    #  Create mode                                                         #
    # ------------------------------------------------------------------ #
    manifest = generate_manifest(
        args.notebook_dir, args.month_only, args.hash_algo, args.merkle_algo,
        exclude=exclude,
    )
    manifest_name = f"hashes-{manifest['created']}.json"
    manifest_path = out_dir / manifest_name
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _qprint(f"Manifest created: {manifest_path}")

    # SSH sig output path: from --sig if a .sshsig path given, else default
    ssh_sig_out = next(
        (p for p in sig_paths if p.suffix == ".sshsig"),
        manifest_path.with_suffix(manifest_path.suffix + ".sshsig"),
    )

    # ---- Signing ----
    want_gpg = args.gpg is not None
    want_ssh = args.ssh_sign

    if args.no_sign:
        _qprint("[INFO] Signing skipped (--no-sign).")

    elif want_gpg and want_ssh:
        _sign_with_gpg(manifest_path, key_fpr=args.gpg or None, key_file=args.gpg_k)
        _sign_with_ssh(manifest_path, ssh_sig_out, ssh_kl_path, prefer_fido, keyname)

    elif want_gpg:
        _sign_with_gpg(manifest_path, key_fpr=args.gpg or None, key_file=args.gpg_k)

    elif want_ssh:
        _sign_with_ssh(manifest_path, ssh_sig_out, ssh_kl_path, prefer_fido, keyname)

    else:
        sign_choice = _prompt_signing_menu()
        if sign_choice in (1, 3):
            _sign_with_gpg(manifest_path, key_fpr=None, key_file=None)
        if sign_choice in (2, 3):
            _sign_with_ssh(manifest_path, ssh_sig_out, ssh_kl_path, prefer_fido, keyname)


if __name__ == "__main__":
    main()
