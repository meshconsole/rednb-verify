#!/usr/bin/env python3
"""
rednb-verify
Version: 0.6.1

RedNotebook integrity verification tool.
Creates and verifies cryptographic manifests for notebook directories.

CLI/Commands:
rednb-verify.py [options] [notebook_directory]
"-m", "--month-only"       : Hashes only month files
"-D", "--per-day"          : Hash individual day entries within month files (requires PyYAML)
"-j", "--jobs N"           : Parallel hashing workers (0 = auto, default: 1)
"-o", "--output"           : Output directory for manifest (default: journal parent)
"--verify"                 : Verification mode
"--manifest"               : Manifest file to verify against
"--report txt|json"        : Report format during --verify (default: txt)
"--hash ALGO"              : Hash algorithm for files (default: sha256)
"--hash-list"              : Print available hash algorithms and exit
"--hash-merkle"            : Hash algorithm for Merkle tree (default: same as --hash)
"--gpg [FINGERPRINT]"      : Sign with GPG; optional fingerprint pre-selects key (skips menu)
"--gpg-k FILE"             : GPG armored key file; implies --gpg
"--ssh-sign"               : Sign with SSH key (skips menu)
"--ssh-verify"             : Force SSH signature check during --verify
"--sig FILE[,FILE]"        : Signature file(s) comma-separated (.asc=GPG, .sshsig=SSH)
"--ssh-kl FILE|DIR"        : SSH .pub key file (used directly) or directory to scan; implies --ssh-sign
"--ssh-fido [NAME]"        : Prefer FIDO2/hardware-backed SSH keys; optional name filter
"--no-sign"                : Skip all signing
"--resign MANIFEST"        : Re-sign an existing manifest (requires --gpg and/or --ssh-sign)
"--warn-age DAYS"          : Warn during verify if manifest is older than N days
"--verbose / -v"           : Print per-file hash timing and detailed progress
"--quiet"                  : Suppress non-error output; implies --no-sign unless signing is explicit
"--exclude PATTERN"        : Exclude files matching glob (repeatable)
"--exclude-from FILE"      : File of glob patterns to exclude (one per line, # = comment)
"--no-config / --no-cf"    : Ignore ~/.config/rednb-verify/config.json for this run
"--config FILE"            : Load a specific config file instead of the default

Exit codes:
  0  all checks passed / manifest created successfully
  1  verification found issues (modified, missing, or unexpected files)
  2  usage or input error (bad arguments, missing files, unsupported algorithm)
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
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

VERSION = "0.6.1"
HASH_ALGO = "sha256"
CONFIG_PATH = Path(os.path.expanduser("~/.config/rednb-verify/config.json"))

# Set by main() before any output
_quiet: bool = False
_verbose: bool = False


def _qprint(msg: str) -> None:
    """Print only when not in quiet mode."""
    if not _quiet:
        print(msg)


def _vprint(msg: str) -> None:
    """Print only in verbose mode (quiet still suppresses it)."""
    if _verbose and not _quiet:
        print(msg)


def _require_yaml():
    """Import and return the yaml module, or exit with a clear install message."""
    try:
        import yaml  # type: ignore
        return yaml
    except ImportError:
        print("[ERROR] --per-day requires PyYAML:  pip install pyyaml")
        sys.exit(2)


# ---------- Config ----------

def load_config(path: Path = CONFIG_PATH) -> Dict:
    """Load a config JSON file if present. Defaults to ~/.config/rednb-verify/config.json."""
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] Could not load config {path}: {exc}", file=sys.stderr)
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
    jobs: int = 1,
) -> Dict[str, str]:
    exclude = exclude or []

    # Gather candidate paths first (always sequential — os.walk is not thread-safe)
    paths_to_hash: List[tuple] = []
    for root, _, filenames in os.walk(base):
        for name in filenames:
            path = Path(root) / name
            rel = path.relative_to(base)
            rel_str = rel.as_posix()
            if month_only and not is_month_file(path):
                continue
            if any(fnmatch.fnmatch(path.name, pat) or fnmatch.fnmatch(rel_str, pat) for pat in exclude):
                continue
            paths_to_hash.append((path, rel_str))

    files: Dict[str, str] = {}

    if jobs == 1:
        # Sequential — original behavior
        for path, rel_str in paths_to_hash:
            if _verbose:
                t0 = time.perf_counter()
                files[rel_str] = hash_file(path, algo)
                elapsed_ms = (time.perf_counter() - t0) * 1000
                _vprint(f"  hashing {rel_str} ... {elapsed_ms:.2f}ms")
            else:
                files[rel_str] = hash_file(path, algo)
    else:
        # Parallel — print as each file completes when verbose
        _lock = threading.Lock()

        def _hash_one(path: Path, rel_str: str) -> tuple:
            t0 = time.perf_counter()
            h = hash_file(path, algo)
            if _verbose:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                with _lock:
                    _vprint(f"  hashing {rel_str} ... {elapsed_ms:.2f}ms")
            return rel_str, h

        max_workers = jobs if jobs > 0 else None
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_hash_one, p, r): r for p, r in paths_to_hash}
            for future in as_completed(futures):
                rel_str, h = future.result()
                files[rel_str] = h

    return dict(sorted(files.items()))


def collect_files_per_day(
    base: Path,
    algo: str,
    exclude: Optional[List[str]] = None,
    jobs: int = 1,
) -> Dict[str, str]:
    """Hash individual day entries within RedNotebook YYYY-MM.txt month files.

    Each entry is identified by path ``YYYY-MM/DD`` (e.g. ``2026-05/14``).
    Day content is serialised to canonical JSON before hashing so that all
    fields (text, tags, custom categories) are captured.

    Requires PyYAML (``pip install pyyaml``).
    """
    yaml = _require_yaml()
    exclude = exclude or []

    # Collect all (day_key, day_data) pairs from every month file
    entries: List[tuple] = []
    for month_path in sorted(base.glob("[0-9][0-9][0-9][0-9]-[0-9][0-9].txt")):
        rel_month = month_path.relative_to(base).as_posix()
        if any(fnmatch.fnmatch(month_path.name, pat) or fnmatch.fnmatch(rel_month, pat) for pat in exclude):
            continue
        try:
            content = yaml.safe_load(month_path.read_text(encoding="utf-8"))
        except Exception as exc:
            _qprint(f"[WARN] Could not parse {month_path.name}: {exc}")
            continue
        if not isinstance(content, dict):
            continue
        year_month = month_path.stem  # e.g. "2026-05"
        for day_num in sorted(content.keys()):
            if not isinstance(day_num, int):
                continue
            day_key = f"{year_month}/{day_num:02d}"
            entries.append((day_key, content[day_num]))

    files: Dict[str, str] = {}

    def _hash_day(day_key: str, day_data) -> tuple:
        # Canonicalise: dicts → sorted JSON; plain strings kept as-is
        if isinstance(day_data, dict):
            canonical = json.dumps(day_data, ensure_ascii=False, sort_keys=True)
        else:
            canonical = str(day_data) if day_data is not None else ""
        t0 = time.perf_counter()
        h = hashlib.new(algo, canonical.encode("utf-8")).hexdigest()
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return day_key, h, elapsed_ms

    if jobs == 1:
        for day_key, day_data in entries:
            key, h, elapsed_ms = _hash_day(day_key, day_data)
            files[key] = h
            if _verbose:
                _vprint(f"  hashing {key} ... {elapsed_ms:.2f}ms")
    else:
        _lock = threading.Lock()

        def _hash_day_parallel(day_key: str, day_data) -> tuple:
            key, h, elapsed_ms = _hash_day(day_key, day_data)
            if _verbose:
                with _lock:
                    _vprint(f"  hashing {key} ... {elapsed_ms:.2f}ms")
            return key, h

        max_workers = jobs if jobs > 0 else None
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_hash_day_parallel, k, d): k for k, d in entries}
            for future in as_completed(futures):
                key, h = future.result()
                files[key] = h

    return dict(sorted(files.items()))


def generate_manifest(
    notebook: Path,
    month_only: bool,
    algo: str,
    merkle_algo: str,
    exclude: Optional[List[str]] = None,
    per_day: bool = False,
    jobs: int = 1,
) -> Dict:
    if per_day and not month_only:
        # per-day/full-tree: individual day entries + all non-month files.
        # Pass the YYYY-MM.txt glob to collect_files so month files are
        # never hashed twice and don't appear in verbose output.
        _MONTH_GLOB = "[0-9][0-9][0-9][0-9]-[0-9][0-9].txt"
        day_files = collect_files_per_day(notebook, algo, exclude=exclude, jobs=jobs)
        other_files = collect_files(
            notebook, False, algo,
            exclude=list(exclude) + [_MONTH_GLOB],
            jobs=jobs,
        )
        files = dict(sorted({**day_files, **other_files}.items()))
        mode = "per-day/full-tree"
    elif per_day and month_only:
        # per-day/month-only: individual day entries, no attachments
        files = collect_files_per_day(notebook, algo, exclude=exclude, jobs=jobs)
        mode = "per-day/month-only"
    elif month_only:
        # month-only: whole YYYY-MM.txt files, no attachments
        files = collect_files(notebook, True, algo, exclude=exclude, jobs=jobs)
        mode = "month-only"
    else:
        # full-tree: every file as-is
        files = collect_files(notebook, False, algo, exclude=exclude, jobs=jobs)
        mode = "full-tree"

    hashes = list(files.values())
    manifest: Dict = {
        "tool": "rednb-verify",
        "version": VERSION,
        "created": utc_timestamp(),
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "hash_algorithm": algo,
        "merkle_hash": merkle_algo,
        "mode": mode,
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
    jobs: int = 1,
) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {"ok": [], "missing": [], "modified": [], "new": []}
    algo = manifest.get("hash_algorithm", "sha256")
    expected = {f["path"]: f[algo] for f in manifest["files"]}
    exclude = list(manifest.get("exclude", []))
    if extra_exclude:
        exclude.extend(extra_exclude)
    mode = manifest.get("mode", "full-tree")
    _MONTH_GLOB = "[0-9][0-9][0-9][0-9]-[0-9][0-9].txt"
    if mode == "per-day/full-tree":
        day_files = collect_files_per_day(notebook, algo, exclude=exclude, jobs=jobs)
        other_files = collect_files(
            notebook, False, algo,
            exclude=list(exclude) + [_MONTH_GLOB],
            jobs=jobs,
        )
        actual = dict(sorted({**day_files, **other_files}.items()))
    elif mode in ("per-day", "per-day/month-only"):
        # "per-day" kept for backward compatibility with v0.6.0 manifests
        actual = collect_files_per_day(notebook, algo, exclude=exclude, jobs=jobs)
    elif mode in ("month-files", "month-only"):
        # "month-files" kept for backward compatibility with pre-v0.6.0 manifests
        actual = collect_files(notebook, True, algo, exclude=exclude, jobs=jobs)
    else:
        actual = collect_files(notebook, False, algo, exclude=exclude, jobs=jobs)
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
    global _quiet, _verbose

    # Pre-scan argv so --no-config/--no-cf and --config FILE take effect
    # before argparse runs (config must be loaded before set_defaults).
    _no_config = "--no-config" in sys.argv or "--no-cf" in sys.argv
    _config_path = CONFIG_PATH
    if not _no_config:
        for i, arg in enumerate(sys.argv[1:], 1):
            if arg == "--config" and i + 1 < len(sys.argv):
                _config_path = Path(sys.argv[i + 1]).expanduser()
                break
            if arg.startswith("--config="):
                _config_path = Path(arg.split("=", 1)[1]).expanduser()
                break
    config = {} if _no_config else load_config(_config_path)
    _config_active = bool(config)

    parser = argparse.ArgumentParser(
        description="rednb-verify — RedNotebook integrity and tamper detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Create manifest — signing menu appears
  rednb-verify.py ~/journal

  # Skip signing
  rednb-verify.py ~/journal --no-sign

  # Verbose: show per-file hash timing
  rednb-verify.py ~/journal --no-sign --verbose

  # Parallel hashing (4 workers)
  rednb-verify.py ~/journal --no-sign --jobs 4

  # Per-day hashing (requires PyYAML)
  rednb-verify.py ~/journal --per-day --no-sign

  # Exclude patterns from a file
  rednb-verify.py ~/journal --exclude-from ~/my-excludes.txt --no-sign

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

  # Re-sign an existing manifest
  rednb-verify.py --resign hashes-....json --gpg
  rednb-verify.py --resign hashes-....json --ssh-sign
  rednb-verify.py --resign hashes-....json --gpg --ssh-sign

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

  # Verify with JSON report and age warning
  rednb-verify.py ~/journal --verify --manifest hashes-....json --report json --warn-age 90

  # Verify GPG + SSH signatures in one run
  rednb-verify.py ~/journal --verify --manifest hashes-....json \\
    --sig hashes-....json.asc,hashes-....json.sshsig

exit codes:
  0  all checks passed / manifest created successfully
  1  verification found issues (modified, missing, or unexpected files)
  2  usage or input error (bad arguments, missing files, unsupported algorithm)

supported hash algorithms:
  sha256 (default), sha512, sha3_256, sha3_512, blake2b, blake2s ...
  use --hash-list to see all available algorithms
"""
    )
    parser.add_argument("notebook_dir", type=Path, nargs="?",
                        help="Path to the RedNotebook journal directory")
    parser.add_argument("-m", "--month-only", action="store_true",
                        help="Hash only YYYY-MM.txt files")
    parser.add_argument("-o", "--output", type=Path,
                        help="Output directory (default: parent of journal directory)")
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
    parser.add_argument("--resign", type=Path, default=None, metavar="MANIFEST",
                        help="Re-sign an existing manifest (requires --gpg and/or --ssh-sign)")
    parser.add_argument("--warn-age", type=int, default=None, dest="warn_age", metavar="DAYS",
                        help="Warn during --verify if manifest is older than N days")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print per-file hash timing and detailed progress")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress non-error output; implies --no-sign unless signing is explicit")
    parser.add_argument("--exclude", action="append", metavar="PATTERN",
                        help="Exclude files matching glob pattern (repeatable)")
    parser.add_argument("--exclude-from", type=Path, default=None, metavar="FILE",
                        help="File of glob patterns to exclude (one per line, # = comment)")
    parser.add_argument("-j", "--jobs", type=int, default=1, metavar="N",
                        help="Parallel hashing workers (0 = auto, default: 1)")
    parser.add_argument("-D", "--per-day", action="store_true",
                        help="Hash individual day entries within month files (requires PyYAML)")
    parser.add_argument("--no-config", "--no-cf", action="store_true", dest="no_config",
                        help="Ignore ~/.config/rednb-verify/config.json for this run")
    parser.add_argument("--config", type=Path, metavar="FILE",
                        help="Load a specific config file instead of the default")

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
    if config.get("manifest_age_warn_days"):
        cfg["warn_age"] = int(config["manifest_age_warn_days"])
    if config.get("jobs") is not None:
        cfg["jobs"] = int(config["jobs"])
    if cfg:
        parser.set_defaults(**cfg)

    args = parser.parse_args()

    # Activate output modes before any printing
    _quiet = args.quiet
    _verbose = args.verbose

    if args.quiet and args.verbose:
        print("[ERROR] --quiet and --verbose are mutually exclusive.")
        sys.exit(2)

    # Notify user that a config file is in effect
    if _config_active:
        _qprint(f"[INFO] Using config: {_config_path}")

    # Validate --report format
    if args.report not in ("txt", "json"):
        print(f"[ERROR] --report must be 'txt' or 'json', got: {args.report!r}")
        sys.exit(2)

    # --hash-list: print available algorithms and exit (no notebook_dir needed)
    if args.hash_list:
        print("Available hash algorithms:")
        for algo in sorted(hashlib.algorithms_guaranteed):
            print(f"  {algo}")
        sys.exit(0)

    # notebook_dir required for all modes except --resign
    if args.notebook_dir is None and not args.resign:
        parser.error("notebook_dir is required")

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
    exclude: List[str] = list(args.exclude or [])

    # --exclude-from: read patterns from file and merge into exclude list
    if args.exclude_from:
        excf = Path(os.path.expanduser(str(args.exclude_from)))
        if not excf.exists():
            print(f"[ERROR] --exclude-from file not found: {excf}")
            sys.exit(2)
        for raw_line in excf.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                exclude.append(line)
        _vprint(f"[INFO] Loaded exclusion patterns from {excf.name}")

    # --jobs validation
    if args.jobs < 0:
        print("[ERROR] --jobs must be 0 (auto) or a positive integer.")
        sys.exit(2)
    jobs: int = args.jobs

    # Resolve output directory
    if args.resign:
        out_dir = (args.output or args.resign.resolve().parent).resolve()
    else:
        out_dir = (args.output or args.notebook_dir.resolve().parent).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    want_gpg = args.gpg is not None
    want_ssh = args.ssh_sign

    # ------------------------------------------------------------------ #
    #  Resign mode                                                         #
    # ------------------------------------------------------------------ #
    if args.resign:
        manifest_path = args.resign.resolve()
        if not manifest_path.exists():
            print(f"[ERROR] Manifest not found: {manifest_path}")
            sys.exit(2)
        try:
            json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[ERROR] Could not read manifest: {exc}")
            sys.exit(2)
        if not want_gpg and not want_ssh:
            print("[ERROR] --resign requires a signing method: --gpg and/or --ssh-sign")
            sys.exit(2)
        ssh_sig_out = next(
            (p for p in sig_paths if p.suffix == ".sshsig"),
            manifest_path.with_suffix(manifest_path.suffix + ".sshsig"),
        )
        _qprint(f"Re-signing: {manifest_path.name}")
        if want_gpg:
            _sign_with_gpg(manifest_path, key_fpr=args.gpg or None, key_file=args.gpg_k)
        if want_ssh:
            _sign_with_ssh(manifest_path, ssh_sig_out, ssh_kl_path, prefer_fido, keyname)
        return

    # ------------------------------------------------------------------ #
    #  Verify mode                                                         #
    # ------------------------------------------------------------------ #
    if args.verify:
        if not args.manifest:
            print("[ERROR] --verify requires --manifest")
            sys.exit(2)

        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))

        # Manifest age warning
        if args.warn_age is not None:
            try:
                created = datetime.strptime(
                    manifest["created"], "%Y%m%dT%H%M%SZ"
                ).replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - created).days
                if age_days > args.warn_age:
                    print(
                        f"[WARN] Manifest is {age_days} days old — consider refreshing "
                        f"(threshold: {args.warn_age} days)."
                    )
            except (KeyError, ValueError):
                pass

        results = verify_manifest(manifest, args.notebook_dir, extra_exclude=exclude, jobs=jobs)

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
    # Determine and display mode when verbose
    if args.per_day and not args.month_only:
        _mode_label = "per-day/full-tree"
    elif args.per_day and args.month_only:
        _mode_label = "per-day/month-only"
    elif args.month_only:
        _mode_label = "month-only"
    else:
        _mode_label = "full-tree"
    _vprint(f"Hashing ({_mode_label}): {args.notebook_dir}")
    manifest = generate_manifest(
        args.notebook_dir, args.month_only, args.hash_algo, args.merkle_algo,
        exclude=exclude,
        per_day=args.per_day,
        jobs=jobs,
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
