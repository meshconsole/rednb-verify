#!/usr/bin/env python3
"""
rednb-verify
Version: 0.7.2

RedNotebook integrity verification tool.
Creates and verifies cryptographic manifests for notebook directories.

CLI/Commands:
rednb-verify.py [options] [notebook_directory]
"-m", "--month-only"       : Hashes only month files
"-D", "--per-day"          : Hash individual day entries within month files (requires PyYAML)
"-j", "--jobs N"           : Parallel hashing workers (0 = auto, default: 1)
"-o", "--output"           : Output directory for manifest (default: journal parent)
"--verify [FILE|DIR]"      : Verify mode; optional manifest path/dir (auto-finds latest if omitted)
"--manifest-type txt|json" : Manifest creation format (default: txt)
"--report txt|json"        : Report format during --verify (default: txt)
"--hash ALGO[:LEN]"        : Hash algorithm (default: sha256); shake_128/shake_256 require :LEN
"--hash-list"              : Print available hash algorithms and exit
"--hash-merkle"            : Hash algorithm for Merkle tree (default: same as --hash)
"--gpg [FINGERPRINT]"      : Sign with GPG; optional fingerprint pre-selects key (skips menu)
"--gpg-k FILE"             : GPG armored key file; implies --gpg
"--ssh [FILE_OR_DIR]"      : Sign with SSH key; optional .pub file or directory to scan (default: ~/.ssh)
"--ssh-verify"             : Force SSH signature check during --verify
"--sig FILE[,FILE]"        : Signature file(s) comma-separated (.asc=GPG, .sshsig/.sig=SSH)
"--ssh-fido [NAME]"        : Prefer FIDO2/hardware-backed SSH keys; optional name filter
"--no-sign"                : Skip all signing
"--resign MANIFEST"        : Re-sign an existing manifest (requires --gpg and/or --ssh)
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

VERSION = "0.8.0"
HASH_ALGO = "sha256"
CONFIG_PATH = Path(os.path.expanduser("~/.config/rednb-verify/config.json"))

# Manifest structural contract. Separate from VERSION (build identifier).
# Bump only on a BREAKING structural change (renamed/removed/retyped field),
# never for an optional addition. Manifests without this field = version 0.
MANIFEST_SCHEMA_VERSION = 1

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
        print(f"{_tag('ERROR')} --per-day requires PyYAML:  pip install pyyaml")
        sys.exit(2)


# ---------- Colour helpers ----------
# Applied only when stdout/stderr is a real TTY (no colour when piped/redirected).

_ANSI_RESET = "\033[0m"
_ANSI: Dict[str, str] = {
    "INFO":  "\033[33m",   # yellow
    "OK":    "\033[97m",   # bright white
    "WARN":  "\033[91m",   # light red
    "ERROR": "\033[91m",   # light red
}


def _tag(label: str, *, stream=None) -> str:
    """Return a coloured [LABEL] tag.  Falls back to plain text on non-TTY."""
    tty = (stream or sys.stdout).isatty()
    code = _ANSI.get(label.upper(), "")
    if code and tty:
        return f"{code}[{label}]{_ANSI_RESET}"
    return f"[{label}]"


def _info(msg: str) -> None:
    _qprint(f"{_tag('INFO')} {msg}")


def _ok(msg: str) -> None:
    _qprint(f"{_tag('OK')} {msg}")


def _warn(msg: str) -> None:
    """Cosmetic-tier warning: suppressed by --quiet."""
    if not _quiet:
        print(f"{_tag('WARN')} {msg}")


def _warn_security(msg: str) -> None:
    """Security-tier warning: ALWAYS printed, ALWAYS to stderr, ignores --quiet."""
    print(f"{_tag('WARN', stream=sys.stderr)} {msg}", file=sys.stderr)


def _err(msg: str) -> None:
    print(f"{_tag('ERROR', stream=sys.stderr)} {msg}", file=sys.stderr)


# ---------- Config ----------

def load_config(path: Path = CONFIG_PATH) -> Dict:
    """Load a config JSON file if present.  Empty files are silently ignored."""
    if path.exists():
        try:
            text = path.read_text(encoding="utf-8").strip()
            if not text:
                return {}
            return json.loads(text)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"{_tag('WARN', stream=sys.stderr)} Could not load config {path}: {exc}",
                  file=sys.stderr)
    return {}


def save_config(config: Dict, path: Path = CONFIG_PATH) -> None:
    """Write the config dict to disk as pretty JSON, creating parent dirs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=4, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def _normalize_gpg_fpr(fpr: str) -> str:
    """GPG fingerprints compared case-insensitively, spaces stripped (D3)."""
    return fpr.replace(" ", "").upper()


# --set-cf / --add-trust field → trust list key
_CF_TRUST_FIELDS = {"trust-gpg": "gpg", "trust-ssh": "ssh"}


def _parse_cf_token(token: str) -> tuple:
    """Parse 'field:value[,value...]' → (field, [values]).

    Splits on the FIRST colon only (G5), so dir:C:\\path keeps its drive colon.
    Returns (field, None) if no colon is present.
    """
    field, sep, rest = token.partition(":")
    if not sep:
        return field.strip(), None
    values = [v.strip() for v in rest.split(",") if v.strip()]
    return field.strip(), values


def apply_set_cf(config: Dict, tokens: List[str]) -> None:
    """Apply --set-cf tokens to config in place (REPLACE semantics)."""
    for token in tokens:
        field, values = _parse_cf_token(token)
        if values is None:
            _err(f"--set-cf expects field:value, got: {token!r}")
            sys.exit(2)
        if field in _CF_TRUST_FIELDS:
            kind = _CF_TRUST_FIELDS[field]
            if kind == "gpg":
                values = [_normalize_gpg_fpr(v) for v in values]
            config.setdefault("trust", {})[kind] = list(dict.fromkeys(values))
        elif field == "trust-level":
            level = (values[0].lower() if values else "")
            if level not in ("high", "low"):
                _err(f"trust-level must be 'high' or 'low', got: {values!r}")
                sys.exit(2)
            config["trust_level"] = level
        elif field == "dir":
            config["dir"] = values[0]  # single path; last wins if repeated
        else:
            _err(f"Unknown --set-cf field: {field!r} "
                 "(expected trust-gpg, trust-ssh, trust-level, dir)")
            sys.exit(2)


def apply_add_trust(config: Dict, tokens: List[str]) -> None:
    """Apply --add-trust tokens to config in place (APPEND + de-dupe, order kept)."""
    for token in tokens:
        field, values = _parse_cf_token(token)
        if values is None:
            _err(f"--add-trust expects field:value, got: {token!r}")
            sys.exit(2)
        if field not in _CF_TRUST_FIELDS:
            _err(f"--add-trust only supports trust-gpg / trust-ssh, got: {field!r}")
            sys.exit(2)
        kind = _CF_TRUST_FIELDS[field]
        if kind == "gpg":
            values = [_normalize_gpg_fpr(v) for v in values]
        existing = config.get("trust", {}).get(kind, [])
        config.setdefault("trust", {})[kind] = list(dict.fromkeys(existing + values))


# ---------- Utilities ----------

# Algorithms whose digest() / hexdigest() require an explicit byte-length argument.
_VARIABLE_LENGTH_ALGOS = {"shake_128", "shake_256"}

# Cryptographically broken hashes — unsafe as the SOLE integrity hash.
_WEAK_ALGOS = {"md5", "sha1"}

# Canonical manifest warning strings (stored in the manifest "warnings" field).
WARN_WEAK_HASH = "WEAK HASHING ALGORITHM(S) IN USE ALONE"
WARN_UNSIGNED = "MANIFEST UNSIGNED"
WARN_EXCLUDED = "FILES EXCLUDED FROM MANIFEST"
WARN_NO_FILES = "NO FILES FOUND IN NOTEBOOK DIRECTORY"
WARN_NO_DAYS = "NO DAY ENTRIES FOUND"


def _parse_algo_spec(spec: str) -> tuple:
    """Parse 'algo' or 'algo:length' → (algo_name, length_or_None).

    shake_128 and shake_256 require a length, e.g. 'shake_128:32'.
    All other algorithms ignore the length component even if provided.
    """
    if ":" in spec:
        algo, _, length_str = spec.partition(":")
        try:
            return algo.strip(), int(length_str.strip())
        except ValueError:
            return spec.strip(), None
    return spec.strip(), None


def _hexdigest(h, length: Optional[int]) -> str:
    """Call h.hexdigest() with or without a length argument."""
    return h.hexdigest(length) if length is not None else h.hexdigest()


def _validate_algo_spec_or_exit(spec: str, label: str) -> tuple:
    """Validate one algo spec against the registry; exit(2) with a clear message.

    Returns (name, length) on success. Note: AVAILABLE_HASHES is defined just
    below hash_file, so this is only called from main() after module load.
    """
    name, length = _parse_algo_spec(spec)
    if name not in AVAILABLE_HASHES:
        if name in _OPTIONAL_PIP:
            _err(f"{label} {name!r} needs an optional package: "
                 f"pip install {_OPTIONAL_PIP[name]}")
        else:
            _err(f"Unsupported algorithm for {label}: {spec!r}")
        sys.exit(2)
    if name in _VARIABLE_LENGTH_ALGOS and length is None:
        _err(f"{name} requires a length: use {label} {name}:32")
        sys.exit(2)
    if name not in _VARIABLE_LENGTH_ALGOS and length is not None:
        _err(f"{name} does not support a length parameter (remove :{length})")
        sys.exit(2)
    try:
        _hexdigest(_new_hasher(name), length)
    except TypeError as exc:
        _err(f"Algorithm error for {label} {spec!r}: {exc}")
        sys.exit(2)
    return name, length


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def hash_file(path: Path, algo_spec: str) -> str:
    """Hash a file using an algorithm spec ('algo' or 'algo:length')."""
    algo, length = _parse_algo_spec(algo_spec)
    h = hashlib.new(algo)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return _hexdigest(h, length)


# Optional hash backends beyond hashlib's guaranteed set. Each entry maps an
# algorithm NAME to a zero-arg constructor returning an object with
# .update(bytes) and .hexdigest(). Populated once at import time.
AVAILABLE_HASHES: Dict[str, object] = {}
for _algo in hashlib.algorithms_guaranteed:
    # bind _algo per-iteration via default arg
    AVAILABLE_HASHES[_algo] = (lambda a: (lambda: hashlib.new(a)))(_algo)
try:
    import blake3 as _blake3_mod
    AVAILABLE_HASHES["blake3"] = _blake3_mod.blake3
except ImportError:
    pass
try:
    import xxhash as _xxhash_mod
    AVAILABLE_HASHES["xxh3"] = _xxhash_mod.xxh3_128
except ImportError:
    pass

# Known optional algorithms and the pip package that provides each.
_OPTIONAL_PIP = {"blake3": "blake3", "xxh3": "xxhash"}


def _new_hasher(name: str):
    """Return a fresh hasher for an algorithm name, or None if unavailable."""
    ctor = AVAILABLE_HASHES.get(name)
    return ctor() if ctor is not None else None


def hash_file_multi(path: Path, specs: List[str]) -> Dict[str, str]:
    """Hash a file with N algorithms in a SINGLE read pass.

    Returns {spec: hexdigest} keyed by the original spec string
    (e.g. 'sha256', 'shake_128:32'). Caller is responsible for having
    validated the specs.
    """
    parsed = [(spec, *_parse_algo_spec(spec)) for spec in specs]
    hashers = {spec: _new_hasher(name) for spec, name, _ in parsed}
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            for h in hashers.values():
                h.update(chunk)
    return {spec: _hexdigest(hashers[spec], length) for spec, _, length in parsed}


def hash_bytes_multi(data: bytes, specs: List[str]) -> Dict[str, str]:
    """Hash an in-memory byte string with N algorithms. Returns {spec: hexdigest}."""
    out: Dict[str, str] = {}
    for spec in specs:
        name, length = _parse_algo_spec(spec)
        h = _new_hasher(name)
        h.update(data)
        out[spec] = _hexdigest(h, length)
    return out


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

def merkle_root(hashes: List[str], algo_spec: str) -> str:
    if not hashes:
        return ""
    algo, length = _parse_algo_spec(algo_spec)
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            h = hashlib.new(algo, left + right)
            next_level.append(h.digest(length) if length is not None else h.digest())
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
        _err("Invalid selection.")
        return None
    idx = int(choice)
    if idx < 0 or idx >= len(keys):
        _err("Selection out of range.")
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
        _err("Invalid selection.")
        return None
    idx = int(choice)
    if idx < 0 or idx >= len(candidates):
        _err("Selection out of range.")
        return None
    return candidates[idx]


def select_ssh_key(
    ssh_key: Path,
    require_private: bool,
    prefer_fido: bool,
    keyname: Optional[str],
) -> Optional[SshKeyCandidate]:
    """Resolve an SSH key from a direct .pub file or a directory to scan."""
    if ssh_key.is_file():
        try:
            line = ssh_key.read_text(encoding="utf-8").splitlines()[0]
        except (OSError, IndexError):
            _warn(f"Could not read public key: {ssh_key}")
            return None
        parsed = _parse_pubkey_line(line)
        if not parsed:
            _warn(f"Could not parse public key: {ssh_key}")
            return None
        key_type, comment = parsed
        priv_path = ssh_key.with_suffix("")
        if require_private and not priv_path.exists():
            _warn(f"Private key not found alongside {ssh_key.name}")
            return None
        return SshKeyCandidate(
            pub_path=ssh_key,
            priv_path=priv_path if priv_path.exists() else None,
            key_type=key_type,
            comment=comment,
            filename=ssh_key.name,
            is_fido="sk-" in key_type,
        )
    candidates = scan_ssh_keys(ssh_key, require_private=require_private)
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
    algos: List[str],
    exclude: Optional[List[str]] = None,
    jobs: int = 1,
) -> Dict[str, Dict[str, str]]:
    """Hash files under base with one or more algorithms.

    Returns {rel_path: {spec: hexdigest}}. Each file is hashed with every spec
    in a single read pass (multi mode); a single-spec list yields a one-key dict.
    """
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

    files: Dict[str, Dict[str, str]] = {}

    if jobs == 1:
        for path, rel_str in paths_to_hash:
            t0 = time.perf_counter()
            files[rel_str] = hash_file_multi(path, algos)
            if _verbose:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                _vprint(f"  hashing {rel_str} ... {elapsed_ms:.2f}ms")
    else:
        _lock = threading.Lock()

        def _hash_one(path: Path, rel_str: str) -> tuple:
            t0 = time.perf_counter()
            h = hash_file_multi(path, algos)
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
    algos: List[str],
    exclude: Optional[List[str]] = None,
    jobs: int = 1,
) -> Dict[str, Dict[str, str]]:
    """Hash individual day entries within RedNotebook YYYY-MM.txt month files.

    Each entry is identified by path ``YYYY-MM/DD`` (e.g. ``2026-05/14``).
    Day content is serialised to canonical JSON before hashing so that all
    fields (text, tags, custom categories) are captured. Returns
    {day_key: {spec: hexdigest}} — multi-hashed like collect_files.

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
            _warn(f"Could not parse {month_path.name}: {exc}")
            continue
        if not isinstance(content, dict):
            continue
        year_month = month_path.stem  # e.g. "2026-05"
        for day_num in sorted(content.keys()):
            if not isinstance(day_num, int):
                continue
            day_key = f"{year_month}/{day_num:02d}"
            entries.append((day_key, content[day_num]))

    files: Dict[str, Dict[str, str]] = {}

    def _hash_day(day_key: str, day_data) -> tuple:
        # Canonicalise: dicts → sorted JSON; plain strings kept as-is
        if isinstance(day_data, dict):
            canonical = json.dumps(day_data, ensure_ascii=False, sort_keys=True)
        else:
            canonical = str(day_data) if day_data is not None else ""
        t0 = time.perf_counter()
        digests = hash_bytes_multi(canonical.encode("utf-8"), algos)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return day_key, digests, elapsed_ms

    if jobs == 1:
        for day_key, day_data in entries:
            key, digests, elapsed_ms = _hash_day(day_key, day_data)
            files[key] = digests
            if _verbose:
                _vprint(f"  hashing {key} ... {elapsed_ms:.2f}ms")
    else:
        _lock = threading.Lock()

        def _hash_day_parallel(day_key: str, day_data) -> tuple:
            key, digests, elapsed_ms = _hash_day(day_key, day_data)
            if _verbose:
                with _lock:
                    _vprint(f"  hashing {key} ... {elapsed_ms:.2f}ms")
            return key, digests

        max_workers = jobs if jobs > 0 else None
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_hash_day_parallel, k, d): k for k, d in entries}
            for future in as_completed(futures):
                key, digests = future.result()
                files[key] = digests

    return dict(sorted(files.items()))


def _concat_merkle_root(files: Dict[str, Dict[str, str]], algos: List[str],
                        concat_algo: str) -> str:
    """Merkle root where each leaf is the per-file concatenation (alphabetical
    by algo) of all file-hash bytes, combined with concat_algo."""
    leaves = []
    for p in files:
        blob = b"".join(bytes.fromhex(files[p][a]) for a in sorted(algos))
        leaves.append(blob.hex())
    return merkle_root(leaves, concat_algo)


def generate_manifest(
    notebook: Path,
    month_only: bool,
    algos: List[str],
    merkle_algo: str,
    exclude: Optional[List[str]] = None,
    per_day: bool = False,
    jobs: int = 1,
    merkle_select: Optional[List[str]] = None,
    concat_algo: Optional[str] = None,
) -> Dict:
    algos = sorted(algos)          # alphabetical ordering throughout (man notes)
    multi = len(algos) > 1
    day_count: Optional[int] = None  # None = not a per-day mode
    if per_day and not month_only:
        # per-day/full-tree: individual day entries + all non-month files.
        # Pass the YYYY-MM.txt glob to collect_files so month files are
        # never hashed twice and don't appear in verbose output.
        _MONTH_GLOB = "[0-9][0-9][0-9][0-9]-[0-9][0-9].txt"
        day_files = collect_files_per_day(notebook, algos, exclude=exclude, jobs=jobs)
        other_files = collect_files(
            notebook, False, algos,
            exclude=list(exclude) + [_MONTH_GLOB],
            jobs=jobs,
        )
        files = dict(sorted({**day_files, **other_files}.items()))
        day_count = len(day_files)
        mode = "per-day/full-tree"
    elif per_day and month_only:
        # per-day/month-only: individual day entries, no attachments
        files = collect_files_per_day(notebook, algos, exclude=exclude, jobs=jobs)
        day_count = len(files)
        mode = "per-day/month-only"
    elif month_only:
        # month-only: whole YYYY-MM.txt files, no attachments
        files = collect_files(notebook, True, algos, exclude=exclude, jobs=jobs)
        mode = "month-only"
    else:
        # full-tree: every file as-is
        files = collect_files(notebook, False, algos, exclude=exclude, jobs=jobs)
        mode = "full-tree"

    # Collect creation-time warnings (recorded regardless of --quiet).
    warnings: List[str] = []
    weak_present = any(_parse_algo_spec(a)[0] in _WEAK_ALGOS for a in algos)
    if weak_present and not multi:        # weak hash used ALONE
        warnings.append(WARN_WEAK_HASH)
    if exclude:
        warnings.append(WARN_EXCLUDED)
    if not files:
        warnings.append(WARN_NO_FILES)
    if day_count == 0:
        warnings.append(WARN_NO_DAYS)

    manifest: Dict = {
        "tool": "rednb-verify",
        "version": VERSION,
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "created": utc_timestamp(),
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "mode": mode,
    }

    if multi:
        # files entry: {path, hashes: {algo: hex, ... alphabetical}}
        manifest["hash_algorithm"] = algos
        manifest["files"] = [
            {"path": p, "hashes": {a: files[p][a] for a in algos}}
            for p in files
        ]
        # Field order: concatenated tree before individual trees (man notes).
        if concat_algo:
            manifest["merkle_root_concat"] = {
                concat_algo: _concat_merkle_root(files, algos, concat_algo)
            }
        # Individual per-algo trees: selected subset, or all algos by default.
        tree_algos = sorted(merkle_select) if merkle_select else algos
        manifest["merkle_roots"] = {
            a: merkle_root([files[p][a] for p in files], a) for a in tree_algos
        }
    else:
        algo = algos[0]
        manifest["hash_algorithm"] = algo
        manifest["merkle_hash"] = merkle_algo
        manifest["files"] = [{"path": p, algo: files[p][algo]} for p in files]
        if concat_algo:
            manifest["merkle_root_concat"] = {
                concat_algo: _concat_merkle_root(files, algos, concat_algo)
            }
        manifest["merkle_root"] = merkle_root(
            [files[p][algo] for p in files], merkle_algo
        )

    if exclude:
        manifest["exclude"] = exclude
    if warnings:
        manifest["warnings"] = warnings
    return manifest


# ---------- Verification ----------

def verify_manifest(
    manifest: Dict,
    notebook: Path,
    extra_exclude: Optional[List[str]] = None,
    jobs: int = 1,
) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {"ok": [], "missing": [], "modified": [], "new": []}
    ha = manifest.get("hash_algorithm", "sha256")
    multi = isinstance(ha, list)
    algos = sorted(ha) if multi else [ha]

    # Normalise expected to {path: {algo: hash}} for both single and multi.
    if multi:
        expected = {f["path"]: dict(f["hashes"]) for f in manifest["files"]}
    else:
        expected = {f["path"]: {ha: f[ha]} for f in manifest["files"]}

    exclude = list(manifest.get("exclude", []))
    if extra_exclude:
        exclude.extend(extra_exclude)
    mode = manifest.get("mode", "full-tree")
    _MONTH_GLOB = "[0-9][0-9][0-9][0-9]-[0-9][0-9].txt"
    if mode == "per-day/full-tree":
        day_files = collect_files_per_day(notebook, algos, exclude=exclude, jobs=jobs)
        other_files = collect_files(
            notebook, False, algos,
            exclude=list(exclude) + [_MONTH_GLOB],
            jobs=jobs,
        )
        actual = dict(sorted({**day_files, **other_files}.items()))
    elif mode in ("per-day", "per-day/month-only"):
        # "per-day" kept for backward compatibility with v0.6.0 manifests
        actual = collect_files_per_day(notebook, algos, exclude=exclude, jobs=jobs)
    elif mode in ("month-files", "month-only"):
        # "month-files" kept for backward compatibility with pre-v0.6.0 manifests
        actual = collect_files(notebook, True, algos, exclude=exclude, jobs=jobs)
    else:
        actual = collect_files(notebook, False, algos, exclude=exclude, jobs=jobs)

    # actual is {path: {algo: hash}}. A file is ok only if EVERY hash matches.
    for path, exp in expected.items():
        if path not in actual:
            results["missing"].append(path)
        elif actual[path] != exp:
            results["modified"].append(path)
        else:
            results["ok"].append(path)
    for path in actual:
        if path not in expected:
            results["new"].append(path)
    return results


def _write_text_manifest(manifest: Dict) -> str:
    """Serialise a manifest dict to human-readable text format (single or multi)."""
    ha = manifest.get("hash_algorithm", "sha256")
    multi = isinstance(ha, list)
    algos = sorted(ha) if multi else [ha]
    lines = [
        "rednb-verify manifest",
        f"version: {manifest.get('version', VERSION)}",
        f"schema_version: {manifest.get('schema_version', MANIFEST_SCHEMA_VERSION)}",
        f"created: {manifest['created']}",
        f"date: {manifest['date']}",
        f"hash_algorithm: {', '.join(algos) if multi else ha}",
        f"mode: {manifest.get('mode', 'full-tree')}",
    ]
    if not multi:
        lines.insert(7, f"merkle_hash: {manifest.get('merkle_hash', ha)}")
    if manifest.get("exclude"):
        lines.append(f"exclude: {', '.join(manifest['exclude'])}")
    if manifest.get("warnings"):
        lines.append(f"warnings: {', '.join(manifest['warnings'])}")
    # Concatenated tree first (man notes), then individual trees / single root.
    if manifest.get("merkle_root_concat"):
        ca, croot = next(iter(manifest["merkle_root_concat"].items()))
        lines.append(f"merkle_root_concat: {ca} {croot}")
    if multi:
        lines.append("merkle_roots:")
        for a in sorted(manifest.get("merkle_roots", {})):
            lines.append(f"         {a}: {manifest['merkle_roots'][a]}")
    else:
        lines.append(f"merkle_root: {manifest.get('merkle_root', '')}")
    lines += ["", "files:"]
    for i, entry in enumerate(manifest["files"], 1):
        lines.append(f"  {i:>5}. {entry['path']}")
        if multi:
            for a in algos:
                lines.append(f"         {a}: {entry['hashes'][a]}")
        else:
            lines.append(f"         {ha}: {entry[ha]}")
    return "\n".join(lines) + "\n"


def _parse_text_manifest(text: str) -> Dict:
    """Parse a text-format manifest back to a dict (single or multi mode)."""
    import re as _re
    manifest: Dict = {}
    raw_files: List[Dict] = []      # [{"path":p, "_hashes":{algo:hash}}]
    merkle_roots: Dict[str, str] = {}
    section = "header"              # header → merkle_roots → files
    current: Optional[Dict] = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("rednb-verify manifest"):
            continue
        if stripped == "files:":
            section = "files"
            continue
        if stripped == "merkle_roots:":
            section = "merkle_roots"
            continue
        if section == "header":
            if ": " in stripped:
                key, _, val = stripped.partition(": ")
                manifest[key.strip()] = val.strip()
        elif section == "merkle_roots":
            if ": " in stripped:
                a, _, root = stripped.partition(": ")
                merkle_roots[a.strip()] = root.strip()
        else:  # files
            m = _re.match(r"\d+\.\s+(.+)", stripped)
            if m:
                current = {"path": m.group(1).strip(), "_hashes": {}}
                raw_files.append(current)
            elif ": " in stripped and current is not None:
                a, _, h = stripped.partition(": ")
                current["_hashes"][a.strip()] = h.strip()

    # hash_algorithm: comma-separated → multi (list); single string otherwise.
    ha = manifest.get("hash_algorithm", "sha256")
    if isinstance(ha, str) and "," in ha:
        algos = [a.strip() for a in ha.split(",") if a.strip()]
        manifest["hash_algorithm"] = sorted(algos)
        multi = True
    else:
        multi = False

    # merkle_root_concat stored as "algo root" → {algo: root}
    if isinstance(manifest.get("merkle_root_concat"), str):
        parts = manifest["merkle_root_concat"].split(None, 1)
        if len(parts) == 2:
            manifest["merkle_root_concat"] = {parts[0]: parts[1]}
        else:
            del manifest["merkle_root_concat"]

    files_out: List[Dict] = []
    for rf in raw_files:
        if multi:
            files_out.append({"path": rf["path"], "hashes": rf["_hashes"]})
        else:
            files_out.append({"path": rf["path"], **rf["_hashes"]})
    manifest["files"] = files_out
    if multi:
        manifest["merkle_roots"] = merkle_roots

    # exclude / warnings stored as comma-separated strings — convert to lists
    for _list_key in ("exclude", "warnings"):
        if _list_key in manifest and isinstance(manifest[_list_key], str):
            manifest[_list_key] = [e.strip() for e in manifest[_list_key].split(",") if e.strip()]
    # schema_version is numeric
    if "schema_version" in manifest:
        try:
            manifest["schema_version"] = int(manifest["schema_version"])
        except (TypeError, ValueError):
            pass
    return manifest


def _load_manifest(path: Path) -> Dict:
    """Load a manifest file; auto-detects JSON or text format by extension."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return _parse_text_manifest(text)


def check_manifest_schema(manifest: Dict, schema_ignore: bool, yes: bool) -> None:
    """Three-direction schema_version check at verify time.

    equal  → proceed
    lower  → security warning + best-effort + interactive prompt (quiet auto-continues)
    higher → refuse + exit 2, unless --schema-ignore
    """
    found = manifest.get("schema_version", 0)
    try:
        found = int(found)
    except (TypeError, ValueError):
        found = 0

    if found == MANIFEST_SCHEMA_VERSION:
        return

    if found > MANIFEST_SCHEMA_VERSION:
        if not schema_ignore:
            _err(f"Manifest schema version {found} is newer than this tool "
                 f"supports (max: {MANIFEST_SCHEMA_VERSION}).")
            _err("        Upgrade rednb-verify, or re-run with --schema-ignore "
                 "to attempt anyway.")
            sys.exit(2)
        _warn_security(f"--schema-ignore: verifying schema {found} with a tool that "
                       f"supports {MANIFEST_SCHEMA_VERSION} — results may be unreliable.")
        return

    # found < current (old manifest, includes absent = 0)
    _warn_security(f"Old manifest format (schema {found}); trust cannot be "
                   "fully evaluated. Hash and signature checks still apply.")
    if not _quiet and not yes and sys.stdin.isatty():
        if input("Continue verifying this old manifest? [y/N]: ").strip().lower() != "y":
            _info("Verification cancelled.")
            sys.exit(0)


def write_report(results: Dict[str, List[str]], report_path: Path, manifest_path: Path) -> None:
    """Write JSON if path ends in .json, otherwise human-readable text with numbered lists."""
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
            numbered = [f"  {i:>5}. {f}" for i, f in enumerate(sorted(results[key]), 1)]
            lines += ["", f"--- {label} ---"] + numbered
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
    _warn("Invalid selection — skipping signing.")
    return 4


def _sign_with_gpg(
    manifest_path: Path,
    key_fpr: Optional[str],
    key_file: Optional[Path],
) -> None:
    """Sign with GPG. key_file uses armored export; key_fpr pre-selects keyring key."""
    if not gpg_available():
        _warn("GPG not available — GPG signing skipped.")
        return

    # --- Key file path (temp homedir, no keyring pollution) ---
    if key_file:
        if not _quiet:
            print(NON_REPUDIATION_WARNING)
            if input("Sign with GPG key file? [y/N]: ").strip().lower() != "y":
                _info("GPG signing cancelled.")
                return
        if _gpg_sign_with_keyfile(manifest_path, key_file):
            _ok("Manifest signed with GPG.")
        else:
            _warn("GPG signing failed.")
        return

    # --- Keyring path ---
    try:
        keys = list_secret_keys()
    except subprocess.CalledProcessError:
        _warn("Could not list GPG keys.")
        return
    if not keys:
        _warn("No GPG secret keys found — GPG signing skipped.")
        return

    if key_fpr:
        fpr = key_fpr
        if not _quiet:
            print(NON_REPUDIATION_WARNING)
            if input("Sign this manifest with GPG? [y/N]: ").strip().lower() != "y":
                _info("GPG signing cancelled.")
                return
    elif _quiet:
        if len(keys) == 1:
            fpr = keys[0]["fingerprint"]
        else:
            _err("--quiet with --gpg requires a fingerprint when multiple keys exist.")
            _err(f"        Use: --gpg {keys[0]['fingerprint']}")
            sys.exit(2)
    else:
        print(NON_REPUDIATION_WARNING)
        if input("Sign this manifest with GPG? [y/N]: ").strip().lower() != "y":
            _info("GPG signing cancelled.")
            return
        fpr = choose_gpg_key(keys)
        if fpr is None:
            _info("GPG signing cancelled.")
            return

    if gpg_detach_sign(manifest_path, fpr):
        _ok("Manifest signed with GPG.")
    else:
        _warn("GPG signing failed.")


def _sign_with_ssh(
    manifest_path: Path,
    sig_path: Path,
    ssh_key_path: Path,
    prefer_fido: bool,
    keyname: Optional[str],
) -> None:
    """Sign manifest with SSH."""
    if not ssh_keygen_available():
        _warn("ssh-keygen not available — SSH signing skipped.")
        return
    signer = select_ssh_key(ssh_key_path, require_private=True, prefer_fido=prefer_fido, keyname=keyname)
    if signer is None or signer.priv_path is None:
        _warn("No suitable SSH key found for signing.")
        return
    if not _quiet:
        print(SSH_NON_REPUDIATION_WARNING)
        if input("Sign this manifest with SSH? [y/N]: ").strip().lower() != "y":
            _info("SSH signing cancelled.")
            return
    if ssh_sign_manifest(manifest_path, signer.priv_path, sig_path):
        _ok(f"SSH signature created: {sig_path.name}")
    else:
        _warn("SSH signing failed.")


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

  # Sign with SSH (scans ~/.ssh)
  rednb-verify.py ~/journal --ssh

  # Sign with SSH using a specific key file
  rednb-verify.py ~/journal --ssh ~/.ssh/id_ed25519.pub

  # Sign with both GPG and SSH
  rednb-verify.py ~/journal --gpg --ssh

  # Re-sign an existing manifest
  rednb-verify.py --resign hashes-....json --gpg
  rednb-verify.py --resign hashes-....json --ssh
  rednb-verify.py --resign hashes-....json --gpg --ssh

  # Show available hash algorithms
  rednb-verify.py . --hash-list

  # Exclude editor lock files
  rednb-verify.py ~/journal --exclude "*.tmp" --exclude ".~lock.*"

  # Non-interactive / cron use
  rednb-verify.py ~/journal --quiet --gpg ABCDEF1234567890

  # Verify — auto-find latest manifest in the output directory
  rednb-verify.py ~/journal --verify

  # Verify a specific manifest
  rednb-verify.py ~/journal --verify hashes-....txt

  # Verify with JSON report and age warning
  rednb-verify.py ~/journal --verify hashes-....txt --report json --warn-age 90

  # Verify GPG + SSH signatures in one run
  rednb-verify.py ~/journal --verify hashes-....txt \\
    --sig hashes-....txt.asc,hashes-....txt.sshsig

exit codes:
  0  all checks passed / manifest created successfully
  1  verification found issues (modified, missing, or unexpected files)
  2  usage or input error (bad arguments, missing files, unsupported algorithm)

supported hash algorithms:
  sha256 (default), sha512, sha3_256, sha3_512, blake2b, blake2s ...
  use --hash-list to see all available algorithms
"""
    )
    parser.add_argument("-V", "--version", action="version",
                        version=f"rednb-verify {VERSION}")
    parser.add_argument("notebook_dir", type=Path, nargs="?",
                        help="Path to the RedNotebook journal directory")
    parser.add_argument("-m", "--month-only", action="store_true",
                        help="Hash only YYYY-MM.txt files")
    parser.add_argument("-o", "--output", type=Path,
                        help="Output directory (default: parent of journal directory)")
    parser.add_argument("--verify", nargs="?", const="__auto__", default=None,
                        metavar="MANIFEST_OR_DIR",
                        help="Verify mode: path to a manifest file, or directory to search "
                             "for the latest manifest. Without argument, searches the output "
                             "directory (journal parent by default).")
    parser.add_argument("--manifest-type", nargs="?", const="txt", default="txt",
                        metavar="txt|json", dest="manifest_type",
                        help="Manifest creation format: txt (default) or json")
    parser.add_argument("--report", nargs="?", const="txt", default="txt",
                        metavar="txt|json",
                        help="Verification report format: txt (default) or json")
    parser.add_argument("--hash", default=HASH_ALGO, dest="hash_algo", metavar="ALGO[,ALGO...]",
                        help="Hash algorithm(s) for files (default: sha256). Comma-separate "
                             "for multi-hashing, e.g. sha256,blake2b")
    parser.add_argument("--hash-list", action="store_true",
                        help="Print available hash algorithms and exit")
    parser.add_argument("--hash-merkle", default=None, dest="merkle_algo",
                        metavar="ALGO[,ALGO...]",
                        help="Merkle tree algorithm(s). Single mode: tree combiner "
                             "(default: same as --hash). Multi mode: selects which "
                             "per-algo trees to build (subset of --hash; default: all).")
    parser.add_argument("--hash-merkle-concatenate", nargs="?", const="sha256",
                        default=None, dest="merkle_concat", metavar="ALGO",
                        help="Build one Merkle tree whose leaves are the per-file "
                             "concatenation of all file hashes (default combiner: sha256).")
    parser.add_argument("--gpg", nargs="?", const="", default=None, metavar="FINGERPRINT",
                        help="Sign with GPG; optionally specify key fingerprint (skips menu)")
    parser.add_argument("--gpg-k", type=Path, default=None, metavar="FILE",
                        help="GPG armored key file to sign with; implies --gpg")
    parser.add_argument("--ssh", nargs="?", const="", default=None, metavar="FILE_OR_DIR",
                        help="Sign with SSH key; optionally specify a .pub file or directory "
                             "to scan (default: ~/.ssh)")
    parser.add_argument("--ssh-verify", action="store_true",
                        help="Force SSH signature check during --verify")
    parser.add_argument("--sig", type=str, default=None, metavar="FILE[,FILE]",
                        help="Signature file(s), comma-separated (.asc=GPG, .sshsig/.sig=SSH)")
    parser.add_argument("--ssh-fido", nargs="?", const="", metavar="KEYNAME",
                        help="Prefer FIDO2 hardware keys; optional name filter")
    parser.add_argument("--no-sign", action="store_true",
                        help="Skip all signing")
    parser.add_argument("--resign", type=Path, default=None, metavar="MANIFEST",
                        help="Re-sign an existing manifest (requires --gpg and/or --ssh)")
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
    # --- Config management (Feature 1) ---
    parser.add_argument("--set-cf", action="append", default=None, metavar="FIELD:VALUE",
                        dest="set_cf",
                        help="Set a config field and exit (trust-gpg, trust-ssh, "
                             "trust-level, dir). Repeatable. Replaces the field.")
    parser.add_argument("--set-cf-run", action="append", default=None, metavar="FIELD:VALUE",
                        dest="set_cf_run",
                        help="Like --set-cf but continue running after writing config.")
    parser.add_argument("--add-trust", action="append", default=None, metavar="FIELD:VALUE",
                        dest="add_trust",
                        help="Append fingerprints to a trust list (trust-gpg / trust-ssh), "
                             "de-duplicated. Repeatable.")
    parser.add_argument("--config-out", action="store_true", dest="config_out",
                        help="Print the resulting config as JSON (after --set-cf/--add-trust).")
    parser.add_argument("--trust", choices=("high", "low"), default=None,
                        help="Signing trust level: high (only pinned keys) or low (default).")
    parser.add_argument("--schema-ignore", action="store_true", dest="schema_ignore",
                        help="Verify a manifest with a newer schema version anyway (risky).")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Assume yes to confirmation prompts (automation-friendly).")

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
    if config.get("ssh_key"):
        cfg["ssh"] = os.path.expanduser(config["ssh_key"])
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
        _err("--quiet and --verbose are mutually exclusive.")
        sys.exit(2)

    # ---- Config management (Feature 1): mutate config, optionally write & exit ----
    _set_tokens = (args.set_cf or []) + (args.set_cf_run or [])
    _add_tokens = args.add_trust or []
    _mutates_config = bool(_set_tokens or _add_tokens)
    if _mutates_config:
        if _no_config:
            _err("Cannot modify config while --no-config/--no-cf is set.")
            sys.exit(2)
        apply_set_cf(config, _set_tokens)
        apply_add_trust(config, _add_tokens)
        save_config(config, _config_path)
        _ok(f"Config updated: {_config_path}")
    if args.config_out:
        # In-memory config after any mutation (G3: disk state if no mutation).
        print(json.dumps(config, indent=4, ensure_ascii=False))
    # --set-cf / --add-trust are write-only: exit unless --set-cf-run was used.
    if (_mutates_config or args.config_out) and not args.set_cf_run:
        sys.exit(0)

    # Notify user that a config file is in effect
    if _config_active:
        _info(f"Using config: {_config_path}")

    # Validate format flags
    if args.report not in ("txt", "json"):
        _err(f"--report must be 'txt' or 'json', got: {args.report!r}")
        sys.exit(2)
    if args.manifest_type not in ("txt", "json"):
        _err(f"--manifest-type must be 'txt' or 'json', got: {args.manifest_type!r}")
        sys.exit(2)

    # --hash-list: print available algorithms and exit (no notebook_dir needed)
    if args.hash_list:
        print("Available hash algorithms:")
        for algo in sorted(AVAILABLE_HASHES):
            if algo in _VARIABLE_LENGTH_ALGOS:
                print(f"  {algo}:<length>   (e.g. --hash {algo}:32)")
            else:
                print(f"  {algo}")
        # Mention optional algos that aren't installed
        missing = [a for a in _OPTIONAL_PIP if a not in AVAILABLE_HASHES]
        if missing:
            print("\nOptional (not installed):")
            for a in missing:
                print(f"  {a}   (pip install {_OPTIONAL_PIP[a]})")
        print("\nCombine with commas for multi-hashing, e.g. --hash sha256,blake2b")
        sys.exit(0)

    # notebook_dir: fall back to saved config "dir" when none given (Feature 1)
    if args.notebook_dir is None and not args.resign:
        saved_dir = config.get("dir")
        if saved_dir:
            args.notebook_dir = Path(os.path.expanduser(saved_dir))
            _info(f"Using saved directory: {args.notebook_dir}")
        else:
            parser.error("notebook_dir is required")

    # --gpg-k implies --gpg
    if args.gpg_k is not None and args.gpg is None:
        args.gpg = ""

    # --quiet implies --no-sign unless an explicit signing method was given
    if args.quiet and args.gpg is None and args.ssh is None:
        args.no_sign = True

    # Resolve SSH key location from --ssh argument (None → default ~/.ssh)
    ssh_key_path = (
        Path(os.path.expanduser(args.ssh))
        if args.ssh        # non-empty string = user supplied a path
        else Path(os.path.expanduser("~/.ssh"))
    )

    # --hash may carry multiple comma-separated algos (multi-hashing).
    hash_algos = [a.strip() for a in args.hash_algo.split(",") if a.strip()]
    if not hash_algos:
        _err("--hash requires at least one algorithm.")
        sys.exit(2)
    for spec in hash_algos:
        _validate_algo_spec_or_exit(spec, "--hash")
    args.hash_algos = hash_algos

    # Multi mode must include at least one strong hash (md5/sha1 not trusted alone).
    multi = len(hash_algos) > 1
    strong = [a for a in hash_algos if _parse_algo_spec(a)[0] not in _WEAK_ALGOS]
    if multi and not strong:
        _err("Multi-hashing needs at least one strong algorithm "
             "alongside md5/sha1 (e.g. --hash sha256,md5).")
        sys.exit(2)

    # --hash-merkle: single mode = tree combiner; multi mode = tree selection.
    args.merkle_select = None
    if multi:
        if args.merkle_algo:
            sel = [a.strip() for a in args.merkle_algo.split(",") if a.strip()]
            bad = [a for a in sel if a not in hash_algos]
            if bad:
                _err(f"--hash-merkle {', '.join(bad)} not in --hash set "
                     f"({', '.join(hash_algos)}). In multi mode --hash-merkle "
                     "selects which file-hash trees to build.")
                sys.exit(2)
            args.merkle_select = sel
        args.merkle_algo = hash_algos[0]   # unused in multi; kept non-None
    else:
        args.merkle_algo = args.merkle_algo or hash_algos[0]
        _validate_algo_spec_or_exit(args.merkle_algo, "--hash-merkle")

    # --hash-merkle-concatenate: validate combiner algo if requested.
    if args.merkle_concat:
        _validate_algo_spec_or_exit(args.merkle_concat, "--hash-merkle-concatenate")

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
            _err(f"--exclude-from file not found: {excf}")
            sys.exit(2)
        for raw_line in excf.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                exclude.append(line)
        _vprint(f"{_tag('INFO')} Loaded exclusion patterns from {excf.name}")

    # --jobs validation
    if args.jobs < 0:
        _err("--jobs must be 0 (auto) or a positive integer.")
        sys.exit(2)
    jobs: int = args.jobs

    # Resolve output directory
    if args.resign:
        out_dir = (args.output or args.resign.resolve().parent).resolve()
    else:
        out_dir = (args.output or args.notebook_dir.resolve().parent).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    want_gpg = args.gpg is not None
    want_ssh = args.ssh is not None

    # ------------------------------------------------------------------ #
    #  Resign mode                                                         #
    # ------------------------------------------------------------------ #
    if args.resign:
        manifest_path = args.resign.resolve()
        if not manifest_path.exists():
            _err(f"Manifest not found: {manifest_path}")
            sys.exit(2)
        try:
            _load_manifest(manifest_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            _err(f"Could not read manifest: {exc}")
            sys.exit(2)
        if not want_gpg and not want_ssh:
            _err("--resign requires a signing method: --gpg and/or --ssh")
            sys.exit(2)
        ssh_sig_out = next(
            (p for p in sig_paths if p.suffix in (".sshsig", ".sig")),
            manifest_path.with_suffix(manifest_path.suffix + ".sshsig"),
        )
        _ok(f"Re-signing: {manifest_path.name}")
        if want_gpg:
            _sign_with_gpg(manifest_path, key_fpr=args.gpg or None, key_file=args.gpg_k)
        if want_ssh:
            _sign_with_ssh(manifest_path, ssh_sig_out, ssh_key_path, prefer_fido, keyname)
        return

    # ------------------------------------------------------------------ #
    #  Verify mode                                                         #
    # ------------------------------------------------------------------ #
    if args.verify is not None:
        # Resolve manifest path from --verify argument or auto-search
        verify_arg = args.verify
        if verify_arg == "__auto__":
            verify_arg = str(out_dir)

        target = Path(verify_arg)
        if target.is_dir():
            candidates = sorted(
                list(target.glob("hashes-*.json")) + list(target.glob("hashes-*.txt"))
            )
            if not candidates:
                _err(f"No manifest found in {target}")
                sys.exit(2)
            manifest_path = candidates[-1]
            _info(f"Using latest manifest: {manifest_path.name}")
        else:
            manifest_path = target.resolve()
            if not manifest_path.exists():
                _err(f"Manifest not found: {manifest_path}")
                sys.exit(2)

        try:
            manifest = _load_manifest(manifest_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            _err(f"Could not read manifest: {exc}")
            sys.exit(2)

        # Schema version gate (three-direction check)
        check_manifest_schema(manifest, args.schema_ignore, args.yes)

        # Surface creation-time warnings recorded in the manifest (cosmetic, G6)
        for w in manifest.get("warnings", []):
            _warn(f"Manifest note: {w}")

        # Manifest age warning
        if args.warn_age is not None:
            try:
                created = datetime.strptime(
                    manifest["created"], "%Y%m%dT%H%M%SZ"
                ).replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - created).days
                if age_days > args.warn_age:
                    _warn(
                        f"Manifest is {age_days} days old — consider refreshing "
                        f"(threshold: {args.warn_age} days)."
                    )
            except (KeyError, ValueError):
                pass

        results = verify_manifest(manifest, args.notebook_dir, extra_exclude=exclude, jobs=jobs)

        report_path = out_dir / f"report-{utc_timestamp()}.{args.report}"
        write_report(results, report_path, manifest_path)
        _ok(f"Verification report: {report_path}")

        # Resolve signature files
        _SSH_EXTS = (".sshsig", ".sig")
        if sig_paths:
            gpg_sigs = [p for p in sig_paths if p.suffix == ".asc"]
            ssh_sigs = [p for p in sig_paths if p.suffix in _SSH_EXTS]
            for p in sig_paths:
                if p.suffix not in (".asc",) + _SSH_EXTS:
                    _warn(f"Unknown signature type '{p.name}' — skipped (expected .asc or .sshsig).")
        else:
            auto_asc = manifest_path.with_suffix(manifest_path.suffix + ".asc")
            gpg_sigs = [auto_asc] if auto_asc.exists() else []
            auto_ssh = manifest_path.with_suffix(manifest_path.suffix + ".sshsig")
            auto_sig = manifest_path.with_suffix(manifest_path.suffix + ".sig")
            ssh_sigs = [p for p in (auto_ssh, auto_sig) if p.exists()]
            if args.ssh_verify and not ssh_sigs:
                ssh_sigs = [auto_ssh]  # will report missing below

        # GPG verification
        if not gpg_sigs:
            _warn("Manifest not GPG-signed.")
        else:
            for gpg_sig in gpg_sigs:
                if not gpg_sig.exists():
                    _warn(f"GPG signature not found: {gpg_sig.name}")
                elif not gpg_available():
                    _warn("GPG not available — GPG verification skipped.")
                else:
                    if gpg_verify(manifest_path, gpg_sig):
                        _ok(f"GPG signature verified: {gpg_sig.name}")
                    else:
                        _warn(f"GPG signature invalid: {gpg_sig.name}")

        # SSH verification
        for ssh_sig in ssh_sigs:
            if not ssh_keygen_available():
                _warn("ssh-keygen not available — SSH verification skipped.")
                break
            if not ssh_sig.exists():
                _warn(f"SSH signature not found: {ssh_sig.name}")
                continue
            signer = select_ssh_key(ssh_key_path, require_private=False,
                                    prefer_fido=prefer_fido, keyname=keyname)
            if signer is None:
                _warn("No suitable SSH key found for verification.")
                continue
            canonical_ssh = manifest_path.with_suffix(manifest_path.suffix + ".sshsig")
            result = ssh_verify_manifest(
                manifest_path, ssh_sig, signer.pub_path,
                multiple_signatures=len(ssh_sigs) > 1,
                nonstandard_sig=ssh_sig != canonical_ssh,
            )
            if result.status == "OK":
                _ok(result.message)
            else:
                _qprint(f"{_tag(result.status)} {result.message}")
            for w in result.warnings:
                _warn(w)

        if any(k != "ok" and results[k] for k in results):
            _warn("Verification completed with issues.")
            sys.exit(1)

        _ok("Verification successful.")
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

    # Weak-hash-alone policy (single weak algo) — prompt unless -y/quiet (D2).
    weak_specs = [a for a in args.hash_algos if _parse_algo_spec(a)[0] in _WEAK_ALGOS]
    if weak_specs and not multi:
        if not _quiet:
            _warn(f"Weak hash in use alone: {', '.join(weak_specs)} — "
                  "not collision-resistant.")
            if not args.yes:
                if not sys.stdin.isatty():
                    _err("Refusing to use a weak hash alone without confirmation "
                         "(re-run with -y, or choose a strong hash).")
                    sys.exit(2)
                if input("Proceed with a weak hash? [y/N]: ").strip().lower() != "y":
                    _info("Aborted.")
                    sys.exit(2)

    manifest = generate_manifest(
        args.notebook_dir, args.month_only, args.hash_algos, args.merkle_algo,
        exclude=exclude,
        per_day=args.per_day,
        jobs=jobs,
        merkle_select=args.merkle_select,
        concat_algo=args.merkle_concat,
    )
    manifest_fmt = args.manifest_type  # "txt" or "json"
    ext = ".json" if manifest_fmt == "json" else ".txt"
    manifest_name = f"hashes-{manifest['created']}{ext}"
    manifest_path = out_dir / manifest_name
    if manifest_fmt == "json":
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    else:
        manifest_path.write_text(_write_text_manifest(manifest), encoding="utf-8")
    _ok(f"Manifest created: {manifest_path}")

    # SSH sig output path: from --sig if a .sshsig path given, else default
    ssh_sig_out = next(
        (p for p in sig_paths if p.suffix in (".sshsig", ".sig")),
        manifest_path.with_suffix(manifest_path.suffix + ".sshsig"),
    )

    # ---- Signing ----
    if args.no_sign:
        _info("Signing skipped (--no-sign).")

    elif want_gpg and want_ssh:
        _sign_with_gpg(manifest_path, key_fpr=args.gpg or None, key_file=args.gpg_k)
        _sign_with_ssh(manifest_path, ssh_sig_out, ssh_key_path, prefer_fido, keyname)

    elif want_gpg:
        _sign_with_gpg(manifest_path, key_fpr=args.gpg or None, key_file=args.gpg_k)

    elif want_ssh:
        _sign_with_ssh(manifest_path, ssh_sig_out, ssh_key_path, prefer_fido, keyname)

    else:
        sign_choice = _prompt_signing_menu()
        if sign_choice in (1, 3):
            _sign_with_gpg(manifest_path, key_fpr=None, key_file=None)
        if sign_choice in (2, 3):
            _sign_with_ssh(manifest_path, ssh_sig_out, ssh_key_path, prefer_fido, keyname)


if __name__ == "__main__":
    main()
