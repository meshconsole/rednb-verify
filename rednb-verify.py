#!/usr/bin/env python3
"""
rednb-verify
Version: 0.12.0

RedNotebook integrity verification tool.
Creates and verifies cryptographic manifests for notebook directories.

CLI/Commands:
rednb-verify.py [options] [notebook_directory]

Manifest creation:
"-m", "--month-only"          : Hashes only month files
"-D", "--per-day"             : Hash individual day entries within month files (requires PyYAML)
"-j", "--jobs N"              : Parallel hashing workers (0 = auto, default: 1)
"-o", "--output"             : Output dir for manifest (create) or report (verify; requires --report)
"--manifest-type txt|json"    : Manifest creation format (default: txt)
"--no-bullets"                : Text manifest: don't prefix per-file hash lines with '- '
"--hash ALGO[:LEN][,ALGO...]" : Hash algorithm(s); comma-separate for multi-hashing
"--hash-list"                 : Print available hash algorithms and exit
"--hash-merkle ALGO[,...]"    : Merkle algo (single: combiner; multi: select trees)
"--hash-merkle-concatenate [ALGO]" : One tree over per-file concatenated hashes
"--exclude PATTERN"           : Exclude files matching glob (repeatable)
"--exclude-from FILE"         : File of glob patterns to exclude (one literal pattern per line)
"--symlink-targets MODE"      : Record symlink targets: none|full|hash[:ALGO[:LEN]] (default: hash = sha256 of target)
"--no-symlink-table"          : Omit the symlink table (alias for --symlink-targets none)
"--privacy"                   : Minimise manifest disclosure (currently implies --no-symlink-table)
"--lock"                      : After writing, chmod the manifest (and any .asc/.sshsig/.sig/.tsr) read-only (best-effort, not true WORM)

Manifest chaining (each manifest links the previous one by hash — makes the SEQUENCE tamper-evident):
"--prev-manifest FILE|DIR"    : Link to a previous manifest (a directory auto-selects its latest, like --verify)
"--prev-hash ALGO[:LEN][,...]" : Hash algorithm(s) for the link (default: sha256; comma-separate for multiple)

Signing:
"--gpg [FINGERPRINT]"         : Sign with GPG; optional fingerprint pre-selects key
"--gpg-k FILE"                : GPG armored key file; implies --gpg
"--ssh [FILE_OR_DIR]"         : Sign with SSH key; optional .pub file or directory
"--ssh-fido [NAME]"           : Prefer FIDO2/hardware-backed SSH keys; optional name filter
"--trust high|low"            : Signing trust level (default: low)
"--no-sign"                   : Skip all signing
"--resign MANIFEST"           : Re-sign an existing manifest (requires --gpg and/or --ssh)

Timestamping (RFC 3161 — strictly opt-in; --tsa is the tool's ONLY network operation):
"--tsa NAME|URL"              : Request a trusted timestamp at create (detached hashes-....tsr by default)
"--tsa-embed"                 : With --tsa: embed ONE stamp over the placement root as tsa_stamp (1 request)
"--tsa-embed-separate"        : With --tsa: embed placement + content stamps separately (2 requests)
"--tsa-cert CAFILE"           : TSA CA certificate to verify tokens during --verify (local check)
"--ignore-tsa"                : During --verify, skip all timestamp-token checks
"--tsa-list"                  : Print the built-in TSA registry and exit (no network)
"--offline"                   : Assert no network: refuses --tsa (offline is already the default)

Verification:
"--verify [FILE|DIR]"         : Verify mode; optional manifest path/dir (auto-finds latest if omitted)
"--report txt|json"           : Write a verify report file (txt|json). Omit = verdict only, no file. -o sets its location and requires this flag
"--ssh-verify"                : Force SSH signature check during --verify
"--ignore-sig"                : Verify integrity only; skip all signature checks
"--ignore-symlinks"           : During --verify, skip the symlink-table comparison and symlink warnings
"--ignore-chain"              : During --verify, skip manifest chain verification (--prev-manifest)
"--files-only"                : During --verify, skip checks that aren't about the files themselves; shorthand for --ignore-sig --ignore-tsa --ignore-chain (symlinks still checked)
"--sig FILE[,FILE]"           : Signature file(s) comma-separated (.asc=GPG, .sshsig/.sig=SSH)
"--warn-age DAYS"             : Warn during verify if manifest is older than N days
"--schema-ignore"             : Verify a newer-schema manifest anyway (risky)

Validation:
"--validate [FILE|DIR]"       : Validate a manifest/report against the embedded JSON schema and exit (needs optional jsonschema)
"--dump-schema manifest|report" : Print the embedded JSON schema to stdout and exit

General:
"-V", "--version"            : Print version and exit
"-v", "--verbose"            : Print per-file hash timing and detailed progress
"--quiet"                     : Suppress non-error output; implies --no-sign unless signing is explicit
"-y", "--yes"                : Assume yes to confirmation prompts
"--json"                      : Emit result as one JSON document on stdout (logs to stderr) for piping
"--install-opt"               : Let the tool 'pip install' optional packages a command needs (the only path that runs pip)

Config management:
"--set-cf FIELD:VALUE"        : Set a config field and exit (trust-gpg, trust-ssh, trust-level, dir)
"--set-cf-run FIELD:VALUE"    : Like --set-cf but continue running
"--add-trust FIELD:VALUE"     : Append fingerprints to a trust list (de-duplicated)
"--config-out"                : Print the resulting config as JSON
"--no-config / --no-cf"       : Ignore ~/.config/rednb-verify/config.json for this run
"--config FILE"               : Load a specific config file instead of the default

Exit codes:
  0  all checks passed / manifest created successfully
  1  verification found issues (modified/missing/new files, invalid or untrusted signature)
  2  usage or input error (bad arguments, missing files, unsupported algorithm)
  3  signing refused (untrusted key under --trust high)
"""

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import re
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

VERSION = "0.12.0"
HASH_ALGO = "sha256"
CONFIG_PATH = Path(os.path.expanduser("~/.config/rednb-verify/config.json"))

# Default parallel hashing workers: leave a couple of cores free for the OS
# and whatever else the user is doing, rather than defaulting to fully
# sequential. Floored at 1 so a 1-2 core machine (a budget laptop, a
# container, a VPS) never computes 0 or negative workers. cpu_count() can
# return None in some sandboxed environments, hence the "or 1".
DEFAULT_JOBS = max(1, (os.cpu_count() or 1) - 2)

# Manifest structural contract. Separate from VERSION (build identifier).
# Bump only on a BREAKING structural change (renamed/removed/retyped field),
# never for an optional addition. Manifests without this field = version 0.
MANIFEST_SCHEMA_VERSION = 3

# Set by main() before any output
_quiet: bool = False
_verbose: bool = False
# In --json mode, stdout is reserved for the machine-readable JSON document, so
# all human/log output is routed to stderr to keep stdout pipe-clean.
_json_mode: bool = False


def _log_stream():
    return sys.stderr if _json_mode else sys.stdout


def _qprint(msg: str) -> None:
    """Print only when not in quiet mode."""
    if not _quiet:
        print(msg, file=_log_stream())


def _vprint(msg: str) -> None:
    """Print only in verbose mode (quiet still suppresses it)."""
    if _verbose and not _quiet:
        print(msg, file=_log_stream())


def _require_yaml():
    """Import and return the yaml module, or exit with a clear install message."""
    try:
        import yaml  # type: ignore
        return yaml
    except ImportError:
        _err("--per-day needs PyYAML, which is not installed.")
        _err("        Install it with:  pip install pyyaml")
        sys.exit(2)


# ---------- Colour helpers ----------
# Applied only when stdout/stderr is a real TTY (no colour when piped/redirected).

_ANSI_RESET = "\033[0m"
_ANSI: Dict[str, str] = {
    "INFO":  "\033[33m",   # yellow
    "OK":    "\033[97m",   # bright white
    "PASS":  "\033[92m",   # bright green
    "WARN":  "\033[91m",   # light red
    "FAIL":  "\033[91m",   # light red
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
    _qprint(f"{_tag('INFO', stream=_log_stream())} {msg}")


def _ok(msg: str) -> None:
    _qprint(f"{_tag('OK', stream=_log_stream())} {msg}")


def _pass(msg: str) -> None:
    _qprint(f"{_tag('PASS', stream=_log_stream())} {msg}")


def _warn(msg: str) -> None:
    """Cosmetic-tier warning: suppressed by --quiet."""
    if not _quiet:
        print(f"{_tag('WARN', stream=_log_stream())} {msg}", file=_log_stream())


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


def _now_stamp() -> str:
    """Human-readable UTC stamp for per-file verbose log lines."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- Hashing progress bar (normal mode only) ----------
# A hand-rolled \r-overwrite bar (no tqdm/rich dependency) shown ONLY in
# normal mode: --verbose already gives full per-file lines and shouldn't also
# fight the bar for the same terminal line; --quiet stays fully silent;
# --json keeps stdout pipe-clean; a non-TTY (piped/redirected) run gets no
# escape codes, mirroring _tag()'s own TTY check.

_SPINNER_FRAMES_BRAILLE = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_SPINNER_FRAMES_ASCII = ["|", "/", "-", "\\"]
_spinner_frames_cache: Optional[List[str]] = None


def _spinner_frames() -> List[str]:
    """Braille spinner when the terminal's encoding can render it, else a
    plain ASCII fallback. Windows consoles commonly default to cp1252, which
    cannot encode these characters at all — printing them unconditionally
    would crash the tool with a UnicodeEncodeError the first time the
    progress bar ticks, not just render oddly. Checked once and cached."""
    global _spinner_frames_cache
    if _spinner_frames_cache is None:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        try:
            "".join(_SPINNER_FRAMES_BRAILLE).encode(encoding)
            _spinner_frames_cache = _SPINNER_FRAMES_BRAILLE
        except (UnicodeEncodeError, LookupError):
            _spinner_frames_cache = _SPINNER_FRAMES_ASCII
    return _spinner_frames_cache


def _progress_active() -> bool:
    return not _quiet and not _verbose and not _json_mode and sys.stdout.isatty()


def _format_elapsed(seconds: float) -> str:
    """Milliseconds while under 1s (finer-grained, matches short hash times),
    seconds with one decimal once elapsed reaches a full second."""
    ms = seconds * 1000
    if ms < 1000:
        return f"{ms:.0f}ms"
    return f"{seconds:.1f}s"


def _progress_tick(done: int, total: int, phase_start: float) -> None:
    """Redraw the hashing progress line in place. `done` also drives the
    spinner frame, so it advances once per completed file rather than on a
    separate wall-clock timer — simple, thread-safe, and proportional to
    real progress (a single very large file just holds its frame until done)."""
    if not _progress_active():
        return
    frames = _spinner_frames()
    spinner = frames[done % len(frames)]
    pct = round((done / total) * 100) if total else 100
    elapsed = _format_elapsed(time.perf_counter() - phase_start)
    text = f"{spinner} Hashing... {done}/{total} files ({pct}%) [Time Elapsed: {elapsed}]"
    try:
        sys.stdout.write("\r\x1b[2K" + text)
        sys.stdout.flush()
    except UnicodeEncodeError:
        # Last-resort guard: the cached frame set already matches the
        # encoding at cache time, but stdout can be reconfigured mid-run in
        # rare cases. Never let a cosmetic progress update crash the tool.
        pass


def _progress_clear() -> None:
    """Erase the progress line so the next normal print() starts fresh."""
    if _progress_active():
        sys.stdout.write("\r\x1b[2K")
        sys.stdout.flush()


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
    """RFC 6962-style Merkle root with domain separation.

    Two hardening measures distinguish this from a naive Merkle tree, both
    aimed at the same class of attack — making two different file sets collide
    to the same root:

    * Leaf nodes are hashed with a ``0x00`` prefix and internal nodes with
      ``0x01``. Without this, a leaf digest and an internal digest are computed
      identically, so an attacker can present an internal node's two children
      as if they were a single leaf (a second-preimage forgery of the tree
      shape).
    * Odd nodes are promoted to the next level unchanged rather than being
      duplicated. Duplication is the CVE-2012-2459 weakness: a tree over
      ``[A, B, C]`` (with C duplicated) yields the same root as a real
      four-file tree ``[A, B, C, C]``, so files can be silently added or
      removed without changing the root.

    See the "Merkle tree" section of the README for the worked example.
    """
    if not hashes:
        return ""
    algo, length = _parse_algo_spec(algo_spec)

    def _node(prefix: bytes, *parts: bytes) -> bytes:
        h = hashlib.new(algo, prefix + b"".join(parts))
        return h.digest(length) if length is not None else h.digest()

    # Leaf level: domain-separate every file hash with a 0x00 prefix.
    level = [_node(b"\x00", bytes.fromhex(h)) for h in hashes]
    # Internal levels: pair with a 0x01 prefix; promote a trailing odd node.
    while len(level) > 1:
        next_level = [
            _node(b"\x01", level[i], level[i + 1])
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2 == 1:
            next_level.append(level[-1])
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
        # `ssh-keygen -Y verify` reads the signed data from STDIN (not a
        # positional argument), so feed the manifest file on stdin.
        with manifest_path.open("rb") as data_in:
            subprocess.run(
                ["ssh-keygen", "-Y", "verify",
                 "-f", str(allowed_path),
                 "-I", SSH_SIGNER_IDENTITY,
                 "-n", SSH_NAMESPACE,
                 "-s", str(sig_path)],
                stdin=data_in, cwd=manifest_path.parent, check=True,
                capture_output=True, text=True,
            )
    except subprocess.CalledProcessError:
        return SshVerifyResult("FAIL", "SSH signature verification failed.", warnings)
    finally:
        Path(allowed_path).unlink(missing_ok=True)
    return SshVerifyResult("OK", "SSH signature verified.", warnings)


def ssh_key_fingerprint(pub_path: Path) -> Optional[str]:
    """Return the SHA256:... fingerprint of an SSH public key, or None."""
    if not ssh_keygen_available():
        return None
    try:
        result = subprocess.run(
            ["ssh-keygen", "-lf", str(pub_path)],
            capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError:
        return None
    for token in result.stdout.split():
        if token.startswith("SHA256:"):
            return token
    return None


def gpg_verified_fingerprint(manifest: Path, signature: Path) -> Optional[str]:
    """Return the primary-key fingerprint that produced a VALID gpg signature.

    Uses --status-fd so the result is the cryptographically verified signer,
    not anything self-declared (defends against key substitution, C1).
    """
    try:
        result = subprocess.run(
            ["gpg", "--verify", "--status-fd", "1",
             str(signature.resolve()), str(manifest.resolve())],
            capture_output=True, text=True,
        )
    except OSError:
        return None
    for line in result.stdout.splitlines():
        parts = line.split()
        # [GNUPG:] VALIDSIG <fpr> <date> ...
        if len(parts) >= 3 and parts[0] == "[GNUPG:]" and parts[1] == "VALIDSIG":
            return _normalize_gpg_fpr(parts[2])
    return None


def gpg_fingerprint_from_keyfile(key_file: Path) -> Optional[str]:
    """Import an armored GPG key into a temp homedir and return its fingerprint."""
    tmp_home = Path(tempfile.mkdtemp(prefix="rednb-gpgfpr-"))
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
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "fpr":
                return _normalize_gpg_fpr(parts[9])
    except subprocess.CalledProcessError:
        return None
    finally:
        shutil.rmtree(tmp_home, ignore_errors=True)
    return None


# ---------- Trust ----------

def resolve_trust_level(cli_trust: Optional[str], config: Dict) -> str:
    """CLI --trust overrides config trust_level; default 'low'."""
    return cli_trust or config.get("trust_level") or "low"


def is_key_trusted(kind: str, fpr: str, config: Dict) -> bool:
    """kind = 'gpg' | 'ssh'. GPG compared normalized; SSH compared verbatim (D3)."""
    trusted = config.get("trust", {}).get(kind, [])
    if kind == "gpg":
        norm = _normalize_gpg_fpr(fpr)
        return any(_normalize_gpg_fpr(t) == norm for t in trusted)
    return fpr in trusted


def trust_gate_signing(kind: str, fpr: Optional[str], trust_level: str,
                       config: Dict) -> bool:
    """Enforce trust policy before signing. Returns True to proceed.

    high + untrusted → refuse (exit 3). low → always proceed, notify.
    """
    label = kind.upper()
    if fpr is None:
        # Can't determine the key's fingerprint.
        if trust_level == "high":
            _err(f"Cannot determine {label} key fingerprint — refusing to sign "
                 "(--trust high).")
            sys.exit(3)
        _warn_security(f"Could not determine {label} key fingerprint; signing anyway "
                       "(--trust low).")
        return True
    trusted = is_key_trusted(kind, fpr, config)
    if trust_level == "high":
        if not trusted:
            _err(f"Untrusted {label} key {fpr} — refusing to sign (--trust high).")
            sys.exit(3)
        return True
    # low
    if trusted:
        _info(f"{label} signing key is trusted: {fpr}")
    else:
        _warn_security(f"Signing with UNTRUSTED {label} key: {fpr}")
    return True


def trust_gate_verify(kind: str, fpr: Optional[str], trust_level: str,
                      config: Dict) -> bool:
    """At verify time, check the VERIFIED key against the trust list (C1).

    Returns True if acceptable. Under --trust high, an untrusted/unknown signer
    returns False (caller treats verification as failed → exit 1).
    """
    label = kind.upper()
    if trust_level != "high":
        return True
    if fpr is None:
        _warn_security(f"Could not extract {label} signer fingerprint to check trust.")
        return False
    if is_key_trusted(kind, fpr, config):
        return True
    _warn_security(f"VERIFIED {label} signature from UNTRUSTED key {fpr} "
                   "(--trust high) — possible key substitution.")
    return False


# ---------- Randomart (fingerprint visualisation) ----------

_RANDOMART_CHARS = " .o+=*BOX@%&#/^SE"  # 17 chars; 15=S (start), 16=E (end)


def fingerprint_randomart(data: bytes, title: str = "") -> str:
    """Drunken-Bishop ASCII art over raw bytes (Dirk Loss algorithm)."""
    w, h = 17, 9
    grid = [[0] * w for _ in range(h)]
    x, y = w // 2, h // 2
    for byte in data:
        for shift in (0, 2, 4, 6):
            move = (byte >> shift) & 3
            x += -1 if move in (0, 2) else 1
            y += -1 if move in (0, 1) else 1
            x = max(0, min(w - 1, x))
            y = max(0, min(h - 1, y))
            grid[y][x] += 1
    start = (h // 2, w // 2)
    grid[start[0]][start[1]] = 15   # 'S'
    grid[y][x] = 16                 # 'E'
    top = f"+--[{title}]".ljust(w + 1, "-") + "+"
    out = [top[: w + 2]]
    for row in grid:
        out.append("|" + "".join(_RANDOMART_CHARS[min(v, 16)] for v in row) + "|")
    out.append("+" + "-" * w + "+")
    return "\n".join(out)


def show_randomart_ssh(pub_path: Path) -> None:
    """Print SSH key randomart: native ssh-keygen -lv if available, else custom."""
    if _quiet:
        return
    try:
        result = subprocess.run(
            ["ssh-keygen", "-lv", "-f", str(pub_path)],
            capture_output=True, text=True, check=True,
        )
        print(result.stdout.rstrip())
        return
    except (OSError, subprocess.CalledProcessError):
        pass
    fpr = ssh_key_fingerprint(pub_path)
    if fpr:
        # Strip 'SHA256:' and base64-decode to bytes for the art.
        import base64
        b64 = fpr.split(":", 1)[1]
        try:
            raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
        except Exception:
            raw = fpr.encode()
        print(fingerprint_randomart(raw, "SSH"))


def show_randomart_gpg(fpr: str) -> None:
    """Print GPG fingerprint randomart (custom Drunken Bishop over fpr bytes)."""
    if _quiet or not fpr:
        return
    try:
        raw = bytes.fromhex(fpr)
    except ValueError:
        raw = fpr.encode()
    print(fingerprint_randomart(raw, "GPG"))


# ---------- TSA (RFC 3161 trusted timestamping) ----------
# Strictly OPT-IN: nothing here runs unless --tsa is passed on the command
# line. The single network operation is the timestamp REQUEST at create time;
# verification of a token is fully local (openssl ts -verify against a CA).

@dataclass(frozen=True)
class _TSA:
    """A known timestamp authority.

    key_type is the signing-key family observed in live testing (2026-07):
    RSA hosts verify with this tool alone (the bundled rfc3161ng backend);
    EC hosts require openssl on PATH to verify locally, because rfc3161ng's
    signature check is RSA-only. ca_url points at the provider's official CA
    repository so a user can obtain a trust anchor for --tsa-cert (a pointer
    only — the tool never downloads or bundles these itself).
    """
    url: str
    key_type: str   # "RSA" or "EC"
    ca_url: str      # official CA/root repository page (pointer, may be "")


TSA_SERVERS: Dict[str, _TSA] = {
    "digicert":   _TSA("http://timestamp.digicert.com", "RSA",
                       "https://www.digicert.com/kb/digicert-root-certificates.htm"),
    "sectigo":    _TSA("http://timestamp.sectigo.com", "RSA",
                       "https://www.sectigo.com/knowledge-base/detail/Sectigo-Root-Certificates"),
    "globalsign": _TSA("http://timestamp.globalsign.com/tsa/r6advanced1", "RSA",
                       "https://support.globalsign.com/ca-certificates/root-certificates"),
    "certum":     _TSA("http://time.certum.pl", "RSA",
                       "https://www.certum.eu/en/cert_expertise_root_certificates/"),
    "apple":      _TSA("http://timestamp.apple.com/ts01", "RSA",
                       "https://www.apple.com/certificateauthority/"),
    "freetsa":    _TSA("https://freetsa.org/tsr", "EC",
                       "https://freetsa.org/"),
}

# Manifest fields that may carry an embedded timestamp entry.
TSA_FIELDS = ("tsa_stamp", "tsa_merkle", "tsa_concat", "tsa_content")


def openssl_available() -> bool:
    try:
        subprocess.run(["openssl", "version"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False


def resolve_tsa(arg: str) -> str:
    """Map a registry short name to its URL, or accept an http(s) URL verbatim.

    There is deliberately no fallback default: contacting a third party must
    always be an explicit user choice.
    """
    if arg.lower() in TSA_SERVERS:
        return TSA_SERVERS[arg.lower()].url
    if arg.startswith(("http://", "https://")):
        return arg
    _err(f"Unknown TSA {arg!r}. Use --tsa-list for known names, "
         "or pass a full http(s):// URL.")
    sys.exit(2)


def _tsa_query_bytes(data_path: Path) -> Optional[bytes]:
    """Build a DER timestamp query (RFC 3161 TimeStampReq) over a file's bytes."""
    result = subprocess.run(
        ["openssl", "ts", "-query", "-data", str(data_path), "-sha256", "-cert"],
        capture_output=True,
    )
    return result.stdout if result.returncode == 0 else None


def _tsa_http_post(url: str, tsq: bytes, timeout: int = 30) -> Optional[bytes]:
    """POST the query to the TSA. Single request, fixed timeout, no retries —
    keeping the network footprint predictable and minimal."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(
        url, data=tsq, method="POST",
        headers={"Content-Type": "application/timestamp-query"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except (urllib.error.URLError, OSError) as exc:
        _err(f"TSA request failed: {exc}")
        return None


def _tsa_lib_available() -> bool:
    return _module_available("rfc3161ng")


def tsa_backend_available() -> bool:
    """A timestamp can be produced/checked if openssl OR the library is present."""
    return openssl_available() or _tsa_lib_available()


def _lib_request(data: bytes, url: str) -> Optional[bytes]:
    """Request a token via the rfc3161ng library (the openssl-free path, for
    Windows). EXPERIMENTAL — validate on your platform before relying on it."""
    try:
        import rfc3161ng
        from pyasn1.codec.der import encoder
        stamper = rfc3161ng.RemoteTimestamper(
            url, hashname="sha256", include_tsa_certificate=True, timeout=30)
        tsr = stamper(data=data, return_tsr=True)
        return encoder.encode(tsr)
    except Exception as exc:  # noqa: BLE001 — surface any lib/network error clearly
        _err(f"TSA request (rfc3161ng backend) failed: {exc}")
        return None


def _find_signer_certificate_der(signed_data) -> Optional[bytes]:
    """Find the DER bytes of the actual TSA signer certificate inside a CMS
    `certificates` SET, by matching signerInfo's issuerAndSerialNumber.

    RFC 5652 does not define an order for the `certificates` SET. Some TSAs
    (e.g. DigiCert, GlobalSign, Certum) happen to send the leaf/signer cert
    first, which is what rfc3161ng.api.load_certificate()'s default
    (certificates[0]) silently assumes. Others (Apple, Sectigo) send it
    root-first — under that ordering, load_certificate() picks the CA's own
    certificate instead of the signer's, so any signature check against it
    fails with InvalidSignature even though the token itself is valid. This
    identifies the real signer the spec-correct way instead of guessing
    index 0, so the fix works regardless of the order a given TSA uses.
    Returns None (falls back to the library's own default) if the SET or
    signerInfo isn't shaped as expected.
    """
    try:
        from pyasn1.codec.der import encoder as der_encoder
        from cryptography import x509
    except Exception:  # noqa: BLE001
        return None
    try:
        certs = signed_data['certificates']
        signer_info = signed_data['signerInfos'][0]
        issuer_and_serial = signer_info['issuerAndSerialNumber']
        issuer_der = der_encoder.encode(issuer_and_serial['issuer'])
        serial = int(issuer_and_serial['serialNumber'])
    except Exception:  # noqa: BLE001
        return None
    try:
        for i in range(len(certs)):
            cert_der = der_encoder.encode(certs[i][0])
            cert_obj = x509.load_der_x509_certificate(cert_der)
            if cert_obj.issuer.public_bytes() == issuer_der and cert_obj.serial_number == serial:
                return cert_der
    except Exception:  # noqa: BLE001
        return None
    return None


def _embedded_certs(signed_data) -> list:
    """All certificates carried inside the token, as cryptography x509 objects.
    These are the intermediates (and often the root) a TSA bundles so a
    verifier can build the chain without fetching anything."""
    from pyasn1.codec.der import encoder as der_encoder
    from cryptography import x509
    out = []
    try:
        certs = signed_data['certificates']
    except Exception:  # noqa: BLE001
        return out
    for i in range(len(certs)):
        try:
            out.append(x509.load_der_x509_certificate(der_encoder.encode(certs[i][0])))
        except Exception:  # noqa: BLE001
            continue
    return out


def _cert_signed_by(child, parent) -> bool:
    """True if `parent`'s public key verifies `child`'s signature (i.e. parent
    issued child). Signature-only: no date/EKU/revocation checks."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
    try:
        key = parent.public_key()
        algo = child.signature_hash_algorithm
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes,
                       padding.PKCS1v15(), algo)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(algo))
        else:
            return False
        return True
    except (InvalidSignature, Exception):  # noqa: BLE001
        return False


def _build_and_verify_chain(leaf, intermediates: list, anchors: list,
                            max_depth: int = 10) -> bool:
    """Build a signature chain from `leaf` up through `intermediates` until a
    certificate is issued by (or equal to) one of the trusted `anchors`.

    This is what lets a user pass a provider's ROOT to --tsa-cert and have it
    work even when the signer is issued by an intermediate (openssl's -CAfile
    behaviour). It is deliberately a *signature* chain only — it does NOT do
    full RFC 5280 path validation (no revocation, no EKU, no validity-period
    checks; the latter is intentional, since a timestamp must stay verifiable
    after the signing cert expires). openssl remains the fully-rigorous path.
    """
    from cryptography.hazmat.primitives import hashes
    if not anchors:
        return False
    anchor_fps = set()
    anchor_by_subject: Dict[bytes, list] = {}
    for a in anchors:
        try:
            anchor_fps.add(a.fingerprint(hashes.SHA256()))
            anchor_by_subject.setdefault(a.subject.public_bytes(), []).append(a)
        except Exception:  # noqa: BLE001
            continue
    inter_by_subject: Dict[bytes, list] = {}
    for c in intermediates:
        try:
            inter_by_subject.setdefault(c.subject.public_bytes(), []).append(c)
        except Exception:  # noqa: BLE001
            continue

    current = leaf
    seen = set()
    for _ in range(max_depth):
        try:
            fp = current.fingerprint(hashes.SHA256())
        except Exception:  # noqa: BLE001
            return False
        # If the current cert is itself a trusted anchor, we're done.
        if fp in anchor_fps:
            return True
        if fp in seen:
            return False
        seen.add(fp)
        issuer_bytes = current.issuer.public_bytes()
        # Directly issued by a trusted anchor?
        for a in anchor_by_subject.get(issuer_bytes, []):
            if _cert_signed_by(current, a):
                return True
        # Otherwise step up through an embedded intermediate.
        nxt = None
        for c in inter_by_subject.get(issuer_bytes, []):
            if c.fingerprint(hashes.SHA256()) not in seen and _cert_signed_by(current, c):
                nxt = c
                break
        if nxt is None:
            return False
        current = nxt
    return False


def _system_trust_anchors() -> list:
    """Root certificates from the OS trust store (Windows ROOT store, macOS
    keychain roots, or the system bundle on Linux), as x509 objects. Returns
    [] if none can be loaded. No network."""
    import ssl
    import warnings
    from cryptography import x509
    from cryptography.utils import CryptographyDeprecationWarning
    anchors = []
    try:
        ctx = ssl.create_default_context()
        for der in ctx.get_ca_certs(binary_form=True):
            try:
                # Some real, OS-trusted roots predate RFC 5280 and carry a
                # non-positive serial number; cryptography warns (not yet a
                # hard error) when loading these. It's expected noise about a
                # store we don't control, not something the user can act on —
                # the per-cert except below already handles the day this
                # becomes a real exception instead of a warning.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", CryptographyDeprecationWarning)
                    anchors.append(x509.load_der_x509_certificate(der))
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        return []
    return anchors


def _fetch_issuers_via_aia(certs: list, timeout: int = 30) -> list:
    """Follow each cert's Authority Information Access 'caIssuers' URL and
    download the issuer certificate(s). Network — callers must gate this behind
    explicit consent (never --offline, never without a prompt). Returns the
    fetched x509 certs (best effort; failures are skipped silently)."""
    import urllib.request
    import urllib.error
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
    fetched = []
    seen_urls = set()
    for cert in certs:
        try:
            aia = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        except Exception:  # noqa: BLE001
            continue
        for desc in aia:
            if desc.access_method != AuthorityInformationAccessOID.CA_ISSUERS:
                continue
            url = getattr(desc.access_location, "value", None)
            if not url or not url.startswith(("http://", "https://")) or url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read()
            except (urllib.error.URLError, OSError):
                continue
            for loader in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
                try:
                    fetched.append(loader(body))
                    break
                except Exception:  # noqa: BLE001
                    continue
    return fetched


def _signer_key_type(tst) -> Optional[str]:
    """'RSA' or 'EC' for a token's signer certificate, or None if it can't be
    determined. Used at create time to tell the user whether this tool alone
    (rfc3161ng, RSA-only) can later verify the token."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    try:
        der = _find_signer_certificate_der(tst.content)
        if der is None:
            return None
        key = x509.load_der_x509_certificate(der).public_key()
    except Exception:  # noqa: BLE001
        return None
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC"
    return None


def _token_key_type(tsr: bytes) -> Optional[str]:
    """'RSA'/'EC'/None for a raw .tsr's signer. Convenience wrapper that decodes
    the token first (used where only the token bytes are on hand)."""
    try:
        import rfc3161ng
        tst = rfc3161ng.decode_timestamp_response(tsr).time_stamp_token
        return _signer_key_type(tst)
    except Exception:  # noqa: BLE001
        return None


def _tsa_keytype_confirm(tsr: bytes, *, assume_yes: bool, quiet: bool) -> bool:
    """At create time, tell the user whether the just-obtained token can be
    verified by this tool alone, and — only when it can't (an EC signer with no
    openssl on PATH) — ask whether to keep it. Returns True to keep, False to
    drop. Auto-keeps under -y / --quiet / a non-interactive stdin (with the
    warning still printed, so the record isn't silently lost)."""
    kt = _token_key_type(tsr)
    if kt == "RSA":
        _info("Timestamp signer key: RSA — verifiable by this tool alone at "
              "--verify (with --tsa-cert <CA>, or omit it to use your system store).")
        return True
    if kt == "EC":
        if openssl_available():
            _info("Timestamp signer key: EC — verifiable here via openssl.")
            return True
        _warn("Timestamp signer key: EC — this tool's built-in backend (rfc3161ng) "
              "cannot verify EC signatures and openssl isn't on PATH, so you will "
              "NOT be able to verify this timestamp on this machine (it stays valid "
              "and verifiable on any host with openssl).")
        if assume_yes or quiet or not sys.stdin.isatty():
            return True
        try:
            ans = input(f"{_tag('WARN')} Keep this EC timestamp anyway? [Y/n] ")
        except EOFError:
            return True
        return ans.strip().lower() not in ("n", "no")
    # Undetectable key type (e.g. rfc3161ng not installed): stay silent, keep.
    return True


def _lib_verify(data: bytes, tsr: bytes, ca_file: Optional[Path],
                *, system_store: bool = False, allow_online: bool = False) -> Optional[bool]:
    """Verify via rfc3161ng: (1) the token's own signature validates over
    `data` using its embedded signer certificate, and (2) that signer chains to
    a trusted anchor. Both must hold for True. EXPERIMENTAL.

    The trust anchor for step 2 comes from, in order: `ca_file` (a PEM bundle
    of one or more certs passed as --tsa-cert); else, if `system_store` is set,
    the OS root store. Step 2 builds the chain through the token's embedded
    intermediates (via _build_and_verify_chain), so passing a provider's ROOT
    works even when the signer was issued by an intermediate — matching
    openssl's -CAfile behaviour. If `allow_online` is set and the offline chain
    can't reach an anchor, missing issuers are fetched via each cert's AIA
    caIssuers URL and the chain is retried (callers MUST gate this behind
    explicit consent — never under --offline).

    check_timestamp()'s `certificate=` parameter is NOT "the CA to trust" — it
    is the certificate the SIGNATURE is checked against; we pass the correctly
    identified signer cert (see _find_signer_certificate_der).

    Known limitation: check_timestamp's final signature check always calls
    the RSA PKCS1v15 verify path regardless of key type, so a token signed
    with an EC key (e.g. FreeTSA's TSA certs) cannot be checked here — that
    surfaces as an inconclusive (None) result, not a false pass. The earlier,
    cheaper message-imprint check (which is the actual tamper-evidence
    mechanism) still runs and still catches a data/token mismatch regardless
    of key type, so tamper detection is unaffected by this limitation — only
    full cryptographic non-repudiation is. Step 2 is a signature chain only,
    not full RFC 5280 path validation (no revocation/EKU); openssl with
    --tsa-cert remains the fully-rigorous path.
    """
    try:
        import rfc3161ng
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
    except Exception as exc:  # noqa: BLE001
        _warn(f"Library-backend timestamp verify inconclusive: {exc}")
        return None

    try:
        tst = rfc3161ng.decode_timestamp_response(tsr).time_stamp_token
    except Exception as exc:  # noqa: BLE001
        _warn(f"Library-backend timestamp verify inconclusive: {exc}")
        return None

    # Resolve trust anchors up front so a caller that provided nothing usable
    # gets a clear inconclusive rather than a misleading failure.
    anchors: list = []
    if ca_file is not None:
        try:
            anchors = x509.load_pem_x509_certificates(ca_file.read_bytes())
        except Exception as exc:  # noqa: BLE001
            _warn(f"Library-backend timestamp verify inconclusive: {exc}")
            return None
    elif system_store:
        anchors = _system_trust_anchors()
        if not anchors:
            _warn("Library-backend timestamp verify inconclusive: could not load "
                  "any system trust-store roots")
            return None

    # Correctly-identified signer cert DER bytes, or None to fall back to
    # the library's own certificates[0] default (see _find_signer_certificate_der).
    signer_cert_der = _find_signer_certificate_der(tst.content)
    certificate_arg = signer_cert_der if signer_cert_der is not None else b""

    # Step 1: the token's own signature over `data`, checked against its own
    # embedded signer certificate.
    try:
        rfc3161ng.check_timestamp(tst, certificate=certificate_arg, data=data, hashname="sha256")
    except InvalidSignature:
        return False
    except ValueError:
        # e.g. "Message imprint mismatch" — the library's own tamper signal,
        # not a tooling limitation.
        return False
    except TypeError:
        _warn("Library-backend timestamp verify inconclusive: token uses an EC "
              "signing key, which this backend cannot check (RSA-only) — "
              "verify with openssl externally or install openssl")
        return None
    except Exception as exc:  # noqa: BLE001
        _warn(f"Library-backend timestamp verify inconclusive: {exc}")
        return None

    # Step 2: the signer certificate chains to a trusted anchor.
    try:
        from rfc3161ng.api import load_certificate
        if signer_cert_der is not None:
            leaf_cert = x509.load_der_x509_certificate(signer_cert_der)
        else:
            leaf_cert = load_certificate(tst.content, b"")
        intermediates = _embedded_certs(tst.content)
        if _build_and_verify_chain(leaf_cert, intermediates, anchors):
            return True
        if allow_online:
            fetched = _fetch_issuers_via_aia([leaf_cert] + intermediates)
            if fetched and _build_and_verify_chain(leaf_cert, intermediates + fetched, anchors):
                return True
        # The signer's own signature over the data already validated (step 1),
        # so this is NOT tampering — it's a trust-anchor problem.
        if ca_file is None:
            # System-store path: the user pinned no CA, so an unknown root is
            # inconclusive, not a failure. Crying "failed" here would be a
            # false tamper report for a legitimate-but-untrusted TSA.
            _warn("Library-backend timestamp verify inconclusive: the token's "
                  "signer does not chain to any system trust-store root (unknown "
                  "CA) — pass --tsa-cert with the provider's root, or install openssl")
            return None
        # A CA was explicitly pinned and the token does not chain to it: that is
        # a real verification failure (as openssl -CAfile would also report).
        return False
    except Exception as exc:  # noqa: BLE001
        _warn(f"Library-backend timestamp verify inconclusive: {exc}")
        return None


def _tsa_request_bytes(data: bytes, url: str, label: str = "") -> Optional[bytes]:
    """Backend-agnostic timestamp request. Prefers openssl (broadly tested);
    falls back to the rfc3161ng library when openssl isn't installed."""
    _info(f"Requesting timestamp from {url}{label}")
    if openssl_available():
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
            tmp = Path(tf.name)
        try:
            tsq = _tsa_query_bytes(tmp)
            if tsq is None:
                _err("openssl could not build the timestamp query")
                return None
            return _tsa_http_post(url, tsq)
        finally:
            tmp.unlink(missing_ok=True)
    if _tsa_lib_available():
        return _lib_request(data, url)
    _err("No TSA backend available (need openssl on PATH, or 'pip install rfc3161ng').")
    return None


def tsa_timestamp_file(data_path: Path, url: str) -> Optional[bytes]:
    """Request an RFC 3161 token over a file. Returns raw .tsr bytes or None."""
    return _tsa_request_bytes(data_path.read_bytes(), url)


def tsa_timestamp_data(data: bytes, url: str, label: str = "") -> Optional[bytes]:
    """Request a token over in-memory bytes (used for embedded root stamps)."""
    return _tsa_request_bytes(data, url, label)


def tsa_token_time(tsr: bytes) -> str:
    """Best-effort human timestamp from a token (openssl, else the library)."""
    if openssl_available():
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(tsr)
            tmp = Path(tf.name)
        try:
            result = subprocess.run(["openssl", "ts", "-reply", "-in", str(tmp), "-text"],
                                    capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.strip().startswith("Time stamp:"):
                    return line.split(":", 1)[1].strip()
            return ""
        finally:
            tmp.unlink(missing_ok=True)
    if _tsa_lib_available():
        try:
            import rfc3161ng
            tst = rfc3161ng.decode_timestamp_response(tsr).time_stamp_token
            return str(rfc3161ng.get_timestamp(tst))
        except Exception:  # noqa: BLE001
            return ""
    return ""


def tsa_verify_data(data: bytes, tsr: bytes, ca_file: Optional[Path],
                    *, allow_online: bool = False) -> Optional[bool]:
    """Verify a token against data, locally. True/False = verified/failed;
    None = no usable backend or inconclusive.

    ca_file is the trust anchor (--tsa-cert). When given AND openssl is on PATH,
    the rigorous openssl -CAfile path is used. When ca_file is None, the anchor
    is the OS system trust store (via the library backend). allow_online lets
    the library backend fetch missing issuer certs over the network (AIA) — the
    caller must have already obtained the user's consent."""
    if ca_file is not None and openssl_available():
        with tempfile.NamedTemporaryFile(delete=False) as df:
            df.write(data)
            data_tmp = Path(df.name)
        with tempfile.NamedTemporaryFile(delete=False) as rf:
            rf.write(tsr)
            tsr_tmp = Path(rf.name)
        try:
            result = subprocess.run(
                ["openssl", "ts", "-verify", "-data", str(data_tmp),
                 "-in", str(tsr_tmp), "-CAfile", str(ca_file)],
                capture_output=True,
            )
            return result.returncode == 0
        finally:
            data_tmp.unlink(missing_ok=True)
            tsr_tmp.unlink(missing_ok=True)
    if _tsa_lib_available():
        return _lib_verify(data, tsr, ca_file,
                           system_store=(ca_file is None), allow_online=allow_online)
    return None


def _tsa_entry(url: str, tsr: bytes) -> Dict[str, str]:
    return {
        "tsa": url,
        "time": tsa_token_time(tsr),
        "token_b64": base64.b64encode(tsr).decode("ascii"),
    }


def _tsa_placement(manifest: Dict, compute_if_missing: bool = False) -> tuple:
    """(field_name, root_value) for the placement stamp.

    Single-hash mode stamps merkle_root as 'tsa_merkle'; multi-hash mode
    collapses the per-algo trees to the single concatenated root ('tsa_concat'),
    computing and STORING merkle_root_concat when the manifest lacks one so
    verify can recompute the same value.
    """
    multi = isinstance(manifest.get("hash_algorithm"), list)
    if not multi:
        return "tsa_merkle", manifest.get("merkle_root")
    mrc = manifest.get("merkle_root_concat")
    if not mrc and compute_if_missing:
        files = {e["path"]: dict(e["hashes"]) for e in manifest["files"]}
        root = _concat_merkle_root(files, manifest["hash_algorithm"], "sha256")
        manifest["merkle_root_concat"] = {"sha256": root}
        _info("Computed concat root for timestamp")
        mrc = manifest["merkle_root_concat"]
    return "tsa_concat", (next(iter(mrc.values())) if mrc else None)


def _tsa_content_value(manifest: Dict) -> Optional[str]:
    """The value the content stamp covers: content_root (single-hash), or the
    alphabetical 'algo:root,algo:root' join of content_roots (multi-hash)."""
    if manifest.get("content_root"):
        return manifest["content_root"]
    crs = manifest.get("content_roots") or {}
    return ",".join(f"{a}:{crs[a]}" for a in sorted(crs)) or None


def _tsa_stamped_value(manifest: Dict, field: str) -> Optional[str]:
    """Recover the value an embedded stamp covers, from the manifest's own
    stored roots (the token authenticates the manifest's claim; integrity
    checks separately tie the disk state to the manifest)."""
    if field == "tsa_content":
        return _tsa_content_value(manifest)
    if field == "tsa_concat" or (field == "tsa_stamp"
                                 and isinstance(manifest.get("hash_algorithm"), list)):
        mrc = manifest.get("merkle_root_concat") or {}
        return next(iter(mrc.values()), None)
    return manifest.get("merkle_root")


def tsa_embed_into_manifest(manifest: Dict, url: str, separate: bool) -> bool:
    """Request and embed timestamp stamp(s) over the manifest's root values.

    Stamps cover ROOT values (stable hex strings), never the manifest itself —
    embedding a token into the very bytes it covers would invalidate it.
    Single mode: one request, field 'tsa_stamp'. Separate mode: one placement
    stamp (tsa_merkle/tsa_concat) plus one content stamp (tsa_content), so a
    third party can attest each dimension independently.
    """
    if separate:
        field, value = _tsa_placement(manifest, compute_if_missing=True)
        targets = [(field, value), ("tsa_content", _tsa_content_value(manifest))]
    else:
        _, value = _tsa_placement(manifest, compute_if_missing=True)
        targets = [("tsa_stamp", value)]
    if any(v is None for _, v in targets):
        _err("Manifest lacks the root value(s) to timestamp")
        return False
    for i, (field, value) in enumerate(targets):
        label = f" ({i + 1}/{len(targets)})" if len(targets) > 1 else ""
        tsr = tsa_timestamp_data(value.encode("utf-8"), url, label)
        if tsr is None:
            # Preserve the hashing work: mark this stamp and any remaining ones
            # 'failed' so the manifest still records the intent; --resign can
            # add a real token later. Already-succeeded stamps are kept.
            for f, _ in targets[i:]:
                manifest[f] = "failed"
            return False
        manifest[field] = _tsa_entry(url, tsr)
    return True


# ---------- Optional dependencies (preflight + --install-opt) ----------

# pip package name -> import name, for availability checks and installation.
_OPTIONAL_PIP: Dict[str, str] = {
    "pyyaml": "yaml",
    "jsonschema": "jsonschema",
    "rfc3161ng": "rfc3161ng",
    "blake3": "blake3",
    "xxhash": "xxhash",
}


def _module_available(import_name: str) -> bool:
    import importlib.util
    try:
        return importlib.util.find_spec(import_name) is not None
    except (ImportError, ValueError):
        return False


@dataclass
class _Capability:
    """A requested feature's dependency. Satisfied if it is available now.
    pip_pkgs can install it; ext_tools are system commands we cannot install."""
    name: str
    ok: bool
    pip_pkgs: tuple = ()
    ext_tools: tuple = ()


def _required_capabilities(args) -> List[_Capability]:
    """Only the dependencies the *requested* operation actually needs."""
    caps: List[_Capability] = []
    if getattr(args, "per_day", False):
        caps.append(_Capability("--per-day", _module_available("yaml"),
                                pip_pkgs=("pyyaml",)))
    if getattr(args, "validate", None) is not None:
        caps.append(_Capability("--validate", _module_available("jsonschema"),
                                pip_pkgs=("jsonschema",)))
    if getattr(args, "tsa", None):
        caps.append(_Capability(
            "--tsa timestamping",
            openssl_available() or _module_available("rfc3161ng"),
            pip_pkgs=("rfc3161ng",), ext_tools=("openssl",)))
    if getattr(args, "gpg", None) is not None or getattr(args, "gpg_k", None) is not None:
        caps.append(_Capability("GPG signing", gpg_available(), ext_tools=("gpg",)))
    if getattr(args, "ssh", None) is not None or getattr(args, "ssh_fido", None) is not None:
        caps.append(_Capability("SSH signing", ssh_keygen_available(),
                                ext_tools=("ssh-keygen",)))
    return caps


def _pip_install(pkgs: List[str]) -> bool:
    cmd = [sys.executable, "-m", "pip", "install", *pkgs]
    _info("Running: " + " ".join(cmd))
    try:
        return subprocess.run(cmd).returncode == 0
    except OSError as exc:
        _err(f"Could not run pip: {exc}")
        return False


def install_all_optional() -> None:
    """`--install-opt` alone: install every missing optional package and exit."""
    missing = [p for p, imp in _OPTIONAL_PIP.items() if not _module_available(imp)]
    if not missing:
        _ok("All optional packages are already installed.")
        return
    _info("Missing optional packages: " + ", ".join(missing))
    if _pip_install(missing):
        _ok("Optional packages installed. Re-run your command to use them.")
    else:
        _err("Some packages failed to install; see pip output above.")
        sys.exit(1)


def preflight_dependencies(args) -> None:
    """Verify the requested operation's dependencies BEFORE doing any work.

    Missing pip libraries → print the exact `pip install` line and ask the user
    to re-run with --install-opt (or, when --install-opt is given, install them
    and stop so they re-run). Missing external tools (gpg/ssh-keygen; openssl
    only when the pip alternative is also absent) can't be installed for the
    user, so we exit with a plain reason. Nothing here touches pip or the
    network unless --install-opt was explicitly passed.
    """
    missing = [c for c in _required_capabilities(args) if not c.ok]
    if not missing:
        return
    pip_missing = [c for c in missing if c.pip_pkgs]      # installable for the user
    ext_missing = [c for c in missing if not c.pip_pkgs]  # external-only

    for c in missing:
        fixes = []
        if c.pip_pkgs:
            fixes.append("pip install " + " ".join(c.pip_pkgs))
        if c.ext_tools:
            fixes.append(("or install " if c.pip_pkgs else "install ")
                         + "/".join(c.ext_tools) + " on your system")
        _err(f"{c.name} is unavailable — {'; '.join(fixes)}.")

    # External tools we cannot install for the user → hard stop with a reason.
    if ext_missing:
        _err("The program(s) above must be installed and on your PATH; re-run once they are.")
        sys.exit(2)

    # Only pip-installable libraries remain.
    pkgs = sorted({p for c in pip_missing for p in c.pip_pkgs})
    if getattr(args, "install_opt", False):
        if _pip_install(pkgs):
            _ok("Installed. Please re-run your command to use it.")
            sys.exit(0)
        _err("Installation failed; see pip output above.")
        sys.exit(1)
    _err("Install with:  pip install " + " ".join(pkgs))
    _err("Or re-run with --install-opt and rednb-verify will install it for you.")
    sys.exit(2)


def _bad_path_hint(raw: str) -> str:
    """Extra guidance appended when a path argument doesn't resolve.

    A literal '"' inside a path can never be a legitimate Windows filename
    character — its presence here is a reliable sign of a specific, common
    shell mishap: a quoted path ending in a single backslash right before the
    closing quote (e.g. "C:\\journal\\") escapes that quote instead of ending
    the argument, silently swallowing the rest of the command line into this
    one path. Flag substrings surviving inside the string are the tell.
    """
    if '"' in raw or re.search(r"\s-{1,2}[A-Za-z]", raw):
        return (" This looks like a quoted path ending in a backslash before "
                "the closing quote — that swallows the rest of the command "
                "into this one argument on Windows. Drop the trailing "
                "backslash, double it (\\\\), or use forward slashes (/).")
    return ""


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
    _info("Counting files...")

    # Gather candidate paths first (always sequential — os.walk is not thread-safe)
    paths_to_hash: List[tuple] = []
    for root, _, filenames in os.walk(base):
        for name in filenames:
            path = Path(root) / name
            rel = path.relative_to(base)
            rel_str = rel.as_posix()
            # Broken symlinks have no content to hash; they are still recorded
            # in the symlink table. Skipping them here avoids an open() crash.
            if path.is_symlink() and not path.exists():
                continue
            if month_only and not is_month_file(path):
                continue
            if any(fnmatch.fnmatch(path.name, pat) or fnmatch.fnmatch(rel_str, pat) for pat in exclude):
                continue
            paths_to_hash.append((path, rel_str))

    files: Dict[str, Dict[str, str]] = {}
    total = len(paths_to_hash)
    _ok(f"{total} files to hash")
    phase_start = time.perf_counter()

    if jobs == 1:
        for i, (path, rel_str) in enumerate(paths_to_hash, 1):
            t0 = time.perf_counter()
            try:
                files[rel_str] = hash_file_multi(path, algos)
            except OSError:
                if _verbose:
                    _vprint(f"{_tag('FAIL', stream=_log_stream())} {i}/{total} "
                            f"{rel_str} {_now_stamp()}")
                _progress_clear()
                raise
            if _verbose:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                _vprint(f"{_tag('OK', stream=_log_stream())} {i}/{total} {rel_str} "
                        f"{_now_stamp()} ({elapsed_ms:.2f}ms)")
            _progress_tick(i, total, phase_start)
    else:
        _lock = threading.Lock()
        _done = 0  # count of files completed so far, in COMPLETION order (not
                   # submission order, since parallel jobs finish out of order)

        def _hash_one(path: Path, rel_str: str) -> tuple:
            # _done increments and both the verbose line and the progress-bar
            # redraw happen under the SAME lock, so concurrent threads never
            # interleave writes to the same terminal line.
            nonlocal _done
            t0 = time.perf_counter()
            try:
                h = hash_file_multi(path, algos)
            except OSError:
                with _lock:
                    _done += 1
                    if _verbose:
                        _vprint(f"{_tag('FAIL', stream=_log_stream())} {_done}/{total} "
                                f"{rel_str} {_now_stamp()}")
                    _progress_clear()
                raise
            elapsed_ms = (time.perf_counter() - t0) * 1000
            with _lock:
                _done += 1
                if _verbose:
                    _vprint(f"{_tag('OK', stream=_log_stream())} {_done}/{total} {rel_str} "
                            f"{_now_stamp()} ({elapsed_ms:.2f}ms)")
                _progress_tick(_done, total, phase_start)
            return rel_str, h

        max_workers = jobs if jobs > 0 else None
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_hash_one, p, r): r for p, r in paths_to_hash}
            for future in as_completed(futures):
                rel_str, h = future.result()
                files[rel_str] = h

    _progress_clear()
    return dict(sorted(files.items()))


def _hash_target(target: str, algo_spec: str) -> str:
    """Hash a symlink target string (utf-8) with an 'algo[:length]' spec.

    Used so the manifest can commit to *where* a symlink points without storing
    the path in cleartext — the target may reveal home directories, usernames,
    or the existence of off-notebook data, which is sensitive in a shareable,
    signed artifact.
    """
    algo, length = _parse_algo_spec(algo_spec)
    h = _new_hasher(algo)
    h.update(target.encode("utf-8"))
    return _hexdigest(h, length)


def collect_symlinks(base: Path, exclude: Optional[List[str]] = None) -> Dict[str, str]:
    """Return {rel_posix_path: raw_target} for every symlink under base.

    Both file and directory symlinks are reported (os.walk does not descend into
    symlinked directories, so they would otherwise go unrecorded). The literal
    link target from os.readlink is returned verbatim — that is the value an
    attacker changes when repointing a link, so it is what we commit to.
    """
    exclude = exclude or []
    out: Dict[str, str] = {}
    for root, dirs, filenames in os.walk(base):  # followlinks=False (default)
        for name in list(dirs) + list(filenames):
            path = Path(root) / name
            if not path.is_symlink():
                continue
            rel = path.relative_to(base).as_posix()
            if any(fnmatch.fnmatch(path.name, pat) or fnmatch.fnmatch(rel, pat)
                   for pat in exclude):
                continue
            try:
                out[rel] = os.readlink(path)
            except OSError:
                out[rel] = ""
    return dict(sorted(out.items()))


def escaping_symlinks(base: Path, exclude: Optional[List[str]] = None) -> List[str]:
    """Return 'rel -> target' for symlinks whose target resolves OUTSIDE base.

    An escaping link pulls in (and hashes) data from elsewhere on the system, or
    can be repointed to leak/point at sensitive paths — worth flagging in a
    tamper-evidence tool, regardless of the recording policy.
    """
    base_real = base.resolve()
    out: List[str] = []
    for rel, target in collect_symlinks(base, exclude=exclude).items():
        try:
            real = (base / rel).parent.joinpath(target).resolve()
        except (OSError, ValueError):
            continue
        try:
            real.relative_to(base_real)
        except ValueError:
            out.append(f"{rel} -> {target}")
    return out


def _build_symlink_table(links: Dict[str, str], policy: str) -> List[Dict[str, str]]:
    """Turn {path: target} into manifest entries per the symlink policy.

    policy is 'full' (store cleartext target) or 'hash:<algo-spec>' (store a
    digest of the target). 'none' is handled by the caller (no table at all).
    """
    if policy == "full":
        return [{"path": p, "target": t} for p, t in links.items()]
    spec = policy.split(":", 1)[1]
    return [{"path": p, "target_hash": _hash_target(t, spec)} for p, t in links.items()]


def _resolve_symlink_policy(args) -> str:
    """Turn the --symlink-targets / --no-symlink-table / --privacy flags into a
    canonical policy string: 'none', 'full', or 'hash:<algo-spec>'."""
    if getattr(args, "no_symlink_table", False) or getattr(args, "privacy", False):
        return "none"
    raw = (getattr(args, "symlink_targets", None) or "hash").strip()
    if raw in ("none", "full"):
        return raw
    if raw == "hash":
        return "hash:sha256"
    if raw.startswith("hash:"):
        spec = raw[len("hash:"):]
        _validate_algo_spec_or_exit(spec, "--symlink-targets")
        return "hash:" + spec
    _err(f"--symlink-targets must be none|full|hash[:ALGO[:LEN]], got: {raw!r}")
    sys.exit(2)


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
    _info("Counting files...")

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
    total = len(entries)
    _ok(f"{total} files to hash")
    phase_start = time.perf_counter()

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
        for i, (day_key, day_data) in enumerate(entries, 1):
            key, digests, elapsed_ms = _hash_day(day_key, day_data)
            files[key] = digests
            if _verbose:
                _vprint(f"{_tag('OK', stream=_log_stream())} {i}/{total} {key} "
                        f"{_now_stamp()} ({elapsed_ms:.2f}ms)")
            _progress_tick(i, total, phase_start)
    else:
        _lock = threading.Lock()
        _done = 0  # completion order, same rationale as collect_files

        def _hash_day_parallel(day_key: str, day_data) -> tuple:
            # _done, the verbose line, and the progress redraw all happen
            # under the SAME lock -- see collect_files for why.
            nonlocal _done
            key, digests, elapsed_ms = _hash_day(day_key, day_data)
            with _lock:
                _done += 1
                if _verbose:
                    _vprint(f"{_tag('OK', stream=_log_stream())} {_done}/{total} {key} "
                            f"{_now_stamp()} ({elapsed_ms:.2f}ms)")
                _progress_tick(_done, total, phase_start)
            return key, digests

        max_workers = jobs if jobs > 0 else None
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_hash_day_parallel, k, d): k for k, d in entries}
            for future in as_completed(futures):
                key, digests = future.result()
                files[key] = digests

    _progress_clear()

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
    symlink_policy: str = "hash:sha256",
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
        manifest["hash_algorithm"] = algos
        # Merkle roots are written before the file list (matches the text
        # manifest, and puts the summary commitment ahead of the detail).
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
        # Move-invariant content root: leaves sorted by hash VALUE rather than
        # path, so the root commits to the *set* of file contents regardless of
        # where each lives. Lets verify tell "all content present, just moved"
        # apart from real tampering. (schema v3)
        manifest["content_roots"] = {
            a: merkle_root(sorted(files[p][a] for p in files), a) for a in tree_algos
        }
        # files entry: {path, hashes: {algo: hex, ... alphabetical}}. Assignment
        # to manifest["files"] itself is deferred to the end of this function so
        # it serialises as the LAST key in JSON output — every summary field
        # (roots, warnings, symlinks, TSA stamps) is visible before the detail.
        files_entry = [
            {"path": p, "hashes": {a: files[p][a] for a in algos}}
            for p in files
        ]
    else:
        algo = algos[0]
        manifest["hash_algorithm"] = algo
        manifest["merkle_hash"] = merkle_algo
        if concat_algo:
            manifest["merkle_root_concat"] = {
                concat_algo: _concat_merkle_root(files, algos, concat_algo)
            }
        manifest["merkle_root"] = merkle_root(
            [files[p][algo] for p in files], merkle_algo
        )
        # Move-invariant content root (leaves sorted by hash value). schema v3.
        manifest["content_root"] = merkle_root(
            sorted(files[p][algo] for p in files), merkle_algo
        )
        files_entry = [{"path": p, algo: files[p][algo]} for p in files]

    if exclude:
        manifest["exclude"] = exclude

    # Symlink table (schema v2). Symlinked files are also content-hashed above;
    # the table additionally commits to where each link points so a file<->link
    # swap or a target change is detectable. The table is recorded even when
    # empty so the manifest commits to "zero symlinks here" — a symlink added
    # later is then caught as new. 'none' records nothing at all.
    if symlink_policy != "none":
        links = collect_symlinks(notebook, exclude=exclude)
        manifest["symlink_targets"] = symlink_policy
        manifest["symlinks"] = _build_symlink_table(links, symlink_policy)

    if warnings:
        manifest["warnings"] = warnings

    # "files" goes last: every summary/verdict-relevant field (roots, warnings,
    # symlinks) should be visible at a glance before the per-file detail. Note
    # that signing/TSA-embedding (in main(), after this function returns) can
    # still add keys afterward — _manifest_files_last() re-asserts this order
    # right before the manifest is actually serialised.
    manifest["files"] = files_entry
    return manifest


def _manifest_files_last(manifest: Dict) -> None:
    """Move the 'files' key to the end of the dict's iteration order, in place.

    Re-inserting a key via pop+assign moves it to the end (Python dicts keep a
    key's original position on update, only a fresh insertion appends). Needed
    because signing/TSA-embedding add keys to the manifest after
    generate_manifest() already put 'files' last.
    """
    if "files" in manifest:
        manifest["files"] = manifest.pop("files")


def _lock_file_readonly(path: Path) -> bool:
    """Best-effort mark a file read-only via chmod. Cross-platform: on POSIX
    this clears the write bits; on Windows, Python's chmod maps directly to
    the FILE_ATTRIBUTE_READONLY flag (Explorer's "Read-only" checkbox), no
    subprocess needed.

    This is defense-in-depth, not true WORM: the owner (or root/Administrator)
    can always chmod it back. It protects against accidental overwrite and
    casual tampering, not a privileged attacker. For a real write-once
    guarantee, store the manifest on WORM/object-lock media — see the README
    'File Safety' section.
    """
    try:
        path.chmod(0o444)
        return True
    except OSError:
        return False


# ---------- Verification ----------

def verify_manifest(
    manifest: Dict,
    notebook: Path,
    extra_exclude: Optional[List[str]] = None,
    jobs: int = 1,
    ignore_symlinks: bool = False,
) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {
        "ok": [], "missing": [], "modified": [], "new": [],
        "symlink_ok": [], "symlink_changed": [], "symlink_missing": [], "symlink_new": [],
    }
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

    # ---- Symlink table comparison (schema v2) ----
    # Detects a recorded symlink that vanished or became a regular file
    # (symlink_missing), one whose target changed (symlink_changed), and any
    # symlink present now but not recorded (symlink_new) — e.g. a regular file
    # swapped for a link. Content checks above can't catch identical-content or
    # link<->file swaps, so this is where that tamper-evidence lives.
    policy = manifest.get("symlink_targets")
    recorded = manifest.get("symlinks")
    if not ignore_symlinks and recorded is not None and policy and policy != "none":
        current = collect_symlinks(notebook, exclude=exclude)
        expected_links = {e["path"]: e for e in recorded}
        use_hash = policy.startswith("hash:")
        spec = policy.split(":", 1)[1] if use_hash else None
        for p, entry in expected_links.items():
            if p not in current:
                results["symlink_missing"].append(p)
                continue
            if use_hash:
                matches = _hash_target(current[p], spec) == entry.get("target_hash")
            else:
                matches = current[p] == entry.get("target")
            (results["symlink_ok"] if matches else results["symlink_changed"]).append(p)
        for p in current:
            if p not in expected_links:
                results["symlink_new"].append(p)

    # ---- Move-invariant content-root verification (schema v3) ----
    # Recompute the move-invariant root (leaves sorted by hash value) from the
    # live files and compare to the stored one. A "match" means the exact set of
    # file contents is intact — any path discrepancy is then a relocation, not
    # tampering. Manifests without a content root (older schema) skip this.
    results["moved"] = []
    results["content_root_status"] = []
    if not multi and manifest.get("content_root") is not None:
        m_algo = manifest.get("merkle_hash", ha)
        actual_root = merkle_root(sorted(actual[p][ha] for p in actual), m_algo)
        results["content_root_status"] = (
            ["match"] if actual_root == manifest["content_root"] else ["mismatch"]
        )
    elif multi and manifest.get("content_roots") is not None:
        ok = True
        for a, stored_root in manifest["content_roots"].items():
            actual_root = merkle_root(sorted(actual[p][a] for p in actual if a in actual[p]), a)
            if actual_root != stored_root:
                ok = False
                break
        results["content_root_status"] = ["match"] if ok else ["mismatch"]

    # When the content set matches but paths differ, pair missing↔new entries
    # by identical content so the report can show what moved where.
    if results["content_root_status"] == ["match"]:
        def _sig(d: Dict[str, str]) -> tuple:
            return tuple(sorted(d.items()))
        new_by_sig: Dict[tuple, List[str]] = {}
        for p in results["new"]:
            new_by_sig.setdefault(_sig(actual[p]), []).append(p)
        for p in sorted(results["missing"]):
            cands = new_by_sig.get(_sig(expected[p]))
            if cands:
                results["moved"].append(f"{p} -> {cands.pop(0)}")

    return results


def _write_text_manifest(manifest: Dict, bullets: bool = True) -> str:
    """Serialise a manifest dict to human-readable text format (single or multi).

    When ``bullets`` is True (default), per-file hash lines are prefixed with
    '- ' for readability.  Merkle-root lines are never bulleted (they are
    summary values, not list items).
    """
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
    sb = manifest.get("signed_by", {})
    if sb.get("gpg"):
        lines.append(f"signed_by_gpg: {sb['gpg']}")
    if sb.get("ssh"):
        lines.append(f"signed_by_ssh: {sb['ssh']}")
    # Concatenated tree first (man notes), then individual trees / single root.
    if manifest.get("merkle_root_concat"):
        ca, croot = next(iter(manifest["merkle_root_concat"].items()))
        lines.append(f"merkle_root_concat: {ca} {croot}")
    if multi:
        lines.append("merkle_roots:")
        for a in sorted(manifest.get("merkle_roots", {})):
            lines.append(f"         {a}: {manifest['merkle_roots'][a]}")
        if manifest.get("content_roots"):
            lines.append("content_roots:")
            for a in sorted(manifest["content_roots"]):
                lines.append(f"         {a}: {manifest['content_roots'][a]}")
    else:
        lines.append(f"merkle_root: {manifest.get('merkle_root', '')}")
        if manifest.get("content_root"):
            lines.append(f"content_root: {manifest['content_root']}")
    # Manifest chaining: one inline-JSON header line, same round-trip approach
    # as the TSA fields below (a nested dict doesn't fit the flat key: value
    # header format otherwise).
    if manifest.get("prev"):
        lines.append(f"prev: {json.dumps(manifest['prev'], ensure_ascii=False)}")
    # Embedded TSA stamps: one inline-JSON header line per field, so the token
    # round-trips exactly through the text format.
    for _tf in TSA_FIELDS:
        if manifest.get(_tf):
            lines.append(f"{_tf}: {json.dumps(manifest[_tf], ensure_ascii=False)}")
    # Symlink table (schema v2): a numbered "path -> target" list, with the
    # recording policy noted on the header line so verify knows how to compare.
    # Written even when empty so the manifest still commits to "zero symlinks".
    if "symlinks" in manifest:
        policy = manifest.get("symlink_targets", "hash:sha256")
        lines += ["", f"symlinks: (targets: {policy})"]
        for i, entry in enumerate(manifest["symlinks"], 1):
            tgt = entry.get("target", entry.get("target_hash", ""))
            lines.append(f"  {i:>5}. {entry['path']} -> {tgt}")

    bullet = "- " if bullets else ""
    lines += ["", "files:"]
    for i, entry in enumerate(manifest["files"], 1):
        lines.append(f"  {i:>5}. {entry['path']}")
        if multi:
            for a in algos:
                lines.append(f"         {bullet}{a}: {entry['hashes'][a]}")
        else:
            lines.append(f"         {bullet}{ha}: {entry[ha]}")
    return "\n".join(lines) + "\n"


def _parse_text_manifest(text: str) -> Dict:
    """Parse a text-format manifest back to a dict (single or multi mode)."""
    import re as _re
    manifest: Dict = {}
    raw_files: List[Dict] = []      # [{"path":p, "_hashes":{algo:hash}}]
    merkle_roots: Dict[str, str] = {}
    content_roots: Dict[str, str] = {}
    sym_entries: List[tuple] = []   # [(path, target_or_hash)]
    sym_policy: Optional[str] = None
    saw_symlinks = False            # header seen, even if the table is empty
    section = "header"              # header → merkle_roots → symlinks → files
    current: Optional[Dict] = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("rednb-verify manifest"):
            # The "tool" field is implied by this banner in text format;
            # reconstruct it so the parsed dict matches the JSON schema.
            manifest["tool"] = "rednb-verify"
            continue
        if not stripped:
            continue
        if stripped == "files:":
            section = "files"
            continue
        if stripped == "merkle_roots:":
            section = "merkle_roots"
            continue
        if stripped == "content_roots:":
            section = "content_roots"
            continue
        if stripped.startswith("symlinks:"):
            section = "symlinks"
            saw_symlinks = True
            m = _re.search(r"targets:\s*([^)]+)", stripped)
            sym_policy = m.group(1).strip() if m else "hash:sha256"
            continue
        if section == "header":
            if ": " in stripped:
                key, _, val = stripped.partition(": ")
                manifest[key.strip()] = val.strip()
        elif section == "merkle_roots":
            if ": " in stripped:
                a, _, root = stripped.partition(": ")
                merkle_roots[a.strip()] = root.strip()
        elif section == "content_roots":
            if ": " in stripped:
                a, _, root = stripped.partition(": ")
                content_roots[a.strip()] = root.strip()
        elif section == "symlinks":
            m = _re.match(r"\d+\.\s+(.+?)\s+->\s+(.*)$", stripped)
            if m:
                sym_entries.append((m.group(1).strip(), m.group(2).strip()))
        else:  # files
            m = _re.match(r"\d+\.\s+(.+)", stripped)
            if m:
                current = {"path": m.group(1).strip(), "_hashes": {}}
                raw_files.append(current)
            else:
                # Tolerate an optional '- ' bullet prefix on hash lines.
                h_line = stripped[2:] if stripped.startswith("- ") else stripped
                if ": " in h_line and current is not None:
                    a, _, h = h_line.partition(": ")
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
        if content_roots:
            manifest["content_roots"] = content_roots

    # Rebuild the symlink table from the parsed entries (empty table preserved).
    if saw_symlinks:
        policy = sym_policy or "hash:sha256"
        manifest["symlink_targets"] = policy
        key = "target_hash" if policy.startswith("hash:") else "target"
        manifest["symlinks"] = [{"path": p, key: t} for p, t in sym_entries]

    # exclude / warnings stored as comma-separated strings — convert to lists
    for _list_key in ("exclude", "warnings"):
        if _list_key in manifest and isinstance(manifest[_list_key], str):
            manifest[_list_key] = [e.strip() for e in manifest[_list_key].split(",") if e.strip()]
    # signed_by reconstructed from signed_by_gpg / signed_by_ssh header lines
    sb: Dict[str, str] = {}
    _g = manifest.pop("signed_by_gpg", None)
    _s = manifest.pop("signed_by_ssh", None)
    if _g:
        sb["gpg"] = _g
    if _s:
        sb["ssh"] = _s
    if sb:
        manifest["signed_by"] = sb
    # schema_version is numeric
    if "schema_version" in manifest:
        try:
            manifest["schema_version"] = int(manifest["schema_version"])
        except (TypeError, ValueError):
            pass
    # Manifest chaining: "prev" was written as inline JSON — rebuild the dict.
    if isinstance(manifest.get("prev"), str):
        try:
            manifest["prev"] = json.loads(manifest["prev"])
        except json.JSONDecodeError:
            pass
    # Embedded TSA stamps were written as inline JSON — rebuild the dicts.
    for _tf in TSA_FIELDS:
        if isinstance(manifest.get(_tf), str):
            try:
                manifest[_tf] = json.loads(manifest[_tf])
            except json.JSONDecodeError:
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
    # Content-root status + moved files (schema v3).
    _crs = results.get("content_root_status") or []
    if _crs:
        lines.append(f"{'Content root:':<14} {_crs[0]}")
    if results.get("moved"):
        lines.append(f"{'Moved:':<14} {len(results['moved'])}")
    # Symlink tallies (schema v2) — only shown when the manifest carried a table.
    _sym_keys = ("symlink_ok", "symlink_changed", "symlink_missing", "symlink_new")
    if any(results.get(k) for k in _sym_keys):
        lines += [
            "",
            f"{'Symlinks OK:':<14} {len(results['symlink_ok'])}",
            f"{'Sym changed:':<14} {len(results['symlink_changed'])}",
            f"{'Sym removed:':<14} {len(results['symlink_missing'])}",
            f"{'Sym new:':<14} {len(results['symlink_new'])}",
        ]
    sections = [
        ("OK", "ok"), ("NEW", "new"), ("MISSING", "missing"), ("MODIFIED", "modified"),
        ("MOVED", "moved"),
        ("SYMLINK CHANGED", "symlink_changed"),
        ("SYMLINK REMOVED", "symlink_missing"),
        ("SYMLINK NEW", "symlink_new"),
    ]
    for label, key in sections:
        if results.get(key):
            numbered = [f"  {i:>5}. {f}" for i, f in enumerate(sorted(results[key]), 1)]
            lines += ["", f"--- {label} ---"] + numbered
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _resolve_manifest_path(arg: str, out_dir: Path, label: str = "manifest") -> Path:
    """Resolve a --verify / --validate / --prev-manifest argument to a manifest
    file path.

    Accepts an explicit file, a directory to search for the latest manifest, or
    the '__auto__' sentinel (search the output directory). `label` only affects
    the messages printed (default "manifest", matching the original behaviour);
    --prev-manifest passes "previous manifest" so its messages read clearly.
    """
    if arg == "__auto__":
        arg = str(out_dir)
    target = Path(arg)
    if target.is_dir():
        _info(f"Directory provided for {label}, choosing latest")
        candidates = sorted(
            list(target.glob("hashes-*.json")) + list(target.glob("hashes-*.txt"))
        )
        if not candidates:
            _err(f"No {label} found in {target}")
            sys.exit(2)
        _info(f"Using latest {label}: {candidates[-1].name}")
        return candidates[-1]
    target = target.resolve()
    if not target.exists():
        _err(f"{label.capitalize()} not found: {target}" + _bad_path_hint(arg))
        sys.exit(2)
    return target


def compute_prev_link(prev_path: Path, hash_specs: List[str]) -> Dict:
    """Build the 'prev' chain-link field for --prev-manifest: hash(es) of the
    PREVIOUS manifest FILE's raw bytes (not its parsed contents -- the same
    "hash the file as written" approach --tsa already uses), plus enough of
    its own metadata (filename, created, height) to inspect the chain without
    opening every prior manifest.

    Called before signing, so the signature covers the link -- altering an
    earlier manifest breaks its hash here and every link after it.
    """
    hashes = hash_file_multi(prev_path, hash_specs)
    prev_manifest = _load_manifest(prev_path)
    prev_height = 0
    prev_chain = prev_manifest.get("prev")
    if isinstance(prev_chain, dict):
        try:
            prev_height = int(prev_chain.get("height", 0))
        except (TypeError, ValueError):
            prev_height = 0
    return {
        "file": prev_path.name,
        "created": prev_manifest.get("created", ""),
        "height": prev_height + 1,
        "hashes": hashes,
    }


def verify_chain(manifest_path: Path, manifest: Dict) -> tuple:
    """Walk a manifest chain backward from `manifest`, verifying each link's
    stored hash(es) against the actual previous-manifest file, all the way to
    genesis (the first manifest with no 'prev' field) or the first broken
    link. Previous manifests are expected alongside the current one (i.e. in
    manifest_path's own directory) since 'prev.file' stores a bare filename.

    Returns (status, detail):
      "no-chain" -- manifest has no 'prev' field; nothing to check
      "ok"       -- every link back to genesis verified; detail says how many
      "broken"   -- a hash mismatch was found -- the linked file was altered
                    after being chained (tampering signal, not inconclusive)
      "missing"  -- a previous manifest file could not be found/read/parsed
                    (inconclusive: can't confirm, but doesn't prove tampering
                    -- e.g. the operator may have deliberately pruned old
                    manifests)
    """
    prev = manifest.get("prev")
    if not isinstance(prev, dict):
        return "no-chain", ""
    current_dir = manifest_path.parent
    depth = 0
    while isinstance(prev, dict):
        depth += 1
        prev_file = prev.get("file", "")
        prev_path = current_dir / prev_file
        hashes = prev.get("hashes", {})
        if not prev_file or not hashes:
            return "missing", f"link {depth} has an incomplete 'prev' record"
        if not prev_path.exists():
            return "missing", f"{prev_file} (link {depth}) not found in {current_dir}"
        try:
            actual = hash_file_multi(prev_path, list(hashes.keys()))
        except (OSError, ValueError) as exc:
            return "missing", f"{prev_file} (link {depth}) could not be hashed: {exc}"
        if actual != hashes:
            return "broken", (f"{prev_file} (link {depth}) hash mismatch -- it was "
                              "altered after being chained")
        try:
            prev_manifest = _load_manifest(prev_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            return "missing", f"{prev_file} (link {depth}) could not be parsed: {exc}"
        prev = prev_manifest.get("prev")
    return "ok", f"verified {depth} link(s) back to genesis"


# JSON Schemas are EMBEDDED here as the single source of truth so --validate is
# self-contained — it works from the single downloaded rednb-verify.py with no
# sibling schema/ folder. The schema/*.json files are exports generated from
# these dicts (see --dump-schema); a test asserts they stay in sync.
_TSA_ENTRY_SCHEMA: Dict = {
    "type": "object",
    "required": ["tsa", "token_b64"],
    "properties": {
        "tsa": {"type": "string", "description": "TSA URL the token came from"},
        "time": {"type": "string", "description": "Asserted timestamp (informational)"},
        "token_b64": {"type": "string", "description": "Base64 RFC 3161 token (.tsr bytes)"},
    },
    "additionalProperties": False,
}

# A tsa_* field is either a token entry or the literal "failed" marker (a stamp
# that was attempted but couldn't be obtained — see --resign to add one later).
_TSA_FIELD_SCHEMA: Dict = {"oneOf": [_TSA_ENTRY_SCHEMA, {"const": "failed"}]}

# Manifest chaining (--prev-manifest): links this manifest to the previous one
# by hash of its raw file bytes, so the SEQUENCE of manifests is tamper-evident
# (altering an earlier manifest breaks every link after it). Optional field,
# schema v3 -- no version bump, same as how the tsa_* fields were added.
_PREV_SCHEMA: Dict = {
    "type": "object",
    "required": ["file", "hashes"],
    "properties": {
        "file": {"type": "string", "description": "Filename of the previous manifest in the chain"},
        "created": {"type": "string", "description": "The previous manifest's own 'created' timestamp (informational)"},
        "height": {"type": "integer", "minimum": 1, "description": "Position in the chain (1 = first link after genesis)"},
        "hashes": {
            "type": "object",
            "minProperties": 1,
            "additionalProperties": {"type": "string"},
            "description": "Hash(es) of the previous manifest FILE's raw bytes, keyed by algorithm spec (--prev-hash)",
        },
    },
    "additionalProperties": False,
}

MANIFEST_SCHEMA: Dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://github.com/meshconsole/rednb-verify/schema/manifest-v3.schema.json",
    "title": "rednb-verify manifest (schema version 3)",
    "type": "object",
    "required": ["tool", "schema_version", "created", "date", "mode", "hash_algorithm", "files"],
    "properties": {
        "tool": {"const": "rednb-verify"},
        "version": {"type": "string"},
        "schema_version": {"type": "integer", "minimum": 2},
        "created": {
            "type": "string",
            "pattern": "^[0-9]{8}T[0-9]{6}Z$",
            "description": "UTC creation stamp, e.g. 20260617T120000Z",
        },
        "date": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
        "mode": {
            "enum": [
                "full-tree",
                "month-only",
                "per-day/full-tree",
                "per-day/month-only",
                "per-day",
                "month-files",
            ]
        },
        "hash_algorithm": {
            "oneOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}, "minItems": 1},
            ]
        },
        "merkle_hash": {"type": "string"},
        "files": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": {"type": "string"},
                    "hashes": {
                        "type": "object",
                        "minProperties": 1,
                        "additionalProperties": {"type": "string"},
                    },
                },
                "oneOf": [
                    {"required": ["hashes"]},
                    {"allOf": [{"not": {"required": ["hashes"]}}, {"minProperties": 2}]},
                ],
            },
        },
        "merkle_root": {"type": "string"},
        "merkle_roots": {"type": "object", "additionalProperties": {"type": "string"}},
        "merkle_root_concat": {"type": "object", "additionalProperties": {"type": "string"}},
        "content_root": {
            "type": "string",
            "description": "Move-invariant Merkle root over the multiset of file content hashes (schema v3)",
        },
        "content_roots": {
            "type": "object",
            "additionalProperties": {"type": "string"},
            "description": "Per-algorithm move-invariant content roots, multi-hash mode (schema v3)",
        },
        "exclude": {"type": "array", "items": {"type": "string"}},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "signed_by": {
            "type": "object",
            "properties": {"gpg": {"type": "string"}, "ssh": {"type": "string"}},
            "additionalProperties": False,
        },
        "symlink_targets": {
            "type": "string",
            "pattern": "^(none|full|hash:.+)$",
            "description": "How symlink targets are recorded: 'full', or 'hash:<algo-spec>'",
        },
        "symlinks": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": {"type": "string"},
                    "target": {"type": "string"},
                    "target_hash": {"type": "string"},
                },
                "oneOf": [{"required": ["target"]}, {"required": ["target_hash"]}],
            },
        },
        "tsa_stamp": _TSA_FIELD_SCHEMA,
        "tsa_merkle": _TSA_FIELD_SCHEMA,
        "tsa_concat": _TSA_FIELD_SCHEMA,
        "tsa_content": _TSA_FIELD_SCHEMA,
        "prev": _PREV_SCHEMA,
    },
}

REPORT_SCHEMA: Dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://github.com/meshconsole/rednb-verify/schema/report-v1.schema.json",
    "title": "rednb-verify verification report (--report json)",
    "type": "object",
    "required": ["ok", "missing", "modified", "new"],
    "properties": {
        "ok": {"type": "array", "items": {"type": "string"}},
        "missing": {"type": "array", "items": {"type": "string"}},
        "modified": {"type": "array", "items": {"type": "string"}},
        "new": {"type": "array", "items": {"type": "string"}},
        "moved": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Relocated files as 'old/path -> new/path' (schema v3 move detection)",
        },
        "content_root_status": {
            "type": "array",
            "items": {"enum": ["match", "mismatch"]},
            "maxItems": 1,
            "description": "['match'] when the move-invariant content root verifies; [] if absent",
        },
        "symlink_ok": {"type": "array", "items": {"type": "string"}},
        "symlink_changed": {"type": "array", "items": {"type": "string"}},
        "symlink_missing": {"type": "array", "items": {"type": "string"}},
        "symlink_new": {"type": "array", "items": {"type": "string"}},
    },
}

EMBEDDED_SCHEMAS: Dict[str, Dict] = {"manifest": MANIFEST_SCHEMA, "report": REPORT_SCHEMA}


def validate_against_schema(obj: Dict, schema_name: str, *, required: bool = True
                            ) -> Optional[List[str]]:
    """Validate an object against an EMBEDDED schema ('manifest' or 'report').

    Returns a list of human-readable error strings ([] means valid), or None
    when the optional 'jsonschema' package is unavailable. With required=True
    (the explicit --validate path) a missing package exits(2) with install
    guidance; with required=False (best-effort auto-validate) it returns None
    so a stdlib-only install never blocks.
    """
    try:
        import jsonschema
    except ImportError:
        if required:
            _err("--validate needs the optional 'jsonschema' package: "
                 "pip install jsonschema")
            sys.exit(2)
        return None
    validator = jsonschema.Draft202012Validator(EMBEDDED_SCHEMAS[schema_name])
    errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]


def _schema_for(obj: Dict, path: Path) -> str:
    """Pick the right embedded schema for a loaded object: 'manifest' or 'report'."""
    if "tool" in obj or "files" in obj:
        return "manifest"
    if path.name.startswith("report") or any(
        k in obj for k in ("ok", "missing", "modified", "new")
    ):
        return "report"
    return "manifest"


def validate_manifest_schema(manifest: Dict, *, required: bool = True
                             ) -> Optional[List[str]]:
    """Validate a manifest dict against the embedded manifest schema."""
    return validate_against_schema(manifest, "manifest", required=required)


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


def _confirm_sign(warning_box: str, prompt: str, yes: bool) -> bool:
    """Show the non-repudiation warning and confirm. -y / --quiet auto-confirm."""
    if _quiet or yes:
        return True
    print(warning_box)
    return input(prompt).strip().lower() == "y"


def resolve_gpg_signer(
    key_fpr: Optional[str],
    key_file: Optional[Path],
    trust_level: str,
    config: Dict,
    yes: bool,
) -> Optional[str]:
    """Resolve a GPG signing fingerprint: randomart → trust gate → confirm.

    Returns the fingerprint to sign with, or None if unavailable/cancelled.
    May exit(3) under --trust high with an untrusted key.
    """
    if not gpg_available():
        _warn("GPG not available — GPG signing skipped.")
        return None

    if key_file:
        fpr = gpg_fingerprint_from_keyfile(key_file)
        if not fpr:
            _warn("Could not read GPG key file — GPG signing skipped.")
            return None
    else:
        try:
            keys = list_secret_keys()
        except subprocess.CalledProcessError:
            _warn("Could not list GPG keys.")
            return None
        if not keys:
            _warn("No GPG secret keys found — GPG signing skipped.")
            return None
        if key_fpr:
            fpr = _normalize_gpg_fpr(key_fpr)
        elif _quiet or yes:
            if len(keys) == 1:
                fpr = _normalize_gpg_fpr(keys[0]["fingerprint"])
            else:
                _err("--quiet/-y with --gpg needs a fingerprint when multiple keys exist.")
                _err(f"        Use: --gpg {keys[0]['fingerprint']}")
                sys.exit(2)
        else:
            sel = choose_gpg_key(keys)
            if sel is None:
                _info("GPG signing cancelled.")
                return None
            fpr = _normalize_gpg_fpr(sel)

    show_randomart_gpg(fpr)
    trust_gate_signing("gpg", fpr, trust_level, config)   # may exit(3)
    if not _confirm_sign(NON_REPUDIATION_WARNING,
                         "Sign this manifest with GPG? [y/N]: ", yes):
        _info("GPG signing cancelled.")
        return None
    return fpr


def resolve_ssh_signer(
    ssh_key_path: Path,
    prefer_fido: bool,
    keyname: Optional[str],
    trust_level: str,
    config: Dict,
    yes: bool,
) -> Optional[SshKeyCandidate]:
    """Resolve an SSH signing key: randomart → trust gate → confirm."""
    if not ssh_keygen_available():
        _warn("ssh-keygen not available — SSH signing skipped.")
        return None
    signer = select_ssh_key(ssh_key_path, require_private=True,
                            prefer_fido=prefer_fido, keyname=keyname)
    if signer is None or signer.priv_path is None:
        _warn("No suitable SSH key found for signing.")
        return None
    fpr = ssh_key_fingerprint(signer.pub_path)
    show_randomart_ssh(signer.pub_path)
    trust_gate_signing("ssh", fpr, trust_level, config)   # may exit(3)
    if not _confirm_sign(SSH_NON_REPUDIATION_WARNING,
                         "Sign this manifest with SSH? [y/N]: ", yes):
        _info("SSH signing cancelled.")
        return None
    return signer


def do_gpg_sign(manifest_path: Path, fpr: str, key_file: Optional[Path]) -> bool:
    """Perform the GPG signature (keyfile via temp homedir, else keyring)."""
    if key_file:
        return _gpg_sign_with_keyfile(manifest_path, key_file)
    return gpg_detach_sign(manifest_path, fpr)


class ConciseArgumentParser(argparse.ArgumentParser):
    """On a usage error, print a short message + hint instead of the full usage
    block (the industry-standard pattern: `git`, `ls`, `cargo`, …)."""

    def error(self, message: str):
        _err(message)
        sys.stderr.write(f"See '{self.prog} --help' for usage.\n")
        sys.exit(2)


def main():
    global _quiet, _verbose, _json_mode

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

    parser = ConciseArgumentParser(
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
  1  verification found issues (modified/missing/new files, invalid or untrusted signature)
  2  usage or input error (bad arguments, missing files, unsupported algorithm)
  3  signing refused (untrusted key under --trust high)

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
                        help="Output directory for the manifest (create) or the report "
                             "(verify; requires --report). Default: parent of the journal "
                             "directory. With --verify it does NOT choose which manifest to "
                             "verify — pass that to --verify.")
    parser.add_argument("--verify", nargs="?", const="__auto__", default=None,
                        metavar="MANIFEST_OR_DIR",
                        help="Verify mode: path to a manifest file, or directory to search "
                             "for the latest manifest. Without argument, searches the output "
                             "directory (journal parent by default).")
    parser.add_argument("--manifest-type", nargs="?", const="txt", default="txt",
                        metavar="txt|json", dest="manifest_type",
                        help="Manifest creation format: txt (default) or json")
    parser.add_argument("--report", nargs="?", const="txt", default=None,
                        metavar="txt|json",
                        help="Write a verification report file (txt or json). When omitted, "
                             "--verify prints the verdict only and writes no report. "
                             "-o/--output sets where the report goes and requires this flag.")
    parser.add_argument("--json", action="store_true", dest="json",
                        help="Emit the result (manifest on create, report on verify) as a "
                             "single JSON document on stdout for piping; all logs go to stderr")
    parser.add_argument("--no-bullets", action="store_true", dest="no_bullets",
                        help="Text manifest: don't prefix per-file hash lines with '- '")
    parser.add_argument("--hash", default=HASH_ALGO, dest="hash_algo", metavar="ALGO[,ALGO...]",
                        help="Hash algorithm(s) for files (default: sha256). Comma-separate "
                             "for multi-hashing, e.g. sha256,blake2b")
    parser.add_argument("--hash-list", action="store_true",
                        help="Print available hash algorithms and exit")
    parser.add_argument("--dump-schema", nargs="?", const="manifest", default=None,
                        dest="dump_schema", metavar="manifest|report",
                        help="Print the embedded JSON schema (manifest or report) to "
                             "stdout and exit — e.g. to regenerate schema/*.json")
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
    parser.add_argument("--ignore-sig", action="store_true", dest="ignore_sig",
                        help="During --verify, check integrity only and skip all "
                             "signature checks (returns 0 when hashes match)")
    parser.add_argument("--ignore-symlinks", action="store_true", dest="ignore_symlinks",
                        help="During --verify, skip the symlink-table comparison and "
                             "symlink warnings (parallel to --ignore-sig)")
    parser.add_argument("--ignore-chain", action="store_true", dest="ignore_chain",
                        help="During --verify, skip manifest chain verification "
                             "(parallel to --ignore-sig/--ignore-symlinks/--ignore-tsa)")
    parser.add_argument("--files-only", action="store_true", dest="files_only",
                        help="During --verify, skip checks that aren't about the files "
                             "themselves: signatures, TSA timestamps, and manifest chain "
                             "verification. Shorthand for --ignore-sig --ignore-tsa "
                             "--ignore-chain together. Symlinks are still checked -- "
                             "use --ignore-symlinks separately if you want those skipped "
                             "too.")
    parser.add_argument("--sig", type=str, default=None, metavar="FILE[,FILE]",
                        help="Signature file(s), comma-separated (.asc=GPG, .sshsig/.sig=SSH)")
    parser.add_argument("--ssh-fido", nargs="?", const="", metavar="KEYNAME",
                        help="Prefer FIDO2 hardware keys; optional name filter")
    parser.add_argument("--no-sign", action="store_true",
                        help="Skip all signing")
    parser.add_argument("--resign", type=Path, default=None, metavar="MANIFEST",
                        help="Re-sign an existing manifest (requires --gpg and/or --ssh)")
    parser.add_argument("--lock", action="store_true",
                        help="After writing, chmod the manifest (and any .asc/.sshsig/.sig/"
                             ".tsr sidecar) read-only. Best-effort defense-in-depth against "
                             "accidental overwrite/tampering, not true WORM — the owner can "
                             "still chmod it back. See README 'File Safety' for real "
                             "write-once storage options.")
    # --- Manifest chaining: link this manifest to the previous one by hash,
    # making the SEQUENCE of manifests tamper-evident. ---
    parser.add_argument("--prev-manifest", type=str, default=None, metavar="FILE|DIR",
                        dest="prev_manifest",
                        help="Link to a previous manifest by hash (manifest chaining). "
                             "A directory auto-selects its latest manifest, like --verify.")
    parser.add_argument("--prev-hash", default=None, dest="prev_hash_algo",
                        metavar="ALGO[:LEN][,ALGO...]",
                        help="Hash algorithm(s) for the --prev-manifest link (default: "
                             "sha256). Comma-separate for multiple algorithms, same "
                             "syntax as --hash. Requires --prev-manifest.")
    # --- Timestamping (RFC 3161) — the ONLY flags that can touch the network ---
    parser.add_argument("--tsa", default=None, metavar="NAME|URL",
                        help="Request an RFC 3161 timestamp at create time from a known "
                             "TSA name (see --tsa-list) or an http(s) URL. Saves a detached "
                             "token next to the manifest (hashes-....tsr) unless an embed "
                             "flag is given. This is the tool's only network operation.")
    parser.add_argument("--tsa-embed", action="store_true", dest="tsa_embed",
                        help="With --tsa: embed ONE stamp over the placement root "
                             "(merkle_root, or the concat root in multi-hash mode) as "
                             "'tsa_stamp' instead of writing a detached token (1 request)")
    parser.add_argument("--tsa-embed-separate", action="store_true", dest="tsa_embed_separate",
                        help="With --tsa: embed SEPARATE stamps for the placement root "
                             "(tsa_merkle/tsa_concat) and the content root (tsa_content) "
                             "so each can be attested independently (2 requests)")
    parser.add_argument("--tsa-cert", type=Path, default=None, dest="tsa_cert", metavar="CAFILE",
                        help="TSA CA certificate used to verify timestamp tokens during "
                             "--verify (verification is fully local)")
    parser.add_argument("--ignore-tsa", action="store_true", dest="ignore_tsa",
                        help="During --verify, skip all timestamp-token checks "
                             "(parallel to --ignore-sig)")
    parser.add_argument("--tsa-list", action="store_true", dest="tsa_list",
                        help="Print the built-in TSA registry (names and URLs) and exit — "
                             "no network")
    parser.add_argument("--offline", action="store_true",
                        help="Assert that no network is used: refuses --tsa. The tool is "
                             "offline by default; this makes it explicit")
    parser.add_argument("--install-opt", action="store_true", dest="install_opt",
                        help="Permit the tool to 'pip install' the optional Python "
                             "packages a command needs (pyyaml/jsonschema/rfc3161ng/…). "
                             "Alone, installs all missing optional packages and exits. "
                             "The only path that runs pip; nothing installs without it.")
    parser.add_argument("--warn-age", type=int, default=None, dest="warn_age", metavar="DAYS",
                        help="Warn during --verify if manifest is older than N days")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print per-file hash timing and detailed progress")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress non-error output; implies --no-sign unless signing is explicit")
    parser.add_argument("--exclude", action="append", metavar="PATTERN",
                        help="Exclude files matching glob pattern (repeatable)")
    parser.add_argument("--exclude-from", type=Path, default=None, metavar="FILE",
                        help="File of glob patterns to exclude (one literal pattern per line)")
    parser.add_argument("-j", "--jobs", type=int, default=DEFAULT_JOBS, metavar="N",
                        help="Parallel hashing workers (0 = auto/all cores; "
                             f"default: max(1, cores-2) = {DEFAULT_JOBS} on this machine)")
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
    parser.add_argument("--symlink-targets", default="hash", dest="symlink_targets",
                        metavar="none|full|hash[:ALGO[:LEN]]",
                        help="How to record symlink targets (default: hash = sha256 of "
                             "the target). 'full' stores the cleartext target; 'none' "
                             "omits the table.")
    parser.add_argument("--no-symlink-table", action="store_true", dest="no_symlink_table",
                        help="Omit the symlink table (alias for --symlink-targets none).")
    parser.add_argument("--privacy", action="store_true",
                        help="Minimise disclosure in the manifest (currently implies "
                             "--no-symlink-table).")
    parser.add_argument("--validate", nargs="?", const="__auto__", default=None,
                        metavar="MANIFEST_OR_DIR",
                        help="Validate a manifest against the JSON schema and exit "
                             "(requires the optional 'jsonschema' package).")
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
    _json_mode = args.json

    if args.quiet and args.verbose:
        _err("--quiet and --verbose are mutually exclusive.")
        sys.exit(2)

    # ---- --dump-schema: print an embedded JSON schema and exit ----
    if args.dump_schema is not None:
        if args.dump_schema not in EMBEDDED_SCHEMAS:
            _err(f"--dump-schema must be 'manifest' or 'report', got: {args.dump_schema!r}")
            sys.exit(2)
        print(json.dumps(EMBEDDED_SCHEMAS[args.dump_schema], indent=2, ensure_ascii=False))
        return

    # ---- --tsa-list: print the TSA registry and exit (no network) ----
    if args.tsa_list:
        print("Known timestamp authorities (use with --tsa <name>, or pass any URL):")
        for name in sorted(TSA_SERVERS):
            e = TSA_SERVERS[name]
            tag = "" if e.key_type == "RSA" else "  [EC: needs openssl to verify locally]"
            print(f"  {name:<12} {e.url}{tag}")
            if e.ca_url:
                print(f"  {'':<12}   CA certs: {e.ca_url}")
        print()
        print("Key type: RSA hosts can be verified by this tool alone (bundled")
        print("rfc3161ng backend). EC hosts (marked) need openssl on PATH to verify")
        print("locally. Pass a provider's root/intermediate to --tsa-cert at --verify,")
        print("or omit it to try your system trust store.")
        return

    # ---- --install-opt alone: install every missing optional package, exit ----
    if (args.install_opt and args.notebook_dir is None and args.verify is None
            and args.validate is None and args.resign is None):
        install_all_optional()
        return

    # ---- Timestamping flag validation (network is strictly opt-in) ----
    if args.offline and args.tsa:
        _err("--offline forbids network flags: remove --tsa (the tool is "
             "offline by default; --offline makes that explicit).")
        sys.exit(2)
    if (args.tsa_embed or args.tsa_embed_separate) and not args.tsa:
        _err("--tsa-embed/--tsa-embed-separate require --tsa <name|url>.")
        sys.exit(2)
    if args.tsa_embed and args.tsa_embed_separate:
        _err("--tsa-embed and --tsa-embed-separate are mutually exclusive.")
        sys.exit(2)
    tsa_url: Optional[str] = None
    if args.tsa:
        if args.verify is not None:
            _err("--tsa is a create-time flag; to check a token during --verify, "
                 "pass --tsa-cert CAFILE (or --ignore-tsa to skip).")
            sys.exit(2)
        _warn("--tsa is an EXPERIMENTAL feature (network + a new code path). "
              "See README 'Trusted Timestamping' for what's been tested so far.")
        # openssl-or-library availability is enforced by preflight_dependencies().
        tsa_url = resolve_tsa(args.tsa)

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
    if args.report is not None and args.report not in ("txt", "json"):
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

    # notebook_dir: fall back to saved config "dir" when none given (Feature 1).
    # --validate works on a manifest alone, so it doesn't need a notebook dir.
    if args.notebook_dir is None and not args.resign and args.validate is None:
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

    # --files-only: at --verify, skip every check that does NOT directly
    # examine the files themselves -- signatures, TSA timestamps, and manifest
    # chain history are all checks on metadata/provenance, not on file
    # content. Symlinks are NOT included here: a symlink is a monitored
    # filesystem entry like any other, so --ignore-symlinks stays a separate,
    # deliberate opt-out rather than something --files-only silently implies.
    if args.files_only:
        args.ignore_sig = True
        args.ignore_tsa = True
        args.ignore_chain = True

    # Resolve effective trust level (CLI > config > "low") and warn if mis-set.
    trust_level = resolve_trust_level(args.trust, config)
    if trust_level == "high":
        _trust = config.get("trust", {})
        if not _trust.get("gpg") and not _trust.get("ssh"):
            _warn_security("Trust level is HIGH but no keys are pinned. "
                           "All signing will be refused. "
                           "Use --add-trust or --set-cf to pin fingerprints.")

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

    # --prev-hash may carry multiple comma-separated algos, same as --hash;
    # requires --prev-manifest (mirrors --tsa-embed requiring --tsa).
    if args.prev_hash_algo is not None and args.prev_manifest is None:
        _err("--prev-hash requires --prev-manifest.")
        sys.exit(2)
    if args.prev_manifest is not None and args.resign:
        _err("--prev-manifest cannot be combined with --resign (chaining only "
             "applies when a NEW manifest is created — --resign never rewrites "
             "manifest content, only adds a signature).")
        sys.exit(2)
    args.prev_hash_specs = []
    if args.prev_manifest is not None:
        prev_hash_specs = [a.strip() for a in (args.prev_hash_algo or "sha256").split(",")
                           if a.strip()]
        if not prev_hash_specs:
            _err("--prev-hash requires at least one algorithm.")
            sys.exit(2)
        for spec in prev_hash_specs:
            _validate_algo_spec_or_exit(spec, "--prev-hash")
        args.prev_hash_specs = prev_hash_specs

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
        # Each non-blank line is a literal glob pattern. No comment syntax:
        # a journal file may legitimately start with '#'.
        for raw_line in excf.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line:
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
    elif args.notebook_dir is not None:
        out_dir = (args.output or args.notebook_dir.resolve().parent).resolve()
    else:
        # --validate with no notebook dir: search/anchor at the cwd.
        out_dir = (args.output or Path.cwd()).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Check the requested operation's optional/external dependencies up front,
    # before any hashing — so a missing lib/tool is a clear message, not a
    # mid-run failure. May install (only with --install-opt) or exit.
    preflight_dependencies(args)

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
        # C3: --resign never rewrites the manifest (would break existing sigs),
        # so signed_by is not updated here.
        _ok(f"Re-signing: {manifest_path.name}")
        if want_gpg:
            fpr = resolve_gpg_signer(args.gpg or None, args.gpg_k, trust_level, config, args.yes)
            if fpr:
                if do_gpg_sign(manifest_path, fpr, args.gpg_k):
                    _ok("Manifest signed with GPG")
                else:
                    _warn("GPG signing failed")
        if want_ssh:
            signer = resolve_ssh_signer(ssh_key_path, prefer_fido, keyname,
                                        trust_level, config, args.yes)
            if signer:
                if ssh_sign_manifest(manifest_path, signer.priv_path, ssh_sig_out):
                    _ok(f"SSH signature created: {ssh_sig_out.name}")
                else:
                    _warn("SSH signing failed")
        return

    # ------------------------------------------------------------------ #
    #  Validate mode (JSON schema check only)                             #
    # ------------------------------------------------------------------ #
    if args.validate is not None:
        doc_path = _resolve_manifest_path(args.validate, out_dir)
        try:
            doc = _load_manifest(doc_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            _err(f"Could not read file: {exc}")
            sys.exit(2)
        schema_name = _schema_for(doc, doc_path)
        kind = "Report" if schema_name == "report" else "Manifest"
        errors = validate_against_schema(doc, schema_name, required=True)
        if errors:
            _err(f"{kind} failed schema validation ({len(errors)} error(s)):")
            for e in errors:
                _err(f"  {e}")
            sys.exit(1)
        _ok(f"{kind} is schema-valid: {doc_path.name}")
        return

    # ------------------------------------------------------------------ #
    #  Verify mode                                                         #
    # ------------------------------------------------------------------ #
    if args.verify is not None:
        # -o/--output only directs the report file. With --verify it does
        # nothing unless a report is being generated, and it never selects which
        # manifest to verify (that is the --verify argument). Erroring here stops
        # the silent confusion of "-o picked the wrong/old manifest".
        if args.output is not None and args.report is None:
            _err("-o/--output only sets where a report is written; with --verify it "
                 "has no effect unless you also pass --report txt|json.")
            _err("        To choose which manifest to verify, pass it to --verify "
                 "(a file or a directory), e.g. --verify .testing/output")
            sys.exit(2)

        if not args.notebook_dir.is_dir():
            _err(f"Notebook directory not found: {args.notebook_dir}"
                 + _bad_path_hint(str(args.notebook_dir)))
            sys.exit(2)

        # Resolve manifest path from --verify argument or auto-search
        verify_arg = args.verify
        if verify_arg == "__auto__":
            verify_arg = str(out_dir)

        target = Path(verify_arg)
        if target.is_dir():
            _info("Directory provided for manifest, choosing latest")
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
                _err(f"Manifest not found: {manifest_path}"
                     + _bad_path_hint(verify_arg))
                sys.exit(2)

        try:
            manifest = _load_manifest(manifest_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            _err(f"Could not read manifest: {exc}")
            sys.exit(2)

        # Schema version gate (three-direction check)
        check_manifest_schema(manifest, args.schema_ignore, args.yes)

        # Auto-validate against the JSON schema before verifying — catches a
        # malformed/truncated manifest early. Best-effort: skipped silently if
        # 'jsonschema' isn't installed (it's an optional dependency).
        _schema_errs = validate_manifest_schema(manifest, required=False)
        if _schema_errs:
            _warn(f"Manifest schema: {len(_schema_errs)} validation issue(s) "
                  "(run --validate for detail)")

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

        # ---- Fail fast if the manifest uses an algorithm this build cannot
        #      compute. Verifying only a subset would give false confidence. ----
        _ha = manifest.get("hash_algorithm", "sha256")
        _algos_used = _ha if isinstance(_ha, list) else [_ha]
        _missing_algos: List[str] = []
        for _spec in _algos_used:
            _name = _parse_algo_spec(_spec)[0]
            if _name not in AVAILABLE_HASHES and _name not in _missing_algos:
                _missing_algos.append(_name)
        if _missing_algos:
            _hint = ", ".join(
                f"{a} (pip install {_OPTIONAL_PIP[a]})" if a in _OPTIONAL_PIP else a
                for a in _missing_algos
            )
            _qprint(f"{_tag('WARN')} Missing Algorithms: {_hint}")
            sys.exit(1)

        results = verify_manifest(manifest, args.notebook_dir, extra_exclude=exclude,
                                  jobs=jobs, ignore_symlinks=args.ignore_symlinks)

        # A report file is written only when --report is requested; otherwise the
        # terminal verdict (and --json on stdout) is the result.
        if args.report is not None:
            report_path = out_dir / f"report-{utc_timestamp()}.{args.report}"
            write_report(results, report_path, manifest_path)
            _info(f"Verification report: {report_path}")

        # ---- Integrity tallies ----
        n_missing = len(results["missing"])
        n_modified = len(results["modified"])
        n_new = len(results["new"])
        n_ok = len(results["ok"])
        n_expected = n_ok + n_missing + n_modified   # files the manifest expects
        integrity_failed = bool(n_missing or n_modified or n_new)

        # ---- Symlink tallies (schema v2) ----
        n_sl_changed = len(results["symlink_changed"])
        n_sl_missing = len(results["symlink_missing"])
        n_sl_new = len(results["symlink_new"])
        symlink_failed = bool(n_sl_changed or n_sl_missing or n_sl_new)

        # ---- Content-root status (schema v3) ----
        # "match" => the exact set of file contents is intact; any path
        # discrepancy is then a relocation (move/rename/swap), not tampering.
        content_match = (results.get("content_root_status") or [None])[0] == "match"
        files_relocated = content_match and integrity_failed

        # ---- Signature policy ----
        # A manifest is treated as unsigned only if it carries the UNSIGNED
        # marker AND names no signer.  Such manifests verify on integrity alone
        # (exit 0).  A manifest that does NOT declare itself unsigned is assumed
        # to expect a signature; if none validates, authenticity is unestablished
        # and verification "completes with issues" (exit 1).
        # --ignore-sig forces integrity-only checking on any manifest.
        manifest_unsigned = (WARN_UNSIGNED in manifest.get("warnings", [])
                             and not manifest.get("signed_by"))
        check_sigs = not args.ignore_sig                # attempt signature checks?
        if args.ignore_sig:
            _warn("Flag --ignore-sig in use")
        sig_required = check_sigs and (not manifest_unsigned or args.ssh_verify)

        trust_failed = False   # C1: untrusted verified signer under --trust high
        sig_invalid = False    # a signature that IS present failed to validate
        sig_verified = False   # at least one signature validated successfully

        if check_sigs:
            # Resolve signature files
            _SSH_EXTS = (".sshsig", ".sig")
            if sig_paths:
                gpg_sigs = [p for p in sig_paths if p.suffix == ".asc"]
                ssh_sigs = [p for p in sig_paths if p.suffix in _SSH_EXTS]
                for p in sig_paths:
                    if p.suffix not in (".asc",) + _SSH_EXTS:
                        _warn(f"Unknown signature type '{p.name}' — skipped "
                              "(expected .asc or .sshsig)")
            else:
                auto_asc = manifest_path.with_suffix(manifest_path.suffix + ".asc")
                gpg_sigs = [auto_asc] if auto_asc.exists() else []
                auto_ssh = manifest_path.with_suffix(manifest_path.suffix + ".sshsig")
                auto_sig = manifest_path.with_suffix(manifest_path.suffix + ".sig")
                ssh_sigs = [p for p in (auto_ssh, auto_sig) if p.exists()]

            # GPG verification
            for gpg_sig in gpg_sigs:
                if not gpg_sig.exists():
                    _warn(f"GPG signature not found: {gpg_sig.name}")
                elif not gpg_available():
                    _warn("GPG not available — GPG verification skipped")
                else:
                    if gpg_verify(manifest_path, gpg_sig):
                        _ok(f"GPG signature verified: {gpg_sig.name}")
                        sig_verified = True
                        v_fpr = gpg_verified_fingerprint(manifest_path, gpg_sig)
                        if v_fpr:
                            show_randomart_gpg(v_fpr)
                        if not trust_gate_verify("gpg", v_fpr, trust_level, config):
                            trust_failed = True
                    else:
                        sig_invalid = True

            # SSH verification
            for ssh_sig in ssh_sigs:
                if not ssh_keygen_available():
                    _warn("ssh-keygen not available — SSH verification skipped")
                    break
                if not ssh_sig.exists():
                    _warn(f"SSH signature not found: {ssh_sig.name}")
                    continue
                signer = select_ssh_key(ssh_key_path, require_private=False,
                                        prefer_fido=prefer_fido, keyname=keyname)
                if signer is None:
                    _warn("No suitable SSH key found for verification")
                    continue
                canonical_ssh = manifest_path.with_suffix(manifest_path.suffix + ".sshsig")
                result = ssh_verify_manifest(
                    manifest_path, ssh_sig, signer.pub_path,
                    multiple_signatures=len(ssh_sigs) > 1,
                    nonstandard_sig=ssh_sig != canonical_ssh,
                )
                if result.status == "OK":
                    _ok(result.message)
                    sig_verified = True
                    show_randomart_ssh(signer.pub_path)
                    v_fpr = ssh_key_fingerprint(signer.pub_path)
                    if not trust_gate_verify("ssh", v_fpr, trust_level, config):
                        trust_failed = True
                else:
                    sig_invalid = True
                for w in result.warnings:
                    _warn(w)

        # ---- TSA timestamp checks (fully local: openssl or rfc3161ng) ----
        tsa_failed = False
        # Soft "could not confirm, but not proven tampered" reasons collected
        # across the whole verify — printed as ONE combined non-PASS verdict at
        # the end (see "Terminal verdict" below) rather than a bare warning
        # that let verification silently read as successful.
        issues: List[str] = []
        _tsr_path = manifest_path.with_suffix(manifest_path.suffix + ".tsr")
        _embedded = [f for f in TSA_FIELDS if isinstance(manifest.get(f), dict)]
        _failed_markers = [f for f in TSA_FIELDS if manifest.get(f) == "failed"]
        _tsa_present = _tsr_path.exists() or bool(_embedded)
        for _f in _failed_markers:
            _warn(f"Timestamp was not applied ({_f}: failed) — add one later with --resign")
        _tsa_labels = ([_tsr_path.name] if _tsr_path.exists() else []) + list(_embedded)
        if args.ignore_tsa:
            if _tsa_present:
                _warn("Flag --ignore-tsa in use")
        elif _tsa_present:
            if not tsa_backend_available():
                _warn("TSA timestamp present but no backend (openssl / rfc3161ng) — "
                      "timestamp not verified")
                issues.append(f"TSA backend not available ({', '.join(_tsa_labels)})")
            else:
                if not openssl_available():
                    # Only the rfc3161ng fallback has shown issues so far; openssl
                    # itself has no known problems, so don't alarm users who have it.
                    _warn("--tsa verification is EXPERIMENTAL on this backend "
                          "(rfc3161ng, used because openssl isn't on PATH). RSA-signed "
                          "tokens have verified correctly across every provider tested "
                          "(digicert, globalsign, certum, apple, sectigo). EC-signed "
                          "tokens (e.g. freetsa) can't be checked here — RSA-only "
                          "library limitation — and correctly surface as inconclusive "
                          "rather than a false failure. See README 'Trusted "
                          "Timestamping'.")
                if args.tsa_cert is None:
                    # No pinned CA: verify the token's cert chain against the OS
                    # trust store instead of refusing outright. The user can still
                    # pin a CA with --tsa-cert or skip with --ignore-tsa.
                    _info("No --tsa-cert given — checking the timestamp's certificate "
                          "chain against your system trust store (pass --tsa-cert to "
                          "pin a specific CA, or --ignore-tsa to skip).")

                # Network is opt-in: only when the offline (system-store) check is
                # inconclusive, only in the no-cert path, and never under --offline
                # / -y / --quiet / a non-interactive stdin.
                _online = {"asked": False, "ok": False}

                def _online_allowed() -> bool:
                    if args.offline:
                        return False
                    if _online["asked"]:
                        return _online["ok"]
                    _online["asked"] = True
                    if args.yes or args.quiet or not sys.stdin.isatty():
                        return False
                    try:
                        ans = input(f"{_tag('WARN')} Timestamp CA not in your system "
                                    "store. Fetch the issuer certificate(s) online to "
                                    "complete verification? [y/N] ")
                    except EOFError:
                        ans = ""
                    _online["ok"] = ans.strip().lower() in ("y", "yes")
                    return _online["ok"]

                def _check_tsa(label: str, data: bytes, tsr: bytes, extra: str = "") -> None:
                    nonlocal tsa_failed
                    result = tsa_verify_data(data, tsr, args.tsa_cert)
                    # Online issuer-fetch can only help an RSA token whose signature
                    # already validates but whose chain is missing an intermediate.
                    # It cannot help an EC token (the signature itself is uncheckable
                    # here), so don't prompt for a fetch that can't change the result.
                    if (result is None and args.tsa_cert is None
                            and _token_key_type(tsr) == "RSA" and _online_allowed()):
                        result = tsa_verify_data(data, tsr, None, allow_online=True)
                    if result is True:
                        _src = " [system trust store]" if args.tsa_cert is None else ""
                        _ok(f"TSA timestamp verified: {label}{extra}{_src}")
                    elif result is False:
                        _qprint(f"{_tag('FAIL')} TSA timestamp failed: {label}")
                        tsa_failed = True
                    else:
                        # None: inconclusive. A TSA claim exists and wasn't ignored,
                        # so an unconfirmed result must not read as a clean PASS.
                        if args.tsa_cert is None:
                            # Reason (EC key, or CA not in store) is in the preceding
                            # backend warning; keep this line cause-neutral.
                            _warn(f"TSA timestamp inconclusive: {label} (unconfirmed; "
                                  "pass --tsa-cert with the provider's root, or install "
                                  "openssl)")
                        else:
                            _warn(f"TSA timestamp inconclusive: {label} "
                                  "(verify with openssl externally or install openssl)")
                        issues.append(f"TSA timestamp could not be verified ({label})")

                if _tsr_path.exists():
                    _check_tsa(_tsr_path.name, manifest_path.read_bytes(),
                               _tsr_path.read_bytes())
                for _field in _embedded:
                    _value = _tsa_stamped_value(manifest, _field)
                    try:
                        _token = base64.b64decode(manifest[_field].get("token_b64", ""))
                    except (ValueError, TypeError):
                        _token = b""
                    if _value and _token:
                        _t = manifest[_field].get("time", "")
                        _check_tsa(_field, _value.encode("utf-8"), _token,
                                   f" ({_t})" if _t else "")
                    else:
                        _qprint(f"{_tag('FAIL')} TSA timestamp failed: {_field}")
                        tsa_failed = True

        # ---- Manifest chain verification (--prev-manifest at create time).
        # Fully local: walks 'prev' links back to genesis, re-hashing each
        # previous manifest file found alongside this one. ----
        chain_failed = False
        if args.ignore_chain:
            if isinstance(manifest.get("prev"), dict):
                _warn("Flag --ignore-chain in use")
        else:
            _chain_status, _chain_detail = verify_chain(manifest_path, manifest)
            if _chain_status == "ok":
                _ok(f"Manifest chain verified: {_chain_detail}")
            elif _chain_status == "broken":
                _qprint(f"{_tag('FAIL')} Manifest chain broken: {_chain_detail}")
                chain_failed = True
            elif _chain_status == "missing":
                _warn(f"Manifest chain could not be fully verified: {_chain_detail}")
                issues.append(f"manifest chain incomplete ({_chain_detail})")
            # "no-chain": this manifest isn't chained -- nothing to report.

        # ------------------------- Terminal verdict ------------------------- #
        if args.ignore_symlinks:
            _warn("Flag --ignore-symlinks in use")
        else:
            if manifest.get("symlinks"):
                _warn("Symlinks Present")
            for _esc in escaping_symlinks(args.notebook_dir, exclude=exclude):
                _warn(f"Symlink points outside the notebook: {_esc}")

        # Content-root pass: the full set of file contents is intact.
        if content_match:
            _ok("Move-invariant/Content Merkle root pass: All files present")

        if files_relocated:
            # Bytes all present, only their placement changed.
            _qprint(f"{_tag('FAIL')} Files moved")
        elif integrity_failed:
            _qprint(f"{_tag('FAIL')} {n_missing} Missing, {n_modified} Modified, "
                    f"{n_new} New/Moved, {n_ok}/{n_expected} OK")
        if symlink_failed:
            _qprint(f"{_tag('FAIL')} Symlinks: {n_sl_changed} Changed, "
                    f"{n_sl_missing} Removed, {n_sl_new} New")
        if sig_invalid:
            _qprint(f"{_tag('FAIL')} Manifest failed Signature")
        if trust_failed:
            _qprint(f"{_tag('FAIL')} Untrusted signer (--trust high)")

        hard_fail = (integrity_failed or symlink_failed or sig_invalid
                     or trust_failed or tsa_failed or chain_failed)
        # A manifest that expects a signature but produced none: hashes are
        # intact, but authenticity could not be established.
        if sig_required and not sig_verified:
            issues.append("manifest implies a signature, but none could be verified")

        # In --json mode, emit the report to stdout regardless of outcome.
        if args.json:
            print(json.dumps(results, indent=2, ensure_ascii=False))

        if hard_fail:
            sys.exit(1)
        if issues:
            # Hashes are intact, but something that was actually checked (an
            # explicitly requested TSA verification, or an implied signature)
            # could not be confirmed — a soft PASS here would be misleading.
            _qprint(f"{_tag('FAIL')} Verification completed with issues: "
                    f"{'; '.join(issues)}")
            sys.exit(1)

        # Success.  Unsigned manifests pass on integrity alone — the UNSIGNED
        # note printed above already flags the absence of a signature.
        _pass("Verification successful")
        return

    # ------------------------------------------------------------------ #
    #  Create mode                                                         #
    # ------------------------------------------------------------------ #
    if not args.notebook_dir.is_dir():
        _err(f"Notebook directory not found: {args.notebook_dir}"
             + _bad_path_hint(str(args.notebook_dir)))
        sys.exit(2)

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
        symlink_policy=_resolve_symlink_policy(args),
    )
    # Flag links that reach outside the notebook — their content is pulled in
    # from elsewhere, and they are a repointing attack surface.
    for _esc in escaping_symlinks(args.notebook_dir, exclude=exclude):
        _warn(f"Symlink points outside the notebook: {_esc}")

    # ---- Manifest chaining (--prev-manifest, before write so the signature
    # and any --tsa timestamp also cover the link). Hashes the PREVIOUS
    # manifest's raw file bytes -- if that file is later altered, this hash
    # no longer matches, and the break is detectable at verify time. ----
    if args.prev_manifest is not None:
        prev_path = _resolve_manifest_path(args.prev_manifest, out_dir,
                                           label="previous manifest")
        try:
            manifest["prev"] = compute_prev_link(prev_path, args.prev_hash_specs)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            _err(f"Could not read --prev-manifest: {exc}")
            sys.exit(2)
        _ok(f"Linked to previous manifest: {prev_path.name} "
            f"(height {manifest['prev']['height']})")

    # ---- Embedded TSA stamps (before write, so signatures cover them). The
    # stamps cover root VALUES, so adding them cannot invalidate themselves. ----
    if tsa_url and (args.tsa_embed or args.tsa_embed_separate):
        if not tsa_embed_into_manifest(manifest, tsa_url, args.tsa_embed_separate):
            # Don't throw away the hashing: the manifest now carries tsa_*: "failed"
            # markers and is written anyway; --resign can add a real token later.
            _warn("Timestamping failed — recorded as 'failed' in the manifest; "
                  "add a token later with --resign.")
        else:
            # Tell the user whether these stamps are verifiable by the tool alone;
            # drop them if they're EC-signed and unverifiable here and the user
            # declines (all stamps share the TSA's key type, so one check suffices).
            _sample = next((manifest[f] for f in TSA_FIELDS
                            if isinstance(manifest.get(f), dict)), None)
            if _sample is not None:
                try:
                    _tok = base64.b64decode(_sample.get("token_b64", ""))
                except (ValueError, TypeError):
                    _tok = b""
                if _tok and not _tsa_keytype_confirm(_tok, assume_yes=args.yes,
                                                     quiet=args.quiet):
                    for _f in TSA_FIELDS:
                        manifest.pop(_f, None)
                    _warn("EC timestamp dropped at your request — manifest written "
                          "without a stamp.")

    manifest_fmt = args.manifest_type  # "txt" or "json"
    ext = ".json" if manifest_fmt == "json" else ".txt"
    manifest_name = f"hashes-{manifest['created']}{ext}"
    manifest_path = out_dir / manifest_name

    # SSH sig output path: from --sig if a .sshsig path given, else default
    ssh_sig_out = next(
        (p for p in sig_paths if p.suffix in (".sshsig", ".sig")),
        manifest_path.with_suffix(manifest_path.suffix + ".sshsig"),
    )

    # ---- Decide signing methods ----
    do_gpg = do_ssh = False
    if args.no_sign:
        pass
    elif want_gpg or want_ssh:
        do_gpg, do_ssh = want_gpg, want_ssh
    elif not sys.stdin.isatty():
        # Non-interactive session (piped/cron/no TTY): don't block on the menu —
        # default to skip-signing, mirroring how --quiet implies --no-sign.
        _info("Non-interactive session; skipping signing "
              "(use --gpg/--ssh to sign, or --no-sign to silence)")
    else:
        choice = _prompt_signing_menu()
        do_gpg, do_ssh = choice in (1, 3), choice in (2, 3)

    # ---- Resolve identities BEFORE writing (so signatures cover signed_by, C2) ----
    gpg_fpr: Optional[str] = None
    ssh_signer: Optional[SshKeyCandidate] = None
    if do_gpg:
        gpg_fpr = resolve_gpg_signer(args.gpg or None, args.gpg_k,
                                     trust_level, config, args.yes)
    if do_ssh:
        ssh_signer = resolve_ssh_signer(ssh_key_path, prefer_fido, keyname,
                                        trust_level, config, args.yes)

    # ---- signed_by (C1: a display hint; trust at verify uses the verified key) ----
    signed_by: Dict[str, str] = {}
    if gpg_fpr:
        signed_by["gpg"] = gpg_fpr
    if ssh_signer:
        _sfpr = ssh_key_fingerprint(ssh_signer.pub_path)
        if _sfpr:
            signed_by["ssh"] = _sfpr
    if signed_by:
        manifest["signed_by"] = signed_by
    else:
        manifest.setdefault("warnings", [])
        if WARN_UNSIGNED not in manifest["warnings"]:
            manifest["warnings"].append(WARN_UNSIGNED)

    # ---- Write the manifest (now contains signed_by / UNSIGNED) ----
    # Re-assert files-last: tsa_embed_into_manifest and signed_by above both
    # add keys after generate_manifest() already put "files" last once.
    _manifest_files_last(manifest)
    if manifest_fmt == "json":
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    else:
        manifest_path.write_text(
            _write_text_manifest(manifest, bullets=not args.no_bullets),
            encoding="utf-8",
        )
    if args.no_sign:
        _info("Signing skipped (--no-sign)")
    _ok(f"Manifest created: {manifest_path}")
    _written_files = [manifest_path]   # tracks this run's own output, for --lock

    # ---- Sign the finished file ----
    if gpg_fpr:
        if do_gpg_sign(manifest_path, gpg_fpr, args.gpg_k):
            _ok("Manifest signed with GPG.")
            _written_files.append(manifest_path.with_suffix(manifest_path.suffix + ".asc"))
        else:
            _warn("GPG signing failed.")
    if ssh_signer:
        if ssh_sign_manifest(manifest_path, ssh_signer.priv_path, ssh_sig_out):
            _ok(f"SSH signature created: {ssh_sig_out.name}")
            _written_files.append(ssh_sig_out)
        else:
            _warn("SSH signing failed.")

    # ---- Detached TSA token (default --tsa mode): timestamp the WRITTEN
    # manifest bytes, after signing, and save the token as a .tsr sidecar
    # (same pattern as the .asc / .sshsig signature files). ----
    if tsa_url and not (args.tsa_embed or args.tsa_embed_separate):
        tsr = tsa_timestamp_file(manifest_path, tsa_url)
        if tsr is None:
            # The manifest is already written (and signed) — don't waste that.
            _warn("Timestamping failed — the manifest is written but has no .tsr "
                  "token; add one later with --resign.")
            # Halt so an interactive user notices; -y (or non-interactive) continues.
            if sys.stdin.isatty() and not args.yes:
                sys.exit(1)
        elif not _tsa_keytype_confirm(tsr, assume_yes=args.yes, quiet=args.quiet):
            _warn("EC timestamp dropped at your request — manifest written "
                  "without a .tsr token.")
        else:
            tsr_path = manifest_path.with_suffix(manifest_path.suffix + ".tsr")
            tsr_path.write_bytes(tsr)
            _time = tsa_token_time(tsr)
            _ok(f"Timestamp token saved: {tsr_path.name}"
                + (f" ({_time})" if _time else ""))
            _written_files.append(tsr_path)

    # ---- --lock: chmod this run's own output read-only, last (after every
    # write above). Best-effort defense-in-depth, not true WORM — see
    # _lock_file_readonly's docstring and README 'File Safety'. ----
    if args.lock:
        locked = [p for p in _written_files if _lock_file_readonly(p)]
        if locked:
            _ok("Locked read-only: " + ", ".join(p.name for p in locked))
        else:
            _warn("--lock: could not mark any output file read-only")

    # --json: echo the finished manifest to stdout for piping (logs are on stderr).
    if args.json:
        print(json.dumps(manifest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Ctrl+C at any prompt (or during a long hash run): exit quietly with the
        # conventional SIGINT code (128 + 2) instead of dumping a traceback.
        print(f"\n{_tag('INFO', stream=sys.stderr)} Aborted.", file=sys.stderr)
        sys.exit(130)
    except EOFError:
        # stdin closed / non-interactive (e.g. piped) when a prompt needs input.
        _err("No input available (stdin closed); aborting.")
        sys.exit(2)
