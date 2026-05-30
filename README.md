# rednb-verify

**rednb-verify** (short for *rednotebook-verify*) is an integrity and verification tool designed to detect tampering in **RedNotebook** journals.

It creates cryptographic manifests of notebook entries and optionally signs them with GPG or SSH keys, producing a verifiable snapshot of the notebook at a specific point in time.

The project focuses on **tamper detection, auditability, and long-term trust** — not secrecy.

**Version:** 0.7.2 | **Python:** 3.10+ | **Dependencies:** stdlib only (`pyyaml` required only for `--per-day`)

---

## Quick Start

```bash
# Create a manifest (signing menu appears; saved next to the journal)
python rednb-verify.py ~/journal

# Create a manifest without signing
python rednb-verify.py ~/journal --no-sign

# Per-day granularity — hash each day entry individually (requires PyYAML)
python rednb-verify.py ~/journal --per-day --no-sign

# Parallel hashing (4 workers) with per-file timing
python rednb-verify.py ~/journal --no-sign --jobs 4 --verbose

# Verify the journal (auto-finds the latest manifest)
python rednb-verify.py ~/journal --verify

# Verify against a specific manifest
python rednb-verify.py ~/journal --verify hashes-20260528T120000Z.txt

# Verify with JSON report, warn if manifest is older than 90 days
python rednb-verify.py ~/journal --verify hashes-20260528T120000Z.txt --report json --warn-age 90

# Re-sign an existing manifest with GPG
python rednb-verify.py --resign hashes-20260528T120000Z.txt --gpg
```

---

## Usage

```
rednb-verify.py [options] [notebook_dir]
```

### Arguments

| Flag | Description |
|---|---|
| `notebook_dir` | Path to the RedNotebook journal directory |
| `-m`, `--month-only` | Hash only `YYYY-MM.txt` month files (skip attachments, config, etc.) |
| `-D`, `--per-day` | Hash individual day entries within month files; manifest path format `YYYY-MM/DD`. Combine with `--month-only` to control whether non-month files are also included (requires `pyyaml`) |
| `-j N`, `--jobs N` | Parallel hashing workers (`0` = auto via `os.cpu_count()`; default: `1`) |
| `-o`, `--output DIR` | Output directory for the manifest (default: parent of the journal directory) |
| `-V`, `--version` | Print version and exit |
| `--verify [FILE\|DIR]` | Verify mode — pass a manifest file directly, a directory to search, or omit to auto-find the latest manifest in the output directory |
| `--manifest-type [txt\|json]` | Manifest file format: `txt` (default) or `json` |
| `--report [txt\|json]` | Verification report format: `txt` human-readable (default) or `json` structured |
| `--hash ALGO[:LEN]` | Hash algorithm for files (default: `sha256`). `shake_128` and `shake_256` require a byte length: `--hash shake_128:32` |
| `--hash-list` | Print available hash algorithms and exit |
| `--hash-merkle ALGO` | Hash algorithm for the Merkle tree (default: same as `--hash`) |
| `--gpg [FPR]` | Sign with GPG; optionally specify a key fingerprint to skip the selection menu |
| `--gpg-k FILE` | GPG armored key export file to sign with; implies `--gpg` |
| `--ssh [FILE_OR_DIR]` | Sign with SSH key; optionally specify a `.pub` file or directory to scan (default: `~/.ssh`) |
| `--ssh-verify` | Force SSH signature check during `--verify` |
| `--sig FILE[,FILE]` | Signature file(s), comma-separated; `.asc`=GPG, `.sshsig`=SSH |
| `--ssh-fido [NAME]` | Prefer FIDO2/hardware-backed SSH keys; optional name filter |
| `--no-sign` | Skip all signing prompts |
| `--resign FILE` | Re-sign an existing manifest without re-hashing (requires `--gpg` and/or `--ssh`) |
| `--warn-age DAYS` | During `--verify`, print a warning if the manifest is older than N days |
| `-v`, `--verbose` | Print per-file hash timing and detailed progress |
| `--quiet` | Suppress all non-error output; implies `--no-sign` unless a signing flag is given |
| `--exclude PATTERN` | Exclude files matching a glob pattern (repeatable); patterns stored in the manifest |
| `--exclude-from FILE` | File of glob patterns to exclude (one per line; `#` = comment) |
| `--no-config`, `--no-cf` | Ignore `~/.config/rednb-verify/config.json` for this run |
| `--config FILE` | Load a specific config file instead of the default |

### Examples

```bash
# Hash only month files, save manifest alongside the journal
python rednb-verify.py ~/journal --month-only --output ~/journal

# Create manifest and skip signing
python rednb-verify.py ~/journal --no-sign

# Show per-file hash timing
python rednb-verify.py ~/journal --no-sign --verbose

# Use blake2b for file hashes, sha256 for the Merkle tree
python rednb-verify.py ~/journal --hash blake2b --hash-merkle sha256

# Create and sign — interactive menu asks how to sign
python rednb-verify.py ~/journal

# Sign with SSH (scans ~/.ssh for keys)
python rednb-verify.py ~/journal --ssh

# Sign with a specific SSH key file
python rednb-verify.py ~/journal --ssh ~/.ssh/id_ed25519.pub

# Sign with a FIDO2/YubiKey-backed SSH key
python rednb-verify.py ~/journal --ssh --ssh-fido

# Sign with both GPG and SSH
python rednb-verify.py ~/journal --gpg --ssh

# Exclude editor lock files and temp files
python rednb-verify.py ~/journal --exclude "*.tmp" --exclude ".~lock.*"

# Exclude patterns from a file (like .gitignore)
python rednb-verify.py ~/journal --exclude-from ~/journal-excludes.txt

# Per-day hashing, full-tree (day entries + attachments)
python rednb-verify.py ~/journal --per-day --no-sign

# Per-day hashing, month-only (day entries only, no attachments)
python rednb-verify.py ~/journal --per-day --month-only --no-sign

# Parallel hashing with auto worker count
python rednb-verify.py ~/journal --jobs 0 --no-sign

# Non-interactive / cron use (suppress output, pre-select GPG key)
python rednb-verify.py ~/journal --quiet --gpg ABCDEF1234567890

# Re-sign an existing manifest without re-hashing the journal
python rednb-verify.py --resign ~/journal/hashes-20260528T120000Z.txt --gpg
python rednb-verify.py --resign ~/journal/hashes-20260528T120000Z.txt --ssh
python rednb-verify.py --resign ~/journal/hashes-20260528T120000Z.txt --gpg --ssh

# Verify — auto-find latest manifest
python rednb-verify.py ~/journal --verify

# Verify against a specific manifest
python rednb-verify.py ~/journal --verify ~/journal/hashes-20260528T120000Z.txt

# Verify with both GPG and SSH signatures at the same time
python rednb-verify.py ~/journal \
  --verify ~/journal/hashes-20260528T120000Z.txt \
  --sig ~/journal/hashes-20260528T120000Z.txt.asc,~/journal/hashes-20260528T120000Z.txt.sshsig \
  --report json

# Verify and warn if manifest is older than 90 days
python rednb-verify.py ~/journal \
  --verify ~/journal/hashes-20260528T120000Z.txt \
  --warn-age 90
```

---

## Manifest Format

Manifests are named `hashes-<timestamp>.txt` (default) or `hashes-<timestamp>.json`. Use `--manifest-type json` to produce JSON instead of the default text format.

### Text format (default)

```
rednb-verify manifest
version: 0.7.1
created: 20260528T120000Z
date: 2026-05-28
hash_algorithm: sha256
merkle_hash: sha256
mode: full-tree
merkle_root: fe2402e74e8d9a317b6469875e3c704ec2b9fa585db1f49c495282f53a3410cf

files:
      1. 2026-05.txt
         sha256: fe2402e74e8d9a317b6469875e3c704ec2b9fa585db1f49c495282f53a3410cf
      2. pexels-photo.jpg
         sha256: a3f1bc8e0d2741c59930cf5a29e4b87d3e1092f54c8d70a1e3b29d84c7f02e11
```

### JSON format (`--manifest-type json`)

```json
{
  "tool": "rednb-verify",
  "version": "0.7.1",
  "created": "20260528T120000Z",
  "date": "2026-05-28",
  "hash_algorithm": "sha256",
  "merkle_hash": "sha256",
  "mode": "full-tree",
  "files": [
    {
      "path": "2026-05.txt",
      "sha256": "fe2402e74e8d9a317b6469875e3c704ec2b9fa585db1f49c495282f53a3410cf"
    }
  ],
  "merkle_root": "fe2402e74e8d9a317b6469875e3c704ec2b9fa585db1f49c495282f53a3410cf"
}
```

**Fields:**
- `hash_algorithm` — algorithm used for individual file hashes; also the field name on each file entry
- `merkle_hash` — algorithm used to compute the Merkle tree root
- `date` — creation date in `YYYY-MM-DD` for human readability
- `created` — full UTC timestamp for machine use
- `mode` — one of `full-tree`, `month-only`, `per-day/full-tree`, `per-day/month-only`

---

## Signing

### GPG

If GPG is available and secret keys are found, you are prompted to sign after manifest creation. A detached ASCII-armoured signature (`hashes-....txt.asc`) is created alongside the manifest.

Interactive key selection shows fingerprint and expiry for each key.

### SSH

Use `--ssh` to sign with an SSH key. The tool scans `~/.ssh` for key pairs and prompts for selection if multiple are found. Pass a `.pub` file or directory to use a specific key:

```bash
# Sign with SSH (scans ~/.ssh)
python rednb-verify.py ~/journal --ssh

# Sign with a specific key file directly
python rednb-verify.py ~/journal --ssh ~/.ssh/id_ed25519.pub

# Sign scanning a specific directory
python rednb-verify.py ~/journal --ssh ~/.ssh/work-keys/
```

The signature is saved as `<manifest>.sshsig`. During `--verify`, pass `--ssh-verify` to force an SSH check, or use `--sig` to specify the file explicitly.

#### FIDO2 / Hardware Keys

SSH keys backed by FIDO2 hardware (YubiKey, SoloKey, etc.) use key types prefixed with `sk-` (e.g. `sk-ssh-ed25519`). Use `--ssh-fido` to prefer these keys automatically. The private key operation happens on the hardware device — the private key never touches disk.

```bash
# Sign preferring any FIDO2-backed key
python rednb-verify.py ~/journal --ssh --ssh-fido

# Sign preferring a specific FIDO2 key by name
python rednb-verify.py ~/journal --ssh --ssh-fido yubikey
```

### Verifying Multiple Signatures

Use `--sig` with a comma-separated list to verify GPG and SSH signatures in a single run. The type is detected by extension (`.asc` → GPG, `.sshsig` → SSH):

```bash
python rednb-verify.py ~/journal \
  --verify hashes-20260528T120000Z.txt \
  --sig hashes-20260528T120000Z.txt.asc,hashes-20260528T120000Z.txt.sshsig
```

When `--sig` is omitted, both signature types are still auto-detected from the manifest directory.

---

## Modes

The combination of `--per-day` and `--month-only` controls what gets hashed and at what granularity:

| Flags | Mode | What is hashed |
|---|---|---|
| _(neither)_ | `full-tree` | Every file as a whole |
| `--month-only` | `month-only` | Whole `YYYY-MM.txt` files only |
| `--per-day` | `per-day/full-tree` | Individual day entries **+** all non-month files |
| `--per-day --month-only` | `per-day/month-only` | Individual day entries only |

`per-day/full-tree` gives the most complete coverage: day-level granularity within journal entries and whole-file hashes for attachments and other assets.

### Per-Day Detail

`--per-day` provides finer-grained tamper detection by hashing each journal day individually. The manifest contains one entry per day in the format `YYYY-MM/DD`:

```json
{
  "path": "2026-05/27",
  "sha256": "52255c968cf2ae3e792cd71090850421f900422a0b44e4d79c8508c77e3f083f"
}
```

RedNotebook month files are YAML. Each day is parsed with **PyYAML** (`pip install pyyaml`) and its full content — text, tags, and all custom categories — is canonicalised to sorted JSON before hashing, so any edit to any field is detected.

Verification automatically reads the `mode` field from the manifest and uses the matching strategy. Backward-compatible with manifests created by earlier versions.

---

## Verification Report

`--report` writes a verification report alongside the manifest (in the journal's parent directory by default). Format is controlled by the argument:

- `--report` or `--report txt` — human-readable numbered list (default)
- `--report json` — structured JSON

### Text format (default)

```
rednb-verify report — 2026-05-28
Manifest: hashes-20260528T120000Z.txt

OK:        2
New:       1
Missing:   0
Modified:  0

--- OK ---
      1. 2026-05.txt
      2. pexels-photo.jpg

--- NEW ---
      1. 2026-06.txt
```

### JSON format (`--report json`)

```json
{
  "ok": ["2026-05.txt", "pexels-photo.jpg"],
  "missing": [],
  "modified": [],
  "new": ["2026-06.txt"]
}
```

**Categories:**
- `ok` — files matching the manifest exactly
- `missing` — files in the manifest that are no longer present
- `modified` — files whose hash has changed
- `new` — files present in the notebook not tracked by the manifest

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All checks passed / manifest created successfully |
| `1` | Verification found issues — modified, missing, or new files |
| `2` | Usage or input error — bad arguments, missing files, unsupported algorithm |

---

## Config File

`~/.config/rednb-verify/config.json` is loaded automatically as a default layer. CLI flags always override config values. An empty or missing config file is silently ignored.

```json
{
    "hash": "sha256",
    "hash_merkle": null,
    "quiet": false,
    "no_sign": false,
    "gpg_key": "FINGERPRINT",
    "ssh_key": "~/.ssh/id_ed25519.pub",
    "exclude": ["*.tmp", ".~lock.*"],
    "manifest_age_warn_days": 90,
    "jobs": 4
}
```

A notification is printed when a config file is in use. Use `--no-config` / `--no-cf` to ignore it for a single run, or `--config FILE` to load an alternate file.

---

## What This Tool Is Not

- **Not encryption** — files remain readable; this tool proves whether they changed
- **Not access control** — anyone with file access can read entries
- **Not a backup** — integrity verification only

---

## Non-Repudiation Warning ⚠️

**Signing a manifest is a serious cryptographic act.**

By signing, you assert that these files existed in this exact form at or before the signing time. Anyone with your public key can verify this claim.

- You cannot later deny authorship of signed content
- If your signing key is compromised, past signatures remain valid
- Sign only on trusted systems
- Prefer hardware-backed keys (FIDO2 / smart cards)

---

## Threat Model

### Assets Protected
- Integrity of RedNotebook entries
- Trustworthiness of timestamps
- Authenticity of signed manifests

### Adversaries Considered
- Curious or careless users
- Malicious insiders with filesystem access
- Malware modifying journal files
- Post-event tampering attempts
- Attackers without access to signing keys

### Out of Scope
- Full system compromise
- Kernel-level attackers
- Live memory attacks
- Supply-chain attacks on cryptographic libraries

### Threats Addressed
- Silent modification of entries
- Deletion of journal files
- Rewriting history after the fact
- Undetected retroactive edits

### Threats Not Fully Prevented
- Tampering **before** signing
- Editing on a compromised system
- Timestamp manipulation at OS level
- Forged history using stolen signing keys

---

## Forensic Considerations

rednb-verify proves **that** tampering occurred, not **who** did it.

Standard filesystems do not reliably record who edited a file, from which program, or with what intent. `mtime` and `ctime` are not cryptographically trustworthy and can be altered.

True forensic attribution requires audit frameworks (e.g. Linux `auditd`), immutable logs, and mandatory access controls. rednb-verify is intentionally filesystem-agnostic and does not claim attribution beyond integrity proof.

---

## Design Principles

- Single file, minimal dependencies (stdlib only; PyYAML optional for `--per-day`)
- Deterministic output
- Explicit trust boundaries
- No hidden metadata
- Human-inspectable manifests
- Hardware security encouraged, not required

---

## Planned

- RFC 3161 trusted timestamping (cryptographic proof of time from a timestamp authority)
- Manifest chaining (each manifest references the previous one, making history tamper-evident)
- `--json` output mode (structured JSON on stdout for piping and scripting)
- Direct FIDO2/CTAP2 integration (hardware signing without SSH key setup)
- RedNotebook UI integration

---

## Project Status

Active development. Review, testing, and cryptographic scrutiny are welcome.
