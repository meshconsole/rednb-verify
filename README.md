# rednb-verify

**rednb-verify** (short for *rednotebook-verify*) is an integrity and verification tool designed to detect tampering in **RedNotebook** journals or file directories.

It creates cryptographic manifests of notebook entries and optionally signs them with GPG or SSH keys, producing a verifiable snapshot of the notebook at a specific point in time.

The project focuses on **tamper detection, auditability, and long-term trust** — not secrecy.

**Version:** 0.11.0 | **Python:** 3.10+ | **Dependencies:** stdlib only (`pyyaml` for `--per-day`, `jsonschema` for `--validate`, `rfc3161ng` for `--tsa` without openssl)

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [What This Tool Is Not](#what-this-tool-is-not)
- [Non-Repudiation Warning](#non-repudiation-warning-)
- [Usage](#usage)
  - [Manifest creation](#manifest-creation) · [Signing](#signing) · [Timestamping](#timestamping) · [Verification](#verification) · [Validation](#validation) · [Config management](#config-management) · [Examples](#examples) · [Other](#other)
- [Missing Dependencies (--install-opt)](#missing-dependencies---install-opt)
- [Manifest Format](#manifest-format)
- [Signing](#signing-1)
- [Modes](#modes)
- [Verification Report](#verification-report)
- [Exit Codes](#exit-codes)
- [Hashing Progress](#hashing-progress)
- [Multi-Hashing](#multi-hashing)
- [Merkle Tree](#merkle-tree)
- [Move detection](#move-detection)
- [Symlinks](#symlinks)
- [Schema & Validation](#schema--validation)
- [Trust & Signing](#trust--signing)
- [Trusted Timestamping (RFC 3161)](#trusted-timestamping-rfc-3161)
- [Config File](#config-file)
- [Threat Model](#threat-model)
- [Forensic Considerations](#forensic-considerations)
- [Design Principles](#design-principles)
- [Planned](#planned)
- [Project Status](#project-status)

---

## Installation

**No install required.** Download the single file and run it:

```bash
curl -O https://raw.githubusercontent.com/meshconsole/rednb-verify/main/rednb-verify.py
python rednb-verify.py --version
```

**Requirements:**
- Python 3.10+
- No mandatory third-party packages — runs on stdlib only

**Optional dependencies** — only needed for specific flags:

```bash
pip install pyyaml       # --per-day
pip install jsonschema   # --validate
pip install rfc3161ng    # --tsa, if openssl isn't on your system (e.g. stock Windows)
# or install everything at once:
pip install -r requirements.txt
```

Don't want to figure out which package a flag needs? Let the tool do it — see [Missing Dependencies (--install-opt)](#missing-dependencies---install-opt) below.

**External tools** used when available (not required for basic operation):
- `gpg` — for GPG signing and verification
- `ssh-keygen` — for SSH signing and verification (ships with OpenSSH)
- `openssl` — for RFC 3161 trusted timestamping (`--tsa`); **not required** — if it's missing, `--tsa` uses the optional `rfc3161ng` Python package instead (see above)

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

## Usage

```
rednb-verify.py [options] [notebook_dir]
```

### Manifest creation

Run the tool against a directory to hash its contents and write a manifest.

| Flag | Description |
|---|---|
| `notebook_dir` | Path to the RedNotebook journal (or any directory) to hash (optional if `dir` is saved in config) |
| `-m`, `--month-only` | Hash only `YYYY-MM.txt` month files (skip attachments, config, etc.) |
| `-D`, `--per-day` | Hash individual day entries within month files; manifest path format `YYYY-MM/DD`. Combine with `--month-only` to control whether non-month files are also included (requires `pyyaml`) |
| `-j N`, `--jobs N` | Parallel hashing workers. `0` = auto (all cores, via the thread pool's own default). Default: `max(1, cores - 2)` — leaves headroom for the OS and whatever else you're doing, floored at `1` so a 1-2 core machine never computes 0 or fewer workers. Parallelism never changes the manifest's contents (paths are sorted before writing), only speed |
| `-o`, `--output DIR` | Output directory for the manifest (create), or the report (verify — requires `--report`). Default: parent of the journal directory. With `--verify` it does **not** select which manifest to verify — that's the `--verify` argument |
| `--manifest-type [txt\|json]` | Manifest file format: `txt` (default) or `json` |
| `--no-bullets` | In a `txt` manifest, don't prefix per-file hash lines with `- ` (Merkle-root lines are never bulleted) |
| `--hash ALGO[:LEN][,ALGO...]` | Hash algorithm(s) for files (default: `sha256`). Comma-separate for **multi-hashing** (e.g. `sha256,blake2b`). `shake_128`/`shake_256` require a byte length: `shake_128:32` |
| `--hash-list` | Print available hash algorithms (incl. optional `blake3`/`xxh3`) and exit |
| `--hash-merkle ALGO[,...]` | Single mode: Merkle tree combiner (default: same as `--hash`). Multi mode: selects which per-algo trees to build (subset of `--hash`) |
| `--hash-merkle-concatenate [ALGO]` | Build one Merkle tree whose leaves are the per-file concatenation of all file hashes (default combiner: `sha256`) |
| `--exclude PATTERN` | Exclude files matching a glob pattern (repeatable); patterns stored in the manifest |
| `--exclude-from FILE` | File of glob patterns to exclude — one literal pattern per line. No comment syntax: a journal filename may legitimately start with `#` |
| `--symlink-targets MODE` | How to record symlink targets: `none` \| `full` \| `hash[:ALGO[:LEN]]` (default: `hash` = sha256 of the target). See [Symlinks](#symlinks) |
| `--no-symlink-table` | Omit the symlink table (alias for `--symlink-targets none`) |
| `--privacy` | Minimise what the manifest discloses (currently implies `--no-symlink-table`) |

### Signing

Signing happens at creation time (or later with `--resign`). See [Signing](#signing-1) and [Trust & Signing](#trust--signing).

| Flag | Description |
|---|---|
| `--gpg [FPR]` | Sign with GPG; optionally specify a key fingerprint to skip the selection menu |
| `--gpg-k FILE` | GPG armored key export file to sign with; implies `--gpg` |
| `--ssh [FILE_OR_DIR]` | Sign with SSH key; optionally specify a `.pub` file or directory to scan (default: `~/.ssh`) |
| `--ssh-fido [NAME]` | Prefer FIDO2/hardware-backed SSH keys; optional name filter |
| `--trust [high\|low]` | Signing trust level (default: `low`). `high` only allows pinned keys to sign — and also rejects untrusted signers at verify |
| `--no-sign` | Skip all signing prompts |
| `--resign FILE` | Re-sign an existing manifest without re-hashing or rewriting it (requires `--gpg` and/or `--ssh`) |

### Timestamping

Prove a manifest existed at a point in time via an RFC 3161 Timestamp Authority. **Strictly opt-in** — `--tsa` is the tool's *only* network operation; nothing is ever sent unless you pass it. See [Trusted Timestamping](#trusted-timestamping-rfc-3161).

| Flag | Description |
|---|---|
| `--tsa NAME\|URL` | Request a timestamp at create time from a known TSA name (see `--tsa-list`) or any `http(s)://` URL (incl. self-hosted). Default output: detached `hashes-….tsr` token next to the manifest |
| `--tsa-embed` | With `--tsa`: embed **one** stamp over the placement root (`merkle_root`, or the concat root in multi-hash mode) as `tsa_stamp` — 1 request, no detached file |
| `--tsa-embed-separate` | With `--tsa`: embed **separate** stamps for the placement root (`tsa_merkle`/`tsa_concat`) and the content root (`tsa_content`), so a third party can attest each independently — 2 requests |
| `--tsa-cert CAFILE` | TSA CA certificate used to verify tokens during `--verify` (verification is fully local — no network) |
| `--ignore-tsa` | During `--verify`, skip all timestamp-token checks (parallel to `--ignore-sig`) |
| `--tsa-list` | Print the built-in TSA registry (names → URLs) and exit — no network |
| `--offline` | Assert that no network is used: refuses `--tsa`. The tool is offline by default; this makes the guarantee explicit in the command |

### Verification

Check a directory against a previously created manifest.

| Flag | Description |
|---|---|
| `--verify [FILE\|DIR]` | Verify mode — pass a manifest file directly, a directory to search, or omit to auto-find the latest manifest in the output directory |
| `--report [txt\|json]` | Write a verification **report file** (`txt` or `json`). Omit it and `--verify` prints the verdict only, writing no file. `-o` sets where the report goes and requires this flag |
| `--ssh-verify` | Force SSH signature check during `--verify` |
| `--ignore-sig` | During `--verify`, check integrity only and skip all signature checks (returns `0` when hashes match) |
| `--ignore-symlinks` | During `--verify`, skip the symlink-table comparison and symlink warnings (parallel to `--ignore-sig`) |
| `--sig FILE[,FILE]` | Signature file(s), comma-separated; `.asc`=GPG, `.sshsig`/`.sig`=SSH |
| `--warn-age DAYS` | During `--verify`, print a warning if the manifest is older than N days |
| `--schema-ignore` | Verify a manifest whose schema is newer than this tool supports (risky) |

### Validation

Check a manifest's structure without touching the journal — useful in CI or before relying on a manifest.

| Flag | Description |
|---|---|
| `--validate [FILE\|DIR]` | Validate a manifest **or report** against the embedded JSON schema and exit. Requires the optional `jsonschema` package. See [Schema & Validation](#schema--validation) |
| `--dump-schema [manifest\|report]` | Print the embedded JSON schema to stdout and exit (no dependency needed) — e.g. to regenerate `schema/*.json` or feed an external validator |

### Config management

| Flag | Description |
|---|---|
| `--set-cf FIELD:VALUE` | Set a config field and exit. Fields: `trust-gpg`, `trust-ssh`, `trust-level`, `dir`. Repeatable; **replaces** the field |
| `--set-cf-run FIELD:VALUE` | Like `--set-cf` but continues running afterward |
| `--add-trust FIELD:VALUE` | **Append** fingerprints to a trust list (`trust-gpg`/`trust-ssh`), de-duplicated |
| `--config-out` | Print the resulting config as JSON (after applying `--set-cf`/`--add-trust`) |
| `--no-config`, `--no-cf` | Ignore `~/.config/rednb-verify/config.json` for this run |
| `--config FILE` | Load (and write, for `--set-cf`) a specific config file instead of the default |

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

# Record symlink targets as cleartext (local/forensic use)
python rednb-verify.py ~/journal --no-sign --symlink-targets full

# Privacy mode — don't record a symlink table at all
python rednb-verify.py ~/journal --no-sign --privacy

# Validate a manifest against the JSON schema (needs: pip install jsonschema)
python rednb-verify.py --validate ~/journal/hashes-20260528T120000Z.json

# Pipe a verification report straight into jq (logs stay on stderr)
python rednb-verify.py ~/journal --verify --no-sign --json | jq '.modified'
```

### Other

| Flag | Description |
|---|---|
| `-V`, `--version` | Print version and exit |
| `-v`, `--verbose` | Print per-file hash timing and detailed progress |
| `--quiet` | Suppress non-error output; implies `--no-sign` unless a signing flag is given |
| `-y`, `--yes` | Assume yes to confirmation prompts (automation-friendly) |
| `--json` | Emit the result to **stdout** as one JSON document for piping (manifest on create, report on verify); all logs go to stderr, so `… --json \| jq` works |
| `--install-opt` | Permit the tool to `pip install` the optional packages a command needs. Alone, installs every missing optional package and exits. See [Missing Dependencies (--install-opt)](#missing-dependencies---install-opt) |

---

## Missing Dependencies (`--install-opt`)

A few flags need an optional package that isn't part of the stdlib-only default install: `--per-day` needs `pyyaml`, `--validate` needs `jsonschema`, `--tsa` needs `openssl` **or** `rfc3161ng`. GPG/SSH signing need the external `gpg`/`ssh-keygen` programs.

Before doing any work, the tool checks whether the flags you passed have what they need:

- **A missing external program** (`gpg`, `ssh-keygen`) can't be installed for you — the tool exits with a plain reason (e.g. "GPG signing requested but `gpg` was not found on PATH; install GnuPG and re-run").
- **A missing optional Python package** never installs itself silently. The tool prints the exact command and stops:
  ```
  [ERROR] --validate is unavailable — pip install jsonschema.
  [ERROR] Install with:  pip install jsonschema
  [ERROR] Or re-run with --install-opt and rednb-verify will install it for you.
  ```
  Re-run the **same command** with `--install-opt` added, and the tool installs it and stops (a freshly installed package isn't reliably usable in the same process — re-run once more to actually use it):
  ```bash
  python rednb-verify.py ~/journal --validate ~/journal/hashes-....json --install-opt
  # [OK] Installed. Please re-run your command to use it.
  python rednb-verify.py ~/journal --validate ~/journal/hashes-....json
  ```
- **`--install-opt` alone** (no other flags) checks and installs *every* missing optional package in one go:
  ```bash
  pip install -r requirements.txt   # equivalent, if you prefer plain pip
  python rednb-verify.py --install-opt
  ```

`--install-opt` is the **only** thing in this tool that ever runs `pip` — it never runs without you passing it, and it never silently prompts.

---

## Manifest Format

Manifests are named `hashes-<timestamp>.txt` (default) or `hashes-<timestamp>.json`. Use `--manifest-type json` to produce JSON instead of the default text format.

### Text format (default)

```
rednb-verify manifest
version: 0.11.0
schema_version: 3
created: 20260528T120000Z
date: 2026-05-28
hash_algorithm: sha256
mode: full-tree
merkle_hash: sha256
merkle_root: fe2402e74e8d9a317b6469875e3c704ec2b9fa585db1f49c495282f53a3410cf
content_root: 7b1d8c0a4e6f2391c5a0bb9d4e7f10238acf45e6d9b2c1708f3a6e5d4c2b1a09

symlinks: (targets: hash:sha256)

files:
      1. 2026-05.txt
         - sha256: fe2402e74e8d9a317b6469875e3c704ec2b9fa585db1f49c495282f53a3410cf
      2. pexels-photo.jpg
         - sha256: a3f1bc8e0d2741c59930cf5a29e4b87d3e1092f54c8d70a1e3b29d84c7f02e11
```

Per-file hash lines are bulleted with `- ` for readability; Merkle-root lines are not. Use `--no-bullets` to omit the bullets. The `symlinks:` section lists any symbolic links (empty here) — see [Symlinks](#symlinks).

### JSON format (`--manifest-type json`)

```json
{
  "tool": "rednb-verify",
  "version": "0.11.0",
  "schema_version": 3,
  "created": "20260528T120000Z",
  "date": "2026-05-28",
  "mode": "full-tree",
  "hash_algorithm": "sha256",
  "merkle_hash": "sha256",
  "merkle_root": "fe2402e74e8d9a317b6469875e3c704ec2b9fa585db1f49c495282f53a3410cf",
  "content_root": "7b1d8c0a4e6f2391c5a0bb9d4e7f10238acf45e6d9b2c1708f3a6e5d4c2b1a09",
  "files": [
    {
      "path": "2026-05.txt",
      "sha256": "fe2402e74e8d9a317b6469875e3c704ec2b9fa585db1f49c495282f53a3410cf"
    }
  ],
  "symlink_targets": "hash:sha256",
  "symlinks": []
}
```

The full JSON structure is described by the published schema — see [Schema & Validation](#schema--validation).

**Fields:**
- `schema_version` — manifest format version (`3`); verifying an older one prints a security warning
- `hash_algorithm` — algorithm used for individual file hashes; also the field name on each file entry
- `merkle_hash` — algorithm used to compute the Merkle tree root
- `merkle_root` — path-ordered root of the [Merkle tree](#merkle-tree) over the file hashes
- `content_root` — **move-invariant** root over the *set* of file contents (leaves sorted by hash, not path); lets verify tell relocation from tampering — see [Move detection](#move-detection)
- `date` — creation date in `YYYY-MM-DD` for human readability
- `created` — full UTC timestamp for machine use
- `mode` — one of `full-tree`, `month-only`, `per-day/full-tree`, `per-day/month-only`
- `symlink_targets` / `symlinks` — symlink recording policy and table (see [Symlinks](#symlinks))

---

## Signing

### GPG

If GPG is available and secret keys are found, you are prompted to sign after manifest creation. A detached ASCII-armoured signature (`hashes-....txt.asc`) is created alongside the manifest.

Interactive key selection shows fingerprint and expiry for each key.

**Non-interactive runs never block on the signing menu.** In a piped/cron/no-TTY session (and under `--quiet`), the tool skips signing by default and prints `[INFO] Non-interactive session; skipping signing`. Pass `--gpg`/`--ssh` to sign unattended, or `--no-sign` to silence the note.

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

A report file is **opt-in**: pass `--report` and `--verify` writes one (to the journal's parent directory by default, or to `-o`); omit it and `--verify` just prints the terminal verdict (and `--json` to stdout if requested). Format is controlled by the argument:

- `--report` or `--report txt` — human-readable numbered list
- `--report json` — structured JSON

Because `-o`/`--output` only directs the report, using it with `--verify` *without* `--report` is an error — `-o` never selects which manifest to verify (that's the `--verify` argument).

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

### Verdict lines

After writing the report, `--verify` prints a single terminal verdict:

| Line | Meaning | Exit |
|---|---|---|
| `[PASS] Verification successful` | Hashes intact and in place; the manifest is either authentically signed or honestly declares itself unsigned | `0` |
| `[OK] Move-invariant/Content Merkle root pass: All files present` | The complete set of file contents is intact (see [Move detection](#move-detection)) | — |
| `[FAIL] Files moved` | All content is present, but one or more files were relocated/renamed since the manifest | `1` |
| `[FAIL] X Missing, N Modified, Z New/Moved, K/T OK` | File contents actually changed (added/removed/modified) | `1` |
| `[FAIL] Manifest failed Signature` | A signature is present but did not validate (tampering) | `1` |
| `[FAIL] Untrusted signer (--trust high)` | Signature valid, but the signer is not pinned in your trust list | `1` |
| `[WARN] Symlinks Present` | The manifest records symbolic links — review the symlink table | — |
| `[WARN] Symlink points outside the notebook: …` | A symlink's target resolves outside the base directory (data pulled in from elsewhere; a repointing surface). Also printed at create | — |
| `[WARN] Missing Algorithms: blake3 …` | The manifest uses a hash this build cannot compute (verification can't be completed) | `1` |
| `[FAIL] Verification completed with issues: …` | Hashes are intact, but something the manifest asserts couldn't be confirmed. Lists the specific reason(s) — `manifest implies a signature, but none could be verified`, `TSA certificate not provided (…)`, `TSA backend not available (…)`, or `TSA timestamp could not be verified (…)`; see the TSA rows below for which is which | `1` |
| `[OK] TSA timestamp verified: …` | An RFC 3161 token (detached `.tsr` or embedded stamp) verified against `--tsa-cert` | — |
| `[FAIL] TSA timestamp failed: …` | A timestamp token did not verify (tampering or wrong CA) | `1` |
| `[WARN] TSA timestamp present but no --tsa-cert given …` | A token exists but no `--tsa-cert` was given, so nothing was even attempted — reason `TSA certificate not provided`. Also contributes to `[FAIL] Verification completed with issues` (an unchecked TSA claim shouldn't silently read as a pass) | `1` |
| `[WARN] TSA timestamp present but no backend …` | Neither `openssl` nor `rfc3161ng` is available, so the check couldn't even be attempted — reason `TSA backend not available`. Also contributes to `[FAIL] Verification completed with issues` | `1` |
| `[WARN] TSA timestamp inconclusive: …` | `--tsa-cert` **was** given and a check WAS attempted, but the result couldn't be confirmed either way (e.g. a known backend limitation — see [Backend](#backend-openssl-or-rfc3161ng)) — reason `TSA timestamp could not be verified`. Also contributes to `[FAIL] Verification completed with issues` | `1` |

**Integrity vs. authenticity.** Plain `--verify` checks *both* that files are unchanged **and** — when the manifest implies it is signed — that a valid signature establishes authenticity. How a manifest verifies depends on what it declares about itself:

- **The manifest declares itself unsigned** (it was created without signing). `--verify` checks integrity only, prints `[WARN] Manifest note: MANIFEST UNSIGNED`, and returns `0` when the hashes match. No signature is expected.
- **The manifest implies a signature** (it does *not* carry the unsigned marker) but no valid signature is provided. `--verify` prints `[FAIL] Verification completed with issues: …` and returns `1` — the files are intact, but the authenticity the manifest claims could not be confirmed. The same verdict applies if you passed `--tsa-cert` and the timestamp check came back inconclusive — anything you explicitly asked to be checked and couldn't be confirmed blocks a clean `[PASS]`, listing every such reason together.
- **You want integrity only, regardless of what the manifest declares.** Add **`--ignore-sig`** to `--verify`. It skips all signature checks and returns `0` when the hashes match — useful when you have the signed manifest but not its signature file, or simply don't care who signed it.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All checks passed / manifest created successfully |
| `1` | Verification found issues — modified/missing/new files, an invalid signature, an untrusted signer under `--trust high`, a missing signature or algorithm, or authenticity that could not be established (see [Verdict lines](#verdict-lines)) |
| `2` | Usage or input error — bad arguments, missing files, unsupported algorithm |
| `3` | Signing refused — untrusted key under `--trust high` |

Exit codes always fire regardless of `--quiet`, and security-relevant warnings (untrusted key, old/unverifiable manifest) are always printed to stderr even in quiet mode. Routine notices (progress, "signing skipped") are suppressed by `--quiet`.

---

## Hashing Progress

Before hashing, both create and verify print a quick two-line status so a large notebook (or arbitrary directory) never looks like it's hung during the initial scan:

```
[INFO] Counting files...
[OK] 214 files to hash
```

What happens next depends on the mode:

- **Normal mode** (no `--verbose`, no `--quiet`, and stdout is a real terminal) shows a live, self-overwriting progress line:
  ```
  ⠹ Hashing... 87/214 files (41%) [Time Elapsed: 2.3s]
  ```
  The spinner frame advances once per completed file (not on a wall-clock timer), so it's simple, thread-safe under `--jobs`, and proportional to real progress. Elapsed time shows milliseconds while under a second, then seconds with one decimal. On a terminal whose encoding can't render the spinner glyph (some Windows consoles default to `cp1252`), it automatically falls back to a plain `| / - \` spinner instead — detected once per run, never crashes.
- **`--verbose`** replaces the bar with one line per file instead: `[OK] 87/214 2026-05.txt 2026-07-10T11:57:37Z (1.34ms)` — more detail, less concise.
- **`--quiet`** suppresses both the counting lines and the bar entirely.
- **`--json`** suppresses the bar (stdout must stay pure JSON) but keeps the counting lines on stderr.
- Piped or redirected output (not a real TTY) never receives the bar's escape codes, regardless of the above — same detection `_tag()` already uses for colour.

---

## Multi-Hashing

Pass more than one comma-separated algorithm to `--hash` to record several independent hashes per file:

```bash
python rednb-verify.py ~/journal --hash sha256,blake2b
```

Each file is hashed with every algorithm in a single read pass. A file verifies as `ok` **only if every hash matches** — defending against a collision crafted for one algorithm. `md5` and `sha1` may never be used **alone** (you'll be prompted, or it's refused in automation), but they may appear alongside a strong hash.

In multi mode the manifest stores `hash_algorithm` as a list and nests per-file hashes:

```json
{ "path": "2026-05.txt", "hashes": { "blake2b": "...", "sha256": "..." } }
```

**Merkle trees in multi mode:**
- By default one tree is built per algorithm (`merkle_roots`).
- `--hash-merkle sha256` selects a subset of those trees.
- `--hash-merkle-concatenate [ALGO]` builds one extra tree whose leaves are the per-file concatenation of all hashes (`merkle_root_concat`).

Optional faster/non-stdlib algorithms (`blake3`, `xxh3`) are used automatically if installed; `--hash-list` shows what's available and the `pip install` for what isn't.

---

## Merkle Tree

Each manifest records a Merkle root — a single hash that commits to the entire set of per-file hashes. It is the value that gets signed and can be republished out of band, so a notebook's integrity can be summarized by one short string.

The tree is built RFC 6962-style, with two defences against an attacker constructing a *different* file set that hashes to the *same* root:

- **Domain separation.** Leaf nodes are hashed with a `0x00` prefix and internal nodes with `0x01`. Without this, a leaf digest and an internal digest are computed identically, so an internal node's two children could be passed off as a single leaf — a second-preimage forgery of the tree's shape.
- **Odd-node promotion, not duplication.** When a level has an odd number of nodes, the last node is carried up unchanged. Naively *duplicating* it is the [CVE-2012-2459](https://nvd.nist.gov/vuln/detail/CVE-2012-2459) weakness: duplicating the last leaf makes a three-file tree collide with a real four-file tree, so files can be added or removed without changing the root.

### Worked example (sha256)

Three files with contents `alpha`, `beta`, `gamma`. Their sha256 leaf hashes:

```
alpha  8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8
beta   f44e64e75f3948e9f73f8dfa94721c4ce8cbb4f265c4790c702b2d41cfbf2753
gamma  be9d587defa1f0c09ef49eb17e206983a5f8f8289e4281860bd0ee5a19592c67
```

The tree (note `gamma`'s leaf is odd, so it is promoted unchanged):

```
L_alpha = sha256(0x00 ‖ alpha)            34f04379...a98ee518
L_beta  = sha256(0x00 ‖ beta)             9f6d34ba...affb21dd
L_gamma = sha256(0x00 ‖ gamma)            d130c2ca...ae1ebe06

N0      = sha256(0x01 ‖ L_alpha ‖ L_beta) 984d5c63...be46f77c
          (L_gamma promoted)

root    = sha256(0x01 ‖ N0 ‖ L_gamma)
        = bb1e6ce657790b193bfea0ec6c4bb2c8377aba31bb09d25cec48668f0fa3b159
```

The duplicate-leaf attack no longer works — a four-file set `[alpha, beta, gamma, gamma]` produces a **different** root (`c8b59b9e…49c95109`) instead of colliding with the three-file root above. These values are pinned as known-answer vectors in `tests/test_merkle.py`.

> **Schema note.** This construction was introduced in manifest schema **version 2**. Roots produced by schema-1 manifests (rednb-verify ≤ 0.8.0) used the older, vulnerable construction and will not match; verifying such a manifest prints an old-schema security warning. Schema **version 3** adds the move-invariant [content root](#move-detection).

---

## Move detection

Alongside the path-ordered `merkle_root`, a schema-v3 manifest stores a **`content_root`** (`content_roots` in multi-hash mode): the same RFC 6962 tree, but with leaves sorted by **hash value** instead of by path. That makes it **move-invariant** — it commits to the *set* of file contents regardless of where each file lives.

At verify time the content root is recomputed from the live files and compared to the stored one, which separates two very different situations:

- **Content root matches, every path matches** → nothing changed → `[PASS] Verification successful`.
- **Content root matches, but some paths differ** → every byte is still present, files were only **relocated/renamed/swapped** → `[OK] Move-invariant/Content Merkle root pass: All files present` followed by `[FAIL] Files moved` (exit `1`). The report's `MOVED` section pairs each `old/path -> new/path`.
- **Content root differs** → content was genuinely added, removed, or modified → the usual `[FAIL] … Missing/Modified/New` (exit `1`).

So a reshuffled-but-intact tree is reported as a move rather than alarming tampering, while real content changes still fail. Manifests written before schema v3 have no content root and simply skip this check.

---

## Symlinks

Symbolic links are a blind spot for a naive integrity tool: a symlinked file is hashed by its *target's* content, so swapping a real file for a link to an identical-content file elsewhere — or quietly repointing a link — leaves the file hash unchanged. rednb-verify follows symlinks (so their content is still hashed) **and** records a separate **symlink table** committing to where each link points.

At verify time this catches what content hashing alone cannot:

- a recorded symlink that vanished or became a regular file (`Sym removed`)
- a symlink whose target changed (`Sym changed`)
- a symlink that appeared where the manifest committed to none (`Sym new`)

Any of these fails verification (**exit 1**). The table is recorded even when a notebook has zero symlinks, so a link added later is still detected.

A symlink whose target resolves **outside** the base directory is flagged with `[WARN] Symlink points outside the notebook: …` at both create and verify — its content is pulled in from elsewhere on the system, and it's a repointing surface worth eyeballing. To skip all symlink comparison and warnings during a verify (parallel to `--ignore-sig`), pass **`--ignore-symlinks`**.

### Recording policy — `--symlink-targets`

The target path itself can be sensitive — it may expose home directories, usernames, or the existence of off-notebook data — and a manifest is meant to be shared and signed. So the default records a **hash** of the target, not the path:

| Mode | What the manifest stores | Use when |
|---|---|---|
| `hash` *(default)* | `sha256` of the target — detects changes, reveals nothing | almost always |
| `hash:ALGO[:LEN]` | same, with a chosen algorithm (e.g. `hash:blake2b`) | you standardise on another hash |
| `full` | the cleartext target path | local/forensic use where the path is not sensitive |
| `none` | no table at all | you don't want symlinks recorded |

`--no-symlink-table` is an alias for `--symlink-targets none`, and `--privacy` implies it.

In the manifest, hashed and cleartext entries are distinguished by field:

```json
"symlink_targets": "hash:sha256",
"symlinks": [
  { "path": "journal/old.txt", "target_hash": "9f2c…" }
]
```

```json
"symlink_targets": "full",
"symlinks": [
  { "path": "journal/old.txt", "target": "/home/user/archive/2024.txt" }
]
```

---

## Schema & Validation

Every JSON manifest conforms to a **JSON Schema** (Draft 2020-12). The schema is **embedded in the script**, so `--validate` is self-contained — it works from the single downloaded `rednb-verify.py` with no extra files. For external tools (editors, `check-jsonschema`, the links here) the same schemas are also exported at [`schema/manifest-v3.schema.json`](schema/manifest-v3.schema.json) and [`schema/report-v1.schema.json`](schema/report-v1.schema.json); those files are generated from the embedded copies (a test keeps them in sync). Validation lets you catch a malformed or truncated manifest *before* trusting it — handy in CI, or before archiving.

Validate with the built-in flag (requires the optional `jsonschema` package):

```bash
pip install jsonschema

# Validate a specific manifest (or a report — the schema is auto-selected)
python rednb-verify.py --validate hashes-20260617T120000Z.json

# Validate the latest manifest in a directory
python rednb-verify.py --validate ~/journal

# Print / regenerate the schema itself (no dependency needed)
python rednb-verify.py --dump-schema manifest > manifest.schema.json
python rednb-verify.py --dump-schema report
```

A `--verify` run also **auto-validates** the manifest first (best-effort: skipped silently when `jsonschema` isn't installed). This works for text manifests too — they're parsed to the same structure before validation.

Exit codes: `0` valid, `1` schema-invalid (errors are printed with their location), `2` usage error or `jsonschema` not installed.

You can also validate with any standard tool, e.g. [`check-jsonschema`](https://github.com/python-jsonschema/check-jsonschema):

```bash
check-jsonschema --schemafile schema/manifest-v3.schema.json hashes-*.json
```

A minimal valid manifest looks like:

```json
{
  "tool": "rednb-verify",
  "version": "0.11.0",
  "schema_version": 3,
  "created": "20260617T120000Z",
  "date": "2026-06-17",
  "mode": "month-only",
  "hash_algorithm": "sha256",
  "merkle_root": "bb1e6ce6…",
  "content_root": "7b1d8c0a…",
  "files": [
    { "path": "2026-06.txt", "sha256": "be9d587d…" }
  ],
  "symlink_targets": "hash:sha256",
  "symlinks": []
}
```

---

## Trust & Signing

`--trust` controls which keys may sign and which signers are accepted at verify:

- **`low`** (default) — any key may sign; a notification is printed when the key isn't pinned.
- **`high`** — only keys whose fingerprint is pinned in the config trust list may sign (others are refused, **exit 3**), and at verify time a valid signature from an unpinned key **fails** verification (exit 1) — defending against key substitution.

Pin keys with the config-management flags:

```bash
# Pin a GPG fingerprint and an SSH key fingerprint
python rednb-verify.py --add-trust trust-gpg:ABCDEF1234567890
python rednb-verify.py --add-trust "trust-ssh:SHA256:abc123..."

# Make high trust the default, and save a default journal directory
python rednb-verify.py --set-cf trust-level:high
python rednb-verify.py --set-cf dir:~/journal

# Preview the resulting config without writing extra runs
python rednb-verify.py --add-trust trust-gpg:ABCDEF --config-out
```

Before each signing or verification, the key's **fingerprint randomart** is shown (native `ssh-keygen` art for SSH, a Drunken-Bishop rendering for GPG) so you can eyeball-confirm the key out of band. The verified signer's fingerprint is also recorded in the manifest's `signed_by` field as a hint — but trust decisions always use the *cryptographically verified* key, never that field.

> **Pin the maintainer fingerprint out of band.** To trust this project's own releases, obtain the maintainer's published key fingerprint from a separate channel (the project page) and pin it — don't trust a fingerprint that travels with the manifest.

---

## Trusted Timestamping (RFC 3161)

> **⚠ EXPERIMENTAL.** `--tsa` is new. Live testing against all six `--tsa-list` providers found and fixed a real verification bug in the `rfc3161ng` fallback backend; one known limitation (EC-signed tokens) remains — see [Backend](#backend-openssl-or-rfc3161ng) below for exactly what's confirmed working. The tool prints a warning whenever `--tsa` or a `--tsa-cert` check runs.

A signature proves *who* vouched for a manifest; a **trusted timestamp** proves *when* it existed. `--tsa` sends the manifest's hash (never its contents) to a Timestamp Authority, which returns a signed token binding that hash to a UTC time. Anyone can later verify — **fully offline** — that the manifest existed at or before that moment, which defeats back-dating even by the manifest's own author.

**Network policy.** The tool is offline by default and this feature is **strictly opt-in**: the timestamp *request* at create time is the only network operation in the entire tool, it announces itself (`[INFO] Requesting timestamp from <url>`), makes a single POST with a fixed timeout and no retries, and never runs unless you pass `--tsa`. Token *verification* is local (`openssl ts -verify`). Pass `--offline` to make the no-network guarantee explicit in the command itself.

```bash
# Create + timestamp: detached token saved as hashes-....txt.tsr
python rednb-verify.py ~/journal --no-sign --tsa digicert

# Same, against your own/self-hosted TSA
python rednb-verify.py ~/journal --no-sign --tsa https://tsa.example.org/tsr

# Embed ONE stamp over the placement root into the manifest (no sidecar)
python rednb-verify.py ~/journal --no-sign --tsa freetsa --tsa-embed

# Embed SEPARATE placement + content stamps (independent attestation)
python rednb-verify.py ~/journal --no-sign --tsa freetsa --tsa-embed-separate

# Verify, checking the token against the TSA's CA certificate (local, no network)
python rednb-verify.py ~/journal --verify --tsa-cert ~/certs/tsa-ca.pem

# Verify without checking the timestamp
python rednb-verify.py ~/journal --verify --ignore-tsa

# List the built-in TSA registry
python rednb-verify.py --tsa-list
```

### Detached vs embedded

| Mode | What the stamp covers | Where it lives | Requests |
|---|---|---|---|
| *(default)* | the **written manifest file's exact bytes** (strongest claim: covers every root, hash, and field) | detached `hashes-….tsr` sidecar, like `.asc`/`.sshsig` | 1 |
| `--tsa-embed` | the **placement root** (`merkle_root`, or the concat root in multi-hash mode) | `tsa_stamp` field inside the manifest | 1 |
| `--tsa-embed-separate` | the placement root **and** the content root, separately | `tsa_merkle`/`tsa_concat` + `tsa_content` fields | 2 |

Embedded stamps cover **root values**, never the manifest itself — a token embedded into the very bytes it covers would invalidate itself. Because the roots don't change when the stamp fields are added, the manifest stays self-consistent, and signatures applied at creation cover the embedded stamps too. `--tsa-embed-separate` exists for forensics: with separate stamps, a third party can attest the *content* commitment and the *placement* commitment independently — e.g. prove the content set's timestamp without relying on the placement tree, or vice versa. In multi-hash mode the placement stamp uses the single concatenated root (`merkle_root_concat`, computed and stored automatically if absent), and the content stamp covers the alphabetical `algo:root,…` join of `content_roots`.

An embedded stamp entry looks like:

```json
"tsa_stamp": {
  "tsa": "http://timestamp.digicert.com",
  "time": "Jul  3 00:00:00 2026 GMT",
  "token_b64": "MIIC…"
}
```

### If the TSA request fails

Hashing a large notebook can take real time and effort, so a failed timestamp request never throws that work away:

- **Embedded** (`--tsa-embed`/`--tsa-embed-separate`): the failed field is written as the literal string `"failed"` (e.g. `"tsa_stamp": "failed"`) instead of a token, and the manifest is written normally. `--verify` notices this and warns `Timestamp was not applied` rather than treating it as tampering. Add a real token later — once `--resign` supports it (planned; see below).
- **Detached** (default): the manifest (and any signature) is written as usual, just without a `.tsr` file. In an **interactive** terminal without `-y`, the tool halts (exit 1) so you notice; with `-y`, or in a non-interactive/scripted run, it just warns and continues.

### Verifying timestamps

`--verify` checks any detached `.tsr` sidecar and any embedded stamps automatically — but cryptographic verification needs the TSA's **CA certificate** (`--tsa-cert CAFILE`; most TSAs publish theirs). A TSA claim that's present and not ignored is expected to actually be checked: without `--tsa-cert`, or if the check is inconclusive, the tool prints a `[WARN]` explaining why **and** the run ends in `[FAIL] Verification completed with issues` (exit `1`) rather than a silent pass — the same principle as an implied signature nobody could verify. A confirmed-bad token is `[FAIL] TSA timestamp failed` (exit `1`) directly. `--ignore-tsa` is the deliberate opt-out — it skips the checks entirely and allows a clean `[PASS]` with an unconfirmed TSA claim present.

You can also verify a detached token with plain OpenSSL, independent of this tool:

```bash
openssl ts -verify -data hashes-20260703T000000Z.txt \
  -in hashes-20260703T000000Z.txt.tsr -CAfile tsa-ca.pem
```

### Choosing a TSA

`--tsa-list` prints the built-in registry (DigiCert, Sectigo, GlobalSign, Certum, Apple, freeTSA). Public TSAs give you an *independent* attestation; a **self-hosted** TSA (e.g. `openssl ts` or `uts-server`) works with `--tsa <url>` but only convinces parties who trust *your* TSA key — fine for internal audit trails, useless against an accusation of back-dating. Note the request discloses a **hash** of your manifest plus your IP address and the request time to the TSA — not your data.

### Backend: openssl or `rfc3161ng`

`--tsa` needs a way to build and check RFC 3161 requests. **`openssl` is tried first** (widely available on Linux/macOS, and well field-tested); if it isn't on PATH — as on a stock Windows machine, which ships no openssl — the optional **`rfc3161ng`** Python package is used instead (`pip install rfc3161ng`, or `--install-opt`). Nothing else about `--tsa` changes based on the backend.

**Status as of live testing (2026-07-11):**

| | Request (create) | Verify |
|---|---|---|
| `openssl` | ✅ Not yet independently live-tested, but the standard, mature path | ✅ No known issues |
| `rfc3161ng` | ✅ Confirmed working against freeTSA, Apple, DigiCert, Sectigo, GlobalSign, and Certum | ✅ RSA tokens verify against a pinned CA **or** the system trust store (all six providers); EC is a known limitation — see below |

Live testing against all six `--tsa-list` providers found and fixed a real false-negative bug in the `rfc3161ng` verify path: the CMS `certificates` field is an *unordered* set (RFC 5652 defines no order), but the library's own cert lookup naively assumes the first entry is the signer's certificate. Apple and Sectigo both send that set root-first (root/intermediate before the actual signer), so the library ended up checking the signature against the wrong certificate entirely — a false `[FAIL] TSA timestamp failed` for a completely legitimate token (independently proven valid via real `openssl cms -verify -noverify`). Fixed by identifying the true signer certificate via `signerInfo`'s issuer+serial number instead of guessing index 0; regression tests pin both real tokens.

One limitation remains, and is expected to stay: an **EC-signed token** (e.g. freeTSA's) crashes the library's hardcoded-RSA signature check. This is caught and reported as `[WARN] ... inconclusive`, never a false pass or false tamper report — tamper detection itself is unaffected, since the message-imprint check (does this token actually match this data?) runs *before* the signature step and doesn't depend on key type. `openssl`, when available, has no equivalent issue with EC-signed tokens and is used automatically in preference to `rfc3161ng` whenever it's on PATH. `--tsa-list` marks which hosts are EC.

#### Obtaining a trust anchor (`--tsa-cert`)

At `--verify`, the trust anchor comes from one of three places, in order:

1. **`--tsa-cert <file>`** — a PEM with the provider's root (or any cert on the signer's chain). You can pass the **root**; the tool builds the chain through the intermediates the token already carries (matching `openssl -CAfile`). `--tsa-list` links each provider's official CA page. With `openssl` on PATH this uses `openssl ts -verify`; otherwise it uses the `rfc3161ng` backend, which does a signature-chain check only (no revocation/EKU/temporal validation — `openssl` remains the fully-rigorous path).
2. **No `--tsa-cert`** → the tool validates the token's chain against your **OS system trust store** (Windows/macOS/Linux). For well-known commercial TSAs (whose roots ship in the OS store) this means `--verify` "just works" with no cert file and no network. A signer that doesn't chain to any trusted root is reported **inconclusive**, never as tampering.
3. **Online fetch (opt-in)** — if a system-store check is inconclusive only because an intermediate is missing, the tool offers to fetch it via the certificate's AIA `caIssuers` URL. This is the sole verify-time network action: it prompts for a yes/no, is skipped under `-y`/`--quiet`, and is blocked by `--offline`.

At **create** time, the tool reports the token's signer key type (RSA or EC) so you know up-front whether this machine can verify it. If a token is EC-signed and no `openssl` is present, it warns (and, interactively, asks whether to keep the un-verifiable-here token).

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
    "jobs": 4,
    "trust_level": "low",
    "dir": "~/journal",
    "trust": {
        "gpg": ["FINGERPRINT1", "FINGERPRINT2"],
        "ssh": ["SHA256:abc...", "SHA256:def..."]
    }
}
```

A notification is printed when a config file is in use. Use `--no-config` / `--no-cf` to ignore it for a single run, or `--config FILE` to load an alternate file. The `--set-cf` / `--add-trust` flags edit this file for you (always the default file unless `--config` redirects). When `dir` is set, `notebook_dir` may be omitted on the command line.

> **Shell quoting:** quotes are only needed when a value contains spaces. Comma-separate multiple values, e.g. `--set-cf trust-gpg:AB12,CD34`. Repeated flags avoid quotes entirely.

### Config field reference

Every field is optional; an absent field simply falls back to the tool's default. CLI flags always win over config values.

| Field | Type | CLI equivalent | Effect |
|---|---|---|---|
| `hash` | string | `--hash ALGO` | Default file-hash algorithm spec; comma-separate for multi-hashing (`"sha256,blake2b"`) |
| `hash_merkle` | string \| `null` | `--hash-merkle ALGO` | Merkle combiner (single mode) / tree selection (multi mode); `null` = same as `hash` |
| `quiet` | bool | `--quiet` | Suppress non-error output on every run (implies `no_sign` unless a signing key is configured) |
| `no_sign` | bool | `--no-sign` | Never prompt to sign |
| `gpg_key` | string | `--gpg FPR` | GPG fingerprint to sign with (skips the key menu) |
| `ssh_key` | string (path) | `--ssh FILE` | SSH key to sign with; `~` is expanded |
| `exclude` | array of strings | `--exclude PATTERN` | Glob patterns excluded from every run |
| `manifest_age_warn_days` | integer | `--warn-age DAYS` | Warn during `--verify` when the manifest is older than N days |
| `jobs` | integer | `--jobs N` | Parallel hashing workers (`0` = auto; default when unset: `max(1, cores-2)`) |
| `trust_level` | `"high"` \| `"low"` | `--trust high\|low` | Default trust level; written by `--set-cf trust-level:high` |
| `dir` | string (path) | *(positional)* | Default notebook directory when none is given; written by `--set-cf dir:...` |
| `trust.gpg` | array of strings | — | Pinned GPG fingerprints for `--trust high`; written by `--add-trust trust-gpg:...` |
| `trust.ssh` | array of strings | — | Pinned SSH key fingerprints (`SHA256:...`) for `--trust high`; written by `--add-trust trust-ssh:...` |

Only `trust-gpg`, `trust-ssh`, `trust-level`, and `dir` are managed by the `--set-cf` / `--add-trust` flags — the rest are edited by hand (the file is plain JSON).

### Example profiles

**Nightly cron run** — hash a fixed journal quietly with a pre-selected GPG key, and complain at verify time if the newest manifest is stale:

```json
{
    "dir": "~/journal",
    "quiet": true,
    "gpg_key": "AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12",
    "jobs": 0,
    "exclude": ["*.tmp", ".~lock.*"],
    "manifest_age_warn_days": 7
}
```

With that in place, the cron lines shrink to `rednb-verify.py` (create + sign) and `rednb-verify.py --verify` (check).

**High-trust workstation** — only pinned keys may sign, and a valid signature from any *other* key fails verification:

```json
{
    "dir": "~/journal",
    "trust_level": "high",
    "trust": {
        "gpg": ["AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12"],
        "ssh": ["SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"]
    }
}
```

Equivalent to running `--set-cf trust-level:high`, `--add-trust trust-gpg:AB12…`, and `--add-trust "trust-ssh:SHA256:nThbg…"` once.

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

- Single file, minimal dependencies (stdlib only; PyYAML optional for `--per-day`, jsonschema optional for `--validate`)
- Deterministic output
- Explicit trust boundaries
- No hidden metadata
- Human-inspectable manifests
- Hardware security encouraged, not required

---

## Planned

- Manifest chaining (each manifest references the previous one, making history tamper-evident)
- Direct FIDO2/CTAP2 integration (hardware signing without SSH key setup)
- RedNotebook UI integration
- **rednb-verify-config** — GUI config editor (desktop app for managing `~/.config/rednb-verify/config.json`, trusted keys, and saved paths without touching the CLI)

---

## Project Status

Active development. Review, testing, and cryptographic scrutiny are welcome.
