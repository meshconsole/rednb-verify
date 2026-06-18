# rednb-verify

**rednb-verify** (short for *rednotebook-verify*) is an integrity and verification tool designed to detect tampering in **RedNotebook** journals or file directories.

It creates cryptographic manifests of notebook entries and optionally signs them with GPG or SSH keys, producing a verifiable snapshot of the notebook at a specific point in time.

The project focuses on **tamper detection, auditability, and long-term trust** — not secrecy.

**Version:** 0.9.0 | **Python:** 3.10+ | **Dependencies:** stdlib only (`pyyaml` for `--per-day`, `jsonschema` for `--validate`)

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

**Optional dependency** — needed only for `--per-day` (per-day journal entry hashing):

```bash
pip install pyyaml
# or
pip install -r requirements.txt
```

**External tools** used when available (not required for basic operation):
- `gpg` — for GPG signing and verification
- `ssh-keygen` — for SSH signing and verification (ships with OpenSSH)

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

Run the tool against a directory to hash its contents and write a manifest. Signing happens at creation time (or later with `--resign`).

| Flag | Description |
|---|---|
| `notebook_dir` | Path to the RedNotebook journal (or any directory) to hash (optional if `dir` is saved in config) |
| `-m`, `--month-only` | Hash only `YYYY-MM.txt` month files (skip attachments, config, etc.) |
| `-D`, `--per-day` | Hash individual day entries within month files; manifest path format `YYYY-MM/DD`. Combine with `--month-only` to control whether non-month files are also included (requires `pyyaml`) |
| `-j N`, `--jobs N` | Parallel hashing workers (`0` = auto via `os.cpu_count()`; default: `1`) |
| `-o`, `--output DIR` | Output directory for the manifest (default: parent of the journal directory) |
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
| `--gpg [FPR]` | Sign with GPG; optionally specify a key fingerprint to skip the selection menu |
| `--gpg-k FILE` | GPG armored key export file to sign with; implies `--gpg` |
| `--ssh [FILE_OR_DIR]` | Sign with SSH key; optionally specify a `.pub` file or directory to scan (default: `~/.ssh`) |
| `--ssh-fido [NAME]` | Prefer FIDO2/hardware-backed SSH keys; optional name filter |
| `--trust [high\|low]` | Signing trust level (default: `low`). `high` only allows pinned keys to sign — and also rejects untrusted signers at verify |
| `--no-sign` | Skip all signing prompts |
| `--resign FILE` | Re-sign an existing manifest without re-hashing or rewriting it (requires `--gpg` and/or `--ssh`) |

### Verification

Check a directory against a previously created manifest.

| Flag | Description |
|---|---|
| `--verify [FILE\|DIR]` | Verify mode — pass a manifest file directly, a directory to search, or omit to auto-find the latest manifest in the output directory |
| `--report [txt\|json]` | Verification report format: `txt` human-readable (default) or `json` structured |
| `--ssh-verify` | Force SSH signature check during `--verify` |
| `--ignore-sig` | During `--verify`, check integrity only and skip all signature checks (returns `0` when hashes match) |
| `--sig FILE[,FILE]` | Signature file(s), comma-separated; `.asc`=GPG, `.sshsig`/`.sig`=SSH |
| `--warn-age DAYS` | During `--verify`, print a warning if the manifest is older than N days |
| `--schema-ignore` | Verify a manifest whose schema is newer than this tool supports (risky) |

### Validation

Check a manifest's structure without touching the journal — useful in CI or before relying on a manifest.

| Flag | Description |
|---|---|
| `--validate [FILE\|DIR]` | Validate a manifest against the bundled JSON schema and exit. Requires the optional `jsonschema` package. See [Schema & Validation](#schema--validation) |

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
```

### Other

| Flag | Description |
|---|---|
| `-V`, `--version` | Print version and exit |
| `-v`, `--verbose` | Print per-file hash timing and detailed progress |
| `--quiet` | Suppress non-error output; implies `--no-sign` unless a signing flag is given |
| `-y`, `--yes` | Assume yes to confirmation prompts (automation-friendly) |
| `--privacy` | Minimise what the manifest discloses (currently implies `--no-symlink-table`) |

---

## Manifest Format

Manifests are named `hashes-<timestamp>.txt` (default) or `hashes-<timestamp>.json`. Use `--manifest-type json` to produce JSON instead of the default text format.

### Text format (default)

```
rednb-verify manifest
version: 0.9.0
schema_version: 2
created: 20260528T120000Z
date: 2026-05-28
hash_algorithm: sha256
mode: full-tree
merkle_hash: sha256
merkle_root: fe2402e74e8d9a317b6469875e3c704ec2b9fa585db1f49c495282f53a3410cf

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
  "version": "0.9.0",
  "schema_version": 2,
  "created": "20260528T120000Z",
  "date": "2026-05-28",
  "mode": "full-tree",
  "hash_algorithm": "sha256",
  "merkle_hash": "sha256",
  "merkle_root": "fe2402e74e8d9a317b6469875e3c704ec2b9fa585db1f49c495282f53a3410cf",
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
- `schema_version` — manifest format version (`2`); verifying an older one prints a security warning
- `hash_algorithm` — algorithm used for individual file hashes; also the field name on each file entry
- `merkle_hash` — algorithm used to compute the Merkle tree root
- `merkle_root` — root of the [Merkle tree](#merkle-tree) over the file hashes
- `date` — creation date in `YYYY-MM-DD` for human readability
- `created` — full UTC timestamp for machine use
- `mode` — one of `full-tree`, `month-only`, `per-day/full-tree`, `per-day/month-only`
- `symlink_targets` / `symlinks` — symlink recording policy and table (see [Symlinks](#symlinks))

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

### Verdict lines

After writing the report, `--verify` prints a single terminal verdict:

| Line | Meaning | Exit |
|---|---|---|
| `[OK] Verification successful` | Hashes intact; the manifest is either authentically signed or honestly declares itself unsigned | `0` |
| `[FAIL] X Missing, N Modified, Z New/Moved, K/T OK` | One or more files changed (`K/T` = matching/expected files) | `1` |
| `[FAIL] Manifest failed Signature` | A signature is present but did not validate (tampering) | `1` |
| `[FAIL] Untrusted signer (--trust high)` | Signature valid, but the signer is not pinned in your trust list | `1` |
| `[WARN] Missing Algorithms: blake3 …` | The manifest uses a hash this build cannot compute (verification can't be completed) | `1` |
| `[WARN] Verification completed with issues` | Hashes intact, but the manifest implies a signature that could not be established | `1` |

**Integrity vs. authenticity.** Plain `--verify` checks *both* that files are unchanged **and** — when the manifest implies it is signed — that a valid signature establishes authenticity. How a manifest verifies depends on what it declares about itself:

- **The manifest declares itself unsigned** (it was created without signing). `--verify` checks integrity only, prints `[WARN] Manifest note: MANIFEST UNSIGNED`, and returns `0` when the hashes match. No signature is expected.
- **The manifest implies a signature** (it does *not* carry the unsigned marker) but no valid signature is provided. `--verify` prints `[WARN] Verification completed with issues` and returns `1` — the files are intact, but the authenticity the manifest claims could not be confirmed.
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

> **Schema note.** This construction is part of manifest schema **version 2**. Roots produced by schema-1 manifests (rednb-verify ≤ 0.8.0) used the older, vulnerable construction and will not match; verifying such a manifest prints an old-schema security warning.

---

## Symlinks

Symbolic links are a blind spot for a naive integrity tool: a symlinked file is hashed by its *target's* content, so swapping a real file for a link to an identical-content file elsewhere — or quietly repointing a link — leaves the file hash unchanged. rednb-verify follows symlinks (so their content is still hashed) **and** records a separate **symlink table** committing to where each link points.

At verify time this catches what content hashing alone cannot:

- a recorded symlink that vanished or became a regular file (`Sym removed`)
- a symlink whose target changed (`Sym changed`)
- a symlink that appeared where the manifest committed to none (`Sym new`)

Any of these fails verification (**exit 1**). The table is recorded even when a notebook has zero symlinks, so a link added later is still detected.

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

Every JSON manifest conforms to a published **JSON Schema** (Draft 2020-12), shipped in the repo at [`schema/manifest-v2.schema.json`](schema/manifest-v2.schema.json). It lets you catch a malformed or truncated manifest *before* trusting it — handy in CI, or before archiving.

Validate with the built-in flag (requires the optional `jsonschema` package):

```bash
pip install jsonschema

# Validate a specific manifest
python rednb-verify.py --validate hashes-20260617T120000Z.json

# Validate the latest manifest in a directory
python rednb-verify.py --validate ~/journal
```

Exit codes: `0` valid, `1` schema-invalid (errors are printed with their location), `2` usage error or `jsonschema` not installed.

You can also validate with any standard tool, e.g. [`check-jsonschema`](https://github.com/python-jsonschema/check-jsonschema):

```bash
check-jsonschema --schemafile schema/manifest-v2.schema.json hashes-*.json
```

A minimal valid manifest looks like:

```json
{
  "tool": "rednb-verify",
  "version": "0.9.0",
  "schema_version": 2,
  "created": "20260617T120000Z",
  "date": "2026-06-17",
  "mode": "month-only",
  "hash_algorithm": "sha256",
  "merkle_root": "bb1e6ce6…",
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

- RFC 3161 trusted timestamping (cryptographic proof of time from a timestamp authority)
- Manifest chaining (each manifest references the previous one, making history tamper-evident)
- `--json` output mode (structured JSON on stdout for piping and scripting)
- Direct FIDO2/CTAP2 integration (hardware signing without SSH key setup)
- RedNotebook UI integration
- **rednb-verify-config** — GUI config editor (desktop app for managing `~/.config/rednb-verify/config.json`, trusted keys, and saved paths without touching the CLI)

---

## Project Status

Active development. Review, testing, and cryptographic scrutiny are welcome.
