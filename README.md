# rednb-verify

**rednb-verify** (short for *rednotebook-verify*) is an integrity and verification tool designed to detect tampering in **RedNotebook** journals.

It creates cryptographic manifests of notebook entries and optionally signs them with GPG or SSH keys, producing a verifiable snapshot of the notebook at a specific point in time.

The project focuses on **tamper detection, auditability, and long-term trust** — not secrecy.

**Version:** 0.5.5 | **Python:** 3.10+ | **Dependencies:** none (stdlib only)

---

## Quick Start

```bash
# Create a manifest (signing menu appears; saved next to the journal)
python rednb-verify.py ~/journal

# Create a manifest without signing
python rednb-verify.py ~/journal --no-sign

# Verify the journal against a manifest
python rednb-verify.py ~/journal --verify --manifest hashes-20260528T120000Z.json

# Verify and write a JSON report
python rednb-verify.py ~/journal --verify --manifest hashes-20260528T120000Z.json --report json
```

---

## Usage

```
rednb-verify.py [options] notebook_dir
```

### Arguments

| Flag | Description |
|---|---|
| `notebook_dir` | Path to the RedNotebook journal directory |
| `-m`, `--month-only` | Hash only `YYYY-MM.txt` month files (skip attachments, config, etc.) |
| `-o`, `--output DIR` | Output directory for the manifest (default: parent of the journal directory) |
| `--verify` | Verify mode — compare notebook against a manifest |
| `--manifest FILE` | Manifest file to verify against (required with `--verify`) |
| `--report [txt\|json]` | Report format during verify: `txt` human-readable (default) or `json` structured |
| `--hash ALGO` | Hash algorithm for files (default: `sha256`) |
| `--hash-merkle ALGO` | Hash algorithm for the Merkle tree (default: same as `--hash`) |
| `--ssh-sign` | Sign the manifest with an SSH key (skips signing menu) |
| `--ssh-verify` | Force SSH signature check during `--verify` |
| `--sig FILE[,FILE]` | Signature file(s), comma-separated; `.asc`=GPG, `.sshsig`=SSH |
| `--ssh-kl FILE_OR_DIR` | SSH `.pub` key file (used directly) or directory to scan (default: `~/.ssh`) |
| `--ssh-fido [NAME]` | Prefer FIDO2/hardware-backed SSH keys; optional name filter |
| `--no-sign` | Skip all signing prompts |

### Examples

```bash
# Hash only month files, save manifest alongside the journal
python rednb-verify.py ~/journal --month-only --output ~/journal

# Create manifest and skip signing
python rednb-verify.py ~/journal --no-sign

# Use blake2b for file hashes, sha256 for the Merkle tree
python rednb-verify.py ~/journal --hash blake2b --hash-merkle sha256

# Create and sign — interactive menu asks how to sign
python rednb-verify.py ~/journal

# Create and sign with SSH directly (skips menu)
python rednb-verify.py ~/journal --ssh-sign

# Create and sign with a FIDO2/YubiKey-backed SSH key
python rednb-verify.py ~/journal --ssh-sign --ssh-fido

# Use a specific SSH public key file directly (no directory scan)
python rednb-verify.py ~/journal --ssh-sign --ssh-kl ~/.ssh/id_ed25519.pub

# Verify with both GPG and SSH signatures at the same time
python rednb-verify.py ~/journal \
  --verify \
  --manifest ~/journal/hashes-20260528T120000Z.json \
  --sig ~/journal/hashes-20260528T120000Z.json.asc,~/journal/hashes-20260528T120000Z.json.sshsig \
  --report json
```

---

## Manifest Format

Manifests are human-readable JSON files named `hashes-<timestamp>.json`.

```json
{
  "tool": "rednb-verify",
  "version": "0.5.3",
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

- `hash_algorithm` — algorithm used for individual file hashes; also the field name on each file entry
- `merkle_hash` — algorithm used to compute the Merkle tree root
- `date` — creation date in `YYYY-MM-DD` for human readability
- `created` — full UTC timestamp for machine use

---

## Signing

### GPG

If GPG is available and secret keys are found, you are prompted to sign after manifest creation. A detached ASCII-armoured signature (`hashes-....json.asc`) is created alongside the manifest.

Interactive key selection shows fingerprint and expiry for each key.

### SSH

Use `--ssh-sign` to sign with an SSH key. The tool scans `~/.ssh` (or the directory given by `--ssh-kl`) for key pairs and prompts for selection if multiple are found.

Pass a `.pub` file directly to `--ssh-kl` to skip scanning and use that key immediately:

```bash
python rednb-verify.py ~/journal --ssh-sign --ssh-kl ~/.ssh/id_ed25519.pub
```

The signature is saved as `<manifest>.sshsig`. During `--verify`, pass `--ssh-verify` to force an SSH check, or use `--sig` to specify the file explicitly.

#### FIDO2 / Hardware Keys

SSH keys backed by FIDO2 hardware (YubiKey, SoloKey, etc.) use key types prefixed with `sk-` (e.g. `sk-ssh-ed25519`). Use `--ssh-fido` to prefer these keys automatically. The private key operation happens on the hardware device — the private key never touches disk.

```bash
# Sign preferring any FIDO2-backed key
python rednb-verify.py ~/journal --ssh-sign --ssh-fido

# Sign preferring a specific FIDO2 key by name
python rednb-verify.py ~/journal --ssh-sign --ssh-fido yubikey
```

### Verifying Multiple Signatures

Use `--sig` with a comma-separated list to verify GPG and SSH signatures in a single run. The type is detected by extension (`.asc` → GPG, `.sshsig` → SSH):

```bash
python rednb-verify.py ~/journal \
  --verify \
  --manifest hashes-20260528T120000Z.json \
  --sig hashes-20260528T120000Z.json.asc,hashes-20260528T120000Z.json.sshsig
```

When `--sig` is omitted, both signature types are still auto-detected from the manifest directory.

---

## Verification Report

`--report` writes a verification report alongside the manifest (in the journal's parent directory by default). Format is controlled by the argument:

- `--report` or `--report txt` — human-readable text (default)
- `--report json` — structured JSON

The JSON format has four categories:

```json
{
  "ok": ["2026-05.txt"],
  "missing": [],
  "modified": [],
  "new": ["2026-06.txt"]
}
```

- `ok` — files matching the manifest exactly
- `missing` — files in the manifest that are no longer present
- `modified` — files whose hash has changed
- `new` — files present in the notebook not tracked by the manifest

Exit code is `1` if any issues are found, `0` if all tracked files are clean.

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

- Single file, zero non-stdlib dependencies
- Deterministic output
- Explicit trust boundaries
- No hidden metadata
- Human-inspectable manifests
- Hardware security encouraged, not required

---

## Planned

- Direct FIDO2/CTAP2 integration (hardware signing without SSH key setup)
- RedNotebook UI integration
- Per-date and per-entry granularity within month files

---

## Project Status

Active development. Review, testing, and cryptographic scrutiny are welcome.
