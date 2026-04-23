# rednb-verify

**rednb-verify** (short for *rednotebook-verify*) is an integrity and verification tool designed to detect tampering in **RedNotebook** journals.

It creates cryptographic manifests of notebook entries and optionally signs them, producing a verifiable snapshot of the notebook at a specific point in time.

The project focuses on **tamper detection, auditability, and long-term trust**, and not secrecy.

---

## Goals

### 1. Cryptographic Integrity Verification
- Generate cryptographic hashes of RedNotebook entry files
- Detect:
  - Modified files
  - Missing files
  - Unexpected new files
- Store **relative paths only** to preserve portability

### 2. Flexible Signing Backends
- Support **GPG-based signing**
- Do **not** require GPG exclusively
- Allow future signing backends without renaming the project

### 3. Hardware-Backed Signing (Planned)
- Support **FIDO2 / security keys**
- Keep private keys off disk
- Reduce risk of key exfiltration
- Enable high-trust, low-footprint signing workflows

### 4. Increased Tamper Detection Accuracy
- Move beyond coarse monthly detection
- Enable:
  - Per-file detection
  - Optional per-date or per-entry granularity
- Detect tampering **to the specific date**, not just the month file

### 5. RedNotebook Integration (Planned)
- Designed to align with RedNotebook’s storage model
- Possible future forms:
  - External verification script
  - Assisted verification workflow
  - Optional UI hooks or wrappers

### 6. Long-Term Auditability
- Human-readable manifests
- Machine-verifiable signatures
- Suitable for:
  - Journaling
  - Research logs
  - Legal or ministry documentation
  - Any record where trust over time matters

---

## What This Tool Is Not

- ❌ Encryption  
  Files remain readable. This tool proves whether they changed.

- ❌ Access control  
  Anyone with file access can read entries.

- ❌ A backup solution  
  Integrity verification only.

---

## Non-Repudiation Warning ⚠️

**Signing a manifest is a serious cryptographic act.**

By signing a hash manifest, you assert that:

- These files existed
- In this exact form
- At or before the signing time

Anyone with your public key can verify this claim.

### Implications

- You cannot later deny authorship or approval of signed content
- If your signing key is compromised:
  - Past signatures remain valid
  - Future trust may be damaged
- Signing on an untrusted system can permanently undermine credibility

### Recommendations

- Sign only on trusted systems
- Prefer hardware-backed keys (FIDO / smart cards)
- Keep private keys offline when possible
- Read warnings before signing operations

---

## Verification Requirements

To verify a snapshot:

- The notebook directory
- A hash manifest file (e.g. `hashes-YYYYMMDD-HHMMSS.json`)
- The corresponding detached signature file (if signed)

Verification fails if:
- A tracked file is modified
- A tracked file is missing
- An unexpected file appears (optional strict mode)

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
- Editing on compromised systems
- Timestamp manipulation at OS level
- Forged history using stolen signing keys

### Mitigations
- Cryptographic hashes for all tracked files
- Deterministic manifest generation
- Detached signatures
- Hardware-backed keys (planned)
- Human-readable audit files

---

## Forensic Considerations and Concerns

rednb-verify proves **that** tampering occurred, not **who** did it.

Forensic attribution depends on the underlying system:

- Standard filesystems do **not** reliably record:
  - Who edited a file
  - From which program
  - With what intent

At best, you may observe:
- `mtime` (modification time)
- `ctime` (metadata change time)
- Ownership and permissions

These are **not cryptographically trustworthy** and can be altered.

### True Forensic Attribution Requires
- Audit frameworks (e.g. Linux Audit / auditd)
- Immutable logs
- Mandatory access controls
- Centralized logging
- Signed event records

rednb-verify is intentionally **filesystem-agnostic** and does not claim forensic attribution beyond integrity proof.

---

## Design Principles

- Deterministic output
- Minimal dependencies
- Explicit trust boundaries
- No hidden metadata
- Human-inspectable files
- Hardware security encouraged, not required

---

## Project Status

Active development.

Some features described above are planned and not yet implemented.

Review, testing, and cryptographic scrutiny are welcome.
