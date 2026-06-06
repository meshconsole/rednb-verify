# rednb-verify — Man Page Development Notes

> Internal reference for man page and documentation authors.
> Tracks design decisions made during feature specification (v0.8.x branch).
> Do not publish as-is — this is a working notes document.

---

## Version context

- Current stable: **0.7.2** (main branch)
- In-progress: **feature/trust-and-multi-hash** branch
- New features below target the next minor release

---

## Exit codes (updated)

| Code | Meaning |
|---|---|
| `0` | Success — all checks passed / manifest created |
| `1` | Verification issues — modified, missing, or new files |
| `2` | Usage or input error — bad arguments, missing files, unsupported algorithm |
| `3` | Signing refused — untrusted key (new in this release) |

Exit codes always fire regardless of `--quiet`. Errors always go to stderr.

---

## Output channel policy (stdout / stderr / `--quiet`)

Industry-standard convention: `--quiet` suppresses informational NOISE on stdout;
it never blinds the operator to problems. Warnings and errors go to **stderr**.
This matches `curl -s`, `git --quiet`, `rsync --quiet`, `gpg --quiet`, etc.

### The rule
> Under `--quiet`, suppress the noise; never suppress something the operator
> needs to act on. The distinction is SEVERITY/CONSEQUENCE, not "warn vs not-warn."

### Two tiers of warning

**Cosmetic tier** — suppressed by `--quiet`. Expected, low-stakes, already
reflected in exit code and/or the manifest `warnings` field.
- `[INFO]` progress (`Hashing 2026-05.txt...`)
- `[INFO] Using config: ...`
- `[WARN] Manifest not GPG-signed`
- `[INFO] Signing skipped (--no-sign)`

**Security tier** — ALWAYS printed to **stderr**, even under `--quiet`. The
operator must know; silently proceeding would be dangerous.
- `[WARN]` old manifest / schema version 0 — trust cannot be evaluated
- `[WARN]` signing key is untrusted (under `--trust low`)
- `[WARN]` trust level is HIGH but no keys are pinned
- `[WARN]` `--schema-ignore` used — results may be unreliable
- `[ERROR]` anything (always, plus exit code)

### Implementation note
Two helper paths needed:
- `_warn()` — cosmetic tier: respects `--quiet` (suppressed), stdout or stderr
- `_warn_security()` — security tier: ALWAYS prints, ALWAYS to stderr, ignores `--quiet`

Decide a message's tier ONCE at the call site (don't re-derive ad hoc). When in
doubt about whether something is security-relevant, it is — use the security tier.

---

## Feature 1: Trust pinning config (`--set-cf`, `--add-trust`)

### New flags

**`--set-cf field:value[,value...]`**
- Writes/replaces a field in the config file and exits (write-only)
- Repeatable: `--set-cf trust-gpg:ABC --set-cf trust-ssh:DEF`
- Comma-separated values for list fields: `--set-cf trust-gpg:ABC,DEF`
- No alias (`--set-config` does NOT exist — keep consistent with `--no-cf`)
- Always writes to `~/.config/rednb-verify/config.json` unless `--config FILE` redirects

Recognized fields:
| Field | Type | Effect |
|---|---|---|
| `trust-gpg:fp1,fp2,...` | list | Replaces trusted GPG fingerprints |
| `trust-ssh:fp1,fp2,...` | list | Replaces trusted SSH fingerprints |
| `trust-level:high\|low` | string | Sets default trust level |
| `dir:/path/to/notebook` | string | Saves default notebook directory |

**`--set-cf-run`**
- Same as `--set-cf` but proceeds with normal tool operation after writing

**`--add-trust field:value[,value...]`**
- Appends to trust lists with de-duplication, order preserved
- Valid for `trust-gpg` and `trust-ssh` only (not `dir` or `trust-level`)
- De-dupe logic: `list(dict.fromkeys(existing + new_keys))`

**`--config-out`**
- Prints the in-memory config as JSON (shows state AFTER applying `--set-cf`)
- Can be chained: `--set-cf trust-gpg:ABC --config-out` previews result

### Saved `dir` field behavior
- Used as fallback `notebook_dir` when none is given on CLI
- Applies to modes that need a notebook directory (create, verify)
- Prints `[INFO] Using saved directory: /path/to/journal` when active
- Does NOT apply to `--resign`, `--hash-list` (they don't need a dir)

### Config file structure (extended)
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
    "dir": "/home/user/journal",
    "trust": {
        "gpg": ["FINGERPRINT1", "FINGERPRINT2"],
        "ssh": ["SHA256:abc123...", "SHA256:def456..."]
    }
}
```

---

## Feature 2: Signing trust levels (`--trust`)

### New flag

**`--trust {high|low}`**
- `low` (default) — any key may sign; notification printed if untrusted
- `high` — only keys in the trust list may sign; untrusted key → refuse + exit 3
- Settable persistently via `--set-cf trust-level:high`
- CLI `--trust` overrides config value per-run

### Interaction with `--quiet`

| Flags | Key trusted? | Behavior |
|---|---|---|
| _(default / --trust low)_ | any | Sign + `[WARN]` notification if untrusted |
| `--quiet` | any | Sign silently (implies low, no prompts) |
| `--trust high` | yes | Sign |
| `--trust high` | no | `[WARN]` printed + refuse → exit 3 |
| `--quiet --trust high` | yes | Sign silently |
| `--quiet --trust high` | no | `[ERROR]` to stderr + refuse → exit 3 |

### Startup warning
If `trust-level` is `high` and BOTH trust lists (`trust.gpg` and `trust.ssh`) are empty,
print a security-tier `[WARN]` (always stderr) on invocation before any operation:
```
[WARN] Trust level is HIGH but no keys are pinned. All signing will be refused.
       Use --add-trust or --set-cf to pin trusted fingerprints.
```

### Verification with trust
- During `--verify`, if `--trust high` and a `signed_by` fingerprint in the manifest
  is not in the trust list → verification FAILS (not just warns)
- Defends against key substitution attacks
- If manifest has no `signed_by` field (pre-v0.8 = schema_version 0):
  - This is handled by the schema-version check (see Manifest schema versioning).
  - Security-tier `[WARN]` (always stderr) — old manifest, trust cannot be evaluated
  - Show hash/signature verification results (best-effort)
  - Prompt to continue if interactive; `--quiet` auto-continues

### Exit code 3 — machine-readable
Always fires even under `--quiet`. Always prints reason to stderr.
Other software can detect via `$?` / `%ERRORLEVEL%`:
```bash
rednb-verify --quiet --trust high --gpg MYFPR ~/journal
case $? in
  0) : ;;
  1) alert "Tampering detected" ;;
  3) alert "Untrusted signing key — possible substitution" ;;
esac
```

---

## Feature 3: Fingerprint randomart display

### Behavior
- Shown **before** the non-repudiation warning box and signing prompt
- Shown during **both** signing and verification
- Shown regardless of trust match (always display, let user confirm)
- Suppressed under `--quiet`

### SSH keys
- **If OpenSSH available:** `ssh-keygen -lv -f key.pub` (native Drunken Bishop art)
- **If OpenSSH unavailable:** custom Drunken Bishop implementation
  - Strip `SHA256:` prefix from fingerprint
  - Base64-decode the key blob and SHA256-hash it for raw bytes
  - Feed bytes to custom `fingerprint_ascii_art()`

### GPG keys
- Always use custom Drunken Bishop implementation
- Input: hex fingerprint bytes (`bytes.fromhex(fingerprint)`)

### Drunken Bishop implementation
Standard algorithm by Dirk Loss. Chars string (17 chars, including S and E markers):
```python
chars = " .o+=*BOX@%&#/^SE"
#                       ^^ index 15=S (start), index 16=E (end)
```
Grid: 17×9. Start position: (8, 4). Movement: 2-bit pairs from each byte.

Note: The original spec had a bug — 15-char string caused S and E to both
render as `^`. Fixed in implementation with the 17-char string above.

---

## Feature 4: Multi-hashing  — ✅ IMPLEMENTED (v0.8.0)

### Activation
No new flag. Multi mode activates when `--hash` receives more than one
comma-separated algorithm spec. Supports N algorithms.

```
--hash sha256              → single mode (unchanged)
--hash sha256,blake2b      → multi mode (2 algos)
--hash sha256,blake2b,sha3_256  → multi mode (3 algos)
--hash sha256,shake_128:32 → mixed with length spec
```

### Weak hash policy
MD5 and SHA-1 used **alone** in single mode:
- **Non-quiet:** `[WARN]` displayed + confirmation prompt before proceeding
- **Quiet:** proceeds silently
- Manifest `warnings` field is populated regardless of quiet mode (see below)

In multi mode, MD5/SHA-1 may appear alongside strong hashes without warning.

### Optional library registry
```python
AVAILABLE_HASHES = {}
for algo in ("sha256", "sha512", "sha3_256", "blake2b"):
    AVAILABLE_HASHES[algo] = getattr(hashlib, algo)
try:
    import blake3
    AVAILABLE_HASHES["blake3"] = blake3.blake3
except ImportError:
    pass
try:
    import xxhash
    AVAILABLE_HASHES["xxh3"] = xxhash.xxh3_128
except ImportError:
    pass
```
If a requested algo isn't installed: print exact `pip install` command and exit 2.

### Manifest format — per-file entries

**Single mode (unchanged):**
```json
{ "path": "2026-05.txt", "sha256": "abc..." }
```
```
      1. 2026-05.txt
         sha256: abc...
```

**Multi mode — JSON (`hashes` nested, alphabetical):**
```json
{
  "path": "2026-05.txt",
  "hashes": {
    "blake2b": "aaa...",
    "sha256":  "bbb..."
  }
}
```

**Multi mode — text (extra hash lines, alphabetical):**
```
      1. 2026-05.txt
         blake2b: aaa...
         sha256:  bbb...
```

### Manifest top-level hash field
- Single mode: `"hash_algorithm": "sha256"` (string, unchanged)
- Multi mode: `"hash_algorithm": ["blake2b", "sha256"]` (list, alphabetical)

### Verification in multi mode
A file is `ok` ONLY if ALL stored hashes match. Any single mismatch → `modified`.

### Per-day entries in multi mode
Day entries (`YYYY-MM/DD`) receive the same multi-hash treatment as files.
Same `hashes: {}` nested object format.

---

## Feature 4a: Merkle tree in multi mode  — ✅ IMPLEMENTED (v0.8.0)

> Resolution of the spec ambiguity: a per-algo tree for algorithm X uses X's
> per-file hashes as leaves and X as the combiner, so `--hash-merkle` in multi
> mode must name a SUBSET of `--hash` algos (you can't build an X tree without
> X leaf hashes). The "independent sha512 tree" idea from the original notes was
> incoherent (no leaves) and is rejected with a clear error. The concatenated
> tree's combiner CAN be any algo, since its leaves are concatenated bytes.
> Note: verify compares per-file hashes (all-must-match); merkle roots are
> recorded as a published fingerprint but not re-checked at verify (unchanged
> from prior behavior).

### `--hash-merkle` (updated behavior)
Now accepts N comma-separated algorithms, like `--hash`:
- Default (not specified): one tree per algorithm in `--hash` set
- `--hash-merkle sha256` → only sha256 tree (even if --hash has blake2b)
- `--hash-merkle sha256,sha512` → two trees: sha256 + sha512
- `--hash-merkle sha512` → one tree using sha512 (independent of file algos)

### `--hash-merkle-concatenate [ALGO]`
New flag. Builds ONE Merkle tree where each leaf is the concatenation of all
file hashes (alphabetical by algo name) before the tree is computed.

Optional argument: the algorithm used to build the concatenated tree.
Default when no arg given: `sha256`.

```
--hash-merkle-concatenate         → concat tree using sha256
--hash-merkle-concatenate sha512  → concat tree using sha512
```

**Leaf size example** (`--hash sha256,blake2b`):
```
blake2b → 64 bytes
sha256  → 32 bytes
concat (alphabetical) = 64 + 32 = 96 bytes per file

Merkle leaf input = 96 bytes
Merkle tree algo (sha256) hashes each pair of 96-byte leaves → 32-byte root
Final merkle_root_concat = 32 bytes (normal digest size regardless of N algos)
```

Adding sha3_256 (32 bytes) → leaves = 128 bytes → same 32-byte root.

### Combined: both `--hash-merkle` and `--hash-merkle-concatenate`
Allowed. Produces both individual trees AND a concatenated tree in the same manifest.
`--hash-merkle sha256 --hash-merkle-concatenate sha512`:
- Individual: `merkle_roots: {"sha256": "..."}`
- Concatenated: `merkle_root_concat: {"sha512": "..."}`

### Manifest fields (field order: concat before individual)

```json
{
  "merkle_root_concat": {"sha512": "abc..."},
  "merkle_roots": {
    "blake2b": "aaa...",
    "sha256":  "bbb..."
  }
}
```

Single mode (unchanged): `"merkle_root": "abc..."` (plain string)

---

## Cross-cutting features

### `warnings` field in manifest
A list of strings recording important conditions at creation time.
Populated regardless of `--quiet`. Shown during `--verify`.

Known warning strings:
| Condition | Warning string |
|---|---|
| MD5 or SHA-1 used alone | `WEAK HASHING ALGORITHM(S) IN USE ALONE` |
| Manifest not signed | `MANIFEST UNSIGNED` |
| Exclude patterns were applied | `FILES EXCLUDED FROM MANIFEST` |
| Notebook directory was empty | `NO FILES FOUND IN NOTEBOOK DIRECTORY` |
| Per-day mode, no day entries found | `NO DAY ENTRIES FOUND` |

```json
"warnings": [
    "WEAK HASHING ALGORITHM(S) IN USE ALONE",
    "MANIFEST UNSIGNED"
]
```

### `signed_by` field in manifest
Added before signing (key is known at selection time, before the file is written).
Authenticates who signed since the manifest itself is signed.

```json
"signed_by": {
    "gpg": "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
    "ssh": "SHA256:abc123..."
}
```

Multiple signers (GPG + SSH) accumulate in the same object.
Used by `--trust high` verification to cross-reference against trust list.

### Signature write-protection check — DROPPED
Considered and removed. Rationale: the cryptographic signature already protects
against sig tampering (a replaced sig won't verify against a trusted key), so the
check only caught filesystem hygiene — not attacks. It was also inert on Windows
(no NTFS ACL access without pywin32), had arbitrary scope (sig files but not
manifests/journal, which are writable by design), and risked desensitizing users
to warnings. Not implemented.

### Manifest schema versioning

New top-level field on every manifest going forward:
```json
"schema_version": 1
```

`schema_version` is SEPARATE from the existing `version` field:
- `version` → which build of rednb-verify wrote this (e.g. `"0.8.0"`) — informational
- `schema_version` → structural contract of the manifest (integer) — enforced

**Version assignment:**
- Pre-v0.8 manifests have no `schema_version` → treated as **version 0**
- All v0.8 additions (`signed_by`, `warnings`, `hashes` nested, `merkle_roots`,
  `merkle_root_concat`) define **schema_version 1**
- Current tool's max supported schema version is tracked as a constant
  (e.g. `MANIFEST_SCHEMA_VERSION = 1`)

**Bump policy (avoid over-bumping):**
- Adding an OPTIONAL field → no bump (a v1 reader ignores unknown keys)
- Renaming / removing a field, or changing a field's type or meaning → bump (1 → 2)

**Verify behavior — three directions:**

| Manifest schema vs tool max | Situation | Behavior |
|---|---|---|
| Equal | Normal | Verify normally |
| Lower (or absent = 0) | Old manifest | Warn (security tier, stderr) + best-effort verify + interactive prompt; `--quiet` auto-continues |
| Higher | Manifest from a NEWER tool | Refuse + exit 2, unless `--schema-ignore` |

**Lower / version-0 (old manifest) path:**
1. `[WARN]` (security tier — always stderr even under `--quiet`) — old manifest
   format, trust cannot be evaluated
2. Verify hash integrity and signature validity normally
3. Prompt to continue if interactive; `--quiet` auto-continues (warning already
   emitted to stderr)

**Higher (newer manifest) path:**
```
[ERROR] Manifest schema version 2 is newer than this tool supports (max: 1).
        Upgrade rednb-verify, or re-run with --schema-ignore to attempt anyway.
```
Exit 2. `--schema-ignore` downgrades this to a security-tier `[WARN]` and attempts
verification anyway (best-effort, may produce false results — user's risk).

**New flag: `--schema-ignore`**
Bypasses the newer-manifest refusal. Attempts verification regardless of schema
version. Prints a security-tier warning that results may be unreliable.

---

## README reorganization (from spec)

Split Arguments table into two sections:

**Normal operation flags:**
`notebook_dir`, `-m/--month-only`, `-D/--per-day`, `-j/--jobs`, `-o/--output`,
`-V/--version`, `--verify`, `--manifest-type`, `--report`, `--hash`, `--hash-list`,
`--hash-merkle`, `--hash-merkle-concatenate`, `--gpg`, `--gpg-k`, `--ssh`,
`--ssh-verify`, `--sig`, `--ssh-fido`, `--no-sign`, `--resign`, `--warn-age`,
`-v/--verbose`, `--quiet`, `--exclude`, `--exclude-from`, `--trust`,
`--schema-ignore`

**Config management flags:**
`--set-cf`, `--set-cf-run`, `--add-trust`, `--config-out`, `--no-config/--no-cf`, `--config`

---

## Review decisions (C/D/G) — finalized before implementation

### C1. Trust check uses the VERIFIED key, not `signed_by`
The trust comparison MUST use the fingerprint extracted from the actual
cryptographic signature verification (`gpg --verify --status-fd`, or the SHA256
fingerprint of the SSH pubkey that `ssh-keygen -Y verify` validated against).
The manifest `signed_by` field is attacker-controllable text → it is a DISPLAY
HINT ONLY, never the basis of a trust decision.

### C2. Signing refactored into resolve-then-sign
Key identity is resolved BEFORE the manifest is written:
1. Resolve all signing identities (GPG fpr — including extracting it from a
   `--gpg-k` keyfile via a pre-import pass; SSH pubkey fingerprint).
2. Write `signed_by` into the manifest dict.
3. Serialize + write the manifest file.
4. Sign the finished file (GPG and/or SSH) over the bytes that already contain
   `signed_by`, so every signature covers the full identity claim.

### C3. `--resign` does NOT modify the manifest
`--resign` adds detached signature(s) only; it never rewrites the manifest
(which would invalidate any existing signatures). Therefore `--resign` does NOT
update `signed_by` — that field reflects only the original signer(s). A
resigner's identity lives in their detached signature file. (Option (a).)

### D1. Verify-time trust failure → exit 1
`--trust high` + manifest validly signed by an untrusted key during `--verify`
→ exit **1** (verification found a problem) with a security-tier message.
Exit 3 remains reserved for SIGNING refusal only.

### D2. Confirmation prompts → `-y`/`--yes`
- Interactive TTY + weak-hash-alone + non-quiet → print warning, prompt y/N
- `-y`/`--yes` → print warning, proceed without prompting (automation-friendly)
- Non-TTY + no `-y` + non-quiet → print warning, abort exit 2 (never hang, never
  silently proceed)
- `--quiet` → proceed silently (warning still recorded in manifest `warnings`)
- `-y` also auto-confirms the GPG/SSH signing prompts.

### D3. Fingerprint normalization for trust comparison
- GPG: uppercase, strip all spaces, before both store and compare.
- SSH: keep `SHA256:<base64>` verbatim (case-sensitive); compare exactly.

### G-fills (filled gaps, no open question)
- **G1. Text manifest multi-mode:** header `hash_algorithm: blake2b, sha256`
  (comma-joined, alphabetical); parser splits on comma. Per-file: multiple
  indented `algo: hash` lines grouped into a `hashes` dict. `merkle_roots` and
  `merkle_root_concat` get their own header lines. Round-trip must be lossless.
- **G2. `schema_version` header line** in text manifests; read by the
  three-direction check.
- **G3. `--config-out` alone** prints config as loaded from disk (`{}` if none),
  NOT argparse defaults.
- **G4. Empty notebook, multi mode:** `merkle_roots` = `{algo: "", ...}`.
- **G5. `--set-cf` splits on FIRST colon only** (`str.partition(":")`); preserves
  Windows drive colons in `dir:C:\path`.
- **G6. `warnings` field at verify** shown as cosmetic tier (creation-time record).

### New flags summary (this release)
`--trust {high,low}`, `--schema-ignore`, `--hash-merkle-concatenate [ALGO]`,
`--set-cf`, `--set-cf-run`, `--add-trust`, `--config-out`, `-y`/`--yes`.

---

## Open items / deferred

- Config schema versioning: deferred (format still moving). When added, treat
  "no version key" as version 0 so old configs aren't locked out.
- SPHINCS+ / post-quantum signing: future augment to GPG/SSH layer (`pyspx`).
  Current GPG/SSH (RSA/Ed25519) is fine today but not quantum-safe long-term.
- RFC 3161 trusted timestamping
- Manifest chaining
- `--json` output mode
- Direct FIDO2/CTAP2 integration
- RedNotebook UI integration
