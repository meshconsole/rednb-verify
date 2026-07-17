# Moving On

**rednb-verify is finished.**

As of **v0.12.0**, rednb-verify is feature-complete for its original mission:
tamper-evident integrity checking for RedNotebook journals. Hashing, Merkle
trees, move detection, GPG/SSH signing, RFC 3161 trusted timestamping,
manifest chaining, and read-only self-protection are all shipped and tested
(176 tests). No more feature releases are planned for this repo under its
current scope — see [Project Status](README.md#project-status) in the README.

## What's next

### writ-vigil — general-file tamper detection

Development has moved to **writ-vigil** (`meshconsole/writ-vigil`, currently
private — no public link yet), a fork of rednb-verify seeded from this repo's
final release, **v0.12.0**, carrying its full history. It generalizes the
same engine (hashing, Merkle proofs, signing, timestamping, chaining) from
RedNotebook journals to **any directory of files**, and is being ported to
Rust. rednb-verify stays exactly as it is — focused, small, and done — while
writ-vigil carries the tamper-detection work forward for the broader case.

### Integrating with RedNotebook itself

Separately, the plan is to bring integrity checking **into RedNotebook** as a
built-in feature, rather than a standalone tool a user has to know to run.

**Planned new home:**

```
RedNotebook -> File menu -> Journal -> Integrity   (new menu item)
```

This is not yet built or agreed with the RedNotebook maintainer — the first
step is a Show-and-tell discussion on the RedNotebook repository, presenting
rednb-verify and letting the maintainer decide how (or whether) it should be
integrated. A prior, premature pull request for this was withdrawn; the
discussion is the correct next step before any code changes are proposed.

## Summary

| Track | Status |
|---|---|
| rednb-verify (this repo) | Done — v0.12.0, maintenance mode only |
| writ-vigil | Seeded from v0.12.0, in active development (Rust port underway) |
| RedNotebook integration | Planned — pending maintainer discussion; target: File -> Journal -> Integrity |
