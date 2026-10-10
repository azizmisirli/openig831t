# Publication audit

**SOURCE_SUPPORTED:** the publication tools scan curated files and, when requested, Git objects. They do not test hardware compatibility. Run from the repository root after activating the development environment:

```sh
python3 scripts/publication_audit.py --git-objects
python3 scripts/scan_secrets.py
```

The custom audit checks prohibited artifacts, private paths, credential and identifier patterns, size/binary limits, and known private values when a separate untracked rules file is supplied. The independent engine uses `detect-secrets` with network verification disabled. Missing scanner dependencies are an error, not a clean result.

Before Git initialization, the object status is `NOT_INITIALIZED`; only working files have been reviewed. Repeat the object scan after committing, including unreachable objects. A clean current checkout does not prove the historical object database is clean.

The optional `--private-rules` input is an untracked JSON list of known values. Keep it outside the published repository; never put actual identifiers in examples or issue reports. Findings must identify a rule/location without echoing the matched secret. A false-positive exception requires a reason and exact file hash, not a blanket exclusion.

**UNKNOWN:** a clean scan cannot establish that every possible secret pattern was detected. Human provenance, licensing and privacy review remain necessary. See [security policy](../../SECURITY.md), [reproducibility](../../REPRODUCIBILITY.md) and the root publication reports.
