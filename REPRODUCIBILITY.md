# Reproducibility

**SOURCE_SUPPORTED:** the public repository is curated from original code and sanitized summaries. It contains no private exploratory Git history and does not require access to proprietary SDK binaries to run its normal offline suite.

## Offline software replay

From a clean checkout with Python 3.10+:

```sh
make setup
. .venv/bin/activate
make lint
make test
make test-sanitizers
make audit
make docs
make bundle
```

Direct unit tests and an offline smoke check:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m igbridge dry-run
```

Activate `.venv` before running Make targets in each shell; otherwise `python3` may resolve to a different interpreter without the development dependencies. The runtime declares Python 3.10 or newer. The CI source currently configures 3.10, 3.12 and 3.14; this is a configured matrix, not a claim that remote runs have completed. Interpreter/platform differences may affect available tools or skips, so preserve those results. The package metadata uses PEP 440 version `0.1.0a0`; the human release tag is `v0.1.0-research-preview`.

Optional development packages and the C toolchain are separate from the standard-library runtime. `make setup` may download development dependencies. The tests and smoke commands must not enumerate devices, load a modem driver, mount FunctionFS, write configfs or start a data session.

**SOURCE_SUPPORTED:** use the public validation artifacts produced for the exact commit under test. Record command, interpreter/compiler versions, test counts, skips, source hashes and exit status. A skip must remain visible. Do not carry a private pre-curation total into a public release result. Sanitizer assertion totals are not additional Python unit tests.

## Evidence replay limits

**CONFIRMED_TARGET_DEVICE:** sanitized summaries preserve the original USB endpoint map, modem-reported identity, 29-service list and WDA configuration. Source hashes bind them to withheld records. **UNKNOWN to a public-only replay:** the original raw captures cannot be independently reprocessed from this repository because they are not distributed. Hashes alone cannot recreate or authenticate unavailable measurements.

**SOURCE_SUPPORTED:** synthetic fixtures exercise protocol boundaries and failures. They must remain explicitly synthetic and must never be relabeled as hardware output. The serial in a descriptor example is a redaction placeholder, not the captured device serial.

## Kernel and physical validation

**SOURCE_SUPPORTED:** experimental patches target a pinned Linux baseline. Extracted C harnesses and sanitizer checks validate only their selected source logic. **UNKNOWN:** a successful full kernel build, boot-image identity, physical endpoint resources, power stability, actual enable and DJI host behavior. A matching operator-supplied manifest is not remote attestation.

Hardware experiments require a separate exact context and explicit execution flag; they are not part of this reproducibility recipe. See [hardware validation](docs/hardware-validation.md) and [security boundaries](SECURITY.md).

## Direct tool equivalents

Run these from the repository root with the development environment active:

```sh
python3 scripts/check_static.py
python3 scripts/validate_offline.py
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_kernel*.py' -v
python3 scripts/publication_audit.py --git-objects
python3 scripts/scan_secrets.py
python3 scripts/validate_docs.py
python3 scripts/evidence_validator.py
python3 scripts/build_bundle.py --output dist/source-02
```

The bundle destination must not already exist. `make bundle` uses `dist/source`; repeated runs need a different destination, not silent overwrite. Optional test metadata output also requires a new directory, for example `python3 scripts/validate_offline.py --output artifacts/offline-02`. Failure logs can contain local paths and remain in ignored output; they are not automatically publishable evidence.

The Git-object audit reports `NOT_INITIALIZED` before a repository exists. A working-file pass at that point is not a completed object-history scan. Publication requires the post-commit object scan as well. The independent secret engine uses network verification disabled and reports unresolved findings without echoing secret values. Reviewed false positives remain tied to exact file hashes.
