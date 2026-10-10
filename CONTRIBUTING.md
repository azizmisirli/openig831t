# Contributing

Prefer a small, independently reviewable change that closes a named evidence gap. Read [STATUS.md](STATUS.md), the [evidence levels](docs/evidence-levels.md), and [SECURITY.md](SECURITY.md) first.

## Required for every contribution

- State whether evidence is measured, source-supported, inferred, unknown or superseded.
- Identify the exact commit, source artifact/version and reproducible procedure.
- Confirm ownership/permission and redistribution rights; provide primary-source links instead of vendor binaries or manuals.
- Remove personal identifiers, credentials, private paths and raw account/device data.
- Add meaningful boundary or regression tests for behavioral changes; keep hardware access out of normal tests and CI.
- Preserve unknown numeric protocol values and byte-level provenance. Do not silently convert an error or missing field into success.
- Do not claim a working 5G replacement without matching end-to-end physical evidence.

## Development checks

```sh
make lint
make test
make test-sanitizers
make audit
make docs
```

**SOURCE_SUPPORTED:** these checks cover the repository's software/publication scope, not physical compatibility. Record any skips and environment-specific limits.

## Evidence submissions

Candidate submissions need exact SKU and firmware, VID/PID, interface/endpoint map, AT identity, QMI service/version list, WDA Get Data Format, DTR/Sync behavior, OS/kernel and a redaction confirmation. Results from separate modules or firmware revisions must not be combined into a fictional single specimen.

Hardware reports also need board revision, UDC/kernel build identity, power/carrier context, a bounded procedure, cleanup result and explicit consent scope. A failed command is not proof that hardware lacks a radio technology. A generic driver match is not proof of DJI acceptance.

Original code is contributed under the applicable project code license; original documentation and evidence summaries use CC BY 4.0. Kernel-derived material retains its specific licensing. Consult [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Contributions must be professional English and comply with the [Code of Conduct](CODE_OF_CONDUCT.md).
