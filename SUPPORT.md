<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Community support

OpenIG831T is an open-source interoperability research project. Support and collaboration happen through this repository's GitHub Issues and Discussions, according to contributor availability. There is no promised response time or production-support commitment.

**UNKNOWN:** end-to-end DJI 5G replacement, exact candidate compatibility, physical gadget operation and DJI host acceptance remain unverified. Read [STATUS.md](STATUS.md) before interpreting a software test result as hardware evidence.

## Where to ask

- **Discussions:** research questions, interpretation of existing evidence, ideas and coordination before a hardware contribution.
- **Issues:** reproducible software defects, documentation corrections and one bounded evidence gap with a clear completion criterion.
- **Pull requests:** small reviewed changes with meaningful offline checks and the required provenance. See [CONTRIBUTING.md](CONTRIBUTING.md).
- **Security reports:** follow [SECURITY.md](SECURITY.md). Use private vulnerability reporting when available; public issues and Discussions are not private submission channels.

## What helps a useful report

Identify the exact project commit, operating system, relevant software versions, expected behavior and observed result. Prefer a minimal synthetic reproducer. State which checks passed, failed or were not run, and distinguish measured evidence from source-supported interpretation.

For hardware evidence, provide only non-identifying model/SKU, firmware and controller/build context. Keep observations from each unit and firmware configuration separate. Explain authorization, the bounded procedure and cleanup outcome. A protocol error or missing response does not establish that a device lacks a hardware capability.

## Redact before posting

Do not attach device serials, IMEI, IMSI, ICCID, EID, credentials, account details, private paths, identifying network data, proprietary packages, complete vendor manuals or unreviewed raw captures. Read-only commands can still return sensitive data. Use a reviewed sanitized summary or primary-source link and state what was omitted. Do not post private logs in a Discussion while arranging how to contribute.

Hardware work is voluntary and requires owned or explicitly authorized equipment and a separately reviewed scope. Do not infer authorization to run a live test from an issue or contribution request. Normal tests and default CLI plans stay offline.

Community participation follows the [Code of Conduct](CODE_OF_CONDUCT.md). Consult the [roadmap](ROADMAP.md) and [hardware validation notes](docs/hardware-validation.md) for the outstanding research gates.
