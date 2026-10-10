<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Redaction report

| Material | Public treatment |
| --- | --- |
| Exact USB serial, including descriptor UTF-16 bytes | Replaced by `REDACTED_USB_SERIAL`; identifying serial hash removed |
| Private paths, usernames and session directories | Removed; resources use package-relative paths |
| Private exploratory Git history | Not imported; new publication repository |
| Raw target QMI/USB captures | Excluded; metadata summaries and explicitly synthetic fixtures only |
| SIM/IMEI/IMSI/ICCID/account identifiers | Excluded, no identity rewriting implementation |
| Vendor binaries, installers, firmware and manuals | Excluded; public references, hashes and original summaries only |
| Turkish private reports and comments | Original English technical summaries or translated original code comments |
| Full upstream Linux and libqmi source trees | Excluded; reviewed GPL patches/standalone harnesses and minimal independent protocol facts |
| Local generated executables, cache and build outputs | Excluded from source history and bundles |
| Proprietary disassembly and databases | Excluded; concise original static-analysis summaries only |

The full private inventory records source locations outside this repository. Public per-file provenance uses logical source names, not absolute paths. Redaction does not upgrade evidence: synthetic fixtures do not constitute new device measurements. No physical hardware was accessed during publication.
