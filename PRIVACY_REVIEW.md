<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Privacy review

The public tree is a curated export with a new Git history. The original research tree and detailed private inventory remain outside it. Public paths are repository-relative or public source URLs.

The measured USB serial is replaced with `REDACTED_USB_SERIAL`, including its UTF-16 USB descriptor representation. Device serial hashes are omitted. No IMEI, IMSI, ICCID, phone number, SIM identity, account credential, activation token, operator account, private certificate or raw USB capture is included. The publication scan also checks the known local username and exact private serial using a separate, unpublished rules file.

The modem's commercial model and firmware identifiers are technical product facts, not an individual subscriber identity. Public upstream copyright/license notices are preserved. Canonical license texts may contain their publishers' public contact addresses; these are narrowly scoped exceptions, not permission to publish personal contact information.

QMI test vectors are synthetic reconstructions from non-identifying protocol facts. A reconstructed service response uses a different transaction ID and TLV ordering. The 29 measured service/version pairs are preserved as sanitized metadata. Evidence summaries distinguish target observations, family sources and unverified hypotheses.

The custom audit examines current candidate files, every reachable Git tree path and all Git blobs/commits/tags, including unreachable objects. The independent detect-secrets engine runs without network verification. Entropy findings are accepted only as reviewed, content-bound public digest/protocol constants; unresolved findings block publication. No scanner guarantees absence of all possible sensitive information. Provenance review and explicit exclusions are additional gates.

See [redactions](REDACTION_REPORT.md), [exclusions](EXCLUSION_MANIFEST.md) and [scan results](SECURITY_SCAN_REPORT.md). The citation and Git commits use the collective author OpenIG831T contributors, with no personal commit email. The hosting account alias necessarily remains visible in repository URLs, ownership and GitHub activity; no real name or personal profile contact is copied into distribution metadata.
