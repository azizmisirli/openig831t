<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Security scan report

Local curated-file scans passed on 2026-10-10. No unresolved finding remained. Complete Git-object scanning is also a mandatory pre-push and pre-publication gate; the publication script reruns it on committed history. Remote CI/public verification is recorded separately in PUBLICATION_RESULT.md.

Required independent engines:

1. `scripts/publication_audit.py --git-objects`: private paths, exact local private rules, numeric identifiers, credentials, personal emails, prohibited artifacts, binary content and complete Git-object inspection.
2. `scripts/scan_secrets.py`: detect-secrets 1.5.0, all curated candidate files, network verification disabled, reviewed digest/protocol constants only.

Git-object scanning includes unreachable blobs and commit/tag metadata. Tree-path checks are separate from blob deduplication, so an identical file at a forbidden historical path is still detected. Canonical public license notices are preserved. No unresolved finding is acceptable before public visibility.

## Results and boundaries

- Custom path/identifier/artifact audit: PASS; zero findings across the reviewed public candidate files. The exact known local username and original USB serial (including its UTF-16 representation) were additionally checked with unpublished local rules.
- detect-secrets 1.5.0: PASS; zero unresolved findings. The 68 individually reviewed source/protocol digest findings are file-hash-bound in the allowlist. Computed inventory/license digests are verified structurally; verified Git commit digests in the publication report are checked against local history. Other detector types remain active.
- Adversarial scanner tests cover unreachable objects, forbidden paths, staged files and identical-blob aliases; publication tests cover archive substitution, extra release assets, traversal and resume boundaries.
- No private capture, prohibited vendor artifact or unknown-license material is in the curated file inventory.
- Source and documentation archives are compared byte-for-byte with the reviewed immutable release tree before upload and again after download. A scan result is not a guarantee against every unknown leak pattern.
