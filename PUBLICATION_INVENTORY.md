<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Publication inventory

[The machine-readable inventory](PUBLICATION_INVENTORY.json) records every included file's logical source, destination, purpose, origin, ownership, license, redaction, publication decision and SHA256. The full original research tree was inventoried separately; detailed private filenames remain private. Excluded category counts and reasons are summarized in [EXCLUSION_MANIFEST.md](EXCLUSION_MANIFEST.md).

All included records require a known license. Original source is curated into a new tree; private history is not imported. `original-project/` and `research-summary/` are logical provenance labels, not directories included in the release. Standard license texts and Linux-derived patches/harnesses retain their distinct licenses and upstream provenance.

The inventory includes itself. Its own digest uses canonical JSON with only its own `sha256` value replaced by null (sorted keys, compact separators, ASCII encoding). Every other file uses ordinary raw-byte SHA256. Bundle checksums also cover the inventory's exact bytes, avoiding a recursive-hash claim.

`python scripts/evidence_validator.py` checks the complete file set and hashes. `--refresh` updates hashes only for already reviewed records; it refuses new or removed files until their provenance is explicitly reviewed. Recomputing a hash is not a privacy or license approval. Run all publication gates afterwards.
