<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Exclusion manifest

The complete private source inventory covered 25,945 files (excluding Git internals and bytecode caches). 48 original code/patch/harness files were selected for reviewed curation; 25,897 original files were excluded as files. New English documentation and metadata summaries are separate publication artifacts, not copies of excluded reports.

Private classifications are conservative and mutually exclusive. A file may have more than one exclusion reason; the first applicable category is counted. Unknown-license material is not presumed redistributable. The exact private filenames and sensitive values remain only in the local inventory, outside public Git.

| Category | Excluded files | Reason |
| --- | ---: | --- |
| EXCLUDE | 741 | Generated outputs, duplicate material and unrelated artifacts have no publication purpose. |
| PRIVATE_LOCAL_PATH | 3604 | Local paths, execution records or environment-specific reports; relevant facts rewritten without private locations. |
| PRIVATE_PROPRIETARY | 2053 | Vendor binaries, installers, firmware, manuals and proprietary reverse-engineering material are not redistributed. |
| PRIVATE_RAW_CAPTURE | 702 | Raw USB/QMI/other captures may expose identities or session data; sanitized summaries only. |
| PRIVATE_SENSITIVE | 291 | Potential account, device, subscriber or other private identifiers; excluded rather than copied. |
| THIRD_PARTY_REFERENCE_ONLY | 89 | Full upstream/reference material omitted; pinned public URLs and provenance metadata retained. |
| UNKNOWN_LICENSE | 18417 | Redistribution basis was not established; conservative exclusion, not an assertion of infringement. |

No private raw capture, proprietary binary or unknown-license file is included. Public data uses sanitized metadata or synthetic test vectors. GPL-derived patches and standalone harnesses have explicit provenance; full source trees remain external optional inputs.
