# OLD, NEW and MULTI paths

The following is **SOURCE_SUPPORTED** within the inspected SDK 5.18.0 artifact. It is not a runtime trace.

| Path | Observer key | Reviewed format/classification | Scope limit |
| --- | --- | --- | --- |
| OLD | 0x40180040 | Legacy WlmDongleInfo; legacy type-zero/nonzero logic | Not the MULTI type-set parser |
| NEW | 0x4018004A | Separate 159-byte WlmNewDongleInfoMsg path; 137 bytes typed, 22 unresolved | No isDjiDevice field in the reviewed schema |
| MULTI | 0x40180050 | TLV basic-info classification: types 6, 7 or 10 set the typed isDjiDevice value | False records can still be retained/published |

**SUPERSEDED:** assigning the `{6,7,10}` predicate to observer `0x4018004A` is incorrect. It belongs to MULTI basic-info parsing. The NEW wire format must not be equated with a similarly named object serializer or with Assistant output merely because the names resemble each other.

**SOURCE_SUPPORTED:** all three observers can be registered in the same setup path. Registration therefore does not select one active family. NEW RC/Dock routing is a separate decision from modem identity classification. OLD/MULTI normalization and cache sharing do not prove NEW is the same payload or that every route merges identically.

**SOURCE_SUPPORTED:** the reviewed MULTI path can retain prior/default fields when an optional basic-info item is absent; a false value is not inherently a parse failure. Legacy/default/truncated-input behavior also limits producer inferences. **UNKNOWN:** which combination is actually exercised on the target product/firmware.

**UNKNOWN:** accepted-push counts. No runtime observation was performed, so counts are `null`, not zero. A missing trace does not prove rejection, lack of registration, or absence of pushes. [Sanitized path summary](../evidence/sanitized/host-path-status.json).
