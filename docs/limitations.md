# Limitations

**UNKNOWN:** end-to-end 5G replacement, direct compatibility and bridge necessity. The original dongle has not been converted to 5G. No candidate is a proven drop-in replacement.

**UNKNOWN:** exact candidate firmware/composition, physical 9-IN/5-OUT allocation, full kernel build/boot, actual FunctionFS operation, electrical/RF/thermal suitability, DJI host acceptance, active host path, identity requirements and physical packet framing.

**SOURCE_SUPPORTED:** the implementation is deliberately incomplete. MI_00/01/03 behavior and active bulk packet forwarding are unsupported; unknown requests are blocked. The data-plane codec expects complete frames and is not a USB stream reassembler. Identity adaptation is off by default and excludes personal identities. Vendor-specific protocol completeness is not claimed.

**CONFIRMED_TARGET_DEVICE:** WDA reported a configuration. **STRONG_INFERENCE:** expected non-QMAP RAW_IP framing. **UNKNOWN:** actual bulk bytes. Likewise, controller documentation is source evidence, not an observed board result; a service/version entry is not proof of every command.

**SOURCE_SUPPORTED:** offline tests cover selected parser, policy, mapping and cleanup invariants. They cannot prove RF behavior, power safety, host authorization or every kernel/libusb failure mode. Hash-checked operator build metadata is not boot attestation. Process-crash recovery and every hostile filesystem race are not established.

Public summaries omit raw private evidence. Their source hashes preserve lineage without making the originals independently replayable. Public release validation must be rerun after curation; private development test totals cannot be advertised as public CI results.

Missing evidence is neither a failure result nor proof that replacement is impossible. Corrections remain marked SUPERSEDED; they must not be used alongside the current interpretation as if both were true.
