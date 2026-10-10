# Experimental FunctionFS bridge

**SOURCE_SUPPORTED:** the prototype emits the captured five-interface descriptor layout with the actual serial replaced in public examples. **UNKNOWN:** whether the real host requires that exact composition. A descriptor clone is not a complete behavioral clone.

## Three numbering domains

**SOURCE_SUPPORTED:** host-visible interface/endpoint identity, FunctionFS local identity and assigned physical endpoint, and backend modem addresses are explicit mappings. FunctionFS endpoint-file slots are not endpoint addresses. `VIRTUAL_ADDR` alone does not force a controller's physical endpoint choice. Interface-recipient `wIndex` and endpoint-recipient remapping are distinct.

## Experimental kernel scope

**SOURCE_SUPPORTED:** stock Linux v6.12 FunctionFS parsing rejects the target's CDC class-specific descriptors. One opt-in patch adds bounded support for the relevant Header/Call Management/ACM/Union records, preserving declaration/reference and speed-local constraints. A separate exact-address patch is restricted to documented canonical endpoint-name/address semantics and verifies the same physical resource across advertised FS/HS descriptors.

**SOURCE_SUPPORTED:** private CDC bit 30 and exact-address bit 29 are experimental ABI choices. The coordinator uses FS/HS plus those flags only through an explicit build-evidence path. Default first-fit behavior is not silently changed for unrelated users. No automatic descriptor removal, renumbering fallback or minimum-profile substitution is claimed.

**UNKNOWN:** full kernel compile/boot validation, controller FIFO feasibility, physical UDC enable and host acceptance. Source-extracted C harnesses, sanitizer checks and patch-application tests do not complete those gates. An operator manifest and matching hashes are not boot attestation.

## Laboratory coordinator

**SOURCE_SUPPORTED:** after owned staging and descriptor writes, the backend interrupt is actually armed before bind and control output. ENABLE validates 14 endpoint address/type/packet-size/interval records and five interface mappings. Any mismatch stops forwarding. Temporary clients, pending requests, queues and run duration are bounded.

**SOURCE_SUPPORTED:** MI_02 read-only AT and MI_04 read-only QMI are integrated. MI_00/01/03 protocol semantics, AT IRQ/control completeness and active packet forwarding are absent. Cleanup failures are reported as failures or retained obligations. Existing gadgets/mounts are not adopted or recursively removed.

[Architecture](../ARCHITECTURE.md) · [Hardware gates](hardware-validation.md) · [Licensing](../THIRD_PARTY_NOTICES.md)
