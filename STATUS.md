# Research status

**RESEARCH PREVIEW · EXPERIMENTAL**

The Python package uses the PEP 440 version 0.1.0a0; the corresponding public research release is labeled v0.1.0-research-preview.

**UNKNOWN — end-to-end 5G replacement has not been demonstrated.** The measured original dongle has not been converted to 5G. There is no confirmed drop-in candidate, validated physical bridge, or demonstrated DJI host acceptance. The final direct-versus-bridge verdict remains `null`.

| Claim | Evidence level | Scope |
| --- | --- | --- |
| Original USB composition | CONFIRMED_TARGET_DEVICE | One measured IG831T; serial omitted |
| Fibocom NL668T-GL identity | CONFIRMED_TARGET_DEVICE | AT and DMS reported identities, not a silicon proof |
| MI_02 AT / MI_04 QMI | CONFIRMED_TARGET_DEVICE | Read-only control exchanges |
| CTL Sync and 29-service discovery | CONFIRMED_TARGET_DEVICE | Specific measured initialization sequence |
| WDA RAW_IP, aggregation disabled | CONFIRMED_TARGET_DEVICE | Reported default-channel configuration |
| Non-QMAP raw-IP expectation | STRONG_INFERENCE | Not a physical packet capture |
| Original bridge components | SOURCE_SUPPORTED | Code and offline tests exist |
| Static OLD/NEW/MULTI relationships | SOURCE_SUPPORTED | Specific SDK build and bounded functions |
| Candidate firmware compatibility | UNKNOWN | No candidate hardware measurement |
| 9-IN/5-OUT physical UDC feasibility | UNKNOWN | Controller source resources are insufficient proof |
| Physical FunctionFS / full kernel build | UNKNOWN | Not validated / not verified |
| Active host path / identity requirements | UNKNOWN | No target runtime observation |
| Physical bulk framing / end-to-end 5G | UNKNOWN | Not observed / not demonstrated |

[RESEARCH_STATUS.json](RESEARCH_STATUS.json) is the machine-readable counterpart. A publication test pass only verifies the curated software scope. Historical private test counts are not public validation results.

The public tree excludes proprietary binaries, complete vendor manuals, disassembly dumps, identifying raw captures and private history. Sanitized summaries state where raw evidence is withheld; they do not pretend to provide an independently replayable hardware capture.
