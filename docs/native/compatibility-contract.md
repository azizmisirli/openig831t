<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Native 5G compatibility contract

**Overall direct-replacement likelihood: UNKNOWN. Bridge requirement: NOT ESTABLISHED.** This contract targets the measured RC520 build and its original IG831T. No 5G candidate was connected.

MUST means a functional condition for using the selected, unchanged native path. It does not mean every observed byte or implementation choice is universally required. SHOULD identifies a useful reference behavior; MAY an optional path; UNKNOWN a question requiring evidence.

| Area | Requirement | Contract | Evidence boundary |
| --- | --- | --- | --- |
| USB discovery | MUST | Kernel and selected RIL must recognize the candidate and expose usable nodes. | Original binding measured; candidate binding UNKNOWN. |
| Exact 2ca3:4009 identity | UNKNOWN | The examined RIL also accepts another VID/PID family. | No universal spoof requirement demonstrated. |
| Interface roles | SHOULD | Match the selected profile: original AT3/NET4; Quectel prefix profile AT2/NET4. | Original runtime; Quectel source rule. |
| Five interfaces and endpoint addresses | UNKNOWN | Original descriptor is documented; rejection of alternatives was not measured. | Discovery behavior and candidate descriptors need comparison. |
| Serial protocol | MUST | Provide the native AT dialect on the selected serial port. | 180 original command/terminal pairs; some errors are tolerated. |
| AT identity values | UNKNOWN | Queries do not prove exact model, firmware or identifier comparison. | No unconditional identity rewrite justified. |
| QMI control transport | MUST | Provide valid QMUX/CTL service, client and transaction behavior through the selected control node. | Native application messages measured; USB timing not captured. |
| CTL startup | SHOULD | Handle the measured Sync, Version and client-allocation sequence. | First Sync unanswered; second succeeded; not a universal retry rule. |
| QMI services | MUST | Support the operation subset used by CTL/DMS/NAS/UIM/WDA/WDS. | All advertised services are not proved mandatory. |
| Service versions | UNKNOWN | Honor feature/version negotiation and actual consumer layout. | WDA minor-version feature threshold, not a complete whitelist. |
| Response layout | SHOULD | Account for fixed-offset consumers and bounded TLV interpretation. | Arbitrary unknown TLV placement is not proved tolerated. |
| DTR and notification timing | UNKNOWN | Native wire-level sequence requires its own observation. | Application logs and driver family behavior cannot substitute for USB capture. |
| Accepted data format | MUST | Use the format consumed from the response, not just the requested format. | Ethernet request accepted as RAW_IP response. |
| Non-QMAP RAW_IP | SHOULD | Match the measured WDA and native driver policy. | Aggregation and qmap parameters zero; physical wire remains unmeasured. |
| QMAP / mux / aggregation | UNKNOWN | Do not force translation before measuring the candidate. | Alternate builder is source-only and not the observed path. |
| WDS and Android integration | MUST | Manage data-call lifetime and report address/DNS/gateway/MTU to the framework. | Original profile-based IPv4 Start and native network measured. |
| Stored profile behavior | SHOULD | Preserve the intended profile selection and native authentication semantics. | Profile index 1; no APN value is published. |
| IPv6 or dual-stack | MAY | Alternative source paths exist. | This startup measured IPv4, not IPv6 success. |
| Node permissions | MUST | Satisfy access requirements of the chosen native implementation. | Does not imply every alternative architecture needs identical privileges. |
| NetifName/discovery state | SHOULD | Keep the RIL and dialer adapter selection consistent. | Setter/getter source edge plus measured consumer log. |
| Selected DJI route | UNKNOWN | Candidate route files do not prove active persistent configuration. | Protected selected file was not bypassed. |
| App callback/cache/control | UNKNOWN | Observe each acceptance level separately. | Static paths mapped; runtime L1-L5 not established. |
| Generation/identity capability | UNKNOWN | Use exact-build field semantics. | Generation and support capability are not completed authentication. |
| Enhanced Transmission conditions | MUST if ET is the goal | Meet legitimate product, region, account and service conditions. | Native Internet is not an entitlement result. |

## Candidate priority and concrete differences

| Candidate | Present support | Unresolved gates | Classification |
| --- | --- | --- | --- |
| Quectel RM520N-GL | Published RmNet 2c7c:0801, AT2/QMI4 fits native RIL 2c7c:0xxx / AT2/NET4 rule | Exact firmware/composition/endpoints, installed-kernel binding, QMI versions, data format and app acceptance | DIRECT CANDIDATE for a first laboratory test; not PASS |
| Fibocom FM160 | Manufacturer USB/SA/NSA family; QMI-related family host-driver references | No 2cb7 entry in examined default RIL table; exact QMI composition and alternative discovery UNKNOWN | Alternative; adaptation cost UNKNOWN |
| Fibocom FM150 | USB/QMI family documentation and driver behavior | Exact SKU/firmware/USB roles, candidate binding and consumer compatibility | Deferred alternative |
| Fibocom FM190W-GL | Manufacturer 5G and USB interface information | Exact USB QMI/AT/WDA behavior not established by product features | UNKNOWN; newer radio does not establish closer protocol behavior |

The [Quectel USB guide, Table 1](https://quectel.com/content/uploads/2024/04/Quectel_UMTS_LTE_5G_Linux_USB_Driver_User_Guide_V3.2.pdf) documents the RM520N RmNet role map and a separate MBIM composition. This publication uses that role match as a source-supported reason to prioritize a lab candidate, not as a purchase, shipping-firmware or compatibility guarantee.

The [Fibocom FM160 product](https://www.fibocom.com/en/SeriesProduct/info_itemid_80.html), [FM150-AE](https://www.fibocom.com/jp/products/info_itemid_6083.html) and [FM190W-GL](https://www.fibocom.com/jp/products/5G-FM190W-GL.html) establish product-family features. Exact endpoint numbers, service versions and firmware behavior remain UNKNOWN. The documented upstream [FM160 2cb7:0111 example](https://github.com/torvalds/linux/commit/148f4b32b4504d8a32cf82049b7b9499a4b299ab) is MBIM; it is not proof of a QMI composition or this controller's kernel support.

Same manufacturer does not mean the same discovery rule. Conversely, absence from one examined RIL table does not prove every alternative configuration path rejects a candidate. A vendor driver selecting QMAP does not prove firmware cannot use plain IP. The [candidate overview](../candidate-modems.md) and [protocol report](at-qmi-startup.md) keep those layers separate.

## Identity adaptation is conditional

| Potential adaptation | Current decision |
| --- | --- |
| USB VID/PID or full descriptor emulation | Not proved required; test own-identity recognition first |
| AT model/firmware rewrite | UNKNOWN; establish an actual comparison before proposing it |
| QMI DMS identity or complete version-list rewrite | UNKNOWN; generic queries are not a whitelist |
| AT dialect or QMI layout proxy | Conditional on an exact candidate mismatch |
| QMAP conversion | Conditional on measured wire framing and host policy |
| RIL profile or DJI route integration | Candidate/build-specific; privileged changes are outside this publication procedure |
| IMEI/SIM or entitlement manipulation | Excluded; no bypass implementation is proposed |

A bridge becomes REQUIRED only when a host requirement, a candidate mismatch and an implementable adaptation are demonstrated together. Existing bridge source code is not evidence that a bridge is necessary.

## Remaining evidence gates

| Question | Why still unknown | Exact evidence needed |
| --- | --- | --- |
| Candidate kernel and RIL acceptance | No candidate hardware measured | Same unit's complete descriptors, driver/node binding and passive native startup |
| Native USB DTR/notification timing | Boot record contains application QMI bytes | Passive USB capture; kernel source alone only explains expected behavior |
| Physical native bulk framing | RAW_IP response and driver policy are not packet bytes | Passive USB/network-path capture with correct layer attribution |
| Selected DJI route | The selected persistent file was protected | Authorized existing debug metadata or a sanitized selected configuration |
| Actual OLD/NEW/MULTI path | Static registration does not prove callback execution | Correlated callback, parser, publication, cache and control observations |
| Identity and entitlement gates | Reading identity and displaying Internet are insufficient | Exact decision/result evidence without account values or bypass |
| Candidate service list | Versions depend on exact firmware | Read-only same-unit service/version inventory; count must not be assumed |
| Native teardown | Observation retained the running native session | A future naturally occurring disconnect/stop observation |

Opening a status page without changing a toggle may improve app-state evidence but does not automatically prove all callback/cache levels. New cellular sessions or Enhanced Transmission tests require their own authorized bench scope. This publication does not initiate either.
