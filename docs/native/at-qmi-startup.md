<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RC520 native AT and QMI startup

**MEASURED_RUNTIME + SOURCE_SUPPORTED.** The stock IG831T completed native modem initialization and an IPv4 data-session start on DJI RC Pro 2 (`RC520`), controller firmware `01.00.07.00`, Android build `V55.31.01.39`, Android 11 and DJI Fly 1.21.2. This is an installed-build reference, not a guarantee for another firmware or a tested 5G replacement.

This page preserves the useful protocol findings while omitting identities, APN and credential values, IP addresses, raw payloads, private hashes and local paths. The [sanitized evidence catalog](../../evidence/sanitized/native-at-qmi-startup.json) contains all 180 AT event records, all 46 QMI event records, matching relationships and all 29 advertised service versions. Its command strings are authored templates, not a replayable capture.

## Observation scope and timing

Stock services retained modem ownership. A separately authorized controller reboot generated normal native startup. The collector sent no AT/QMI/DTR, claimed no modem interface and generated no network probe. Static analysis did not execute the copied target binaries.

Published elapsed times use the first native AT command as zero. The scoped AT sequence spans 1,899 ms, with its final terminal result at 1,904 ms. QMI frames run from +1,948 to +4,682 ms; the retained log ends at +4,962 ms. Earlier boot records include a clock correction, and the collector remained alive after the available stream ended. Its lifetime is not evidence of continuous multi-minute protocol coverage.

The native RIL logs its AT selection as MI_03 / `ttyUSB3`, consistent with the installed USB role table and tty-discovery helper. Subsequent exchanges come from that RIL process. This is logged port selection plus source corroboration, not a separate system-call trace. QMI is handled through the native MI_04 path and Fibocom dialer.

## AT catalog: 180 logged command units

There are **145 `OK` and 35 `ERROR` terminal results**, with no overlapping outstanding request or unmatched terminal in the scoped same-process correlation. Response-reader and command-sender threads differ. Unsolicited response-body lines are not automatically solicited results.

One logged command line counts as one unit. Several `COPS` lines combine format setters and queries; the total is not a count of all expanded subcommands. An equals sign can select a query form, and a question mark can appear inside a mixed SET/QUERY line. Neither punctuation alone establishes whether a command changes state.

| Family | Count | OK / ERROR | Purpose | Observed effect classification |
| --- | ---: | ---: | --- | --- |
| `ATE` | 2 | 2 / 0 | Disable command echo | configuration |
| `AT+CMEE` | 3 | 3 / 0 | Enable numeric extended error reporting | configuration |
| `ATI` | 1 | 1 / 0 | Read modem identification | query |
| `ATS0` | 1 | 1 / 0 | Disable automatic answering | configuration |
| `AT+QURCCFG` | 1 | 1 / 0 | Configure the unsolicited-result port | configuration |
| `AT&D` | 1 | 1 / 0 | Configure modem behavior when DTR changes | configuration |
| `AT+CREG` | 2 | 2 / 0 | Configure circuit-switched registration reporting | configuration |
| `AT+CGREG` | 1 | 1 / 0 | Configure packet registration reporting | configuration |
| `AT+CEREG` | 10 | 10 / 0 | Configure or read EPS registration reporting | mixed |
| `AT+CFUN` | 2 | 2 / 0 | Read modem function state | query |
| `AT+CPIN` | 4 | 4 / 0 | Read SIM/PIN status | query |
| `AT+CRSM` | 43 | 43 / 0 | Read SIM file data or file metadata | sim read |
| `AT+QCIMI` | 1 | 0 / 1 | Vendor subscriber-identity query | query |
| `AT+CIMI` | 2 | 2 / 0 | Subscriber-identity query | query |
| `AT+COPS` | 36 | 36 / 0 | Read operator information while changing its output format | mixed |
| `AT+QCFG` | 8 | 4 / 4 | Vendor configuration/query family | unknown vendor effect |
| `AT+C5GREG` | 9 | 0 / 9 | Query 5GS registration | query |
| `AT+GTCCINFO` | 14 | 14 / 0 | Vendor cell-information query | query |
| `AT+QENG` | 9 | 0 / 9 | Vendor engineering/cell-information family | unknown vendor effect |
| `AT+CSQ` | 6 | 6 / 0 | Read signal quality | query |
| `AT+QENDC` | 4 | 0 / 4 | Vendor EN-DC-related family | unknown vendor effect |
| `AT+QSIMCFG` | 7 | 0 / 7 | Vendor SIM-configuration/query family | unknown vendor effect |
| `AT+CGMR` | 1 | 1 / 0 | Read firmware revision | query |
| `AT+CGSN` | 1 | 1 / 0 | Read equipment identity | query |
| `AT+LCTSN` | 1 | 0 / 1 | Vendor serial query | query |
| `AT+CMGL` | 2 | 2 / 0 | List message records | unknown other effect |
| `AT+CLCK` | 2 | 2 / 0 | Facility-lock command family | unknown other effect |
| `AT+CGDCONT` | 3 | 3 / 0 | Read stored PDP contexts | query |
| `AT$QCPDPP` | 2 | 2 / 0 | Read profile authentication settings | query |
| `AT+MGAUTH` | 1 | 1 / 0 | Configure profile authentication | configuration |

### Initialization and safe templates

The first commands disable echo, enable numeric error reporting, read identification, disable automatic answering, select a URC port, configure DTR behavior and enable registration reporting. The observed sequence includes `ATE0`, `AT+CMEE=1`, `ATI`, `ATS0=0`, `AT&D2`, registration-reporting setup, `AT+CFUN?` and `AT+CPIN?`. No native USB DTR request is inferred from `AT&D2`.

The catalog uses templates such as:

- `AT+COPS=3,<format>;+COPS?[;additional-format/query-pairs]`: operator reads mixed with output-format changes.
- `AT+CRSM=<read-operation>,<file>,<p1>,<p2>,<length>[,<remaining-read-parameters>]`: only READ BINARY (176), READ RECORD (178) and GET RESPONSE (192) operations were observed. SIM file identifiers and response contents are not published.
- `AT+CGDCONT?` and `AT$QCPDPP?`: stored context and authentication reads; their returned values are private.
- `AT+MGAUTH=<context>,<auth-mode>,"<username>","<password>"`: an observed native authentication-configuration command. Credential values and lengths are excluded.
- `AT+CGSN=<identity-selector>` and `AT+LCTSN=<selector>,<selector>`: identity queries, not identity writes or acceptance predicates.

A successful identity query does not prove a whitelist comparison. The vendor subscriber query returned `ERROR`, while later subscriber reads returned `OK`; their values are omitted. Nine 5GS-registration queries and the serial query returned `ERROR` without preventing the later LTE data session. These results show tolerance in this observed path, not that every candidate can omit the commands or that all unreported hardware capabilities are absent.

Three context reads and two authentication reads are logged. No `CGDCONT=` context-write command appears in this window. The native authentication command does appear, so the full stock initialization must not be labeled read-only. For other vendor families, the catalog retains `UNKNOWN` effects instead of treating all accepted forms as harmless queries.

## QMI catalog and validation

The capture contains **23 requests, 22 responses and one WDS indication**. All 22 responses match a request by service, allocated client, transaction, message ID and response kind. Two independent offline decoders agree on framing and TLV bounds; every privately retained frame round-trips byte for byte. This audit is stricter than the selected native matcher described below.

| Service / message | Meaning | Requests | Responses | Indications |
| --- | --- | ---: | ---: | ---: |
| CTL / `0x0021` | CTL Get Version Info | 1 | 1 | 0 |
| CTL / `0x0022` | CTL Allocate CID | 5 | 5 | 0 |
| CTL / `0x0027` | CTL Sync | 2 | 1 | 0 |
| WDS / `0x0020` | WDS Start Network | 1 | 1 | 0 |
| WDS / `0x0022` | WDS Get Packet Service Status | 2 | 2 | 1 |
| WDS / `0x002b` | WDS Get Profile Settings | 1 | 1 | 0 |
| WDS / `0x002d` | WDS Get Current Settings | 3 | 3 | 0 |
| WDS / `0x0051` | WDS Set Autoconnect Settings | 1 | 1 | 0 |
| DMS / `0x0023` | DMS Get Revision | 1 | 1 | 0 |
| NAS / `0x004d` | NAS Get System Info | 2 | 2 | 0 |
| UIM / `0x0020` | UIM Read Transparent | 2 | 2 | 0 |
| UIM / `0x002f` | UIM Get Card Status | 1 | 1 | 0 |
| WDA / `0x0020` | WDA Set Data Format | 1 | 1 | 0 |

Of the 22 responses, 21 report success. WDS Set Autoconnect reports result 1 / error 26, `NoEffect`; the native path then continues through SIM, registration and successful data startup. A generic requirement that every initialization response equal success would misrepresent this measured behavior.

### Measured startup order

1. At +1,948 ms, native CTL Sync uses transaction 1. No matching response is captured.
2. A second Sync uses transaction 2 at +3,948 ms and succeeds 30 ms later. The two-second spacing agrees with the selected native one-second response timeout plus one-second failure delay. This is native policy, not a universal readiness guarantee.
3. Get Version Info uses transaction 3, including a one-byte service-selection TLV with value 255, and returns 29 entries. The service list is not an exact-match authorization fingerprint established by this review.
4. Five CTL allocations create clients for WDS, DMS, NAS, UIM and WDA. Later requests correlate with those clients.
5. DMS revision is read; WDA Set Data Format succeeds; the autoconnect-disable request receives `NoEffect`.
6. UIM card status and two transparent-file reads succeed. Identifier/file contents are not published.
7. Stored 3GPP profile 1 is read. NAS system information and packet-service status precede Start; initial packet status is disconnected.
8. One IPv4 WDS Start succeeds and returns a packet-data handle. Current settings, a connected indication, connected status and further settings replies follow. All three settings responses report MTU 1500.

The only captured unsolicited QMI indication is WDS packet-service status. No unsolicited CTL Sync indication appears in this finite window. The application log does not expose USB notification reads, EP0 setup packets or kernel DTR handling, so those events must not be invented to fill gaps in the timeline.

## Advertised service versions

These values are measured service protocol versions, not libqmi release-version `since` annotations. Advertisement does not prove that every message of a service works or establish NR/SA/NSA hardware support. Unknown public enum names remain unassigned rather than guessed.

| ID | Public service name | Advertised version |
| --- | --- | --- |
| `0x00` | CTL | 1.5 |
| `0x01` | WDS | 1.67 |
| `0x02` | DMS | 1.0 |
| `0x03` | NAS | 1.25 |
| `0x04` | QOS | 1.12 |
| `0x05` | WMS | 1.10 |
| `0x07` | AUTH | 1.3 |
| `0x08` | AT | 1.4 |
| `0x09` | VOICE | 2.1 |
| `0x0a` | CAT2 | 2.24 |
| `0x0b` | UIM | 1.87 |
| `0x0c` | PBM | 1.4 |
| `0x0f` | TEST | 1.0 |
| `0x10` | LOC | 2.0 |
| `0x11` | SAR | 1.0 |
| `0x12` | IMS | 1.0 |
| `0x17` | TS | 1.0 |
| `0x18` | TMD | 1.0 |
| `0x1a` | WDA | 1.16 |
| `0x1d` | CSVT | 1.1 |
| `0x1f` | IMSP | 1.0 |
| `0x21` | IMSA | 1.0 |
| `0x22` | COEX | 1.0 |
| `0x24` | PDC | 1.0 |
| `0x29` | RFRPE | 1.0 |
| `0x2a` | DSD | 1.0 |
| `0x2d` | Unassigned in pinned public enum | 1.0 |
| `0x30` | Unassigned in pinned public enum | 1.0 |
| `0x36` | Unassigned in pinned public enum | 1.0 |

The selected native version-capability scan runs only with nonzero QMAP context. It reads fixed result/count positions and tests whether the WDA minor version exceeds 16 to set a feature flag. That inspected comparison does not enforce a matching major version or equality with all 29 entries; zero context skips this scan. This is a bounded source finding, not a proof that every version is tolerated by every native consumer.

## WDA: requested Ethernet, accepted RAW_IP

The native **Set Data Format** request contains QoS disabled, link-layer Ethernet (1) and downlink aggregation disabled. Uplink aggregation, endpoint-selector and mux-ID TLVs are absent. Approximately 32 ms later, the successful response reports **RAW_IP (2), uplink aggregation disabled and downlink aggregation disabled**.

The selected native consumer compares the returned link-layer field with RAW_IP and stores its raw-IP state. The later successful Start demonstrates continuation after the differing response; requesting Ethernet does not establish that the host requires an Ethernet response or Ethernet bytes on USB.

All returned scalar fields that can be safely published are listed below. Numeric limits are response fields, not proof that aggregation was enabled.

| Response TLV | Meaning | Length (bytes) | Value |
| --- | --- | ---: | ---: |
| `0x02` | Operation result | 4 | success / no error |
| `0x10` | QoS header | 1 | 0 |
| `0x11` | Link-layer protocol | 4 | 2 |
| `0x12` | Uplink aggregation protocol | 4 | 0 |
| `0x13` | Downlink aggregation protocol | 4 | 0 |
| `0x14` | NDP signature | 4 | 0 |
| `0x15` | Downlink maximum datagrams | 4 | 0 |
| `0x16` | Downlink maximum size | 4 | 0 |
| `0x17` | Uplink maximum datagrams | 4 | 16 |
| `0x18` | Uplink maximum size | 4 | 4096 |
| `0x1a` | Download minimum padding | 4 | 0 |
| `0x1b` | Flow control | 1 | 0 |

The direction of a TLV matters. Set **request** TLV `0x17` is an eight-byte endpoint selector; Set **response** TLV `0x17` is a four-byte uplink maximum-datagram field. Its returned value 16 is not an interface number. Meanings follow the pinned public [WDA schema](https://github.com/linux-mobile-broadband/libqmi/blob/1c972b8ab901565f26b9f95e1705269277bbfa1b/data/qmi-service-wda.json).

A separate source-only builder branch requests RAW_IP with aggregation enum **5 = QMAP**, derived downlink limits and an endpoint selector. It was not observed in this boot. Enum 5 does not mean QMAPv5, whose enum value is 9. No WDS Bind Mux request was captured. Native bulk packets were not captured here; reported format and zero QMAP driver policy remain distinct from measured physical framing.

## WDS, profile selection and handle lifetimes

The successful Start has exactly these input semantics:

| TLV | Meaning | Observed value |
| --- | --- | --- |
| `0x30` | Technology preference | 1: 3GPP allowed |
| `0x19` | IP family | 4: IPv4 |
| `0x31` | 3GPP profile index | 1 |

There is no explicit APN (`0x14`), authentication (`0x16`), username (`0x17`) or password (`0x18`) TLV in this Start. This does not mean an empty APN was used: the preceding profile read contains an APN field, and its value agrees with native context-1 reads. Profile authentication and the native authentication command both carry numeric mode 3; credential values are private. The vendor command's numeric mode is not given a broader meaning without its own exact command contract.

Current Settings uses request mask `0x2310`: DNS addresses, IP address, gateway information and MTU. Address values are withheld. The message/TLV interpretation follows the pinned public [WDS schema](https://github.com/linux-mobile-broadband/libqmi/blob/1c972b8ab901565f26b9f95e1705269277bbfa1b/data/qmi-service-wds.json).

The source-supported lifecycle is narrower than a measured teardown:

- Successful Start stores a family-specific packet-data handle. The native Start timeout is 120,000 ms; it is an implementation choice, not a proven device-mandated timeout.
- Stop is constructed only for a nonzero stored family-specific handle. The selected source uses a 30,000 ms timeout and clears the stored handle after a successful result.
- Client deinitialization sends releases for nonzero client slots and clears local slots. Local clearing must not be described as confirmation that the modem acknowledged every release.
- An internal index `0x11` is rewritten to wire WDS service `0x01` for an IPv6 path. It is not an IPv6 request to wire service `0x11`. No IPv6 Start was observed.
- Conditional source paths can create/modify profiles, change context/function state or perform reconnect/recovery writes. They were not observed here and are not an instruction to replay them.

No native Stop or client-release exchange appears in the retained window; the native connection remained in use. That is neither a proven cleanup success nor a cleanup failure. A native home-only roaming gate was not established by this scope.

## Parser constraints and compatibility consequences

The selected native response matcher checks service, client and transaction, using an eight-bit transaction for CTL and a sixteen-bit transaction for other services. An explicit message-ID/response-flag predicate was not established in that selected matched branch. The offline evidence audit independently checks both.

Selected lookup loops skip unneeded TLVs by their declared length plus header size, but several command handlers use fixed result, version-count or handle offsets. This supports tolerance of some well-formed unknown TLVs, not universal arbitrary ordering. Selected remaining-length arithmetic also lacks an explicit value-length-within-remaining guard in the reviewed loop. This is a bounded static observation, not a tested exploit, a fuzzing certification or a reason to emulate weaker validation.

For a compatibility implementation, preserve valid message semantics and unknown well-formed fields while keeping bounded parsing, transaction ownership and explicit reply matching. Do not turn an unexpected response into fabricated success. The observed error tolerance and source-only retry paths are distinct from an instruction to apply unlimited retries or configuration writes.

## What is still unknown

- Native USB DTR assertion/clear values and timing, EP0/IRQ sequencing and physical bulk framing.
- Natural Stop/Release acknowledgement behavior outside the startup window.
- Which individual AT commands are indispensable on another modem/profile.
- A global exact identity/firmware allowlist or application entitlement predicate.
- Runtime application callback, publication, cache-commit and control acceptance.
- An actual 5G candidate's compatibility with this exact installed host.

No identity rewriting, forced USB descriptor emulation or bridge requirement follows from this startup capture alone. The findings establish a concrete native protocol reference and explicit test boundaries, not a candidate PASS.
