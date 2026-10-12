<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RC520 native platform, USB and network reference

**CONFIRMED_NATIVE_HOST:** the original IG831T binds to native drivers and supplies an Android cellular network on the examined DJI RC Pro 2. This is a reference for one controller build and one original dongle, not a replacement-modem result or Enhanced Transmission approval.

This independently written summary contains no raw capture, proprietary binary, unit identifier, identifier hash, address, credential or wall-clock timeline. The [structured companion](../../evidence/sanitized/native-platform-usb-network.json) records the same scope with explicit uncertainty. Withheld measurements cannot be independently replayed from the public summary alone.

## Exact platform context

| Item | Examined context |
| --- | --- |
| Controller | DJI RC Pro 2, device family RC520 |
| Controller firmware | 01.00.07.00 |
| Android build | V55.31.01.39 release-keys |
| Android version | 11, API level 30 |
| Reported board / platform | lahaina / lahaina |
| Reported SoC | QCS5430 |
| Kernel version | 5.4.210 |
| Installed `dji.go.v5` | 1.21.2, version code 3114825 |
| Installed `dji.go.v9` | 1.19.4, version code 3113157 |

The controller firmware and Android build are different version namespaces. Package installation does not prove that every package was active or that a particular library or callback ran. The selected AirLink abstraction, MSDK version, aircraft/camera/product enum context, Dock capability, active WLM callback family and runtime identity decision remain unresolved.

The computer-facing controller USB function is distinct from the internal cellular modem. Its MTP/bulk/ADB presentation is not the IG831T composition described below. The internal modem sits on a DWC3/xHCI host path through a hub; transient bus numbers and physical path instances are omitted.

## Device and configuration descriptors

The cached native descriptor and sysfs evidence identifies USB `2ca3:4009`, configuration 1, alternate setting 0 on all five interfaces, at 480 Mbit/s high speed. The device reports USB 2.00, device-release BCD `0x0318`, device class/subclass/protocol `00/00/00`, and a 64-byte endpoint zero. The BCD release field is not assumed to be a modem firmware revision.

There is one configuration. Its total descriptor length is 209 bytes; the device descriptor plus configuration occupy 227 bytes. Configuration attributes `0xa0` advertise bus power and remote wakeup. The advertised maximum is 500 mA; this is neither a measured current draw nor a sufficient power specification for a different modem. Generic manufacturer/product strings are `BAIWANG` / `Baiwang`; unique string values are withheld.

| Interface | Class/subclass/protocol | Interrupt IN | Bulk IN | Bulk OUT | Native binding and observed association |
| --- | --- | --- | --- | --- | --- |
| MI_00 | ff/ff/ff | — | 0x81 | 0x01 | `option` → `ttyUSB0`; specific serial role unresolved |
| MI_01 | ff/00/00 | 0x83 | 0x82 | 0x02 | `option` → `ttyUSB1`; specific serial role unresolved |
| MI_02 | ff/00/00 | 0x85 | 0x84 | 0x03 | `option` → `ttyUSB2`; binding alone does not select the native AT port |
| MI_03 | ff/00/00 | 0x87 | 0x86 | 0x04 | `option` → `ttyUSB3`; native RIL AT selection and exchanges observed |
| MI_04 | ff/ff/ff | 0x89 | 0x88 | 0x05 | `qmi_wwan_f` → `cdc-wdm0` and `dji_mini_net` |

Every bulk endpoint has maximum packet size 512 bytes. Interrupt maximum packet sizes are 10 bytes on MI_01–03 and 8 bytes on MI_04; their encoded interval is 9. Bulk intervals are zero. There are five bulk IN, four interrupt IN and five bulk OUT endpoints: **9 IN + 5 OUT, excluding endpoint zero**. The table does not describe a separate full-speed measurement.

MI_01, MI_02 and MI_03 each include the following class-specific interface descriptors despite using a vendor interface class:

| Functional descriptor | Length | Reported fields |
| --- | --- | --- |
| CDC Header | 5 | CDC version BCD `0x0110` |
| Call Management | 5 | Capabilities 0; data-interface reference 0 |
| Abstract Control Management | 4 | Capabilities 2 |
| Union | 5 | Control-interface reference 0; subordinate-interface reference 0 |

These original references are reported as found, without silently repairing them. Familiar descriptor shapes do not establish DIAG, navigation or firmware roles for the unresolved ports. Native MI_03 AT selection is supported separately by the installed RIL's role table and boot exchanges. Port-selection logging is not a separate trace of the file-open system call.

## Kernel binding and device access

The selected kernel configuration reports built-in USB networking, QMI WWAN, USB serial, generic serial, WWAN serial and option support. A `y` configuration value means built-in for that symbol. A directory under `sys/module` alone does not prove that a `.ko` was dynamically loaded. The exact build relationship between the vendor name `qmi_wwan_f` and its configuration/object files remains unknown. Runtime binding is direct evidence for this original device; it is not a recovered complete kernel USB-ID table. The existence of a `new_id` control does not prove it was used.

The bound network driver reports `Fibocom_QMI_WWAN_Driver_V1.0.5`. Its observed parameters include `qmap_mode=0`, `rx_qmap=0` and `bridge_mode=0`. The aggregation timing parameters are retained numerically in the companion JSON without assuming their units. These parameters are driver policy, not a physical USB payload capture.

| Node | Owner/group | Mode | SELinux object type | Snapshot device number |
| --- | --- | --- | --- | --- |
| `ttyUSB0` | bluetooth / bluetooth | 0660 | `radio_device` | 188:0 |
| `ttyUSB1` | radio / radio | 0660 | `radio_device` | 188:1 |
| `ttyUSB2` | radio / radio | 0660 | `radio_device` | 188:2 |
| `ttyUSB3` | radio / radio | 0660 | `radio_device` | 188:3 |
| `cdc-wdm0` | radio / radio | 0660 | `radio_device` | 180:176 |

Node order and device numbers are snapshot-specific. The normal application environment is not assumed to have the radio or Bluetooth group permissions. Protected file descriptors and process maps were not bypassed, so ownership of every open node is not reconstructed. A suitable authorized access mechanism is necessary for this native path; exact node names, root UID and this vendor's driver name are not established as universal requirements for every implementation.

## Processes and init declarations

Measured process metadata shows `dji_link`, `dji_lte` and `dji_wlm` under root identities and their corresponding SELinux domains. Two `rild` instances select `libreference-ril-dual.so`, using separate instance arguments. They and `fibocom-dial` run under the radio identity; the dialer is in the `rild` SELinux domain. Their effective capabilities include `NET_ADMIN`, `NET_RAW` and `BLOCK_SUSPEND`. Process IDs and full command-line captures are not published.

The captured init declarations support the following narrower statements:

- `dji_link` and `dji_lte` are main-class services under root; the link service declares four stream sockets.
- A separate disabled, oneshot startup service is triggered by boot completion.
- Two main-class RIL services specify the selected library, radio groups and the three capabilities listed above.
- `dji_wlm` has both vendor and system declarations. The system declaration adds `disabled`; import/override precedence was not established. A running process is independently observed, but the declaration conflict is not resolved by guessing.
- `dji.wlm_service` and `dji.wlm_slave_service` are service-control triggers. `sys.dji.route` can restart link, WLM-slave, LTE and configuration-store services.

Declarations do not establish complete runtime order. A process parented to init may have been reparented; that fact alone does not prove direct init launch. Socket or process names do not establish a proprietary LTE-control or Fly callback edge. No service-control property was written by the collector.

## Property inventory and the measured network-name edge

The selected inventory contains **23 property names**, not a complete Android property inventory. Names and code roles are published, while property contents are withheld except for the fixed generic network-device name `dji_mini_net`.

| Property name | Bounded source interpretation |
| --- | --- |
| `dji.lte.pcellid` | Decimal status-field group; native writer and physical meaning not established |
| `lte.service.dongle_temp` | Unsigned-byte status fields; units and writer not established |
| `dji.lte.scellid` | Decimal status field; writer unresolved |
| `dji.lte.rsrp` | Decimal status-field group; units and writer unresolved |
| `dji.lte.fw.version` | Dotted decimal parser and exit clear; not a demonstrated identity allowlist |
| `dji.lte.simcard` | Status/dialing reader; no observed producer |
| `dji.lte.cereg` | Registration-related status reader; no observed producer |
| `dji.lte.imei_sn` | Identity-related parser reference; contents withheld |
| `dji.lte.apn` | Profile-related parser reference; contents withheld |
| `dji.lte.iccid` | Subscriber-related parser reference; contents withheld |
| `lte.dev.apn` | Profile-getter reference; contents withheld |
| `lte.service.cmd` | Command-sender slot; selected native peer unresolved |
| `lte.service.cmd_res` | Result reader/clear; selected native producer unresolved |
| `lte.service.cmd.ext` | Command-extension writer; selected native peer unresolved |
| `dji.lte_dongle_status` | Lifecycle/reset-related writers and readers; not a harmless query channel |
| `ril.fibocom.NetifName` | Source-supported writers and measured dialer reader branch |
| `lte.upgrading_netcard` | Upgrade/deinitialization and reset-exclusion logic; active use unobserved |
| `lte.dev.test` | Test/configuration readers; not exercised |
| `dji.lte.slow_show` | Video-start writer; presence is not acceptance |
| `dji.lte.slow_show_frm` | Video-start initialization writer; presence is not acceptance |
| `dji.wlm_service` | Init service-control trigger |
| `dji.wlm_slave_service` | Init service-control trigger |
| `sys.dji.route` | Init service-restart trigger |

The strongest shared-property edge is `ril.fibocom.NetifName`. The native RIL's original-dongle discovery branch writes `dji_mini_net`; a separate conditional `dji_lte` initialization branch can also write the property. The dialer's main function reads it, takes a nonempty branch and stores the adapter name. A boot message reports the same network-name selection. This closes a source-plus-runtime **consumer** edge, but does not identify the last writer or prove any WLM/Fly acceptance decision.

A command/status provider also exists inside `dji_lte`. However, the selected native dual RIL has no exact literal occurrence of the 14 examined mailbox/status names. That is bounded negative source evidence, not proof that no dynamically constructed name or alternate process can serve them. The provider's active selection and peer remain unknown. The examined property mechanism does not establish generic transaction ownership, freshness or automatic process-death cleanup; it is not a ready-to-use temporary shim contract.

## SELinux rules versus runtime operations

Captured property-context rules map most of the listed names to `default_prop`, `ril.fibocom.NetifName` to `radio_prop`, and `sys.dji.route` to `system_prop`. Per-property runtime context queries were not captured in this scope. These source resolutions are separate from the measured node labels above.

A local libsepol 3.6 reader evaluated the saved active policy and the saved precompiled policy. The files differ, but all **100 selected access-vector decisions per policy** agree; 43 were allowed. The companion JSON retains the ten-domain, per-permission result matrix.

For `property_service:set`, `default_prop` was denied for every examined domain: shell, two untrusted-app domains, platform app, privileged app, RIL, the three selected DJI service domains and system server. `radio_prop` set was allowed only for `rild` among those domains. The selected matrix also covers property-file read/map and `radio_device` character-device open/read/write/ioctl. It does not evaluate `system_prop` set for the route trigger.

The controller reported **Permissive** SELinux mode. A type-enforcement denial is therefore not interchangeable with a measured failed operation. Conversely, permissive mode does not bypass every DAC, Android, service-level or extended-ioctl restriction. No property write or node-access test was performed to turn these static policy decisions into runtime success claims. Root processes and permissive mode describe the examined implementation, not a requirement to weaken another system's security.

## Android network state and passive Binder metadata

Eight post-reboot framework network snapshots were retained. The first had no associated native cellular agent; the remaining seven reported LTE, connected and validated state, roaming false, MTU 1500, and address/DNS information. Address values are withheld. Twenty-four separate state/counter samples show network-device creation followed by native traffic. No observer-generated network probe was used.

An earlier **600-second passive observation on the same RC520** supplied 60 state samples at ten-second intervals and ten framework network snapshots. Driver bindings remained stable; all ten network snapshots were LTE, connected and validated. The first-to-last counter span was approximately 590 seconds, with increases of 276,769 received bytes and 232,570 transmitted bytes. Counter growth is native traffic evidence, not packet content, application attribution or a new Internet test.

A separate 15-second passive trace used existing Binder/process tracepoints, without application hooks. Its framing and parser checks covered 644 complete top-level packets with no reported parse-error statistics. The flow analysis found 10,942 Binder edges: 8,266 transaction-to-reply and 2,676 asynchronous-to-receive edges. The selected process join assigned 10,936 to process pairs; six were not assigned by that join. Selected counts were:

| Process edge | Count |
| --- | ---: |
| RIL → `com.android.phone` | 1 |
| `com.android.phone` → `system_server` | 70 |
| Fly → `system_server` | 103 |

These are IPC metadata counts. They do not identify telephony API arguments, cellular payload use, WLM callbacks, parsing, publication, cache commit, listener delivery or a final LTE-control result. The trace was stopped; no tracing session was left active. Together with process and framework snapshots, the evidence supports native network integration while leaving the intermediate method/parcel sequence unresolved.

## What this reference establishes—and what remains open

The original IG831T has a directly observed USB → kernel/node → native RIL/dialer → Android cellular-network path on this exact controller build. Native AT selection and QMI startup are covered separately in [AT/QMI startup](at-qmi-startup.md). A successful native network does not establish replacement acceptance or Enhanced Transmission entitlement.

The network device reports type 1, MTU 1500 and carrier present. Type 1 does **not** prove Ethernet headers on USB. Raw-IP driver policy and negotiated WDA settings likewise do not substitute for packet bytes. `CONFIG_USB_MON` was not enabled in the captured kernel configuration, and this phase contains **no native physical USB payload capture**. Native on-wire framing remains unconfirmed.

The collection included one explicitly authorized controller reboot. The collector did not claim a modem interface, send AT/QMI/DTR commands, start or stop a packet-data session directly, generate a network probe, restart individual services or elevate privileges. Stock services retained modem ownership and performed their own state-changing initialization. The available boot log is a finite early-startup window; a longer collector lifetime is not continuous protocol coverage.

Protected process maps, file descriptors and the selected persistent route were not bypassed. Candidate configuration templates do not prove which route was active. The exact application callback/cache/control chain, identity requirements, candidate firmware behavior, physical 5G operation and need for a bridge remain **UNKNOWN**. No candidate modem was attached for this reference.
