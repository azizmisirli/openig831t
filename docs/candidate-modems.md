# Candidate modems

**UNKNOWN:** no replacement candidate has been measured by this project. None is a confirmed drop-in replacement, and no winner or exact ordering code is established.

| Candidate family | Available evidence | Missing link |
| --- | --- | --- |
| Quectel RM520N-GL | FAMILY_LEVEL_SOURCE_EVIDENCE: official USB guide and an upstream Linux 2c7c:0801 composition example | Same exact SKU/firmware with complete descriptors, identities, service list, WDA and host result |
| Fibocom FM150 | FAMILY_LEVEL_SOURCE_EVIDENCE: family AT/USB/QMI documentation and host-driver behavior | Same-unit firmware/composition/WDA chain |
| Fibocom FM160 | FAMILY_LEVEL_SOURCE_EVIDENCE: QMI driver composition and separately documented MBIM composition | Do not merge separate PIDs/modes into one firmware specimen |
| Fibocom FM190W-GL and other recent models | FAMILY_LEVEL_SOURCE_EVIDENCE: manufacturer product information | Exact USB versus other transports, firmware, endpoints and QMI/WDA profile |

**SOURCE_SUPPORTED:** the upstream RM520N example places AT on interface 2 and QMI on interface 4, with QMI interrupt `0x88`, bulk IN `0x8e`, bulk OUT `0x0f`. This differs from IG831T endpoints. **UNKNOWN:** its exact modem firmware/order SKU and whether those addresses apply to a unit a contributor owns. A USB `bcdDevice` value is not automatically a firmware revision.

**FAMILY_LEVEL_SOURCE_EVIDENCE:** the current official Quectel 5G-M2 EVB page lists the RM520N series. The generic 5G EVB is a different carrier family. This is not proof that every carrier revision, module variant, power configuration or antenna arrangement is compatible. USB-capable and special non-USB ordering variants must remain distinct.

**UNKNOWN:** whether candidate firmware supports the desired unaggregated RAW_IP mode. A QMAP default in a host driver does not prove that plain-IP firmware operation is impossible. QMI support also does not establish DJI identity or authorization acceptance.

The next useful evidence is a single identified candidate, read-only profile and sanitized record: exact SKU/firmware, descriptor map, AT identity, QMI versions, WDA report and DTR/Sync behavior. The bounded candidate tool does not choose modes or start a session. [Primary references](references.md).
