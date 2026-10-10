# RAW_IP, QMAP and physical framing

**CONFIRMED_TARGET_DEVICE:** inputless WDA Get Data Format returned `RAW_IP` (link-layer value 2) and `DISABLED` (value 0) for both uplink and downlink aggregation. This is a reported current/default-channel configuration, not a WDA Set operation.

**STRONG_INFERENCE:** the reported state is consistent with non-QMAP raw IP for that channel. **UNKNOWN:** physical bulk framing. No actual IP, QMAP or Ethernet packet was captured; a bounded passive read ending empty/aborted cannot establish a packet format or a global absence of traffic. A later endpoint-qualified query error did not undo the successful inputless response and did not identify which selector capability was absent.

**CONFIRMED_TARGET_DEVICE:** a historical WDS Get Packet Service Status result was DISCONNECTED for the queried client/default port. **UNKNOWN:** every possible modem session. The prototype does not create or stop active WDS sessions.

## Offline translator scope

**SOURCE_SUPPORTED:** original codecs validate complete IPv4/IPv6 packet lengths and MTU, QMAP mux/padding/aggregate bounds, and the supported QMAPv5 header layout. Unknown/chained extensions and unsupported MAP commands are rejected. Malformed aggregates are dropped atomically; raw bytes remain available to the caller for its explicit logging policy.

**SOURCE_SUPPORTED:** the v5 extension is four bytes outside the base packet-length count. Uplink checksum offload is not implemented. A checksum-valid flag is not evidence that this software has verified a checksum. IPv6 jumbo packets, checksum verification and stream reassembly are outside the supported scope.

**UNKNOWN:** whether any exact candidate firmware can operate in the desired plain-IP format. A vendor driver's QMAP default does not prove plain-IP firmware support is absent. The codec is not a live USB packet relay; transfer-chunk to complete-frame reassembly remains an integration gate.

[Sanitized WDA summary](../evidence/sanitized/wda-data-format.json) · [Linux rmnet sources](references.md)
