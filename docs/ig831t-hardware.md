# IG831T hardware and reported modem identity

**CONFIRMED_TARGET_DEVICE:** the measured DJI Cellular Dongle 2 specimen identifies as IG831T and exposes USB VID/PID `2ca3:4009` at USB 2.0 high speed. These values describe the measured specimen, not every regional or firmware variant. The actual USB serial is omitted.

| Readout | Value | Evidence |
| --- | --- | --- |
| Manufacturer | Fibocom Wireless Inc. | CONFIRMED_TARGET_DEVICE |
| AT model | NL668T-GL | CONFIRMED_TARGET_DEVICE |
| QMI DMS model | NL668T-GL-00-00 | CONFIRMED_TARGET_DEVICE |
| Firmware | 19906.5090.00.02.00.23 | CONFIRMED_TARGET_DEVICE |
| Hardware revision | V1.0.0 | CONFIRMED_TARGET_DEVICE |

The shorter AT model and longer DMS model are retained as different reported fields. **UNKNOWN:** an independently measured silicon/baseband identity. A model number or another family member's firmware loader is not direct chipset evidence.

**FAMILY_LEVEL_SOURCE_EVIDENCE:** DJI's official guide describes LTE/WCDMA operation. This supports the product's documented cellular scope; it is not a conversion procedure or proof of replacement compatibility. Capability queries and reported identity do not establish a hidden 5G radio.

**UNKNOWN:** exact electrical compatibility with any replacement module. A bare M.2 module is not a drop-in USB-powered dongle. Appropriate carrier, power, RF, SIM and thermal arrangements require exact module and board documentation and physical validation.

[Sanitized identity](../evidence/sanitized/device-identity.json) · [USB map](usb-interface-map.md) · [Official references](references.md)
