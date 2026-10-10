# QMI service map

**CONFIRMED_TARGET_DEVICE:** the successful CTL Get Version Info response contained the following 29 numeric service/version entries for the measured IG831T firmware. **SOURCE_SUPPORTED:** names are annotations from pinned libqmi enums; unknown names remain numeric rather than being invented.

| Service ID | Name annotation | Version |
| --- | --- | --- |
| 0x00 | CTL | 1.5 |
| 0x01 | WDS | 1.67 |
| 0x02 | DMS | 1.0 |
| 0x03 | NAS | 1.25 |
| 0x04 | QOS | 1.12 |
| 0x05 | WMS | 1.10 |
| 0x07 | AUTH | 1.3 |
| 0x08 | AT | 1.4 |
| 0x09 | VOICE | 2.1 |
| 0x0a | CAT2 | 2.24 |
| 0x0b | UIM | 1.87 |
| 0x0c | PBM | 1.4 |
| 0x0f | TEST | 1.0 |
| 0x10 | LOC | 2.0 |
| 0x11 | SAR | 1.0 |
| 0x12 | IMS | 1.0 |
| 0x17 | TS | 1.0 |
| 0x18 | TMD | 1.0 |
| 0x1a | WDA | 1.16 |
| 0x1d | CSVT | 1.1 |
| 0x1f | IMSP | 1.0 |
| 0x21 | IMSA | 1.0 |
| 0x22 | COEX | 1.0 |
| 0x24 | PDC | 1.0 |
| 0x29 | RFRPE | 1.0 |
| 0x2a | DSD | 1.0 |
| 0x2d | UNKNOWN_NUMERIC | 1.0 |
| 0x30 | UNKNOWN_NUMERIC | 1.0 |
| 0x36 | UNKNOWN_NUMERIC | 1.0 |

**SUPERSEDED:** an earlier auxiliary annotation incorrectly associated OMA with 0x0e. The pinned enum uses OMA 0xe2, which is not in this list. The numeric service list was not changed by that correction.

**UNKNOWN:** support for every message in each advertised service. A service/version advertisement does not establish successful WDS data-session creation, radio technology, candidate interoperability, or host acceptance. Valid error responses to capability-inventory commands must not be interpreted as missing hardware.

[Machine-readable summary and source hashes](../evidence/sanitized/qmi-services.json) · [Pinned name source](references.md)
