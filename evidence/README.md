# Public evidence summaries

The `sanitized` directory contains original metadata summaries, not raw captures. No actual USB serial, personal modem/SIM identity, local path or proprietary binary is included.

| Summary | Evidence level | Scope |
| --- | --- | --- |
| [USB composition](sanitized/usb-composition.json) | CONFIRMED_TARGET_DEVICE | Endpoint/class metadata; unresolved roles preserved |
| [Reported identity](sanitized/device-identity.json) | CONFIRMED_TARGET_DEVICE | Product/model/firmware/hardware version; no personal identifiers |
| [QMI services](sanitized/qmi-services.json) | CONFIRMED_TARGET_DEVICE | 29 numeric service/version entries; pinned name annotations |
| [WDA data format](sanitized/wda-data-format.json) | CONFIRMED_TARGET_DEVICE | Reported default-channel configuration, not packets |
| [Host path status](sanitized/host-path-status.json) | SOURCE_SUPPORTED | Bounded static SDK findings and superseded mapping |

Hashes identify withheld source artifacts. They preserve provenance but do not permit public-only replay of a measurement whose raw input is intentionally absent. The project does not claim that publishing a summary authenticates or independently replicates the original experiment.

Synthetic vectors, if included elsewhere, are labeled synthetic and carry no measured-device status. Private-to-public source locations are maintained outside this repository; public provenance uses neutral artifact IDs.

Original summaries are licensed CC BY 4.0. Referenced vendor artifacts are not included or relicensed.

## Native RC520 scope

New controller-specific, non-identifying tables accompany the [RC520 native reference](../docs/native/README.md): platform/USB/network, AT/QMI startup and DJI application contracts. They contain original factual summaries, not raw logs or vendor source.
