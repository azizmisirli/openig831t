# Documentation

**Research Preview — end-to-end 5G replacement has not been demonstrated.**

Start with [status](../STATUS.md), [evidence levels](evidence-levels.md), and [limitations](limitations.md). Original documentation and sanitized evidence summaries are licensed under CC BY 4.0; code and kernel-derived material have separate scopes in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Native controller golden reference

- [RC520 + IG831T overview](native/README.md)
- [USB, kernel, services and network](native/platform-usb-network.md)
- [Native AT/QMI startup and WDA/WDS](native/at-qmi-startup.md)
- [DJI application and identity contract](native/dji-application-contract.md)
- [5G compatibility requirements and remaining gates](native/compatibility-contract.md)

## Measured original device

- [IG831T hardware and identity](ig831t-hardware.md)
- [USB interfaces, endpoints and controls](usb-interface-map.md)
- [AT transport](at-transport.md)
- [QMI initialization](qmi-initialization.md)
- [QMI service map](qmi-service-map.md)
- [RAW_IP and data-plane limits](raw-ip-data-plane.md)

## Host and replacement research

- [DJI host analysis](dji-host-analysis.md)
- [OLD / NEW / MULTI paths and corrections](old-new-multi-paths.md)
- [Runtime observation plan](runtime-observation-plan.md)
- [Candidate modems](candidate-modems.md)
- [FunctionFS bridge](functionfs-bridge.md)
- [Hardware validation gates](hardware-validation.md)

## Reproducing and contributing

- [Architecture](../ARCHITECTURE.md), [reproducibility](../REPRODUCIBILITY.md), [roadmap](../ROADMAP.md)
- [Sanitized evidence](../evidence/README.md), [public references](references.md)
- [Security](../SECURITY.md), [contributing](../CONTRIBUTING.md), [legal and ethical scope](legal-and-ethical-scope.md)
