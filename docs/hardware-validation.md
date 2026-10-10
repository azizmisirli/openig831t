# Hardware validation plan

**UNKNOWN:** physical 9-IN/5-OUT gadget feasibility and simultaneous backend USB-host operation. A controller's nominal endpoint count is not an enabled board-level resource allocation.

| Platform family | Source evidence | Physical result |
| --- | --- | --- |
| AM335x / suitable BeagleBone Black revision | SOURCE_SUPPORTED: relevant controller resources and separate USB roles | UNKNOWN |
| AM62x / suitable SK-AM62 revision | SOURCE_SUPPORTED: endpoint budget and separate controllers; revision-specific routing matters | UNKNOWN |
| CM4/CM5/Pi family | UNKNOWN: a log from one older board is not a family-wide capacity proof | UNKNOWN |

**SOURCE_SUPPORTED:** exact IG831T descriptor reproduction needs 9 IN + 5 OUT non-control endpoints, including endpoint number 9. Do not combine resources from two controllers to satisfy one gadget. Direction/type/maxpacket/FIFO constraints and simultaneous enable matter, not only totals.

## Required bounded gates

1. Identify the exact board revision, kernel configuration/build and booted image provenance.
2. Establish separate host and device USB paths, power/VBUS/PD behavior and exact carrier/module electrical requirements.
3. Validate allocation and enable of every endpoint at the required address/type/packet size; preserve failure evidence.
4. Exercise descriptors and bounded control on a generic laboratory host before an exact DJI-host experiment.
5. Record own-resource cleanup and retained obligations; do not auto-reset, detach another owner's driver or retry unknown writes.
6. Treat active cellular data as a separate authorized experiment with lawful RF use, operator terms and charges understood.

**UNKNOWN:** throughput, latency, packet loss, thermal stability, modem peak power and DJI Enhanced Transmission behavior. USB 2.0 line rate is not application throughput or evidence of 5G performance.

This is an evidence plan, not a wiring recipe or purchase recommendation. No board/carrier is declared safe based only on this repository. [References](references.md).
