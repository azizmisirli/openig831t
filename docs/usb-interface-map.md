# USB interfaces and control path

**CONFIRMED_TARGET_DEVICE:** the target reports one selected configuration with five alternate-zero interfaces. The measured high-speed endpoint map is:

| Interface | Class/subclass/protocol | Endpoints | Role evidence |
| --- | --- | --- | --- |
| 0 | ff/ff/ff | 0x81 bulk IN; 0x01 bulk OUT | UNKNOWN |
| 1 | ff/00/00 | 0x83 interrupt IN; 0x82 bulk IN; 0x02 bulk OUT | UNKNOWN |
| 2 | ff/00/00 | 0x85 interrupt IN; 0x84 bulk IN; 0x03 bulk OUT | CONFIRMED_TARGET_DEVICE: AT |
| 3 | ff/00/00 | 0x87 interrupt IN; 0x86 bulk IN; 0x04 bulk OUT | Native RC520 AT selection and exchanges measured |
| 4 | ff/ff/ff | 0x89 interrupt IN; 0x88 bulk IN; 0x05 bulk OUT | CONFIRMED_TARGET_DEVICE: QMI control |

**CONFIRMED_TARGET_DEVICE:** high-speed bulk maximum packet size is 512 bytes. Interrupt maximum packet sizes are 10 bytes on interfaces 1/2/3 and 8 bytes on interface 4. Five bulk IN, four interrupt IN and five bulk OUT endpoints total **9 IN + 5 OUT**, excluding EP0. The device also reports other-speed descriptor data; that is not evidence of a separate physical full-speed run.

**CONFIRMED_TARGET_DEVICE:** vendor-class interfaces 1/2/3 include CDC Header, Call Management, ACM and Union functional descriptors. The original union references are preserved; they are not silently “repaired.” **UNKNOWN:** naming MI_00/01 as DIAG, GPS or firmware solely from a familiar layout is unjustified. MI_03 now has separate native AT evidence.

## MI_04 controls

**CONFIRMED_TARGET_DEVICE:** the observed control path uses interface-recipient CDC requests on EP0, with `wIndex=4`. The following table is a protocol description, not a live command:

| Purpose | bmRequestType | bRequest | wValue | Data |
| --- | --- | --- | --- | --- |
| SEND_ENCAPSULATED_COMMAND | 0x21 | 0x00 | 0 | QMI request bytes |
| GET_ENCAPSULATED_RESPONSE | 0xa1 | 0x01 | 0 | Bounded response read |
| SET_CONTROL_LINE_STATE | 0x21 | 0x22 | DTR 0 or 1 | No payload |

**SOURCE_SUPPORTED:** the prototype requires a valid response-available notification before its corresponding GET. A successful USB SEND alone is not a successful QMI result. Interface number, endpoint address, FunctionFS endpoint-file slot and backend interface are separate concepts.

[Sanitized endpoint metadata](../evidence/sanitized/usb-composition.json) contains no captured serial or raw packet log.

[Native kernel/node mapping](native/platform-usb-network.md) directly associates MI_04 with cdc-wdm0 and dji_mini_net. Native physical USB packet framing remains unmeasured.
