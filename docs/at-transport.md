# AT transport

**CONFIRMED_TARGET_DEVICE:** MI_02 carries AT command/response traffic through bulk OUT `0x03` and bulk IN `0x84`. Read-only `AT`, `ATI`, `AT+CGMI`, `AT+CGMM` and `AT+CGMR` exchanges were used during the original investigation. Identity values are summarized separately; raw ATI output is not published because it may contain identifying fields.

**SOURCE_SUPPORTED:** the original proxy buffers bounded chunks until an entire permitted command is available, preserves CR/CRLF and echo framing, recognizes bounded response/unsolicited-line behavior, and tracks one pending command. Timeouts and ambiguous/pipelined input stop the channel rather than replaying an uncertain command. A wire fragment is never authorized merely because it starts with an allowed command name.

**SOURCE_SUPPORTED:** optional identity adaptation is off by default and limited to explicitly configured manufacturer/model/firmware response rules. An evidence reference is a configuration prerequisite, not automatic proof that a host requires rewriting. Error or ambiguous responses must not be turned into fabricated successful identities.

**UNKNOWN:** the whole AT command vocabulary, serial-control prerequisites on every firmware, and replacement-modem compatibility. The observed vendor-class CDC-like descriptors do not establish a standard host serial driver's complete behavior.

The laboratory policy excludes composition changes, radio configuration, SIM/IMEI/NV writes, reset, dialing/data mode and unknown commands. CDC line coding, arbitrary RTS manipulation and every serial notification mode are not implemented by the minimal daemon. This is a bounded research proxy, not a general terminal service.
