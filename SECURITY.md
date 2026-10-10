# Security and safe research

This is experimental interoperability software for hardware you own or are explicitly authorized to investigate. It is not an authorized DJI product and is provided without warranty.

## Execution boundaries

**SOURCE_SUPPORTED:** normal imports, offline tests and default CLI plans do not open USB devices or start cellular traffic. Real laboratory entry points require explicit execution flags and exact target configuration. These flags do not establish that an experiment is electrically safe or legally authorized.

The release does not provide IMEI or SIM identity modification, NV/QCN writing, license/entitlement or cryptographic bypass, or a firmware-flashing workflow. There is no automatic data-session creation. Do not transmit on unauthorized bands. Cellular use must comply with applicable law and operator terms, including charges and roaming conditions.

**UNKNOWN:** physical gadget behavior, candidate compatibility, power/RF stability and host acceptance. Timeouts and cleanup safeguards are not a guarantee against every hardware or kernel failure. Do not deploy on safety-critical or production equipment.

## Sensitive data

Do not post tokens, credentials, device serials, IMEI, IMSI, ICCID, EID, account details, network identifiers, proprietary packages or unreviewed packet captures. Raw laboratory outputs can contain such information even when a command is read-only. Use synthetic fixtures or reviewed sanitized summaries. Removing a value from the latest file is insufficient if it remains in Git history.

## Reporting a vulnerability

Responsible disclosure is encouraged. Use the repository's private vulnerability-reporting feature when it is available. Its availability must be verified after publication; no private reporting channel is claimed before then. Do not use a public issue to disclose secrets or actionable details that expose another person's hardware. A non-sensitive public issue may request a secure reporting route without attaching evidence.

The research preview has no promised security-support lifetime or response deadline. Reports should identify the affected commit, offline reproduction, impact and proposed bounds; never trigger a live test on someone else's device.
