<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Sanitized examples

These files contain placeholders or synthetic-derived protocol metadata. They do not authorize hardware access. The laboratory launch template is deliberately `NOT_READY`. No private raw capture, subscriber identity, or real USB serial is included.

The descriptor resource in `src/igbridge/data/ig831t_exact.json` preserves measured composition fields but replaces the serial with `REDACTED_USB_SERIAL`. It is not a byte-identical identity clone.

A live laboratory build manifest additionally needs `patch_root` (the reviewed public patch directory), `patched_source_root` (a local, verified patched kernel tree), all pinned hashes, and independent build/boot evidence. Merely changing the status to `READY` is insufficient.
