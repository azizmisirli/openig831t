<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Licenses and third-party notices

OpenIG831T is a curated interoperability research preview. This file records
source provenance and the license scope of this distribution. It is not legal
advice, a patent clearance, or a statement of vendor authorization.

## License boundaries

| Material | License in this distribution |
| --- | --- |
| Original user-space Python, tests, scripts, build configuration, original validation schemas and query-plan metadata | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| Original documentation, diagrams, independently written evidence summaries and measurement tables | [CC-BY-4.0](LICENSES/CC-BY-4.0.txt), attribution to OpenIG831T contributors |
| Linux-derived experimental patch files and two standalone C harnesses under `patches/linux-functionfs/` | [GPL-2.0-only](LICENSES/GPL-2.0-only.txt); applicable upstream UAPI [Linux-syscall-note](LICENSES/Linux-syscall-note.txt) is retained |
| Optional downloaded libusb header, not bundled | Upstream [LGPL-2.1-or-later](LICENSES/LGPL-2.1-or-later.txt) |
| Standard license texts | Verbatim legal notices, not relicensed as project code |

The root `LICENSE` contains Apache-2.0 for original code. It does not relicense
Linux-derived files or third-party references. Per-file SPDX notices and the
manifest [licenses.json](evidence/manifests/licenses.json) identify exceptions.
Original synthetic byte vectors and technical query metadata distributed with
the Python tests are part of the Apache-2.0 original code. Sanitized measurement
summaries under `evidence/` are CC-BY-4.0 unless a per-file record says otherwise.
These notices do not claim exclusive ownership of protocol facts or numbers.

## Linux FunctionFS and USB gadget code

The patches target Linux v6.12, commit
[`adc218676eef25575469234709c2d87185ca223a`](https://github.com/torvalds/linux/tree/adc218676eef25575469234709c2d87185ca223a).
Full upstream source files are not included. The exact upstream file paths,
URLs, hashes, experimental patch hashes, harness hashes and extracted-function
hashes are recorded in [upstream.json](patches/linux-functionfs/upstream.json).

Relevant upstream notices are:

- `drivers/usb/gadget/function/f_fs.c`: GPL-2.0-or-later; Copyright (C) 2010 Samsung Electronics; author Michal Nazarewicz; based on GadgetFS, Copyright (C) 2003–2004 David Brownell and Copyright (C) 2003 Agilent Technologies.
- `drivers/usb/gadget/epautoconf.c`: GPL-2.0-or-later; Copyright (C) 2004 David Brownell.
- `drivers/usb/gadget/udc/core.c`: GPL-2.0-only; Copyright (C) 2010 Texas Instruments; author Felipe Balbi.
- `drivers/usb/gadget/function/u_fs.h`: GPL-2.0-only; Copyright (C) 2013 Samsung Electronics; author Andrzej Pietrasiewicz.
- `include/uapi/linux/usb/functionfs.h` and `include/uapi/linux/usb/cdc.h`: GPL-2.0-only WITH Linux-syscall-note. The exception accompanies the UAPI headers; it does not make the kernel implementation permissively licensed.

The standalone harnesses include extracted Linux C bodies with original host
shims and tests. They are derivative source, not independent Apache code. This
distribution selects GPL version 2 for portions that permit later versions;
`exact-address.c` also includes GPL-2.0-only UDC code. The harness license comments
preserve upstream copyright attribution and identify 2026 OpenIG831T changes.
The public preparation changed only their leading license/provenance comments;
the tested C bodies are unchanged from the corresponding research artifacts.

The experimental changes provide opt-in CDC functional-descriptor handling and
exact endpoint selection. The three patch files are unchanged byte copies of
the reviewed experimental patches. They carry GPL sidecar notices without
changing patch bytes. The combined patch and the CDC-plus-stacked pair are
alternative ways to produce the same modified source. They must not both be
applied to the same tree.

No compiled kernel, vendor module, or device binary is distributed. Full kernel
build and physical hardware behavior remain unverified. See the
[patch documentation](patches/linux-functionfs/README.md) for the optional,
explicit, hash-verified source-fetch workflow.

## libusb reference

The optional ABI-check header is from [libusb v1.0.29](https://github.com/libusb/libusb/tree/v1.0.29),
`libusb/libusb.h`. Its upstream header and
[COPYING](https://github.com/libusb/libusb/blob/v1.0.29/COPYING) specify
LGPL version 2.1 or, at the recipient's option, a later version. The header is
reference-only and excluded from tracked project files. Its SHA256 and official
fetch URL are in `upstream.json`. No libusb binary is bundled; external runtime
libraries retain their own licenses. Tests skip the optional real-header ABI
check when that verified header is absent.

## libqmi protocol references

The original Python QMI codec and state machine use documented protocol facts
and local interoperability observations; no libqmi C body or generated libqmi
code is included. Query-plan records contain independently written minimal
facts such as service number, message number, request shape and a primary-source
reference. They are not copies of full upstream schema objects.

Reference revision:
[`linux-mobile-broadband/libqmi` commit `1c972b8ab901565f26b9f95e1705269277bbfa1b`](https://github.com/linux-mobile-broadband/libqmi/tree/1c972b8ab901565f26b9f95e1705269277bbfa1b).
The upstream project has mixed licensing; see its
[COPYING](https://github.com/linux-mobile-broadband/libqmi/blob/1c972b8ab901565f26b9f95e1705269277bbfa1b/COPYING)
and individual files. Full service JSON files, generated bindings, tools and
library source are excluded from this release. This avoids assigning an inferred
per-file license to schema material whose redistribution scope was not needed
for the release. A reference to libqmi does not apply its license to an
independently written protocol implementation.

## Excluded proprietary and private material

DJI SDK AAR/JAR files, Windows executables and drivers, shared libraries,
firmware, vendor manuals, complete disassembly, private raw captures, browser
profiles, account data, SIM identifiers and device-specific identities are not
licensed or redistributed by this project. Public references or hashes do not
convey redistribution rights. Unknown-license material is reference-only or
excluded. Source URLs in this repository identify upstream public material;
they are not mirrors of proprietary artifacts.

## Primary license references

- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt)
- [Creative Commons Attribution 4.0 legal code](https://creativecommons.org/licenses/by/4.0/legalcode.txt)
- [Linux GPL-2.0 notice](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/LICENSES/preferred/GPL-2.0)
- [Linux syscall exception](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/LICENSES/exceptions/Linux-syscall-note)
- [libusb COPYING](https://github.com/libusb/libusb/blob/v1.0.29/COPYING)

The standard license texts are included in `LICENSES/`. This audit concerns the
curated files and declared source licenses; it does not determine trademark,
patent, contractual, radio-regulatory or jurisdiction-specific rights.
