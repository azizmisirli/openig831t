<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Experimental Linux FunctionFS patches

These patches target Linux v6.12 commit `adc218676eef25575469234709c2d87185ca223a`.
They are source-level experiments. A full kernel build, physical UDC operation,
FIFO capacity, and DJI host acceptance remain unverified.

| File | Purpose |
| --- | --- |
| `cdc-v6.12.patch` | Opt-in handling of selected CDC functional descriptors; private flag `1U << 30`. |
| `exact-address-stacked-v6.12.patch` | Apply after the CDC patch; opt-in exact endpoint selection, private flag `1U << 29`. |
| `cdc-exact-combined-v6.12.patch` | Equivalent combined patch against unmodified v6.12. |
| `harnesses/cdc.c` | Standalone Linux-derived parser test with host shims; 74 checks. |
| `harnesses/exact-address.c` | Standalone Linux-derived endpoint test with host shims; 1,268 checks. |
| `upstream.json` | Source, patch, harness, extracted-function and expected patched-file hashes. |

The flags are experimental private values, not upstream Linux ABI commitments.
Default FunctionFS behavior stays unchanged unless an experimental flag is set.
The exact-address allocator matches canonical endpoint names, direction, type,
capacity and availability. A canonical name is not proof of controller support
or sufficient FIFO resources. Physical platform qualification is still required.

The descriptor wire order is preserved. The seven-byte USB endpoint descriptor
is copied into a zero-initialized structure rather than reading a nine-byte
structure from a seven-byte buffer. The harness tests that boundary with
AddressSanitizer. Neither harness runs kernel code in a kernel or opens a device.

## Offline checks

The default project tests compile the included standalone C harnesses when a C
compiler is available. They require no network or external source cache. See the
project [reproducibility guide](../../REPRODUCIBILITY.md). Running the test bodies
does not establish that the entire patched kernel compiles or works on hardware.

## Optional source verification

Full upstream files are not bundled. The following command only prints the
fixed download plan and performs no writes or network requests:

```sh
python3 patches/linux-functionfs/fetch_upstream.py
```

Fetch the pinned public source files only with explicit authorization:

```sh
python3 patches/linux-functionfs/fetch_upstream.py --execute-fetch
python3 patches/linux-functionfs/fetch_upstream.py --verify-cache
```

The tool checks each file's length and SHA256 before storing it under
`.cache/upstream/`. It will not overwrite a mismatching file. Linux files use a
commit-pinned URL. The optional libusb header is tag-pinned and additionally
hash-pinned. Downloads do not apply patches, build or install a kernel, load a
module, mount FunctionFS, bind a UDC, or access USB. Tests may use the verified
cache for additional source checks; it is excluded from publication.

Use either the combined patch or the CDC-plus-stacked pair. Preserve the license
headers in upstream files. The Linux-derived patches and harnesses are
GPL-2.0-only in this distribution; applicable UAPI syscall exceptions remain in
effect. The fetch tool is original Apache-2.0 code. See
[third-party notices](../../THIRD_PARTY_NOTICES.md).
