# SPDX-License-Identifier: Apache-2.0
"""Explicit configfs transaction with injectable filesystem and bounded rollback.

No mount, UDC discovery, process invocation or hardware access at import. Ordinary
temporary directories exercise the same plan. Kernel writes need an explicit Linux
adapter and an explicit coordinator bind call. Existing gadgets are never adopted.
"""
from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import sys

from .descriptors import GadgetProfile
from .errors import ConfigurationError, PolicyDenied


class DirectoryFS:
    """Injected ordinary-filesystem adapter. Kernel pseudo-filesystems are forbidden."""
    kernel = False

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        if any(self.root == Path(p) or Path(p) in self.root.parents for p in ("/sys", "/proc", "/dev")):
            raise PolicyDenied("sandbox adapter cannot access kernel pseudo-filesystems")

    def _path(self, relative: str, *, final_symlink: bool = False) -> Path:
        parts = PurePosixPath(relative).parts
        if not parts or any(p in ("..", ".", "/") for p in parts):
            raise ConfigurationError("unsafe relative filesystem path")
        current = self.root
        for index, part in enumerate(parts):
            current = current / part
            if current.is_symlink() and not (final_symlink and index == len(parts) - 1):
                raise PolicyDenied("symlink in transaction path")
        return current

    def exists(self, path: str) -> bool:
        return os.path.lexists(self._path(path, final_symlink=True))

    def identity(self, path: str) -> tuple[int, int]:
        st = self._path(path).stat()
        return st.st_dev, st.st_ino

    def mkdir(self, path: str) -> None:
        self._path(path).mkdir()

    def read_text(self, path: str) -> str:
        return self._path(path).read_text(encoding="utf-8")

    def write_text(self, path: str, value: str) -> None:
        # Configfs writes are single syscalls: partial writes fail, never retry.
        data = value.encode("utf-8")
        fd = os.open(self._path(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            if os.write(fd, data) != len(data):
                raise OSError("partial configfs attribute write")
        finally:
            os.close(fd)

    def symlink(self, target: str, path: str) -> None:
        os.symlink(self._path(target), self._path(path))

    def unlink(self, path: str) -> None:
        self._path(path, final_symlink=True).unlink()

    def remove_attribute(self, path: str) -> None:
        self.unlink(path)

    def rmdir(self, path: str) -> None:
        self._path(path).rmdir()  # no recursive delete of foreign/unexpected objects


class KernelConfigFS(DirectoryFS):
    """Explicit adapter only; caller supplies an already-mounted configfs root.

    The constructor does not open the supplied root. It never mounts or discovers
    UDCs. This class is not exercised on hardware by the offline test suite.
    """
    kernel = True

    def __init__(self, root: str | Path, *, allow_kernel_writes: bool = False):
        if allow_kernel_writes is not True or not sys.platform.startswith("linux"):
            raise PolicyDenied("explicit Linux kernel-write authorization required")
        self.root = Path(root).absolute()
        if str(self.root) != "/sys/kernel/config/usb_gadget":
            raise PolicyDenied("only standard, pre-mounted gadget root supported")

    def remove_attribute(self, path: str) -> None:
        # Kernel-created attributes disappear with their owner directory.
        pass


@dataclass(frozen=True)
class BindReadiness:
    functionfs_descriptors_written: bool = False
    functionfs_strings_written: bool = False
    functionfs_ep0_open: bool = False
    endpoint_resource_plan_verified: bool = False
    coordinator_authorized: bool = False
    # Coordinator has checked the exact experimental build/flag contract and
    # observed a successful full descriptor write. Not a stock-kernel override
    # inferred from VIRTUAL_ADDR or from a source patch existing on disk.
    experimental_descriptor_acceptance_verified: bool = False
    exact_address_allocation_verified: bool = False


class ConfigfsTransaction:
    def __init__(self, profile: GadgetProfile, fs: DirectoryFS, gadget_name: str = "ig831t"):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", gadget_name):
            raise ConfigurationError("invalid gadget name")
        self.profile, self.fs, self.name = profile, fs, gadget_name
        self._identity = None
        self._journal = []
        self.staged = False
        self.bound = False
        self.bind_attempted = False
        self.cleanup_errors = []

    @property
    def function_name(self) -> str:
        return "ffs.ig831t"

    def _owned(self) -> None:
        if self._identity is None or self.fs.identity(self.name) != self._identity:
            raise PolicyDenied("transaction does not own this gadget")

    def _directory(self, relative: str) -> None:
        self._owned()
        if not self.fs.exists(relative):
            self.fs.mkdir(relative)
            self._journal.append(("directory", relative, None))

    def _write(self, relative: str, value: str) -> None:
        self._owned()
        existed = self.fs.exists(relative)
        old = self.fs.read_text(relative) if existed else None
        # Journal before attempting the write, including a possible partial write.
        self._journal.append(("attribute", relative, old))
        self.fs.write_text(relative, value)

    def stage(self, *, serial_number: str | None = None, use_captured_serial: bool = False) -> None:
        if self._identity is not None or self.fs.exists(self.name):
            raise PolicyDenied("existing gadget or reused transaction cannot be adopted")
        if serial_number is not None and use_captured_serial:
            raise ConfigurationError("choose one explicit serial source")
        if use_captured_serial:
            serial_number = self.profile.string(3)
        if not isinstance(serial_number, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,126}", serial_number):
            raise ConfigurationError("explicit safe laboratory or captured serial choice required")
        d, c = self.profile.device, self.profile.high_speed
        self.fs.mkdir(self.name)  # exclusive creation; cannot destroy a prior gadget
        self._identity = self.fs.identity(self.name)
        self._journal.append(("directory", self.name, None))
        try:
            for field, value in {"idVendor": int.from_bytes(d[8:10], "little"),
                                 "idProduct": int.from_bytes(d[10:12], "little"),
                                 "bcdUSB": int.from_bytes(d[2:4], "little"),
                                 "bcdDevice": int.from_bytes(d[12:14], "little"),
                                 "bDeviceClass": d[4], "bDeviceSubClass": d[5],
                                 "bDeviceProtocol": d[6], "bMaxPacketSize0": d[7]}.items():
                self._write(f"{self.name}/{field}", f"0x{value:04x}\n")
            self._write(f"{self.name}/max_speed", "high-speed\n")
            for relative in ("strings", "strings/0x409", "configs", "configs/c.1",
                             "functions", f"functions/{self.function_name}"):
                self._directory(f"{self.name}/{relative}")
            for key, value in {"manufacturer": self.profile.string(1), "product": self.profile.string(2),
                               "serialnumber": serial_number}.items():
                if "\0" in value or "\n" in value:
                    raise ConfigurationError("invalid configfs string")
                self._write(f"{self.name}/strings/0x409/{key}", value + "\n")
            self._write(f"{self.name}/configs/c.1/bmAttributes", f"0x{c[7]:02x}\n")
            self._write(f"{self.name}/configs/c.1/MaxPower", f"{c[8] * 2}\n")
            # iConfiguration=0 preserved: no configuration string is invented.
            link = f"{self.name}/configs/c.1/{self.function_name}"
            self._journal.append(("symlink", link, None))
            self.fs.symlink(f"{self.name}/functions/{self.function_name}", link)
            self.staged = True
        except Exception as exc:
            try:
                self.cleanup()
            except Exception as cleanup_exc:
                raise ConfigurationError("staging failed; rollback incomplete (inspect cleanup_errors)") from cleanup_exc
            raise ConfigurationError("configfs staging failed; rolled back") from exc

    def bind(self, udc: str, *, explicit: bool = False, readiness: BindReadiness | None = None) -> None:
        """Single bind attempt. Post-bind enable/actual-address validation is still required."""
        self._owned()
        if not self.staged or self.bind_attempted or explicit is not True or readiness is None:
            raise PolicyDenied("explicit staged coordinator bind required; no retry")
        if not all(v is True for v in (readiness.functionfs_descriptors_written, readiness.functionfs_strings_written,
                    readiness.functionfs_ep0_open, readiness.endpoint_resource_plan_verified,
                    readiness.coordinator_authorized)):
            raise PolicyDenied("FunctionFS/lifecycle prerequisites incomplete")
        if (not self.profile.compatibility_report()["stock_functionfs_supported"] and
                (readiness.experimental_descriptor_acceptance_verified is not True or
                 readiness.exact_address_allocation_verified is not True)):
            raise PolicyDenied("stock FunctionFS rejects exact class-specific descriptors; no silent adaptation")
        if not isinstance(udc, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", udc):
            raise ConfigurationError("invalid explicit UDC name")
        self.bind_attempted = True
        # UDC is a lifecycle action, not an ordinary restorable attribute.
        # Restoring the old blank value after unbind issues a second unbind;
        # Linux configfs unregister_gadget rejects that with ENODEV.
        self._owned()
        self.fs.write_text(f"{self.name}/UDC", udc + "\n")
        self.bound = True

    def unbind(self) -> None:
        """Unbind owned gadget once, retaining its directories for FD/unmount cleanup."""
        if self._identity is None:
            return
        self._owned()
        self.cleanup_errors = []
        if self.bind_attempted:
            # Failure to unbind must not proceed to dismantling potentially live endpoints.
            try:
                path = f"{self.name}/UDC"
                if self.fs.exists(path) and self.fs.read_text(path).strip():
                    self.fs.write_text(path, "\n")
                if not self.fs.kernel and self.fs.exists(path):
                    self.fs.remove_attribute(path)
            except Exception as exc:
                self.cleanup_errors.append(("unbind", type(exc).__name__))
                raise ConfigurationError("unbind failed; gadget retained") from exc
            self.bound = False

    def cleanup(self) -> None:
        if self._identity is None:
            return
        self.unbind()
        while self._journal:
            kind, path, previous = self._journal[-1]
            try:
                self._owned()
                if kind == "attribute":
                    if previous is None:
                        if self.fs.exists(path):
                            self.fs.remove_attribute(path)
                    else:
                        self.fs.write_text(path, previous)
                elif kind == "symlink":
                    if self.fs.exists(path):
                        self.fs.unlink(path)
                else:
                    self.fs.rmdir(path)
                self._journal.pop()
            except Exception as exc:
                self.cleanup_errors.append((kind, path, type(exc).__name__))
                # Keep the remaining journal; do not recurse into unknown objects.
                raise ConfigurationError("cleanup incomplete; owned journal retained") from exc
        self._identity = None
        self.staged = self.bound = False
