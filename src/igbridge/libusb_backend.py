# SPDX-License-Identifier: Apache-2.0
"""Explicit libusb-1.0 transport, loaded/opened only by open().

No reset, set-configuration, set-alt, detach or clear-halt API is exposed.
Synchronous calls have finite deadlines and never retry. Offline import is safe.
ABI: libusb v1.0.29 public header; Linux/macOS only.
"""
import ctypes as C
from dataclasses import dataclass
import sys
import threading
from .errors import BridgeError, ConfigurationError, ProtocolError
from .usb import Setup

U8, U16, I, P = C.c_uint8, C.c_uint16, C.c_int, C.c_void_p


class DeviceDescriptor(C.Structure):
    _fields_ = [(n, t) for n, t in [
        ('bLength', U8), ('bDescriptorType', U8), ('bcdUSB', U16),
        ('bDeviceClass', U8), ('bDeviceSubClass', U8), ('bDeviceProtocol', U8),
        ('bMaxPacketSize0', U8), ('idVendor', U16), ('idProduct', U16),
        ('bcdDevice', U16), ('iManufacturer', U8), ('iProduct', U8),
        ('iSerialNumber', U8), ('bNumConfigurations', U8)]]


class EndpointDescriptor(C.Structure):
    _fields_ = [('bLength', U8), ('bDescriptorType', U8), ('bEndpointAddress', U8),
                ('bmAttributes', U8), ('wMaxPacketSize', U16), ('bInterval', U8),
                ('bRefresh', U8), ('bSynchAddress', U8), ('extra', P), ('extra_length', I)]


class InterfaceDescriptor(C.Structure):
    _fields_ = [(n, U8) for n in ('bLength', 'bDescriptorType', 'bInterfaceNumber',
        'bAlternateSetting', 'bNumEndpoints', 'bInterfaceClass',
        'bInterfaceSubClass', 'bInterfaceProtocol', 'iInterface')] + [
        ('endpoint', C.POINTER(EndpointDescriptor)), ('extra', P), ('extra_length', I)]


class Interface(C.Structure):
    _fields_ = [('altsetting', C.POINTER(InterfaceDescriptor)), ('num_altsetting', I)]


class ConfigDescriptor(C.Structure):
    _fields_ = [('bLength', U8), ('bDescriptorType', U8), ('wTotalLength', U16),
                ('bNumInterfaces', U8), ('bConfigurationValue', U8),
                ('iConfiguration', U8), ('bmAttributes', U8), ('MaxPower', U8),
                ('interface', C.POINTER(Interface)), ('extra', P), ('extra_length', I)]


class UsbError(BridgeError):
    def __init__(self, operation, code, partial=b''):
        self.operation, self.code, self.partial = operation, code, partial
        super().__init__(f'{operation}: libusb status {code}; partial bytes={len(partial)}')


@dataclass(frozen=True)
class UsbTarget:
    vid: int
    pid: int
    interface: int
    endpoints: tuple  # ((address, transfer_type), ...), exact selected interface
    configuration: int = 1
    alternate: int = 0
    bus: int | None = None
    address: int | None = None
    interface_class: tuple | None = None  # class, subclass, protocol if measured
    endpoint_packets: tuple | None = None  # ((address, maxpacket), ...) if measured


def _bind(lib):
    pp = C.POINTER(P)
    signatures = {
        'init': (I, [pp]), 'exit': (None, [P]),
        'get_device_list': (C.c_ssize_t, [P, C.POINTER(pp)]),
        'free_device_list': (None, [pp, I]),
        'get_device_descriptor': (I, [P, C.POINTER(DeviceDescriptor)]),
        'get_bus_number': (U8, [P]), 'get_device_address': (U8, [P]),
        'get_active_config_descriptor': (I, [P, C.POINTER(C.POINTER(ConfigDescriptor))]),
        'free_config_descriptor': (None, [C.POINTER(ConfigDescriptor)]),
        'open': (I, [P, pp]), 'close': (None, [P]),
        'get_configuration': (I, [P, C.POINTER(I)]),
        'kernel_driver_active': (I, [P, I]),
        'claim_interface': (I, [P, I]), 'release_interface': (I, [P, I]),
        'control_transfer': (I, [P, U8, U8, U16, U16, P, U16, C.c_uint]),
        'interrupt_transfer': (I, [P, U8, P, I, C.POINTER(I), C.c_uint]),
        'bulk_transfer': (I, [P, U8, P, I, C.POINTER(I), C.c_uint]),
    }
    for name, (result, args) in signatures.items():
        f = getattr(lib, 'libusb_' + name)
        f.restype, f.argtypes = result, args
    return lib


class LibUsbBackend:
    def __init__(self, target, library_path=None):
        if not 0 <= target.interface <= 255 or not target.endpoints:
            raise ConfigurationError('explicit interface and endpoint contract required')
        self.target, self.library_path = target, library_path
        self.lib, self.ctx, self.handle = None, P(), P()
        self.claimed = False
        self.control_lock = threading.Lock()
        self.active_interrupts = set()

    @staticmethod
    def _check(operation, result):
        if result < 0:
            raise UsbError(operation, result)
        return result

    def open(self):
        if self.lib is not None:
            raise ConfigurationError('already open/initialized')
        if sys.platform not in ('linux', 'darwin'):
            raise ConfigurationError('only Linux/macOS libusb ABI supported')
        # Even ctypes.util may load platform libraries while it imports.
        # Keep discovery behind the explicit hardware-open boundary.
        from ctypes.util import find_library
        path = self.library_path or find_library('usb-1.0')
        if not path:
            raise ConfigurationError('libusb-1.0 unavailable; no automatic installation')
        self.lib = _bind(C.CDLL(path))
        devices = C.POINTER(P)()
        try:
            self._check('init', self.lib.libusb_init(C.byref(self.ctx)))
            count = self._check('list', self.lib.libusb_get_device_list(self.ctx, C.byref(devices)))
            matches = []
            for j in range(count):
                d = DeviceDescriptor()
                if self.lib.libusb_get_device_descriptor(devices[j], C.byref(d)):
                    continue
                t = self.target
                if (d.idVendor, d.idProduct) != (t.vid, t.pid):
                    continue
                if t.bus is not None and self.lib.libusb_get_bus_number(devices[j]) != t.bus:
                    continue
                if t.address is not None and self.lib.libusb_get_device_address(devices[j]) != t.address:
                    continue
                matches.append(devices[j])
            if len(matches) != 1:
                raise ConfigurationError(f'target must uniquely match; count={len(matches)}')
            dev = matches[0]
            self._validate_descriptor(dev)
            self._check('open', self.lib.libusb_open(dev, C.byref(self.handle)))
            config = I()
            self._check('get_configuration', self.lib.libusb_get_configuration(self.handle, C.byref(config)))
            if config.value != self.target.configuration:
                raise ConfigurationError('active configuration mismatch; will not change it')
            active = self.lib.libusb_kernel_driver_active(self.handle, self.target.interface)
            if active not in (0, -12):  # NOT_SUPPORTED on some platforms; claim decides
                raise ConfigurationError(f'kernel driver attached or query failed: {active}')
            self._check('claim', self.lib.libusb_claim_interface(self.handle, self.target.interface))
            self.claimed = True
            alt = self.control(Setup(0x81, 0x0a, 0, self.target.interface, 1), timeout_ms=1000)
            if alt != bytes([self.target.alternate]):
                raise ConfigurationError('active alternate mismatch; will not change it')
            return self
        except BaseException:
            if devices:
                self.lib.libusb_free_device_list(devices, 1)
                devices = C.POINTER(P)()
            self.close()
            raise
        finally:
            if devices and self.lib:
                self.lib.libusb_free_device_list(devices, 1)

    def _validate_descriptor(self, dev):
        ptr = C.POINTER(ConfigDescriptor)()
        self._check('active_descriptor', self.lib.libusb_get_active_config_descriptor(dev, C.byref(ptr)))
        try:
            cfg = ptr.contents
            if cfg.bConfigurationValue != self.target.configuration:
                raise ConfigurationError('cached active configuration mismatch')
            matches = []
            for j in range(cfg.bNumInterfaces):
                iface = cfg.interface[j]
                for k in range(iface.num_altsetting):
                    d = iface.altsetting[k]
                    if (d.bInterfaceNumber, d.bAlternateSetting) == (self.target.interface, self.target.alternate):
                        if self.target.interface_class is not None and tuple(self.target.interface_class) != (
                                d.bInterfaceClass, d.bInterfaceSubClass, d.bInterfaceProtocol):
                            raise ConfigurationError('selected interface class/subclass/protocol mismatch')
                        if self.target.endpoint_packets is not None:
                            actual_packets = tuple((d.endpoint[n].bEndpointAddress,
                                                    d.endpoint[n].wMaxPacketSize)
                                                   for n in range(d.bNumEndpoints))
                            if dict(actual_packets) != dict(self.target.endpoint_packets):
                                raise ConfigurationError('endpoint maximum packet size mismatch')
                        matches.append(tuple((d.endpoint[n].bEndpointAddress,
                                              d.endpoint[n].bmAttributes & 3)
                                             for n in range(d.bNumEndpoints)))
            if (len(matches) != 1 or len(matches[0]) != len(self.target.endpoints)
                    or set(matches[0]) != set(self.target.endpoints)):
                raise ConfigurationError('selected interface endpoint topology mismatch')
        finally:
            self.lib.libusb_free_config_descriptor(ptr)

    def control(self, setup, data=b'', timeout_ms=2000):
        if not isinstance(setup, Setup):
            raise ProtocolError('validated USB Setup object required')
        if not self.claimed or type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000:
            raise ConfigurationError('claimed interface and finite timeout required')
        if setup.index != self.target.interface or setup.request_type not in (0x21, 0xa1, 0x81):
            raise ProtocolError('control request must target the claimed interface')
        allowed = ((setup.request_type, setup.request, setup.value) in
                   ((0x21, 0, 0), (0xa1, 1, 0), (0x81, 0x0a, 0)))
        allowed |= (setup.request_type == 0x21 and setup.request == 0x22
                    and setup.value in (0, 1) and setup.length == 0)
        if not allowed:
            raise ProtocolError('transport exposes only CDC QMI, DTR and GET_INTERFACE')
        if setup.request in (0, 1) and not 1 <= setup.length <= 4096:
            raise ProtocolError('encapsulated control length outside bounds')
        if setup.request == 0x0a and setup.length != 1:
            raise ProtocolError('GET_INTERFACE requires exactly one byte')
        if setup.length > 4096 or (setup.incoming and data) or (not setup.incoming and len(data) != setup.length):
            raise ProtocolError('control buffer length mismatch')
        buf = C.create_string_buffer(max(setup.length, 1))
        if data:
            C.memmove(buf, data, len(data))
        with self.control_lock:
            n = self._check('control', self.lib.libusb_control_transfer(self.handle,
                setup.request_type, setup.request, setup.value, setup.index, buf,
                setup.length, timeout_ms))
        if n > setup.length:
            raise ProtocolError('libusb returned excessive length')
        if not setup.incoming and n != setup.length:
            raise ProtocolError('short control OUT; no retry')
        return bytes(buf.raw[:n]) if setup.incoming else n

    def transfer(self, endpoint, length=4096, data=None, timeout_ms=250, interrupt=False):
        transfer_type = 3 if interrupt else 2
        if (endpoint, transfer_type) not in self.target.endpoints or not self.claimed:
            raise ConfigurationError('endpoint not part of claimed target interface')
        if not 1 <= timeout_ms <= 10000 or not 1 <= length <= 65536:
            raise ConfigurationError('finite deadline and bounded transfer required')
        incoming = bool(endpoint & 0x80)
        if incoming and data is not None or not incoming and (data is None or len(data) != length):
            raise ProtocolError('endpoint direction/buffer mismatch')
        buf = C.create_string_buffer(length)
        if data is not None:
            C.memmove(buf, data, length)
        n = I()
        fn = self.lib.libusb_interrupt_transfer if interrupt else self.lib.libusb_bulk_transfer
        code = fn(self.handle, endpoint, buf, length, C.byref(n), timeout_ms)
        if not 0 <= n.value <= length:
            raise ProtocolError('transfer count outside buffer')
        result = bytes(buf.raw[:n.value]) if incoming else b''
        if code < 0:
            raise UsbError('interrupt' if interrupt else 'bulk', code, result)
        if not incoming and n.value != length:
            raise ProtocolError('short OUT; no retry')
        return result if incoming else n.value

    def close(self):
        # Caller must first stop/join all transfer threads; do not close under I/O.
        errors = []
        if self.active_interrupts:
            raise ConfigurationError('cancel and drain asynchronous interrupts before close')
        if self.lib:
            if self.claimed:
                code = self.lib.libusb_release_interface(self.handle, self.target.interface)
                if code:
                    errors.append({'operation': 'release', 'code': code})
                self.claimed = False
            if self.handle:
                self.lib.libusb_close(self.handle)
                self.handle = P()
            if self.ctx:
                self.lib.libusb_exit(self.ctx)
                self.ctx = P()
        self.lib = None
        return errors

    def __enter__(self):
        return self.open()

    def __exit__(self, *args):
        self.close()
