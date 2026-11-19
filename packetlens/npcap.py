"""Minimal, ownership-safe ctypes binding to an independently installed Npcap."""

from __future__ import annotations

import ctypes
import os
import socket
import threading
from dataclasses import dataclass
from pathlib import Path


PCAP_ERRBUF_SIZE = 256
PCAP_ERROR = -1
PCAP_ERROR_BREAK = -2
PCAP_ERROR_PERM_DENIED = -8
PCAP_IF_LOOPBACK = 0x1
PCAP_IF_UP = 0x2
PCAP_IF_RUNNING = 0x4
PCAP_IF_CONNECTION_STATUS = 0x30
PCAP_IF_CONNECTION_STATUS_DISCONNECTED = 0x20
LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


class NpcapError(RuntimeError):
    pass


class SockAddr(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort), ("data", ctypes.c_ubyte * 14)]


class SockAddrIn(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort), ("port", ctypes.c_ushort),
                ("address", ctypes.c_ubyte * 4), ("zero", ctypes.c_ubyte * 8)]


class SockAddrIn6(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort), ("port", ctypes.c_ushort),
                ("flowinfo", ctypes.c_uint32), ("address", ctypes.c_ubyte * 16),
                ("scope_id", ctypes.c_uint32)]


class PcapAddr(ctypes.Structure):
    pass


PcapAddrPointer = ctypes.POINTER(PcapAddr)
PcapAddr._fields_ = [("next", PcapAddrPointer), ("addr", ctypes.POINTER(SockAddr)),
                     ("netmask", ctypes.POINTER(SockAddr)), ("broadaddr", ctypes.POINTER(SockAddr)),
                     ("dstaddr", ctypes.POINTER(SockAddr))]


class PcapIf(ctypes.Structure):
    pass


PcapIfPointer = ctypes.POINTER(PcapIf)
PcapIf._fields_ = [("next", PcapIfPointer), ("name", ctypes.c_char_p),
                   ("description", ctypes.c_char_p), ("addresses", PcapAddrPointer),
                   ("flags", ctypes.c_uint32)]


class PcapTimeval(ctypes.Structure):
    # Npcap's timeval uses 32-bit C longs on Windows, including 64-bit Windows.
    _fields_ = [("tv_sec", ctypes.c_int32), ("tv_usec", ctypes.c_int32)]


class PcapPacketHeader(ctypes.Structure):
    _fields_ = [("ts", PcapTimeval), ("caplen", ctypes.c_uint32), ("length", ctypes.c_uint32)]


class BpfInstruction(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint32),
                ("bf_insns", ctypes.POINTER(BpfInstruction))]


PcapHandler = ctypes.WINFUNCTYPE(None, ctypes.c_void_p,
                                ctypes.POINTER(PcapPacketHeader),
                                ctypes.POINTER(ctypes.c_ubyte))


@dataclass(frozen=True, slots=True)
class NpcapDevice:
    identifier: str
    description: str
    ipv4: str = ""
    netmask: str = ""
    flags: int = 0


def _decode(value: bytes | None) -> str:
    return value.decode("utf-8", errors="replace") if value else ""


def _sockaddr_text(pointer) -> str:
    if not pointer:
        return ""
    family = pointer.contents.family
    try:
        if family == socket.AF_INET:
            value = ctypes.cast(pointer, ctypes.POINTER(SockAddrIn)).contents
            return socket.inet_ntop(socket.AF_INET, bytes(value.address))
        if family == socket.AF_INET6:
            value = ctypes.cast(pointer, ctypes.POINTER(SockAddrIn6)).contents
            return socket.inet_ntop(socket.AF_INET6, bytes(value.address))
    except (OSError, ValueError):
        return ""
    return ""


class NpcapApi:
    """Own a loaded DLL and expose only the libpcap calls PacketLens needs."""

    def __init__(self, library, dll_directory_handle=None):
        self.library = library
        self._dll_directory_handle = dll_directory_handle
        self._declare_signatures()

    @classmethod
    def load(cls):
        if os.name != "nt":
            raise NpcapError("Native Npcap capture is available only on Windows.")
        windows = Path(os.environ.get("WINDIR", r"C:\Windows"))
        directory = windows / "System32" / "Npcap"
        dll = directory / "wpcap.dll"
        if not dll.is_file():
            raise NpcapError(
                "Npcap is not installed. Install it separately, then restart PacketLens. "
                "Offline capture analysis remains available.")
        directory_handle = None
        try:
            if hasattr(os, "add_dll_directory"):
                directory_handle = os.add_dll_directory(str(directory))
            library = ctypes.WinDLL(
                str(dll), winmode=LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)
            api = cls(library, directory_handle)
            version = api.version()
            if "npcap" not in version.casefold():
                raise NpcapError("The installed capture library did not identify itself as Npcap.")
            return api
        except NpcapError:
            if directory_handle is not None:
                directory_handle.close()
            raise
        except (OSError, AttributeError) as exc:
            if directory_handle is not None:
                directory_handle.close()
            raise NpcapError(
                "Npcap could not be loaded. Verify that its architecture matches PacketLens "
                "and that the Npcap installation is complete.") from exc

    @staticmethod
    def _signature(function, argtypes, restype):
        function.argtypes = argtypes
        function.restype = restype

    def _declare_signatures(self):
        lib = self.library
        self._signature(lib.pcap_lib_version, [], ctypes.c_char_p)
        self._signature(lib.pcap_findalldevs, [ctypes.POINTER(PcapIfPointer), ctypes.c_char_p], ctypes.c_int)
        self._signature(lib.pcap_freealldevs, [PcapIfPointer], None)
        self._signature(lib.pcap_create, [ctypes.c_char_p, ctypes.c_char_p], ctypes.c_void_p)
        for name in ("pcap_set_snaplen", "pcap_set_promisc", "pcap_set_timeout"):
            self._signature(getattr(lib, name), [ctypes.c_void_p, ctypes.c_int], ctypes.c_int)
        self._signature(lib.pcap_activate, [ctypes.c_void_p], ctypes.c_int)
        self._signature(lib.pcap_dispatch, [ctypes.c_void_p, ctypes.c_int, PcapHandler, ctypes.c_void_p], ctypes.c_int)
        self._signature(lib.pcap_breakloop, [ctypes.c_void_p], None)
        self._signature(lib.pcap_datalink, [ctypes.c_void_p], ctypes.c_int)
        self._signature(lib.pcap_geterr, [ctypes.c_void_p], ctypes.c_char_p)
        self._signature(
            lib.pcap_compile,
            [ctypes.c_void_p, ctypes.POINTER(BpfProgram), ctypes.c_char_p,
             ctypes.c_int, ctypes.c_uint32],
            ctypes.c_int,
        )
        self._signature(
            lib.pcap_setfilter,
            [ctypes.c_void_p, ctypes.POINTER(BpfProgram)],
            ctypes.c_int,
        )
        self._signature(lib.pcap_freecode, [ctypes.POINTER(BpfProgram)], None)
        self._signature(
            lib.pcap_sendpacket,
            [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int],
            ctypes.c_int,
        )
        self._signature(lib.pcap_close, [ctypes.c_void_p], None)

    def version(self) -> str:
        return _decode(self.library.pcap_lib_version())

    def error(self, handle) -> str:
        return _decode(self.library.pcap_geterr(handle)) or "Npcap reported an unspecified error."

    def enumerate_devices(self) -> list[NpcapDevice]:
        head = PcapIfPointer()
        error_buffer = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        result = self.library.pcap_findalldevs(ctypes.byref(head), error_buffer)
        if result != 0:
            raise NpcapError(_decode(error_buffer.value) or "Npcap could not enumerate capture adapters.")
        devices: list[NpcapDevice] = []
        try:
            current = head
            seen_devices: set[int] = set()
            while current:
                current_address = ctypes.addressof(current.contents)
                if current_address in seen_devices or len(seen_devices) >= 4096:
                    raise NpcapError("Npcap returned an invalid capture-adapter list.")
                seen_devices.add(current_address)
                item = current.contents
                ipv4 = netmask = ""
                address = item.addresses
                seen_addresses: set[int] = set()
                while address:
                    address_value = ctypes.addressof(address.contents)
                    if address_value in seen_addresses or len(seen_addresses) >= 256:
                        raise NpcapError("Npcap returned an invalid adapter-address list.")
                    seen_addresses.add(address_value)
                    entry = address.contents
                    candidate = _sockaddr_text(entry.addr)
                    if candidate and entry.addr.contents.family == socket.AF_INET:
                        ipv4 = candidate
                        netmask = _sockaddr_text(entry.netmask)
                        break
                    address = entry.next
                identifier = _decode(item.name)
                if identifier:
                    devices.append(NpcapDevice(identifier, _decode(item.description) or identifier,
                                               ipv4, netmask, int(item.flags)))
                current = item.next
        finally:
            if head:
                self.library.pcap_freealldevs(head)
        return devices

    def open_capture(self, identifier: str, *, snaplen: int = 65535,
                     promiscuous: bool = True, timeout_ms: int = 200):
        error_buffer = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = self.library.pcap_create(identifier.encode("utf-8"), error_buffer)
        if not handle:
            raise NpcapError(_decode(error_buffer.value) or "Npcap could not create a capture handle.")
        try:
            for function, value in ((self.library.pcap_set_snaplen, snaplen),
                                    (self.library.pcap_set_promisc, int(promiscuous)),
                                    (self.library.pcap_set_timeout, timeout_ms)):
                if function(handle, value) != 0:
                    raise NpcapError(self.error(handle))
            activated = self.library.pcap_activate(handle)
            if activated < 0:
                message = self.error(handle)
                if activated == PCAP_ERROR_PERM_DENIED:
                    raise NpcapError("Access to the selected capture adapter was denied.")
                raise NpcapError(f"The selected capture adapter could not be activated: {message}")
            link_type = self.library.pcap_datalink(handle)
            if link_type < 0:
                raise NpcapError(f"Npcap returned an invalid link-layer type: {link_type}")
            return handle, int(link_type), int(activated)
        except Exception:
            self.library.pcap_close(handle)
            raise

    def dispatch(self, handle, count: int, callback) -> int:
        native_callback = PcapHandler(callback)
        return int(self.library.pcap_dispatch(handle, count, native_callback, None))

    def apply_filter(self, handle, expression: str, netmask: int = 0xFFFFFFFF):
        try:
            encoded = expression.encode("ascii")
        except UnicodeEncodeError as exc:
            raise NpcapError("The capture filter contains unsupported characters.") from exc
        program = BpfProgram()
        if self.library.pcap_compile(
                handle, ctypes.byref(program), encoded, 1, ctypes.c_uint32(netmask)) != 0:
            raise NpcapError(f"Npcap could not compile the discovery filter: {self.error(handle)}")
        try:
            if self.library.pcap_setfilter(handle, ctypes.byref(program)) != 0:
                raise NpcapError(f"Npcap could not apply the discovery filter: {self.error(handle)}")
        finally:
            self.library.pcap_freecode(ctypes.byref(program))

    def send_packet(self, handle, data: bytes):
        if not data or len(data) > 65535:
            raise NpcapError("The ARP request has an invalid frame length.")
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        if self.library.pcap_sendpacket(handle, buffer, len(data)) != 0:
            raise NpcapError(f"Npcap could not transmit an ARP request: {self.error(handle)}")

    def breakloop(self, handle):
        self.library.pcap_breakloop(handle)

    def close(self, handle):
        self.library.pcap_close(handle)


_api_lock = threading.Lock()
_api_instance: NpcapApi | None = None


def get_npcap_api() -> NpcapApi:
    global _api_instance
    with _api_lock:
        if _api_instance is None:
            _api_instance = NpcapApi.load()
        return _api_instance


def reset_npcap_api_cache():
    """Testing hook; production code never unloads a native library in use."""
    global _api_instance
    with _api_lock:
        _api_instance = None
