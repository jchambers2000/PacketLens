"""Strict Npcap-to-Windows IPv4 adapter identity verification."""

from __future__ import annotations

import ctypes
import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from packetlens.npcap import (LOAD_LIBRARY_SEARCH_SYSTEM32,
                              PCAP_IF_CONNECTION_STATUS,
                              PCAP_IF_CONNECTION_STATUS_DISCONNECTED,
                              PCAP_IF_RUNNING, PCAP_IF_UP, NpcapError,
                              get_npcap_api)


ERROR_BUFFER_OVERFLOW = 111
NO_ERROR = 0
MAX_ADAPTER_NAME_LENGTH = 256
MAX_ADAPTER_DESCRIPTION_LENGTH = 128
MAX_ADAPTER_ADDRESS_LENGTH = 8
IF_TYPE_ETHERNET_CSMACD = 6
IF_TYPE_IEEE80211 = 71
ETHERNET_COMPATIBLE_TYPES = {IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211}
NPCAP_GUID = re.compile(r"^\\Device\\NPF_(\{[0-9A-Fa-f-]{36}\})$")


class AdapterVerificationError(RuntimeError):
    pass


class IpAddressString(ctypes.Structure):
    pass


IpAddressStringPointer = ctypes.POINTER(IpAddressString)
IpAddressString._fields_ = [
    ("next", IpAddressStringPointer),
    ("ip_address", ctypes.c_char * 16),
    ("ip_mask", ctypes.c_char * 16),
    ("context", ctypes.c_uint32),
]


class IpAdapterInfo(ctypes.Structure):
    pass


IpAdapterInfoPointer = ctypes.POINTER(IpAdapterInfo)
IpAdapterInfo._fields_ = [
    ("next", IpAdapterInfoPointer),
    ("combo_index", ctypes.c_uint32),
    ("adapter_name", ctypes.c_char * (MAX_ADAPTER_NAME_LENGTH + 4)),
    ("description", ctypes.c_char * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
    ("address_length", ctypes.c_uint32),
    ("address", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
    ("index", ctypes.c_uint32),
    ("if_type", ctypes.c_uint32),
    ("dhcp_enabled", ctypes.c_uint32),
    ("current_ip_address", IpAddressStringPointer),
    ("ip_address_list", IpAddressString),
]


@dataclass(frozen=True, slots=True)
class WindowsAdapterRecord:
    adapter_name: str
    description: str
    mac: bytes
    if_type: int
    ipv4_configs: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class VerifiedAdapter:
    npcap_identifier: str
    ipv4: str
    netmask: str
    subnet: str
    mac: bytes
    if_type: int
    description: str

    @property
    def mac_text(self) -> str:
        return ":".join(f"{octet:02X}" for octet in self.mac)


def _decode_array(value) -> str:
    return bytes(value).split(b"\0", 1)[0].decode("mbcs", errors="replace")


def _ip_configs(first: IpAddressString) -> tuple[tuple[str, str], ...]:
    configs = []
    current = ctypes.pointer(first)
    seen: set[int] = set()
    while current:
        address = ctypes.addressof(current.contents)
        if address in seen or len(seen) >= 256:
            raise AdapterVerificationError("Windows returned an invalid adapter-address list.")
        seen.add(address)
        item = current.contents
        ip = _decode_array(item.ip_address)
        mask = _decode_array(item.ip_mask)
        if ip and ip != "0.0.0.0" and mask:
            configs.append((ip, mask))
        current = item.next
    return tuple(configs)


def enumerate_windows_adapters() -> list[WindowsAdapterRecord]:
    if os.name != "nt":
        raise AdapterVerificationError("Native ARP discovery is available only on Windows.")
    dll = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "iphlpapi.dll"
    try:
        library = ctypes.WinDLL(str(dll), winmode=LOAD_LIBRARY_SEARCH_SYSTEM32)
        function = library.GetAdaptersInfo
        function.argtypes = [IpAdapterInfoPointer, ctypes.POINTER(ctypes.c_uint32)]
        function.restype = ctypes.c_uint32
        size = ctypes.c_uint32(0)
        result = function(None, ctypes.byref(size))
        if result not in (NO_ERROR, ERROR_BUFFER_OVERFLOW) or not size.value:
            raise AdapterVerificationError(
                f"Windows could not enumerate IPv4 adapters (error {result}).")
        buffer = ctypes.create_string_buffer(size.value)
        head = ctypes.cast(buffer, IpAdapterInfoPointer)
        result = function(head, ctypes.byref(size))
        if result != NO_ERROR:
            raise AdapterVerificationError(
                f"Windows could not read IPv4 adapter details (error {result}).")
    except AdapterVerificationError:
        raise
    except (OSError, AttributeError) as exc:
        raise AdapterVerificationError("Windows adapter details are unavailable.") from exc

    records = []
    current = head
    seen: set[int] = set()
    while current:
        address = ctypes.addressof(current.contents)
        if address in seen or len(seen) >= 4096:
            raise AdapterVerificationError("Windows returned an invalid adapter list.")
        seen.add(address)
        item = current.contents
        mac_length = int(item.address_length)
        mac = bytes(item.address[:mac_length]) if mac_length <= MAX_ADAPTER_ADDRESS_LENGTH else b""
        records.append(WindowsAdapterRecord(
            _decode_array(item.adapter_name), _decode_array(item.description), mac,
            int(item.if_type), _ip_configs(item.ip_address_list)))
        current = item.next
    return records


def _valid_source_mac(mac: bytes) -> bool:
    return (len(mac) == 6 and mac != b"\0" * 6 and mac != b"\xff" * 6
            and not (mac[0] & 1))


def verify_npcap_adapter(interface, *, windows_records: Iterable[WindowsAdapterRecord] | None = None,
                         api_factory=get_npcap_api) -> VerifiedAdapter:
    """Fail closed unless Npcap and IP Helper identify the same usable adapter."""
    match = NPCAP_GUID.fullmatch(interface.identifier)
    if not match:
        raise AdapterVerificationError("The selected capture adapter has no verifiable Windows GUID.")
    if interface.is_virtual:
        raise AdapterVerificationError("VPN and virtual interfaces are excluded from network discovery.")
    if not interface.is_available:
        raise AdapterVerificationError("The selected network adapter is unavailable.")

    try:
        native = [item for item in api_factory().enumerate_devices()
                  if item.identifier.casefold() == interface.identifier.casefold()]
    except NpcapError as exc:
        raise AdapterVerificationError(str(exc)) from exc
    if len(native) != 1:
        raise AdapterVerificationError("The selected adapter could not be mapped uniquely in Npcap.")
    native_item = native[0]
    if native_item.flags:
        connected = (native_item.flags & PCAP_IF_CONNECTION_STATUS
                     != PCAP_IF_CONNECTION_STATUS_DISCONNECTED)
        if not (native_item.flags & PCAP_IF_UP and native_item.flags & PCAP_IF_RUNNING and connected):
            raise AdapterVerificationError("The selected network adapter is not operational.")
    if native_item.ipv4 != interface.ipv4 or native_item.netmask != interface.netmask:
        raise AdapterVerificationError("Npcap adapter addresses changed; refresh adapters and try again.")

    guid = match.group(1).casefold()
    records = list(windows_records) if windows_records is not None else enumerate_windows_adapters()
    candidates = [item for item in records if item.adapter_name.casefold() == guid]
    if len(candidates) != 1:
        raise AdapterVerificationError("The selected adapter could not be mapped uniquely to Windows.")
    record = candidates[0]
    if record.if_type not in ETHERNET_COMPATIBLE_TYPES:
        raise AdapterVerificationError("The selected adapter does not support Ethernet ARP discovery.")
    if not _valid_source_mac(record.mac):
        raise AdapterVerificationError("Windows did not provide a valid physical adapter address.")
    matching_configs = [config for config in record.ipv4_configs
                        if config == (interface.ipv4, interface.netmask)]
    if len(matching_configs) != 1:
        raise AdapterVerificationError("Windows and Npcap adapter addresses do not match exactly.")
    try:
        subnet = str(ipaddress.IPv4Network(
            (interface.ipv4, interface.netmask), strict=False))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise AdapterVerificationError("The selected adapter has invalid IPv4 configuration.") from exc
    if subnet != interface.subnet:
        raise AdapterVerificationError("The selected adapter subnet changed; refresh adapters and try again.")
    return VerifiedAdapter(
        interface.identifier, interface.ipv4, interface.netmask, subnet,
        record.mac, record.if_type, record.description)
