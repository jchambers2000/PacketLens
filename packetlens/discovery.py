"""Explicit, local-only native ARP discovery with bounded work and cancellation."""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time
import csv
import ctypes
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from packetlens.live_capture import NetworkInterface
from packetlens.npcap import (PCAP_ERROR, PCAP_ERROR_BREAK, NpcapError,
                              get_npcap_api)
from packetlens.runtime import resource_path
from packetlens.windows_adapter import (AdapterVerificationError, VerifiedAdapter,
                                        verify_npcap_adapter)


ETHERNET_LINK_TYPE = 1
ARP_ETHERTYPE = 0x0806
ARP_HARDWARE_ETHERNET = 1
ARP_PROTOCOL_IPV4 = 0x0800
ARP_REQUEST = 1
ARP_REPLY = 2
ARP_FRAME_LENGTH = 42
BROADCAST_MAC = b"\xff" * 6
ZERO_MAC = b"\0" * 6


class DiscoveryError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DiscoveredDevice:
    ip: str
    mac: str
    hostname: str = ""
    status: str = "Responded"
    vendor: str = ""
    discovery_method: str = "ARP response"


def lookup_mac_vendor(mac: str, database_path: str | Path | None = None) -> str:
    """Best-effort lookup against an optional local CSV; never uses a network service."""
    path = Path(database_path) if database_path else resource_path("packetlens", "data", "oui.csv")
    if not path.is_file():
        return ""
    normalized = "".join(character for character in mac.upper() if character in "0123456789ABCDEF")
    if len(normalized) < 6:
        return ""
    prefix = normalized[:6]
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.reader(handle):
                if len(row) >= 2 and row[0].replace(":", "").replace("-", "").upper() == prefix:
                    return row[1].strip()
    except (OSError, UnicodeError, csv.Error):
        return ""
    return ""


def validate_scan_target(subnet: str, interface: NetworkInterface,
                         *, max_hosts: int = 1024) -> ipaddress.IPv4Network:
    """Require the exact private subnet detected on the explicitly selected interface."""
    try:
        target = ipaddress.IPv4Network(subnet, strict=True)
    except ValueError as exc:
        raise DiscoveryError("The selected subnet is not a valid IPv4 network.") from exc
    try:
        interface_network = ipaddress.IPv4Network(interface.subnet)
    except (ValueError, TypeError) as exc:
        raise DiscoveryError("The selected interface has no valid local IPv4 subnet.") from exc
    if target != interface_network:
        raise DiscoveryError("The scan target must match the selected interface's local subnet.")
    if (not target.is_private or target.is_loopback or target.is_link_local
            or target.is_multicast or target.is_unspecified):
        raise DiscoveryError("Only private local IPv4 subnets can be scanned.")
    if max(0, target.num_addresses - 2) > max_hosts:
        raise DiscoveryError(f"The subnet is too large; scans are limited to {max_hosts} hosts.")
    if interface.is_virtual:
        raise DiscoveryError("VPN and virtual interfaces are excluded from network discovery.")
    if not interface.is_available or not interface.is_running:
        raise DiscoveryError("The selected network adapter is unavailable.")
    return target


def _valid_unicast_mac(mac: bytes) -> bool:
    return len(mac) == 6 and mac not in (ZERO_MAC, BROADCAST_MAC) and not (mac[0] & 1)


def build_arp_request(source_mac: bytes, source_ip: str, target_ip: str) -> bytes:
    """Construct one Ethernet ARP request using only verified source identity."""
    if not _valid_unicast_mac(source_mac):
        raise DiscoveryError("The selected adapter has no valid Ethernet source address.")
    try:
        source = socket.inet_aton(str(ipaddress.IPv4Address(source_ip)))
        target = socket.inet_aton(str(ipaddress.IPv4Address(target_ip)))
    except (OSError, ipaddress.AddressValueError) as exc:
        raise DiscoveryError("An ARP request contains an invalid IPv4 address.") from exc
    return struct.pack(
        "!6s6sHHHBBH6s4s6s4s", BROADCAST_MAC, source_mac, ARP_ETHERTYPE,
        ARP_HARDWARE_ETHERNET, ARP_PROTOCOL_IPV4, 6, 4, ARP_REQUEST,
        source_mac, source, ZERO_MAC, target)


def decode_arp_reply(frame: bytes, adapter: VerifiedAdapter,
                     network: ipaddress.IPv4Network,
                     expected_targets: set[str]) -> tuple[str, str] | None:
    """Return a validated sender pair, or None for irrelevant/malformed traffic."""
    if len(frame) < ARP_FRAME_LENGTH:
        return None
    try:
        (ethernet_destination, ethernet_source, ethertype, hardware_type,
         protocol_type, hardware_length, protocol_length, operation,
         sender_mac, sender_ip_bytes, target_mac, target_ip_bytes) = struct.unpack(
             "!6s6sHHHBBH6s4s6s4s", frame[:ARP_FRAME_LENGTH])
        sender_ip = str(ipaddress.IPv4Address(sender_ip_bytes))
        target_ip = str(ipaddress.IPv4Address(target_ip_bytes))
    except (struct.error, ipaddress.AddressValueError):
        return None
    if (ethertype != ARP_ETHERTYPE or hardware_type != ARP_HARDWARE_ETHERNET
            or protocol_type != ARP_PROTOCOL_IPV4 or hardware_length != 6
            or protocol_length != 4 or operation != ARP_REPLY):
        return None
    if (not _valid_unicast_mac(sender_mac) or ethernet_source != sender_mac
            or ethernet_destination != adapter.mac or target_mac != adapter.mac):
        return None
    if target_ip != adapter.ipv4 or sender_ip not in expected_targets:
        return None
    sender_address = ipaddress.IPv4Address(sender_ip)
    if (sender_address not in network or sender_address in (network.network_address,
                                                            network.broadcast_address)
            or sender_ip == adapter.ipv4):
        return None
    return sender_ip, ":".join(f"{octet:02X}" for octet in sender_mac)


def _hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return ""


class DiscoveryEngine:
    def __init__(self, interface: NetworkInterface, subnet: str, *, chunk_size: int = 32,
                 timeout: float = 0.8, send_interval: float = 0.01,
                 probe_func: Callable | None = None,
                 resolver: Callable[[str], str] = _hostname,
                 vendor_lookup: Callable[[str], str] = lookup_mac_vendor,
                 adapter_resolver: Callable = verify_npcap_adapter,
                 api_factory: Callable = get_npcap_api):
        self.interface = interface
        self.network = validate_scan_target(subnet, interface)
        self.chunk_size = max(1, min(chunk_size, 64))
        self.timeout = min(max(timeout, 0.1), 2.0)
        self.send_interval = min(max(send_interval, 0.005), 0.1)
        self._test_probe = probe_func
        self._resolver = resolver
        self._vendor_lookup = vendor_lookup
        self._adapter_resolver = adapter_resolver
        self._api_factory = api_factory
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._api = None
        self._handle = None

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def stop(self):
        self._stop.set()
        with self._lock:
            api, handle = self._api, self._handle
        if api is not None and handle:
            try:
                api.breakloop(handle)
            except (NpcapError, OSError):
                pass

    def _device(self, ip: str, mac: str) -> DiscoveredDevice:
        hostname = self._resolver(ip)
        if ip == self.interface.ipv4 and not hostname:
            hostname = socket.gethostname()
        return DiscoveredDevice(
            ip, mac, hostname, "Responded", self._vendor_lookup(mac), "ARP response")

    @staticmethod
    def _store(devices: dict[str, DiscoveredDevice], device: DiscoveredDevice,
               on_device) -> None:
        if devices.get(device.ip) == device:
            return
        devices[device.ip] = device
        if on_device:
            on_device(device)

    def _run_test_probe(self, addresses: list[str], on_device, on_progress):
        devices: dict[str, DiscoveredDevice] = {}
        for offset in range(0, len(addresses), self.chunk_size):
            if self._stop.is_set():
                break
            chunk = addresses[offset:offset + self.chunk_size]
            for ip, mac in self._test_probe(chunk, self.interface.identifier, self.timeout):
                if self._stop.is_set():
                    break
                self._store(devices, self._device(ip, mac), on_device)
            if on_progress:
                on_progress(min(offset + len(chunk), len(addresses)), len(addresses))
        return list(devices.values())

    def run(self, on_device: Callable[[DiscoveredDevice], None] | None = None,
            on_progress: Callable[[int, int], None] | None = None) -> list[DiscoveredDevice]:
        addresses = [str(ip) for ip in self.network.hosts() if str(ip) != self.interface.ipv4]
        if self._test_probe is not None:
            return self._run_test_probe(addresses, on_device, on_progress)

        api = handle = None
        try:
            adapter = self._adapter_resolver(self.interface)
            if adapter.subnet != str(self.network):
                raise DiscoveryError("The verified adapter subnet does not match the authorized subnet.")
            api = self._api_factory()
            handle, link_type, _warning = api.open_capture(
                self.interface.identifier, promiscuous=False, timeout_ms=100)
            if link_type != ETHERNET_LINK_TYPE:
                api.close(handle)
                raise DiscoveryError(
                    "The selected adapter does not expose Ethernet frames for ARP discovery.")
            with self._lock:
                self._api, self._handle = api, handle
            api.apply_filter(handle, "arp and arp[6:2] = 2")
        except (AdapterVerificationError, NpcapError) as exc:
            if api is not None and handle:
                with self._lock:
                    self._handle = None
                api.close(handle)
                with self._lock:
                    self._api = None
            raise DiscoveryError(str(exc)) from exc

        devices: dict[str, DiscoveredDevice] = {}
        callback_error: list[BaseException] = []
        responses: list[bytes] = []

        def received(_user, header_pointer, data_pointer):
            try:
                if self._stop.is_set() or not header_pointer or not data_pointer:
                    return
                captured = int(header_pointer.contents.caplen)
                original = int(header_pointer.contents.length)
                if captured > original or captured > 65535:
                    raise DiscoveryError("Npcap returned invalid ARP frame metadata.")
                responses.append(ctypes.string_at(data_pointer, captured))
            except BaseException as exc:  # never unwind through the native callback
                callback_error.append(exc)
                self._stop.set()

        try:
            for offset in range(0, len(addresses), self.chunk_size):
                if self._stop.is_set():
                    break
                chunk = addresses[offset:offset + self.chunk_size]
                expected = set(chunk)
                for target in chunk:
                    if self._stop.is_set():
                        break
                    api.send_packet(
                        handle, build_arp_request(adapter.mac, adapter.ipv4, target))
                    if self._stop.wait(self.send_interval):
                        break
                deadline = time.monotonic() + self.timeout
                while not self._stop.is_set() and time.monotonic() < deadline:
                    result = api.dispatch(handle, 32, received)
                    if callback_error:
                        raise callback_error[0]
                    while responses:
                        decoded = decode_arp_reply(
                            responses.pop(0), adapter, self.network, expected)
                        if decoded:
                            self._store(devices, self._device(*decoded), on_device)
                    if result == PCAP_ERROR_BREAK:
                        self._stop.set()
                        break
                    if result == PCAP_ERROR:
                        raise DiscoveryError(
                            f"Discovery stopped because the adapter became unavailable: {api.error(handle)}")
                    if result < PCAP_ERROR_BREAK:
                        raise DiscoveryError(
                            f"Npcap returned an invalid discovery result ({result}).")
                if on_progress:
                    on_progress(min(offset + len(chunk), len(addresses)), len(addresses))
        except PermissionError as exc:
            raise DiscoveryError("Access to ARP discovery was denied.") from exc
        except DiscoveryError:
            raise
        except (NpcapError, OSError, RuntimeError) as exc:
            raise DiscoveryError(f"Network discovery could not continue: {exc}") from exc
        finally:
            with self._lock:
                self._handle = None
            try:
                api.close(handle)
            finally:
                with self._lock:
                    self._api = None
        return list(devices.values())
