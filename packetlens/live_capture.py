"""Bounded, stoppable live capture primitives.

This module contains no UI code so lifecycle behavior can be tested without
opening a network device.
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import threading
from dataclasses import dataclass
from pathlib import Path
import tempfile
from typing import Callable

from packetlens.capture_backend import CapturedFrame, CaptureBackendError
from packetlens.capture_files import write_pcap_frames
from packetlens.npcap import (PCAP_ERROR, PCAP_ERROR_BREAK, PCAP_IF_LOOPBACK,
                              PCAP_IF_CONNECTION_STATUS,
                              PCAP_IF_CONNECTION_STATUS_DISCONNECTED,
                              PCAP_IF_RUNNING, PCAP_IF_UP, NpcapError,
                              get_npcap_api)


class LiveCaptureError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class NetworkInterface:
    identifier: str
    name: str
    description: str
    ipv4: str = ""
    netmask: str = ""
    subnet: str = ""
    is_virtual: bool = False
    is_available: bool = True
    is_running: bool = True

    @property
    def label(self) -> str:
        address = f" — {self.ipv4}" if self.ipv4 else ""
        unavailable = " (unavailable)" if not self.is_available else ""
        return f"{self.name}{address}{unavailable}"


def _mask_text(mask: int) -> str:
    return str(ipaddress.IPv4Address(mask))


def _mock_route_interfaces(route_config) -> list[NetworkInterface]:
    """Compatibility for existing mocked route fixtures; not used in production."""
    routes: dict[tuple[str, str], list[ipaddress.IPv4Network]] = {}
    for network, mask, _gateway, iface, output_ip, _metric in route_config.route.routes:
        if not output_ip or mask in (0, 0xFFFFFFFF):
            continue
        try:
            network_obj = ipaddress.IPv4Network((network, _mask_text(mask)))
            address_obj = ipaddress.IPv4Address(output_ip)
            if (address_obj not in network_obj or network_obj.is_multicast
                    or network_obj.is_loopback or network_obj.is_link_local
                    or network_obj.is_unspecified):
                continue
            routes.setdefault((str(iface), str(output_ip)), []).append(network_obj)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            continue

    interfaces = []
    for item in route_config.ifaces.values():
        identifier = str(getattr(item, "network_name", "") or getattr(item, "name", ""))
        name = str(getattr(item, "name", "") or identifier)
        description = str(getattr(item, "description", "") or name)
        ip = str(getattr(item, "ip", "") or "")
        if not identifier:
            continue
        candidates = routes.get((identifier, ip), [])
        selected = max(candidates, key=lambda route: route.prefixlen, default=None)
        mask = str(selected.netmask) if selected else ""
        subnet = str(selected) if selected else ""
        virtual_words = ("vpn", "tunnel", "tap", "virtual", "loopback", "teredo", "6to4")
        virtual = any(word in f"{name} {description}".casefold() for word in virtual_words)
        interfaces.append(NetworkInterface(identifier, name, description, ip, mask, subnet, virtual))
    return interfaces


def enumerate_interfaces(source=None, *, api_factory: Callable = get_npcap_api) -> list[NetworkInterface]:
    """Return stable Npcap identifiers with local IPv4 subnet information."""
    if source is not None and hasattr(source, "route") and hasattr(source, "ifaces"):
        return _mock_route_interfaces(source)
    try:
        devices = api_factory().enumerate_devices()
    except NpcapError as exc:
        raise LiveCaptureError(str(exc)) from exc
    interfaces = []
    for device in devices:
        subnet = ""
        if device.ipv4 and device.netmask:
            try:
                subnet = str(ipaddress.IPv4Network((device.ipv4, device.netmask), strict=False))
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                pass
        words = f"{device.identifier} {device.description}".casefold()
        virtual = bool(device.flags & PCAP_IF_LOOPBACK) or any(
            word in words for word in ("vpn", "tunnel", "tap", "virtual", "loopback", "teredo", "6to4"))
        connected = (device.flags & PCAP_IF_CONNECTION_STATUS
                     != PCAP_IF_CONNECTION_STATUS_DISCONNECTED)
        running = device.flags == 0 or bool(device.flags & PCAP_IF_RUNNING)
        available = (device.flags == 0 or bool(device.flags & PCAP_IF_UP)) and running and connected
        interfaces.append(NetworkInterface(
            device.identifier, device.description, device.description,
            device.ipv4, device.netmask, subnet, virtual, available, running))
    return interfaces


def npcap_available(legacy_config=None, *, api_factory: Callable = get_npcap_api) -> bool:
    """Require a loadable Npcap API that can successfully query the driver."""
    if legacy_config is not None and hasattr(legacy_config, "use_pcap"):
        return os.name != "nt" or bool(legacy_config.use_pcap)
    try:
        api = api_factory()
        return "npcap" in api.version().casefold() and api.enumerate_devices() is not None
    except (NpcapError, OSError, AttributeError):
        return False


def _coerce_frame(packet, link_type: int | None = None) -> CapturedFrame:
    if isinstance(packet, CapturedFrame):
        return packet
    raw = bytes(packet)
    timestamp = float(getattr(packet, "time", 0.0))
    inferred = 101 if raw and raw[0] >> 4 in (4, 6) else 1
    return CapturedFrame(timestamp, raw, len(raw), len(raw),
                         link_type if link_type is not None else inferred)


def _write_capture(path, frames, link_type):
    """Write copied native frames to a classic PCAP file."""
    write_pcap_frames(path, frames, link_type)


class LiveCaptureEngine:
    """Own one native handle on one worker thread; stop only signals/breaks it."""

    def __init__(self, interface: str, *, max_packets: int = 10_000,
                 api_factory: Callable = get_npcap_api,
                 availability_check: Callable[[], bool] = npcap_available,
                 sniff_func: Callable | None = None):
        if max_packets < 1:
            raise ValueError("max_packets must be positive")
        self.interface = interface
        self.max_packets = max_packets
        self._api_factory = api_factory
        self._availability_check = availability_check
        self._test_sniff = sniff_func
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._packets: list = []
        self._api = None
        self._handle = None
        self._link_type: int | None = None

    @property
    def packets(self) -> list[CapturedFrame]:
        with self._lock:
            return [_coerce_frame(packet, self._link_type) for packet in self._packets]

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    @property
    def link_type(self) -> int | None:
        return self._link_type

    def stop(self):
        self._stop.set()
        with self._lock:
            api, handle = self._api, self._handle
        if api is not None and handle:
            try:
                api.breakloop(handle)
            except (NpcapError, OSError):
                pass

    def _append(self, frame: CapturedFrame, on_packet):
        with self._lock:
            if self._stop.is_set() or len(self._packets) >= self.max_packets:
                self._stop.set()
                return
            self._packets.append(frame)
            at_limit = len(self._packets) >= self.max_packets
        if on_packet:
            on_packet(frame)
        if at_limit:
            self.stop()

    def _run_test_source(self, on_packet):
        def received(packet):
            self._append(_coerce_frame(packet), on_packet)
        try:
            while not self._stop.is_set():
                self._test_sniff(iface=self.interface, prn=received, store=False, timeout=0.25)
        except PermissionError as exc:
            raise LiveCaptureError("Access to the selected capture adapter was denied.") from exc
        except (OSError, RuntimeError) as exc:
            raise LiveCaptureError(f"Live capture could not continue: {exc}") from exc

    def run(self, on_packet: Callable[[CapturedFrame], None] | None = None):
        if not self._availability_check():
            raise LiveCaptureError(
                "Npcap is unavailable or its driver could not be queried. Offline analysis remains available.")
        if self._test_sniff is not None:
            self._run_test_source(on_packet)
            return
        try:
            api = self._api_factory()
            handle, link_type, _warning = api.open_capture(self.interface)
        except NpcapError as exc:
            raise LiveCaptureError(str(exc)) from exc
        with self._lock:
            self._api, self._handle, self._link_type = api, handle, link_type
        callback_error: list[BaseException] = []

        def received(_user, header_pointer, data_pointer):
            try:
                if self._stop.is_set() or not header_pointer or not data_pointer:
                    return
                header = header_pointer.contents
                captured = int(header.caplen)
                original = int(header.length)
                if captured > original or captured > 16 * 1024 * 1024:
                    raise LiveCaptureError("Npcap returned invalid packet length metadata.")
                raw = ctypes.string_at(data_pointer, captured)
                timestamp = int(header.ts.tv_sec) + int(header.ts.tv_usec) / 1_000_000
                self._append(CapturedFrame(timestamp, raw, captured, original, link_type), on_packet)
            except BaseException as exc:  # never unwind through the native callback
                callback_error.append(exc)
                self._stop.set()

        try:
            while not self._stop.is_set():
                result = api.dispatch(handle, 64, received)
                if callback_error:
                    raise callback_error[0]
                if result == PCAP_ERROR_BREAK:
                    break
                if result == PCAP_ERROR:
                    raise LiveCaptureError(
                        f"Capture stopped because the adapter became unavailable: {api.error(handle)}")
                if result < PCAP_ERROR_BREAK:
                    raise LiveCaptureError(f"Npcap returned an invalid capture result ({result}).")
        except LiveCaptureError:
            raise
        except (NpcapError, OSError, RuntimeError) as exc:
            raise LiveCaptureError(f"Live capture could not continue: {exc}") from exc
        finally:
            with self._lock:
                self._handle = None
            try:
                api.close(handle)
            finally:
                with self._lock:
                    self._api = None

    def save(self, destination: str | Path) -> Path:
        frames = self.packets
        if not frames:
            raise LiveCaptureError("No captured packets are available to save.")
        link_types = {frame.link_type for frame in frames}
        if len(link_types) != 1:
            raise LiveCaptureError(
                "The capture contains mixed link-layer types and cannot be saved as one PCAP.")
        path = Path(destination)
        temporary_path = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                    prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False) as handle:
                temporary_path = Path(handle.name)
            _write_capture(temporary_path, frames, next(iter(link_types)))
            os.replace(temporary_path, path)
        except (OSError, PermissionError, CaptureBackendError) as exc:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise LiveCaptureError(f"The capture could not be saved: {exc}") from exc
        return path
