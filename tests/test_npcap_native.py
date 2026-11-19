import ctypes
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import dpkt

from packetlens.analyzer import analyze_capture, analyze_frames
from packetlens.capture_backend import CapturedFrame
from packetlens.live_capture import (LiveCaptureEngine, LiveCaptureError,
                                     enumerate_interfaces, npcap_available)
from packetlens.npcap import (PCAP_ERROR_BREAK, PCAP_IF_RUNNING, PCAP_IF_UP,
                              NpcapApi, NpcapDevice, NpcapError,
                              PcapPacketHeader, PcapTimeval)


class FakeFunction:
    def __init__(self, result=None, implementation=None):
        self.result = result
        self.implementation = implementation
        self.argtypes = None
        self.restype = None
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.implementation(*args) if self.implementation else self.result


class FakeLibrary:
    def __init__(self):
        self.pcap_lib_version = FakeFunction(b"Npcap version test")
        self.pcap_findalldevs = FakeFunction(0)
        self.pcap_freealldevs = FakeFunction(None)
        self.pcap_create = FakeFunction(1)
        self.pcap_set_snaplen = FakeFunction(0)
        self.pcap_set_promisc = FakeFunction(0)
        self.pcap_set_timeout = FakeFunction(0)
        self.pcap_activate = FakeFunction(0)
        self.pcap_dispatch = FakeFunction(0)
        self.pcap_breakloop = FakeFunction(None)
        self.pcap_datalink = FakeFunction(1)
        self.pcap_geterr = FakeFunction(b"test error")
        self.pcap_compile = FakeFunction(0)
        self.pcap_setfilter = FakeFunction(0)
        self.pcap_freecode = FakeFunction(None)
        self.pcap_sendpacket = FakeFunction(0)
        self.pcap_close = FakeFunction(None)


class FakeCaptureApi:
    def __init__(self, frames=None, idle=False):
        self.frames = list(frames or [])
        self.idle = idle
        self.break_event = threading.Event()
        self.closed = 0
        self.opened = 0
        self.breaks = 0

    def version(self):
        return "Npcap version test"

    def enumerate_devices(self):
        return [NpcapDevice(r"\Device\NPF_{TEST}", "Ethernet Test",
                            "192.168.10.5", "255.255.255.0",
                            PCAP_IF_UP | PCAP_IF_RUNNING)]

    def open_capture(self, identifier):
        self.opened += 1
        if identifier == "denied":
            raise NpcapError("Access to the selected capture adapter was denied.")
        return 1234, 1, 0

    def dispatch(self, _handle, _count, callback):
        if self.frames:
            frame = self.frames.pop(0)
            header = PcapPacketHeader(PcapTimeval(int(frame.timestamp),
                                      round((frame.timestamp % 1) * 1_000_000)),
                                      frame.captured_length, frame.original_length)
            buffer = (ctypes.c_ubyte * len(frame.data)).from_buffer_copy(frame.data)
            callback(None, ctypes.pointer(header), buffer)
            return 1
        if self.idle:
            self.break_event.wait(1)
            return PCAP_ERROR_BREAK if self.break_event.is_set() else 0
        return PCAP_ERROR_BREAK

    def breakloop(self, _handle):
        self.breaks += 1
        self.break_event.set()

    def close(self, _handle):
        self.closed += 1

    def error(self, _handle):
        return "adapter disconnected"


def ethernet_ipv4_dns():
    query = dpkt.dns.DNS(id=9, qd=[dpkt.dns.DNS.Q(name="native.test")])
    udp = dpkt.udp.UDP(sport=53000, dport=53, data=bytes(query)); udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton("192.168.10.5"),
                     dst=socket.inet_aton("192.168.10.1"), p=17, ttl=64, data=udp)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00\x11\x22\x33\x44\x55",
                 dst=b"\xaa\xbb\xcc\xdd\xee\xff", type=0x0800, data=ip))


def ethernet_ipv6_udp():
    udp = dpkt.udp.UDP(sport=55000, dport=5353, data=b"ipv6-test"); udp.ulen = len(udp)
    ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, "2001:db8::10"),
                      dst=socket.inet_pton(socket.AF_INET6, "ff02::fb"),
                      nxt=17, hlim=255, data=udp)
    ip.plen = len(udp)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00\x11\x22\x33\x44\x66",
                 dst=b"\x33\x33\x00\x00\x00\xfb", type=0x86DD, data=ip))


class NativeNpcapTests(unittest.TestCase):
    def test_native_signatures_and_structure_alignment(self):
        library = FakeLibrary()
        NpcapApi(library)
        self.assertEqual(ctypes.sizeof(PcapTimeval), 8)
        self.assertEqual(ctypes.sizeof(PcapPacketHeader), 16)
        self.assertEqual(library.pcap_dispatch.restype, ctypes.c_int)
        self.assertEqual(library.pcap_close.argtypes, [ctypes.c_void_p])
        self.assertEqual(len(library.pcap_findalldevs.argtypes), 2)
        self.assertEqual(len(library.pcap_compile.argtypes), 5)
        self.assertEqual(len(library.pcap_sendpacket.argtypes), 3)
        api = NpcapApi(library)
        api.apply_filter(1, "arp")
        api.send_packet(1, b"frame")
        self.assertEqual(len(library.pcap_compile.calls), 1)
        self.assertEqual(len(library.pcap_setfilter.calls), 1)
        self.assertEqual(len(library.pcap_freecode.calls), 1)
        self.assertEqual(len(library.pcap_sendpacket.calls), 1)

    def test_missing_and_dll_loading_failure_are_graceful(self):
        engine = LiveCaptureEngine("missing", availability_check=lambda: False)
        with self.assertRaisesRegex(LiveCaptureError, "Npcap"):
            engine.run()
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("ctypes.WinDLL", side_effect=OSError("bad architecture")), \
             patch("os.add_dll_directory"):
            with self.assertRaisesRegex(NpcapError, "architecture"):
                NpcapApi.load()

    def test_adapter_enumeration_and_availability(self):
        api = FakeCaptureApi()
        interfaces = enumerate_interfaces(api_factory=lambda: api)
        self.assertEqual(interfaces[0].identifier, r"\Device\NPF_{TEST}")
        self.assertEqual(interfaces[0].subnet, "192.168.10.0/24")
        self.assertTrue(interfaces[0].is_available)
        self.assertTrue(npcap_available(api_factory=lambda: api))

    def test_capture_copies_timestamp_lengths_and_normalizes_dns(self):
        raw = ethernet_ipv4_dns()
        frame = CapturedFrame(1700000000.125, raw, len(raw), len(raw) + 4, 1)
        api = FakeCaptureApi([frame])
        engine = LiveCaptureEngine("test", api_factory=lambda: api,
                                   availability_check=lambda: True)
        engine.run()
        captured = engine.packets[0]
        self.assertIsNot(captured.data, frame.data)
        self.assertEqual((captured.timestamp, captured.captured_length, captured.original_length),
                         (1700000000.125, len(raw), len(raw) + 4))
        analysis = analyze_frames(engine.packets)
        self.assertEqual(analysis.packets[0].dns_name, "native.test")
        self.assertEqual(analysis.parser_backend, "dpkt-live")
        self.assertEqual(api.closed, 1)

    def test_live_normalization_preserves_ipv6_udp(self):
        raw = ethernet_ipv6_udp()
        frame = CapturedFrame(1700000001.5, raw, len(raw), len(raw), 1)
        api = FakeCaptureApi([frame])
        engine = LiveCaptureEngine("test", api_factory=lambda: api,
                                   availability_check=lambda: True)
        engine.run()
        packet = analyze_frames(engine.packets).packets[0]
        self.assertEqual((packet.source, packet.destination),
                         ("2001:db8::10", "ff02::fb"))
        self.assertEqual((packet.source_port, packet.destination_port), (55000, 5353))
        self.assertEqual(packet.protocol, "UDP")

    def test_idle_cancellation_breaks_and_closes_handle(self):
        api = FakeCaptureApi(idle=True)
        engine = LiveCaptureEngine("test", api_factory=lambda: api,
                                   availability_check=lambda: True)
        thread = threading.Thread(target=engine.run)
        thread.start()
        deadline = time.time() + 1
        while api.opened == 0 and time.time() < deadline:
            time.sleep(0.005)
        engine.stop()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual((api.breaks, api.closed), (1, 1))

    def test_repeated_sessions_have_independent_cleanup(self):
        for _ in range(2):
            api = FakeCaptureApi()
            engine = LiveCaptureEngine("test", api_factory=lambda api=api: api,
                                       availability_check=lambda: True)
            engine.run()
            self.assertEqual((api.opened, api.closed), (1, 1))

    def test_permission_error_is_actionable(self):
        api = FakeCaptureApi()
        engine = LiveCaptureEngine("denied", api_factory=lambda: api,
                                   availability_check=lambda: True)
        with self.assertRaisesRegex(LiveCaptureError, "denied"):
            engine.run()

    def test_save_reopen_preserves_raw_timestamp_and_lengths(self):
        raw = ethernet_ipv4_dns()
        frame = CapturedFrame(1700000000.25, raw, len(raw), len(raw), 1)
        engine = LiveCaptureEngine("test", availability_check=lambda: True)
        engine._packets = [frame]
        with tempfile.TemporaryDirectory() as directory:
            path = engine.save(Path(directory) / "native.pcap")
            analysis = analyze_capture(path)
        packet = analysis.packets[0]
        self.assertEqual(packet.raw_bytes, raw)
        self.assertEqual(packet.timestamp, 1700000000.25)
        self.assertEqual(packet.original_length, len(raw))

    def test_atomic_save_failure_preserves_destination(self):
        raw = ethernet_ipv4_dns()
        engine = LiveCaptureEngine("test", availability_check=lambda: True)
        engine._packets = [CapturedFrame(1.0, raw, len(raw), len(raw), 1)]
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "existing.pcap"
            destination.write_bytes(b"original")
            with patch("packetlens.live_capture._write_capture", side_effect=OSError("disk full")):
                with self.assertRaises(LiveCaptureError):
                    engine.save(destination)
            self.assertEqual(destination.read_bytes(), b"original")
            self.assertFalse(list(Path(directory).glob("*.tmp")))

    def test_unsupported_link_type_is_retained(self):
        analysis = analyze_frames([CapturedFrame(1.0, b"opaque", 6, 6, 999)])
        self.assertEqual(analysis.packets[0].protocol, "Other")
        self.assertEqual(analysis.packets[0].raw_bytes, b"opaque")

    def test_source_contains_no_privilege_elevation(self):
        source = (Path(__file__).parents[1] / "packetlens" / "npcap.py").read_text(encoding="utf-8")
        self.assertNotIn("runas", source.casefold())
        self.assertNotIn("shellexecute", source.casefold())


if __name__ == "__main__":
    unittest.main()
