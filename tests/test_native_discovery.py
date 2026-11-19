import ctypes
import ipaddress
import socket
import struct
import threading
import time
import unittest

from packetlens.discovery import (ARP_ETHERTYPE, ARP_HARDWARE_ETHERNET,
                                  ARP_PROTOCOL_IPV4, ARP_REPLY, ARP_REQUEST,
                                  BROADCAST_MAC, DiscoveryEngine, DiscoveryError,
                                  build_arp_request, decode_arp_reply)
from packetlens.live_capture import LiveCaptureEngine, NetworkInterface
from packetlens.npcap import (PCAP_ERROR_BREAK, PCAP_IF_RUNNING, PCAP_IF_UP,
                              NpcapDevice, NpcapError, PcapPacketHeader,
                              PcapTimeval)
from packetlens.windows_adapter import (AdapterVerificationError,
                                        IF_TYPE_ETHERNET_CSMACD,
                                        VerifiedAdapter, WindowsAdapterRecord,
                                        verify_npcap_adapter)


GUID = "{12345678-1234-1234-1234-1234567890AB}"
IDENTIFIER = rf"\Device\NPF_{GUID}"
LOCAL_MAC = bytes.fromhex("021122334455")
REMOTE_MAC = bytes.fromhex("02AABBCCDDEE")


def interface(subnet="192.168.50.0/30"):
    return NetworkInterface(
        IDENTIFIER, "Ethernet", "Physical Ethernet", "192.168.50.1",
        "255.255.255.252", subnet, False, True, True)


def verified():
    return VerifiedAdapter(
        IDENTIFIER, "192.168.50.1", "255.255.255.252",
        "192.168.50.0/30", LOCAL_MAC, IF_TYPE_ETHERNET_CSMACD, "Ethernet")


def arp_reply(sender_ip="192.168.50.2", sender_mac=REMOTE_MAC):
    return struct.pack(
        "!6s6sHHHBBH6s4s6s4s", LOCAL_MAC, sender_mac, ARP_ETHERTYPE,
        ARP_HARDWARE_ETHERNET, ARP_PROTOCOL_IPV4, 6, 4, ARP_REPLY,
        sender_mac, socket.inet_aton(sender_ip), LOCAL_MAC,
        socket.inet_aton("192.168.50.1"))


class FakeNativeDiscoveryApi:
    def __init__(self, responses=(), *, idle=False, filter_error=False):
        self.responses = list(responses)
        self.idle = idle
        self.filter_error = filter_error
        self.sent = []
        self.filters = []
        self.opened = 0
        self.closed = 0
        self.breaks = 0
        self.open_event = threading.Event()
        self.break_event = threading.Event()

    def open_capture(self, identifier, **options):
        self.opened += 1
        self.open_event.set()
        self.identifier = identifier
        self.options = options
        return 222, 1, 0

    def apply_filter(self, _handle, expression):
        if self.filter_error:
            raise NpcapError("filter unavailable")
        self.filters.append(expression)

    def send_packet(self, _handle, frame):
        self.sent.append(bytes(frame))

    def dispatch(self, _handle, _count, callback):
        if self.responses:
            frame = self.responses.pop(0)
            header = PcapPacketHeader(PcapTimeval(1, 0), len(frame), len(frame))
            buffer = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
            callback(None, ctypes.pointer(header), buffer)
            return 1
        if self.idle:
            self.break_event.wait(0.5)
            return PCAP_ERROR_BREAK if self.break_event.is_set() else 0
        return 0

    def breakloop(self, _handle):
        self.breaks += 1
        self.break_event.set()

    def close(self, _handle):
        self.closed += 1

    def error(self, _handle):
        return "adapter unavailable"


class FakeLiveApi:
    def __init__(self):
        self.open_event = threading.Event()
        self.break_event = threading.Event()
        self.closed = 0

    def open_capture(self, _identifier):
        self.open_event.set()
        return 111, 1, 0

    def dispatch(self, _handle, _count, _callback):
        self.break_event.wait(0.5)
        return PCAP_ERROR_BREAK if self.break_event.is_set() else 0

    def breakloop(self, _handle):
        self.break_event.set()

    def close(self, _handle):
        self.closed += 1


class NativeDiscoveryTests(unittest.TestCase):
    def test_correct_ethernet_arp_request_structure(self):
        frame = build_arp_request(LOCAL_MAC, "192.168.50.1", "192.168.50.2")
        self.assertEqual(len(frame), 42)
        values = struct.unpack("!6s6sHHHBBH6s4s6s4s", frame)
        self.assertEqual(values[0:3], (BROADCAST_MAC, LOCAL_MAC, ARP_ETHERTYPE))
        self.assertEqual(values[3:8], (ARP_HARDWARE_ETHERNET,
                                      ARP_PROTOCOL_IPV4, 6, 4, ARP_REQUEST))
        self.assertEqual(values[8], LOCAL_MAC)
        self.assertEqual(socket.inet_ntoa(values[9]), "192.168.50.1")
        self.assertEqual(values[10], b"\0" * 6)
        self.assertEqual(socket.inet_ntoa(values[11]), "192.168.50.2")

    def test_verified_adapter_to_npcap_mapping(self):
        native = NpcapDevice(
            IDENTIFIER, "Ethernet", "192.168.50.1", "255.255.255.252",
            PCAP_IF_UP | PCAP_IF_RUNNING | 0x10)
        api = type("Api", (), {"enumerate_devices": lambda _self: [native]})()
        records = [WindowsAdapterRecord(
            GUID, "Ethernet", LOCAL_MAC, IF_TYPE_ETHERNET_CSMACD,
            (("192.168.50.1", "255.255.255.252"),))]
        result = verify_npcap_adapter(
            interface(), windows_records=records, api_factory=lambda: api)
        self.assertEqual((result.npcap_identifier, result.mac, result.subnet),
                         (IDENTIFIER, LOCAL_MAC, "192.168.50.0/30"))

    def test_incorrect_or_ambiguous_adapter_mapping_is_rejected(self):
        native = NpcapDevice(
            IDENTIFIER, "Ethernet", "192.168.50.1", "255.255.255.252",
            PCAP_IF_UP | PCAP_IF_RUNNING | 0x10)
        api = type("Api", (), {"enumerate_devices": lambda _self: [native]})()
        record = WindowsAdapterRecord(
            GUID, "Ethernet", LOCAL_MAC, IF_TYPE_ETHERNET_CSMACD,
            (("192.168.50.1", "255.255.255.252"),))
        with self.assertRaisesRegex(AdapterVerificationError, "uniquely"):
            verify_npcap_adapter(
                interface(), windows_records=[record, record], api_factory=lambda: api)
        mismatch = WindowsAdapterRecord(
            GUID, "Ethernet", LOCAL_MAC, IF_TYPE_ETHERNET_CSMACD,
            (("192.168.51.1", "255.255.255.252"),))
        with self.assertRaisesRegex(AdapterVerificationError, "do not match"):
            verify_npcap_adapter(
                interface(), windows_records=[mismatch], api_factory=lambda: api)

    def test_arp_response_decoding_and_malformed_rejection(self):
        network = ipaddress.IPv4Network("192.168.50.0/30")
        expected = {"192.168.50.2"}
        self.assertEqual(
            decode_arp_reply(arp_reply(), verified(), network, expected),
            ("192.168.50.2", "02:AA:BB:CC:DD:EE"))
        self.assertIsNone(decode_arp_reply(b"short", verified(), network, expected))
        malformed = bytearray(arp_reply())
        malformed[20:22] = struct.pack("!H", ARP_REQUEST)
        self.assertIsNone(decode_arp_reply(bytes(malformed), verified(), network, expected))
        self.assertIsNone(decode_arp_reply(
            arp_reply("192.168.50.2"), verified(), network, {"192.168.50.3"}))

    def test_native_discovery_deduplicates_and_reports_progress(self):
        response = arp_reply()
        api = FakeNativeDiscoveryApi([response, response])
        emitted = []
        progress = []
        engine = DiscoveryEngine(
            interface(), "192.168.50.0/30", timeout=0.1, send_interval=0.005,
            resolver=lambda _ip: "device.local", vendor_lookup=lambda _mac: "Vendor",
            adapter_resolver=lambda _interface: verified(), api_factory=lambda: api)
        devices = engine.run(emitted.append, lambda done, total: progress.append((done, total)))
        self.assertEqual(len(devices), 1)
        self.assertEqual(len(emitted), 1)
        self.assertEqual(progress[-1], (1, 1))
        self.assertEqual(api.filters, ["arp and arp[6:2] = 2"])
        self.assertEqual(len(api.sent), 1)
        self.assertEqual((api.opened, api.closed), (1, 1))
        self.assertIsNone(engine._handle)
        self.assertIsNone(engine._api)

    def test_validated_device_update_replaces_existing_record(self):
        updated_mac = bytes.fromhex("021020304050")
        api = FakeNativeDiscoveryApi([arp_reply(), arp_reply(sender_mac=updated_mac)])
        emitted = []
        engine = DiscoveryEngine(
            interface(), "192.168.50.0/30", timeout=0.1,
            resolver=lambda _ip: "", vendor_lookup=lambda mac: mac,
            adapter_resolver=lambda _interface: verified(), api_factory=lambda: api)
        devices = engine.run(emitted.append)
        self.assertEqual(len(devices), 1)
        self.assertEqual(len(emitted), 2)
        self.assertEqual(devices[0].mac, "02:10:20:30:40:50")

    def test_idle_discovery_cancellation_is_prompt_and_cleans_up(self):
        larger = NetworkInterface(
            IDENTIFIER, "Ethernet", "Physical Ethernet", "192.168.50.10",
            "255.255.255.0", "192.168.50.0/24", False, True, True)
        adapter = VerifiedAdapter(
            IDENTIFIER, larger.ipv4, larger.netmask, larger.subnet,
            LOCAL_MAC, IF_TYPE_ETHERNET_CSMACD, "Ethernet")
        api = FakeNativeDiscoveryApi(idle=True)
        engine = DiscoveryEngine(
            larger, larger.subnet, send_interval=0.005,
            adapter_resolver=lambda _interface: adapter, api_factory=lambda: api)
        thread = threading.Thread(target=engine.run)
        thread.start()
        self.assertTrue(api.open_event.wait(1))
        engine.stop()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual((api.breaks, api.closed), (1, 1))
        self.assertTrue(engine.stopped)

    def test_repeated_sessions_and_filter_failure_cleanup(self):
        for _ in range(2):
            api = FakeNativeDiscoveryApi()
            engine = DiscoveryEngine(
                interface(), "192.168.50.0/30", timeout=0.1,
                adapter_resolver=lambda _interface: verified(),
                api_factory=lambda api=api: api)
            self.assertEqual(engine.run(), [])
            self.assertEqual((api.opened, api.closed), (1, 1))
        failed = FakeNativeDiscoveryApi(filter_error=True)
        engine = DiscoveryEngine(
            interface(), "192.168.50.0/30",
            adapter_resolver=lambda _interface: verified(),
            api_factory=lambda: failed)
        with self.assertRaisesRegex(DiscoveryError, "filter unavailable"):
            engine.run()
        self.assertEqual(failed.closed, 1)
        self.assertIsNone(engine._handle)
        self.assertIsNone(engine._api)

    def test_driver_availability_failure_is_actionable(self):
        engine = DiscoveryEngine(
            interface(), "192.168.50.0/30",
            adapter_resolver=lambda _interface: verified(),
            api_factory=lambda: (_ for _ in ()).throw(NpcapError("Npcap driver unavailable")))
        with self.assertRaisesRegex(DiscoveryError, "driver unavailable"):
            engine.run()

    def test_live_capture_and_discovery_use_independent_handles(self):
        live_api = FakeLiveApi()
        live = LiveCaptureEngine(
            IDENTIFIER, api_factory=lambda: live_api,
            availability_check=lambda: True)
        live_thread = threading.Thread(target=live.run)
        live_thread.start()
        self.assertTrue(live_api.open_event.wait(1))

        discovery_api = FakeNativeDiscoveryApi([arp_reply()])
        discovery = DiscoveryEngine(
            interface(), "192.168.50.0/30", timeout=0.1,
            adapter_resolver=lambda _interface: verified(),
            api_factory=lambda: discovery_api)
        self.assertEqual(len(discovery.run()), 1)
        self.assertTrue(live_thread.is_alive())
        self.assertEqual(discovery_api.closed, 1)
        self.assertEqual(live_api.closed, 0)
        live.stop()
        live_thread.join(1)
        self.assertFalse(live_thread.is_alive())
        self.assertEqual(live_api.closed, 1)


if __name__ == "__main__":
    unittest.main()
