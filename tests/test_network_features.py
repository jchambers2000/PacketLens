import threading
import time
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from packetlens.analyzer import analyze_capture
from tests.packet_factory import Ether, IP, TCP
from packetlens.discovery import (DiscoveryEngine, DiscoveryError, lookup_mac_vendor,
                                  validate_scan_target)
from packetlens.live_capture import (LiveCaptureEngine, LiveCaptureError,
                                     NetworkInterface, enumerate_interfaces)


class FakeConfig:
    def __init__(self):
        physical = SimpleNamespace(
            network_name="if-1", name="Ethernet", description="Physical adapter",
            ip="192.168.50.10")
        vpn = SimpleNamespace(
            network_name="if-2", name="VPN", description="Test VPN tunnel",
            ip="10.8.0.2")
        self.ifaces = SimpleNamespace(values=lambda: [physical, vpn])
        self.route = SimpleNamespace(routes=[
            (3232248320, 4294967040, "0.0.0.0", "if-1", "192.168.50.10", 10),
            (168296448, 4294967040, "0.0.0.0", "if-2", "10.8.0.2", 10),
            (3758096384, 4026531840, "0.0.0.0", "if-1", "192.168.50.10", 20),
        ])


class NetworkFeatureTests(unittest.TestCase):
    def setUp(self):
        self.interface = NetworkInterface(
            "if-1", "Ethernet", "Physical adapter", "192.168.50.10",
            "255.255.255.0", "192.168.50.0/24", False)

    def test_interface_enumeration_includes_subnet_and_virtual_flag(self):
        interfaces = enumerate_interfaces(FakeConfig())
        self.assertEqual(interfaces[0].subnet, "192.168.50.0/24")
        self.assertFalse(interfaces[0].is_virtual)
        self.assertTrue(interfaces[1].is_virtual)

    def test_multicast_route_cannot_replace_real_adapter_subnet(self):
        interface = SimpleNamespace(
            network_name="ethernet", name="Ethernet", description="Physical adapter",
            ip="192.168.50.66")
        config = SimpleNamespace(
            ifaces=SimpleNamespace(values=lambda: [interface]),
            route=SimpleNamespace(routes=[
                (3232248320, 4294967040, "0.0.0.0", "ethernet", "192.168.50.66", 10),
                (3758096384, 4026531840, "0.0.0.0", "ethernet", "192.168.50.66", 20),
            ]))
        result = enumerate_interfaces(config)[0]
        self.assertEqual(result.ipv4, "192.168.50.66")
        self.assertEqual(result.netmask, "255.255.255.0")
        self.assertEqual(result.subnet, "192.168.50.0/24")

    def test_multicast_discovery_target_is_rejected(self):
        multicast = NetworkInterface(
            "if-4", "Ethernet", "Physical", "224.0.0.5", "240.0.0.0", "224.0.0.0/4")
        with self.assertRaisesRegex(DiscoveryError, "private"):
            validate_scan_target("224.0.0.0/4", multicast)

    def test_public_and_unavailable_discovery_targets_are_rejected(self):
        public = NetworkInterface(
            "if-public", "Ethernet", "Physical", "8.8.8.8",
            "255.255.255.0", "8.8.8.0/24")
        with self.assertRaisesRegex(DiscoveryError, "private"):
            validate_scan_target(public.subnet, public)
        unavailable = NetworkInterface(
            "if-down", "Ethernet", "Physical", "192.168.70.10",
            "255.255.255.0", "192.168.70.0/24", False, False, False)
        with self.assertRaisesRegex(DiscoveryError, "unavailable"):
            validate_scan_target(unavailable.subnet, unavailable)

    def test_capture_start_stop_is_bounded_and_stoppable(self):
        packet = Ether() / IP(src="192.168.50.10", dst="192.168.50.1") / TCP(dport=443)
        emitted = threading.Event()

        def fake_sniff(**kwargs):
            if not emitted.is_set():
                kwargs["prn"](packet)
                emitted.set()
            time.sleep(0.01)

        engine = LiveCaptureEngine("if-1", sniff_func=fake_sniff,
                                   availability_check=lambda: True, max_packets=5)
        thread = threading.Thread(target=engine.run)
        thread.start()
        self.assertTrue(emitted.wait(1))
        engine.stop()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(engine.packets), 1)

    def test_capture_limit_stops_session(self):
        packet = IP(src="192.168.50.10", dst="192.168.50.1")

        def fake_sniff(**kwargs):
            kwargs["prn"](packet)

        engine = LiveCaptureEngine("if-1", sniff_func=fake_sniff,
                                   availability_check=lambda: True, max_packets=3)
        engine.run()
        self.assertTrue(engine.stopped)
        self.assertEqual(len(engine.packets), 3)

    def test_saved_capture_can_be_reopened(self):
        packet = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                  IP(src="192.168.50.10", dst="192.168.50.1") / TCP(dport=443))
        engine = LiveCaptureEngine("if-1", availability_check=lambda: True)
        engine._packets.append(packet)
        with tempfile.TemporaryDirectory() as directory:
            path = engine.save(Path(directory) / "saved.pcap")
            analysis = analyze_capture(path)
        self.assertEqual(len(analysis.packets), 1)
        self.assertEqual(analysis.packets[0].source, "192.168.50.10")

    def test_missing_npcap_and_permission_errors_are_clear(self):
        missing = LiveCaptureEngine("if-1", availability_check=lambda: False)
        with self.assertRaisesRegex(LiveCaptureError, "Npcap"):
            missing.run()

        def denied(**_kwargs):
            raise PermissionError("denied")

        engine = LiveCaptureEngine("if-1", sniff_func=denied,
                                   availability_check=lambda: True)
        with self.assertRaisesRegex(LiveCaptureError, "denied"):
            engine.run()

    def test_scan_target_must_match_safe_selected_interface(self):
        target = validate_scan_target("192.168.50.0/24", self.interface)
        self.assertEqual(str(target), "192.168.50.0/24")
        with self.assertRaisesRegex(DiscoveryError, "match"):
            validate_scan_target("192.168.51.0/24", self.interface)
        virtual = NetworkInterface(
            "vpn", "VPN", "VPN", "10.0.0.2", "255.255.255.0", "10.0.0.0/24", True)
        with self.assertRaisesRegex(DiscoveryError, "VPN"):
            validate_scan_target("10.0.0.0/24", virtual)
        large = NetworkInterface(
            "if-3", "Ethernet", "Physical", "10.0.0.2", "255.255.0.0", "10.0.0.0/16")
        with self.assertRaisesRegex(DiscoveryError, "too large"):
            validate_scan_target("10.0.0.0/16", large)

    def test_discovery_cancellation_stops_between_bounded_chunks(self):
        calls = []

        def probe(addresses, _interface, _timeout):
            calls.append(addresses)
            return []

        engine = DiscoveryEngine(self.interface, self.interface.subnet,
                                 chunk_size=8, probe_func=probe, resolver=lambda _ip: "")

        def progress(_completed, _total):
            engine.stop()

        devices = engine.run(on_progress=progress)
        self.assertTrue(engine.stopped)
        self.assertEqual(len(calls), 1)
        self.assertEqual(devices, [])

    def test_optional_vendor_lookup_is_local_and_unknown_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "oui.csv"
            database.write_text("AABBCC,Example Manufacturer\n", encoding="utf-8")
            self.assertEqual(lookup_mac_vendor("AA:BB:CC:12:34:56", database),
                             "Example Manufacturer")
            self.assertEqual(lookup_mac_vendor("00:11:22:33:44:55", database), "")
            self.assertEqual(lookup_mac_vendor("invalid", database), "")


if __name__ == "__main__":
    unittest.main()
