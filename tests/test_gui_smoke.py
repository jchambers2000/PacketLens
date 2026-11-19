import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from tests.packet_factory import (DNS, DNSQR, DNSRR, Ether, IP, IPv6, TCP,
                                  UDP, analyze_packets, wrpcap)
from packetlens.app import PacketLensWindow
from packetlens.discovery import DiscoveredDevice
from packetlens.display import apply_display_preset
from packetlens.pages.traffic import TrafficPage
from packetlens.pages.overview import OverviewPage


class GuiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_window_navigation_and_background_import(self):
        window = PacketLensWindow()
        for index in range(5):
            window.navigation.setCurrentRow(index)
            self.assertEqual(window.pages.currentIndex(), index)

        packet = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                  IP(src="192.0.2.1", dst="198.51.100.2") /
                  TCP(sport=50000, dport=443, flags="S"))
        packet.time = 100.0
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gui-smoke.pcap"
            wrpcap(str(path), [packet])
            window.load_capture(str(path))
            deadline = time.monotonic() + 5
            while window._thread is not None and time.monotonic() < deadline:
                self.app.processEvents()
                time.sleep(0.01)
        self.assertIsNotNone(window.analysis)
        self.assertEqual(window.traffic.model.rowCount(), 1)
        self.assertTrue(window.reports.export_button.isEnabled())
        window.close()

    def test_packet_selection_tracks_sorting_and_filtering(self):
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=443, flags="S"),
            IP(src="10.0.0.3", dst="10.0.0.4") / UDP(dport=53),
            IP(src="10.0.0.5", dst="10.0.0.6") / TCP(dport=80, flags="A"),
        ]
        for index, packet in enumerate(packets):
            packet.time = 100 + index
        page = TrafficPage()
        page.set_packets(analyze_packets(packets).packets)
        page.table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        self.app.processEvents()
        page.table.selectRow(0)
        self.app.processEvents()
        self.assertEqual(page.selected_packet_number, 3)

        page.search.setText("10.0.0.1")
        self.app.processEvents()
        self.assertEqual(page.proxy.rowCount(), 1)
        page.table.selectRow(0)
        self.app.processEvents()
        self.assertEqual(page.selected_packet_number, 1)
        self.assertIn("TCP connection request", page.inspector.header.text())

    def test_finding_opens_its_supporting_packet(self):
        packet = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(dport=53) / DNS(
            qd=DNSQR(qname="example.test"))
        packet.time = 1700000000.0
        analysis = analyze_packets([packet])
        window = PacketLensWindow()
        window._apply_analysis(analysis)
        self.assertEqual(window.findings.list.count(), 1)
        item = window.findings.list.item(0)
        self.assertIn("Next step:", item.text())
        window.findings._open_supporting_packet(item)
        self.app.processEvents()
        self.assertEqual(window.navigation.currentRow(), 1)
        self.assertEqual(window.traffic.selected_packet_number, 1)
        window.close()

    def test_overview_displays_bytes_unique_ips_and_exclusive_protocols(self):
        packets = [IP(src="10.0.0.1", dst="8.8.8.8") / UDP(dport=53) / DNS(
            qd=DNSQR(qname="example.test")),
                   IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=443, flags="S")]
        for index, packet in enumerate(packets):
            packet.time = 1700000000 + index
        analysis = analyze_packets(packets, "overview.pcap")
        page = OverviewPage()
        page.set_analysis(analysis)
        self.assertEqual(page.metric_labels[0].text(), "2")
        self.assertEqual(page.metric_labels[2].text(), f"{analysis.total_bytes:,}")
        self.assertEqual(page.metric_labels[3].text(), "3")
        self.assertEqual(sum(bar.value() for bar in page.protocol_bars.values()), 2)
        self.assertEqual(page.protocol_bars["DNS"].value(), 1)

    def test_exact_ipv4_and_ipv6_device_filtering(self):
        packets = [
            IP(src="192.168.1.1", dst="8.8.8.8") / UDP(dport=53),
            IP(src="192.168.1.10", dst="8.8.4.4") / UDP(dport=53),
        ]
        packets.extend((IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(dport=443),
                        IPv6(src="2001:db8::10", dst="2001:db8::2") / TCP(dport=443)))
        for index, packet in enumerate(packets):
            packet.time = 1700000000 + index
        page = TrafficPage()
        page.set_packets(analyze_packets(packets).packets)
        self.assertEqual(page.filter_by_device("192.168.1.1"), 1)
        self.assertEqual(page.proxy.rowCount(), 1)
        self.assertEqual(page.proxy.index(0, 2).data(), "192.168.1.1")
        self.assertEqual(page.filter_by_device("2001:db8::1"), 1)
        self.assertEqual(page.proxy.rowCount(), 1)
        self.assertEqual(page.proxy.index(0, 2).data(), "2001:db8::1")

    def test_device_investigation_navigation_and_no_match_message(self):
        packet = IP(src="192.168.1.20", dst="8.8.8.8") / UDP(dport=53)
        packet.time = 1700000000
        window = PacketLensWindow()
        window._apply_analysis(analyze_packets([packet]))
        device = DiscoveredDevice("192.168.1.20", "00:11:22:33:44:55")
        window._device_discovered(device)
        self.assertEqual(window.overview.discovered_device_count, 1)
        self.assertTrue(window.network.select_device(device.ip))
        window.network._request_investigation()
        self.app.processEvents()
        self.assertEqual(window.navigation.currentRow(), 1)
        self.assertEqual(window.traffic.device_filter_ip, device.ip)
        self.assertEqual(window.traffic.proxy.rowCount(), 1)

        window.investigate_device("192.168.1.99")
        self.assertEqual(window.traffic.proxy.rowCount(), 0)
        self.assertIn("No captured traffic", window.traffic.device_filter_label.text())
        window.close()

    def test_discovery_updates_unknown_metadata_without_duplicates(self):
        window = PacketLensWindow()
        unknown = DiscoveredDevice("192.168.1.30", "AA:BB:CC:00:00:01")
        window._device_discovered(unknown)
        self.assertTrue(window.network.select_device("192.168.1.30"))
        self.app.processEvents()
        self.assertEqual(window.network.device_values["hostname"].text(), "Unknown")
        self.assertEqual(window.network.device_values["vendor"].text(), "Unknown")
        window._device_discovered(DiscoveredDevice(
            "192.168.1.30", "AA:BB:CC:00:00:01", hostname="printer.local"))
        self.assertEqual(window.network.devices.rowCount(), 1)
        self.app.processEvents()
        self.assertEqual(window.network.device_values["hostname"].text(), "printer.local")
        self.assertEqual(window.network.device_values["vendor"].text(), "Unknown")
        self.assertEqual(window.network.device_values["method"].text(), "ARP response")
        self.assertIn("192.168.1.30", window.traffic.known_devices)
        window.close()

    def test_packet_can_open_matching_discovered_device(self):
        packet = IP(src="192.168.1.50", dst="8.8.8.8") / TCP(dport=443)
        packet.time = 1700000000
        window = PacketLensWindow()
        window._apply_analysis(analyze_packets([packet]))
        window._device_discovered(DiscoveredDevice(
            "192.168.1.50", "AA:BB:CC:00:00:02", hostname="workstation.local"))
        window.traffic.table.selectRow(0)
        self.app.processEvents()
        action = window.traffic.inspector.device_actions_layout.itemAt(0).widget()
        self.assertIn("192.168.1.50", action.text())
        action.click()
        self.app.processEvents()
        self.assertEqual(window.navigation.currentRow(), 2)
        self.assertEqual(window.network.device_values["ip"].text(), "192.168.1.50")
        window.close()

    def test_new_capture_clears_stale_device_filter(self):
        packet = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                  IP(src="192.168.1.40", dst="8.8.8.8") / TCP(dport=443))
        packet.time = 1700000000
        window = PacketLensWindow()
        window._apply_analysis(analyze_packets([packet]))
        window.traffic.filter_by_device("192.168.1.40")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "replacement.pcap"
            wrpcap(str(path), [packet])
            window.load_capture(str(path))
            self.assertEqual(window.traffic.device_filter_ip, "")
            deadline = time.monotonic() + 5
            while window._thread is not None and time.monotonic() < deadline:
                self.app.processEvents()
                time.sleep(0.01)
        window.close()

    def test_scaling_uses_font_metrics_and_long_address_tooltip(self):
        packet = IPv6(src="2001:db8:1111:2222:3333:4444:5555:6666", dst="2001:db8::2") / UDP(dport=53)
        packet.time = 1700000000
        page = TrafficPage()
        apply_display_preset(page, "Comfortable")
        page.set_packets(analyze_packets([packet]).packets)
        self.assertGreaterEqual(page.table.font().pointSizeF(), 10.5)
        self.assertGreater(page.table.verticalHeader().defaultSectionSize(),
                           page.table.fontMetrics().height())
        index = page.model.index(0, 2)
        self.assertEqual(page.model.data(index, Qt.ItemDataRole.ToolTipRole),
                         "2001:db8:1111:2222:3333:4444:5555:6666")

    def test_exact_conversation_filter_and_dns_navigation(self):
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80, flags="S"),
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=2222, dport=80, flags="S"),
            IP(src="10.0.0.3", dst="8.8.8.8") / UDP(sport=53000, dport=53) /
            DNS(id=9, qd=DNSQR(qname="example.test")),
            IP(src="8.8.8.8", dst="10.0.0.3") / UDP(sport=53, dport=53000) /
            DNS(id=9, qr=1, qd=DNSQR(qname="example.test"),
                an=DNSRR(rrname="example.test", rdata="203.0.113.8")),
        ]
        for index, packet in enumerate(packets):
            packet.time = 1700000000 + index
        analysis = analyze_packets(packets)
        page = TrafficPage()
        page.set_analysis(analysis)
        target_row = next(row for row in range(page.conversation_table.rowCount())
                          if ":1111" in page.conversation_table.item(row, 0).text()
                          or ":1111" in page.conversation_table.item(row, 1).text())
        page._open_conversation(page.conversation_table.item(target_row, 0))
        self.assertEqual(page.proxy.rowCount(), 1)
        self.assertEqual(page.proxy.index(0, 0).data(), 1)

        page._open_dns(page.dns_table.item(0, 0))
        self.assertEqual(page.proxy.rowCount(), 2)
        self.assertEqual(page.proxy.packet_numbers, {3, 4})
        self.assertEqual(page.view_stack.currentIndex(), 0)

    def test_derived_views_are_invalidated_for_new_analysis(self):
        dns = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(dport=53) / DNS(
            qd=DNSQR(qname="old.test"))
        dns.time = 1700000000
        replacement = IP(src="10.0.0.5", dst="10.0.0.6") / TCP(dport=443)
        replacement.time = 1700000001
        page = TrafficPage()
        page.set_analysis(analyze_packets([dns]))
        self.assertEqual(page.dns_table.rowCount(), 1)
        page.set_analysis(analyze_packets([replacement]))
        self.assertEqual(page.dns_table.rowCount(), 0)
        self.assertEqual(page.conversation_table.rowCount(), 1)


if __name__ == "__main__":
    unittest.main()
