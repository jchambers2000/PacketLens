import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QApplication
from tests.packet_factory import (ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP,
                                  analyze_packets)
from packetlens.app import PacketLensWindow
from packetlens.display import apply_display_preset, saved_display_preset
from packetlens.live_capture import LiveCaptureEngine, LiveCaptureError
from packetlens.pages.traffic import TrafficPage


def analysis_fixture():
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000, dport=443),
        IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=53000, dport=53) /
        DNS(qd=DNSQR(qname="example.test")),
        IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=60000, dport=5353),
        IP(src="10.0.0.3", dst="10.0.0.4") / ICMP(),
        ARP(psrc="192.168.1.10", pdst="192.168.1.1"),
    ]
    for index, packet in enumerate(packets):
        packet.time = 1700000000 + index
    return analyze_packets(packets, "filters.pcap")


class V06UsabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_display_presets_scale_and_persist(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = QSettings(str(Path(directory) / "display.ini"), QSettings.Format.IniFormat)
            page = TrafficPage()
            apply_display_preset(page, "Compact", settings)
            compact = page.font().pointSizeF()
            apply_display_preset(page, "Large", settings)
            self.assertGreater(page.font().pointSizeF(), compact)
            self.assertEqual(saved_display_preset(settings), "Large")
            self.assertGreater(page.table.verticalHeader().defaultSectionSize(),
                               page.table.fontMetrics().height())

    def test_protocol_exact_ip_and_port_filters(self):
        page = TrafficPage()
        page.set_analysis(analysis_fixture())
        page.protocol_filter.setCurrentText("DNS")
        self.assertEqual(page.proxy.rowCount(), 1)
        page.protocol_filter.setCurrentText("All")
        page.ip_filter.setText("2001:db8::1")
        self.assertEqual(page.proxy.rowCount(), 1)
        page.ip_filter.setText("2001:db8::")
        self.assertEqual(page.proxy.rowCount(), 0)
        page.ip_filter.clear()
        page.port_filter.setText("443")
        self.assertEqual(page.proxy.rowCount(), 1)

    def test_combined_text_protocol_ip_and_port_filters(self):
        page = TrafficPage()
        page.set_analysis(analysis_fixture())
        page.search.setText("example.test")
        page.protocol_filter.setCurrentText("DNS")
        page.ip_filter.setText("10.0.0.1")
        page.port_filter.setText("53")
        self.assertEqual(page.proxy.rowCount(), 1)
        self.assertEqual(page.proxy.index(0, 0).data(), 2)
        self.assertIn("1 of 5", page.match_count.text())

    def test_general_filters_refine_but_never_expand_investigation(self):
        page = TrafficPage()
        page.set_analysis(analysis_fixture())
        page.filter_by_packet_numbers((1, 2), "Evidence")
        page.protocol_filter.setCurrentText("DNS")
        self.assertEqual(page.proxy.rowCount(), 1)
        self.assertEqual(page.proxy.packet_numbers, {1, 2})
        page.clear_general_filters()
        self.assertEqual(page.proxy.rowCount(), 2)
        self.assertEqual(page.proxy.packet_numbers, {1, 2})
        page.clear_investigation_filter()
        self.assertEqual(page.proxy.rowCount(), 5)

    def test_new_analysis_clears_only_capture_specific_context(self):
        page = TrafficPage()
        page.set_analysis(analysis_fixture())
        page.protocol_filter.setCurrentText("TCP")
        page.filter_by_packet_numbers((1,), "Evidence")
        replacement = analysis_fixture()
        page.set_analysis(replacement)
        self.assertFalse(page.investigation_active)
        self.assertEqual(page.protocol_filter.currentText(), "TCP")
        self.assertEqual(page.proxy.rowCount(), 1)

    def test_packet_identity_survives_sorting_with_filters(self):
        page = TrafficPage()
        page.set_analysis(analysis_fixture())
        page.protocol_filter.setCurrentText("DNS")
        page.table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        page.table.selectRow(0)
        self.app.processEvents()
        self.assertEqual(page.selected_packet_number, 2)

    def test_context_status_changes_with_navigation(self):
        window = PacketLensWindow()
        analysis = analysis_fixture()
        window._apply_analysis(analysis)
        window.navigation.setCurrentRow(0)
        self.assertIn("5 packets analyzed", window.status.text())
        window.navigation.setCurrentRow(1)
        self.assertIn("Showing 5 of 5 packets", window.status.text())
        window.navigation.setCurrentRow(3)
        self.assertIn("observations available", window.status.text())
        window.close()

    def test_master_detail_pages_remain_present_at_large_scale(self):
        window = PacketLensWindow()
        window.set_display_preset("Large")
        window.resize(1100, 700)
        window.show()
        self.app.processEvents()
        self.assertGreater(window.findings.details_scroll.viewport().width(), 0)
        self.assertGreater(window.network.details_scroll.viewport().width(), 0)
        self.assertEqual(window.display_size.currentText(), "Large")
        window.set_display_preset("Comfortable")
        window.close()

    def test_failed_capture_save_preserves_existing_destination(self):
        engine = LiveCaptureEngine("mock-interface", availability_check=lambda: True)
        engine._packets = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=443)]
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "existing.pcap"
            destination.write_bytes(b"original capture bytes")
            with patch("packetlens.live_capture._write_capture", side_effect=OSError("disk full")):
                with self.assertRaises(LiveCaptureError):
                    engine.save(destination)
            self.assertEqual(destination.read_bytes(), b"original capture bytes")
            self.assertEqual(list(Path(directory).glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
