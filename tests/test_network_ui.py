import os
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from packetlens.app import STYLE
from packetlens.discovery import DiscoveredDevice
from packetlens.live_capture import NetworkInterface
from packetlens.pages.network import NetworkPage


INTERFACES = [
    NetworkInterface("if-1", "Ethernet", "Physical adapter", "192.168.50.66",
                     "255.255.255.0", "192.168.50.0/24", False),
    NetworkInterface("if-2", "Wi-Fi", "Wireless adapter", "10.0.0.20",
                     "255.255.255.0", "10.0.0.0/24", False),
]


class NetworkUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def _page(self, width=1100, height=760):
        patches = (patch("packetlens.pages.network.enumerate_interfaces", return_value=list(INTERFACES)),
                   patch("packetlens.pages.network.npcap_available", return_value=True))
        active = [item.start() for item in patches]
        self.addCleanup(lambda: [item.stop() for item in reversed(patches)])
        page = NetworkPage()
        page.setStyleSheet(STYLE)
        page.resize(width, height)
        page.show()
        self.app.processEvents()
        return page

    def test_capture_controls_and_adapter_selection_survive_refresh(self):
        page = self._page()
        page.capture_interface.setCurrentIndex(1)
        selected = page.capture_interface.currentData().identifier
        page.refresh_interfaces()
        self.assertEqual(page.capture_interface.currentData().identifier, selected)
        self.assertTrue(page.capture_start.isEnabled())
        page.set_capture_running(True, 12)
        self.assertFalse(page.capture_interface.isEnabled())
        self.assertFalse(page.capture_start.isEnabled())
        self.assertTrue(page.capture_stop.isEnabled())
        self.assertFalse(page.capture_save.isEnabled())
        self.assertEqual(page.capture_state.text(), "CAPTURING")
        page.set_capture_stopping()
        self.assertEqual(page.capture_state.text(), "STOPPING")
        page.set_capture_running(False, 12)
        self.assertTrue(page.capture_interface.isEnabled())
        self.assertTrue(page.capture_save.isEnabled())
        self.assertEqual(page.capture_state.text(), "STOPPED")
        page.close()

    def test_refresh_does_not_silently_replace_missing_capture_adapter(self):
        page = self._page()
        page.capture_interface.setCurrentIndex(1)
        with patch("packetlens.pages.network.enumerate_interfaces",
                   return_value=[INTERFACES[0]]):
            page.refresh_interfaces()
        self.assertEqual(page.capture_interface.currentIndex(), -1)
        self.assertIsNone(page.capture_interface.currentData())
        self.assertFalse(page.capture_start.isEnabled())
        page.set_capture_error("Adapter disconnected")
        self.assertFalse(page.capture_start.isEnabled())
        page.close()

    def test_discovery_authorization_progress_and_zero_result_state(self):
        page = self._page()
        self.assertIn("IPv4: 192.168.50.66", page.address_details.text())
        self.assertFalse(page.scan_start.isEnabled())
        page.confirm.setChecked(True)
        self.assertTrue(page.scan_start.isEnabled())
        page.begin_scan()
        self.assertTrue(page.scan_stop.isEnabled())
        self.assertFalse(page.scan_interface.isEnabled())
        self.assertFalse(page.refresh_button.isEnabled())
        page.set_scan_progress(25, 100)
        self.assertEqual(page.scan_progress.value(), 25)
        self.assertIn("25 of 100", page.scan_status.text())
        page.finish_scan(False)
        self.assertEqual(page.results_stack.currentWidget(), page.device_empty_state)
        self.assertIn("No devices responded", page.device_empty_state.text())
        self.assertTrue(page.refresh_button.isEnabled())
        page.close()

    def test_initial_empty_state_does_not_show_unknown_device_fields(self):
        page = self._page()
        self.assertEqual(page.results_stack.currentWidget(), page.device_empty_state)
        self.assertEqual(page.device_empty_state.text(), "No discovery scan has been run.")
        self.assertTrue(page.device_empty_selection.isVisible())
        self.assertFalse(page.device_content.isVisible())
        self.assertEqual([value.text() for value in page.device_values.values()], ["", "", "", "", "", ""])
        page.close()

    def test_device_selection_details_sorting_and_investigation_signal(self):
        page = self._page()
        device = DiscoveredDevice(
            "2001:db8:1111:2222:3333:4444:5555:6666", "AA:BB:CC:DD:EE:FF",
            "very-long-device-name.example.local", "Responded",
            "Example Offline Manufacturer", "ARP response")
        page.add_device(device)
        self.assertEqual(page.results_stack.currentWidget(), page.devices)
        self.assertEqual(page.results_count.text(), "1 device")
        self.assertTrue(page.select_device(device.ip))
        self.app.processEvents()
        self.assertFalse(page.device_empty_selection.isVisible())
        self.assertEqual(page.device_values["ip"].text(), device.ip)
        self.assertEqual(page.device_values["vendor"].text(), device.vendor)
        self.assertEqual(page.devices.item(0, 0).toolTip(), device.ip)
        self.assertTrue(page.investigate_button.isEnabled())
        received = []
        page.investigate_requested.connect(received.append)
        page.investigate_button.click()
        self.assertEqual(received, [device.ip])
        page.close()

    def test_resize_and_larger_font_keep_splitter_panels_readable(self):
        page = self._page(width=820, height=620)
        page.add_device(DiscoveredDevice(
            "192.168.1.100", "AA:BB:CC:00:00:10", "device.local", "Responded",
            "Manufacturer with a deliberately long local database value", "ARP response"))
        page.select_device("192.168.1.100")
        page.resize(680, 520)
        scaled = QFont(page.font())
        scaled.setPointSizeF(max(15.0, scaled.pointSizeF() * 1.5))
        page.setFont(scaled)
        self.app.processEvents()
        self.assertGreater(page.devices.width(), 0)
        self.assertGreater(page.details_scroll.viewport().width(), 0)
        for value in page.device_values.values():
            self.assertTrue(value.wordWrap())
            self.assertGreater(value.height(), 0)
        page.close()


if __name__ == "__main__":
    unittest.main()
