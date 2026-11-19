import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from packetlens.discovery import lookup_mac_vendor
from packetlens.distribution import dependency_cleanup_issues, distribution_issues
from packetlens.runtime import (bundle_root, resource_path, user_data_directory,
                                write_startup_diagnostic)


class PackagingTests(unittest.TestCase):
    def test_frozen_resource_paths_use_bundle_root_not_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(sys, "frozen", True, create=True), \
                    patch.object(sys, "_MEIPASS", directory, create=True):
                self.assertEqual(bundle_root(), Path(directory).resolve())
                self.assertEqual(resource_path("packetlens", "data", "oui.csv"),
                                 Path(directory).resolve() / "packetlens" / "data" / "oui.csv")

    def test_missing_optional_oui_database_is_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.csv"
            self.assertEqual(lookup_mac_vendor("AA:BB:CC:00:00:01", missing), "")

    def test_startup_diagnostic_uses_local_app_data_only_on_failure(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ, {"LOCALAPPDATA": directory}):
            expected = Path(directory) / "PacketLens"
            self.assertEqual(user_data_directory(), expected)
            self.assertFalse(expected.exists())
            path = write_startup_diagnostic("0.8.4", RuntimeError("startup test"))
            self.assertIsNotNone(path)
            text = path.read_text(encoding="utf-8")
            self.assertIn("PacketLens 0.8.4", text)
            self.assertIn("startup test", text)
            self.assertNotIn("packet payload", text.casefold())

    def test_distribution_validator_accepts_required_runtime_structure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "PacketLens.exe").write_bytes(b"MZ")
            plugin = root / "_internal" / "PySide6" / "plugins" / "platforms"
            plugin.mkdir(parents=True)
            (plugin / "qwindows.dll").write_bytes(b"runtime")
            self.assertEqual(distribution_issues(root), [])

    def test_distribution_validator_rejects_private_and_development_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "PacketLens.exe").write_bytes(b"MZ")
            plugin = root / "_internal" / "platforms"
            plugin.mkdir(parents=True)
            (plugin / "qwindows.dll").write_bytes(b"runtime")
            captures = root / "captures"
            captures.mkdir()
            (captures / "private.pcap").write_bytes(b"capture")
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_app.py").write_text("", encoding="utf-8")
            (root / "wpcap.dll").write_bytes(b"must not redistribute")
            issues = "\n".join(distribution_issues(root))
            self.assertIn("captures", issues)
            self.assertIn("tests", issues)
            self.assertIn("private.pcap", issues)
            self.assertIn("wpcap.dll", issues)

    def test_source_packaging_probe_starts_all_pages_without_network_activity(self):
        import main

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "probe.json"
            argv = ["PacketLens", "--packaging-probe", str(output)]
            with patch.object(sys, "argv", argv), \
                    patch("packetlens.pages.network.enumerate_interfaces", return_value=[]), \
                    patch("packetlens.pages.network.npcap_available", return_value=False):
                self.assertEqual(main.main(), 0)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["version"], "0.8.4")
            self.assertFalse(result["frozen"])
            self.assertEqual(result["page_count"], 5)
            self.assertEqual(result["pages"],
                             ["Overview", "Traffic", "Network", "Findings", "Reports"])

    def test_native_phase3_probe_requires_explicit_authorization(self):
        source = (Path(__file__).parents[1] / "main.py").read_text(encoding="utf-8")
        self.assertIn('"--native-phase3-probe"', source)
        self.assertIn('"--i-own-and-authorize-subnet-scan"', source)

    def test_spec_does_not_reference_private_capture_directory(self):
        spec = (Path(__file__).parents[1] / "PacketLens.spec").read_text(encoding="utf-8")
        self.assertNotIn('"captures"', spec)
        self.assertIn("console=False", spec)
        self.assertIn("COLLECT", spec)

    def test_clean_distribution_requires_widgets_and_rejects_optional_qt_stacks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("Qt6Core.dll", "Qt6Gui.dll", "Qt6Svg.dll", "Qt6Widgets.dll",
                         "QtCore.pyd", "QtGui.pyd", "QtWidgets.pyd", "qwindows.dll",
                         "qmodernwindowsstyle.dll"):
                (root / name).write_bytes(b"runtime")
            self.assertEqual(dependency_cleanup_issues(root), [])
            (root / "Qt6VirtualKeyboard.dll").write_bytes(b"optional")
            issues = "\n".join(dependency_cleanup_issues(root))
            self.assertIn("qt6virtualkeyboard.dll", issues)


if __name__ == "__main__":
    unittest.main()
