import re
import unittest
from pathlib import Path

from packetlens import __version__
from packetlens.distribution import assert_distribution_safe


ROOT = Path(__file__).resolve().parents[1]


class PublicationReadinessTests(unittest.TestCase):
    def test_release_version_is_consistent(self):
        self.assertEqual(__version__, "0.8.4")
        version_resource = (ROOT / "packaging" / "PacketLens.version").read_text(encoding="utf-8")
        build_script = (ROOT / "build_windows.ps1").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("FileVersion', '0.8.4'", version_resource)
        self.assertIn("prodvers=(0, 8, 4, 0)", version_resource)
        self.assertIn('from packetlens import __version__', build_script)
        self.assertIn("0.8.4", readme)

    def test_publication_manifest_is_sorted_unique_and_safe(self):
        manifest = [line.strip() for line in (ROOT / "PUBLICATION_MANIFEST_PROPOSED.txt").read_text(
            encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(manifest, sorted(set(manifest), key=str.casefold))
        forbidden_parts = {".git", ".venv", "build", "captures", "dist", "__pycache__"}
        forbidden_suffixes = {".pcap", ".pcapng", ".zip", ".sha256", ".html", ".env", ".key", ".pem"}
        for relative in manifest:
            path = Path(relative)
            self.assertFalse(forbidden_parts.intersection(path.parts), relative)
            self.assertNotIn(path.suffix.casefold(), forbidden_suffixes, relative)
            self.assertTrue((ROOT / path).is_file(), relative)

    def test_documentation_links_are_local_and_resolve(self):
        for document_name in ("README.md", "CONTRIBUTING.md", "SECURITY.md"):
            text = (ROOT / document_name).read_text(encoding="utf-8")
            for target in re.findall(r"\[[^]]+\]\(([^)]+)\)|!\[[^]]*\]\(([^)]+)\)", text):
                link = next(value for value in target if value)
                if "://" in link or link.startswith("#"):
                    continue
                self.assertTrue((ROOT / link.split("#", 1)[0]).exists(), f"{document_name}: {link}")

    def test_screenshot_set_exists_and_is_png(self):
        expected = {
            "overview.png", "traffic-packet-inspection.png", "network-conversations.png",
            "dns-investigation.png", "network-discovery.png", "findings.png",
            "html-report-preview.png",
        }
        directory = ROOT / "docs" / "screenshots"
        self.assertEqual({path.name for path in directory.glob("*.png")}, expected)
        for path in directory.glob("*.png"):
            self.assertEqual(path.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")

    def test_dependencies_are_exactly_pinned(self):
        runtime = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        build = (ROOT / "requirements-build.txt").read_text(encoding="utf-8").splitlines()
        self.assertTrue(all("==" in line for line in runtime if line and not line.startswith("#")))
        self.assertIn("pyinstaller==6.22.3", build)

    def test_spec_is_windowed_onedir_and_carries_notices(self):
        spec = (ROOT / "PacketLens.spec").read_text(encoding="utf-8")
        self.assertIn("console=False", spec)
        self.assertIn("COLLECT(", spec)
        self.assertIn("THIRD_PARTY_NOTICES.md", spec)
        self.assertIn("THIRD_PARTY_LICENSES", spec)
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        self.assertIn("dpkt-1.9.8-LICENSE.txt", notices)
        self.assertNotIn("captures", spec.casefold())

    def test_compliance_documents_and_complete_license_bundle_exist(self):
        for name in ("THIRD_PARTY_NOTICES.md", "QT_LIBRARY_REPLACEMENT.md",
                     "QT_SOURCE_AVAILABILITY.md"):
            self.assertTrue((ROOT / name).is_file(), name)
        expected = {
            "GPL-3.0.txt", "LGPL-3.0.txt", "Python-3.14.10-LICENSE.txt",
            "OpenSSL-3.5.9-LICENSE.txt", "libffi-3.4.4-LICENSE.txt",
            "dpkt-1.9.8-LICENSE.txt", "dpkt-1.9.8-AUTHORS.txt",
            "PyInstaller-6.22.3-COPYING.txt",
        }
        actual = {path.name for path in (ROOT / "THIRD_PARTY_LICENSES").iterdir()}
        self.assertTrue(expected.issubset(actual))
        project_license = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Apache License", project_license)
        self.assertIn("Version 2.0, January 2004", project_license)
        self.assertIn("http://www.apache.org/licenses/", project_license)

    def test_existing_distribution_remains_content_safe(self):
        distribution = ROOT / "dist" / "PacketLens"
        if distribution.exists():
            assert_distribution_safe(distribution)


if __name__ == "__main__":
    unittest.main()
