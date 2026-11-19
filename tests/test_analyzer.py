import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tests.packet_factory import (DNS, DNSQR, Ether, IP, IPv6, TCP, UDP,
                                  PcapNgWriter, analyze_packets, wrpcap)

from packetlens.analyzer import CaptureError, analyze_capture
from packetlens.reports import build_html_report, write_html_report


class AnalyzerTests(unittest.TestCase):
    def test_extracts_metadata_and_statistics_from_synthetic_pcap(self):
        ethernet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        packets = [
            ethernet / IP(src="10.0.0.2", dst="8.8.8.8") /
            UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.test")),
            ethernet / IP(src="8.8.8.8", dst="10.0.0.2") /
            UDP(sport=53, dport=53000) / DNS(qr=1, qd=DNSQR(qname="example.test")),
            ethernet / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=443, flags="S"),
        ]
        for index, packet in enumerate(packets):
            packet.time = 1000.0 + index * 0.5
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.pcap"
            wrpcap(str(path), packets)
            analysis = analyze_capture(path)
        self.assertEqual(len(analysis.packets), 3)
        self.assertAlmostEqual(analysis.duration, 1.0)
        self.assertEqual(analysis.protocol_counts, {"DNS": 2, "TCP": 1})
        self.assertIn("2001:db8::1", analysis.unique_sources)
        self.assertEqual(analysis.packets[0].destination_port, 53)
        self.assertTrue(any(f.title == "DNS query activity" for f in analysis.findings))
        self.assertEqual(analysis.total_bytes, sum(len(packet) for packet in packets))
        self.assertEqual(analysis.unique_ips,
                         {"10.0.0.2", "8.8.8.8", "2001:db8::1", "2001:db8::2"})
        self.assertEqual(sum(analysis.protocol_counts.values()), len(packets))
        talker = next(item for item in analysis.top_talker_stats if item[0] == "10.0.0.2")
        self.assertEqual(talker[1], 2)
        self.assertGreater(talker[2], 0)

    def test_conservative_finding_thresholds(self):
        packets = []
        for index in range(10):
            packet = IP(src="192.0.2.5", dst="198.51.100.9") / TCP(
                sport=40000, dport=65000, flags="S")
            packet.time = 2000.0 + index
            packets.append(packet)
        analysis = analyze_packets(packets)
        titles = {finding.title for finding in analysis.findings}
        self.assertIn("Repeated traffic to uncommon port 65000", titles)
        self.assertIn("Repeated TCP SYN packets without observed response", titles)
        self.assertNotIn("High-frequency connection pattern", titles)

    def test_reads_synthetic_pcapng(self):
        packet = IP(src="203.0.113.1", dst="203.0.113.2") / UDP(sport=12345, dport=53)
        packet.time = 10.0
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.pcapng"
            with PcapNgWriter(str(path)) as writer:
                writer.write(packet)
            analysis = analyze_capture(path)
        self.assertEqual(len(analysis.packets), 1)
        self.assertEqual(analysis.packets[0].source, "203.0.113.1")

    def test_report_escapes_capture_derived_text(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=443)
        packet.time = 1.0
        analysis = analyze_packets([packet], "<capture>.pcap")
        html = build_html_report(analysis, datetime(2026, 1, 2, tzinfo=timezone.utc))
        self.assertIn("&lt;capture&gt;.pcap", html)
        self.assertNotIn("<capture>.pcap", html)
        self.assertIn("2026-01-02", html)
        with tempfile.TemporaryDirectory() as directory:
            path = write_html_report(analysis, Path(directory) / "report.html")
            exported = path.read_text(encoding="utf-8")
        self.assertTrue(exported.startswith("<!doctype html>"))

    def test_report_escapes_dns_and_conversation_content(self):
        packet = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(dport=53) / DNS(
            qd=DNSQR(qname=b"<script>.test"))
        packet.time = 1700000000
        html = build_html_report(analyze_packets([packet]))
        self.assertIn("&lt;script&gt;.test", html)
        self.assertNotIn("<script>.test", html)
        self.assertIn("DNS investigation", html)
        self.assertIn("Top network conversations", html)

    def test_empty_and_invalid_files_have_clear_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty.pcap"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(CaptureError, "empty"):
                analyze_capture(empty)
            wrong_extension = Path(directory) / "capture.txt"
            wrong_extension.write_text("not a capture")
            with self.assertRaisesRegex(CaptureError, "pcap"):
                analyze_capture(wrong_extension)


if __name__ == "__main__":
    unittest.main()
