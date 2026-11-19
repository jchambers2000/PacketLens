import socket
import struct
import tempfile
import unittest
from pathlib import Path

import dpkt

from packetlens.analyzer import analyze_capture
from packetlens.dpkt_backend import DpktCaptureBackend
from packetlens.capture_files import iter_capture_frames


MAC_A = bytes.fromhex("001122334455")
MAC_B = bytes.fromhex("aabbccddeeff")


def ethernet(payload, kind):
    return bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=kind, data=payload))


def frames():
    a4, b4 = socket.inet_aton("192.168.10.5"), socket.inet_aton("192.168.10.1")
    a6, b6 = socket.inet_pton(socket.AF_INET6, "2001:db8::5"), socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    tcp = dpkt.tcp.TCP(sport=51000, dport=443, flags=dpkt.tcp.TH_SYN, seq=9)
    ip_tcp = dpkt.ip.IP(src=a4, dst=b4, p=6, ttl=64, data=tcp)
    query = dpkt.dns.DNS(id=7, qd=[dpkt.dns.DNS.Q(name="phase1.test", type=1)])
    udp = dpkt.udp.UDP(sport=53000, dport=53, data=bytes(query)); udp.ulen = len(udp)
    ip_dns = dpkt.ip.IP(src=a4, dst=b4, p=17, ttl=64, data=udp)
    icmp = dpkt.icmp.ICMP(type=8, code=0, data=dpkt.icmp.ICMP.Echo(id=1, seq=1))
    ip_icmp = dpkt.ip.IP(src=a4, dst=b4, p=1, ttl=64, data=icmp)
    tcp6 = dpkt.tcp.TCP(sport=52000, dport=8443, flags=dpkt.tcp.TH_ACK)
    ip6 = dpkt.ip6.IP6(src=a6, dst=b6, nxt=6, hlim=64, plen=len(tcp6), data=tcp6)
    icmp6 = dpkt.icmp6.ICMP6(type=128, code=0, data=b"\0\1\0\1")
    ip6_icmp = dpkt.ip6.IP6(src=a6, dst=b6, nxt=58, hlim=64, plen=len(icmp6), data=icmp6)
    arp = dpkt.arp.ARP(op=1, sha=MAC_A, spa=a4, tha=b"\0" * 6, tpa=b4)
    return [ethernet(ip_tcp, 0x0800), ethernet(ip_dns, 0x0800),
            ethernet(ip_icmp, 0x0800), ethernet(ip6, 0x86DD),
            ethernet(ip6_icmp, 0x86DD), ethernet(arp, 0x0806)]


class DpktIntegrationTests(unittest.TestCase):
    def _capture(self, suffix, packet_frames=None, linktype=1):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / f"phase1{suffix}"
        writer_type = dpkt.pcapng.Writer if suffix == ".pcapng" else dpkt.pcap.Writer
        with path.open("wb") as handle:
            writer = writer_type(handle, linktype=linktype)
            for index, raw in enumerate(packet_frames or frames()):
                writer.writepkt(raw, ts=1700000000.125 + index / 1000)
            writer.close()
        return directory, path

    def test_pcap_and_pcapng_cover_required_protocols_and_metadata(self):
        for suffix in (".pcap", ".pcapng"):
            with self.subTest(suffix=suffix):
                directory, path = self._capture(suffix)
                with directory:
                    analysis = analyze_capture(path)
                self.assertEqual([p.protocol for p in analysis.packets],
                                 ["TCP", "DNS", "ICMP", "TCP", "ICMPv6", "ARP"])
                self.assertEqual(analysis.packets[0].tcp_flags, "S")
                self.assertEqual((analysis.packets[0].source_port, analysis.packets[0].destination_port), (51000, 443))
                self.assertEqual(analysis.packets[1].dns_name, "phase1.test")
                self.assertEqual(analysis.packets[3].ip_version, 6)
                self.assertEqual(analysis.packets[0].timestamp, 1700000000.125)
                self.assertEqual(analysis.packets[0].raw_bytes, frames()[0])
                self.assertEqual(analysis.packets[0].captured_length, len(frames()[0]))
                self.assertEqual(analysis.parser_backend, "dpkt")

    def test_non_ethernet_raw_ip_capture(self):
        ip = dpkt.ip.IP(src=socket.inet_aton("198.51.100.1"), dst=socket.inet_aton("198.51.100.2"),
                         p=17, ttl=64, data=dpkt.udp.UDP(sport=1000, dport=2000))
        directory, path = self._capture(".pcap", [bytes(ip)], linktype=101)
        with directory:
            packet = analyze_capture(path).packets[0]
        self.assertEqual((packet.source, packet.destination, packet.protocol),
                         ("198.51.100.1", "198.51.100.2", "UDP"))

    def test_malformed_frame_is_retained_with_diagnostic_evidence(self):
        directory, path = self._capture(".pcap", [b"\x00\x01\x02"])
        with directory:
            result = DpktCaptureBackend().read(path)
            analysis = analyze_capture(path)
        self.assertEqual(result.records[0].protocol, "Malformed")
        self.assertEqual(result.records[0].raw_bytes, b"\x00\x01\x02")
        self.assertTrue(result.diagnostics)
        self.assertEqual(analysis.parser_diagnostics, result.diagnostics)

    def test_pcap_preserves_captured_and_original_lengths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "truncated.pcap"
            global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            packet_header = struct.pack("<IIII", 100, 250000, 3, 60)
            path.write_bytes(global_header + packet_header + b"\x00\x01\x02")
            frame = next(iter(iter_capture_frames(path)))
        self.assertEqual(frame.timestamp, 100.25)
        self.assertEqual((frame.captured_length, frame.original_length), (3, 60))

    def test_normalized_analysis_preserves_evidence_and_investigation(self):
        directory, path = self._capture(".pcap")
        with directory:
            analysis = analyze_capture(path)
        self.assertEqual([packet.number for packet in analysis.packets], list(range(1, 7)))
        self.assertEqual(analysis.dns_activities[0].packet_numbers, (2,))
        self.assertEqual(analysis.conversations[0].packet_numbers, (1,))
        for finding in analysis.findings:
            self.assertTrue(all(1 <= number <= 6 for number in finding.references))

    def test_deterministic_expected_endpoints(self):
        directory, path = self._capture(".pcap")
        with directory:
            analysis = analyze_capture(path)
        self.assertEqual(len(analysis.packets), 6)
        self.assertEqual((analysis.packets[0].source, analysis.packets[0].destination),
                         ("192.168.10.5", "192.168.10.1"))
        self.assertEqual((analysis.packets[3].source, analysis.packets[3].destination),
                         ("2001:db8::5", "2001:db8::1"))


if __name__ == "__main__":
    unittest.main()
