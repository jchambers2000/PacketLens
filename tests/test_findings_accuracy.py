import unittest

from tests.packet_factory import IP, IPv6, TCP, UDP, analyze_packets
from packetlens.reports import build_html_report


def analyze(packets):
    for index, packet in enumerate(packets):
        packet.time = 1700000000 + index * 0.01
    return analyze_packets(packets)


def uncommon_findings(analysis):
    return [finding for finding in analysis.findings
            if finding.title.startswith("Repeated traffic to uncommon")]


class FindingsAccuracyTests(unittest.TestCase):
    def test_normal_https_return_traffic_to_ephemeral_port_is_not_flagged(self):
        packets = [
            IP(src="10.0.0.10", dst="203.0.113.10") / TCP(sport=55000, dport=443, flags="S"),
            IP(src="203.0.113.10", dst="10.0.0.10") / TCP(sport=443, dport=55000, flags="SA"),
            IP(src="10.0.0.10", dst="203.0.113.10") / TCP(sport=55000, dport=443, flags="A"),
        ]
        packets.extend(IP(src="203.0.113.10", dst="10.0.0.10") /
                       TCP(sport=443, dport=55000, flags="PA") for _ in range(8))
        self.assertEqual(uncommon_findings(analyze(packets)), [])

    def test_legitimate_high_client_source_port_to_common_service_is_not_flagged(self):
        packets = [IP(src="10.0.0.20", dst="198.51.100.20") /
                   TCP(sport=62000, dport=443, flags="S")]
        packets.extend(IP(src="10.0.0.20", dst="198.51.100.20") /
                       TCP(sport=62000, dport=443, flags="PA") for _ in range(8))
        self.assertEqual(uncommon_findings(analyze(packets)), [])

    def test_udp_response_traffic_to_client_port_is_not_flagged(self):
        packets = [IP(src="10.0.0.30", dst="8.8.8.8") / UDP(sport=60000, dport=53)]
        packets.extend(IP(src="8.8.8.8", dst="10.0.0.30") /
                       UDP(sport=53, dport=60000) for _ in range(8))
        self.assertEqual(uncommon_findings(analyze(packets)), [])

    def test_mdns_5353_is_not_flagged(self):
        packets = [IP(src="192.168.1.10", dst="224.0.0.251") /
                   UDP(sport=5353, dport=5353) for _ in range(8)]
        packets.append(IP(src="224.0.0.251", dst="192.168.1.10") /
                       UDP(sport=5353, dport=5353))
        self.assertEqual(uncommon_findings(analyze(packets)), [])

    def test_incomplete_capture_with_uncertain_direction_is_not_flagged(self):
        packets = [IP(src="203.0.113.40", dst="10.0.0.40") /
                   TCP(sport=443, dport=63000, flags="PA") for _ in range(10)]
        self.assertEqual(uncommon_findings(analyze(packets)), [])

    def test_one_directional_udp_capture_does_not_invent_roles(self):
        packets = [IP(src="203.0.113.41", dst="10.0.0.41") /
                   UDP(sport=65020, dport=63001) for _ in range(10)]
        self.assertEqual(uncommon_findings(analyze(packets)), [])

    def test_established_unusual_high_port_service_remains_reviewable(self):
        packets = [
            IPv6(src="2001:db8::10", dst="2001:db8::20") /
            TCP(sport=51000, dport=65000, flags="S"),
            IPv6(src="2001:db8::20", dst="2001:db8::10") /
            TCP(sport=65000, dport=51000, flags="SA"),
            IPv6(src="2001:db8::10", dst="2001:db8::20") /
            TCP(sport=51000, dport=65000, flags="A"),
        ]
        packets.extend(IPv6(src="2001:db8::10", dst="2001:db8::20") /
                       TCP(sport=51000, dport=65000, flags="PA") for _ in range(4))
        finding = uncommon_findings(analyze(packets))[0]
        self.assertIn("65000", finding.title)
        self.assertEqual(finding.classification, "Review")
        self.assertIn("client-SYN", finding.triggering_rule)

    def test_bidirectional_udp_pattern_to_unusual_port_is_reviewable(self):
        packets = [IP(src="10.0.0.45", dst="198.51.100.45") /
                   UDP(sport=51000, dport=65010) for _ in range(5)]
        packets.append(IP(src="198.51.100.45", dst="10.0.0.45") /
                       UDP(sport=65010, dport=51000))
        finding = uncommon_findings(analyze(packets))[0]
        self.assertIn("65010", finding.title)
        self.assertIn("bidirectional UDP", finding.triggering_rule)

    def test_related_unusual_ports_are_grouped(self):
        packets = []
        for client, server, port in (("10.0.0.50", "198.51.100.50", 65001),
                                     ("10.0.0.51", "198.51.100.51", 65002)):
            packets.extend(IP(src=client, dst=server) /
                           TCP(sport=50000, dport=port, flags="S" if index == 0 else "PA")
                           for index in range(5))
        findings = uncommon_findings(analyze(packets))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Repeated traffic to uncommon service ports")
        self.assertEqual(len(findings[0].references), 10)

    def test_report_labels_truncated_evidence_preview(self):
        packets = [IP(src="10.0.0.60", dst="198.51.100.60") /
                   TCP(sport=50000, dport=65003, flags="S" if index == 0 else "PA")
                   for index in range(25)]
        analysis = analyze(packets)
        finding = uncommon_findings(analysis)[0]
        self.assertEqual(len(finding.references), 25)
        report = build_html_report(analysis)
        self.assertIn("20 of 25 references shown", report)


if __name__ == "__main__":
    unittest.main()
