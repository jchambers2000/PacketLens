import unittest

from tests.packet_factory import (DNS, DNSQR, DNSRR, IP, IPv6, TCP, UDP,
                                  analyze_packets)


def timed(packets, start=1700000000.0):
    for index, packet in enumerate(packets):
        packet.time = start + index * 0.1
    return packets


class InvestigationTests(unittest.TestCase):
    def test_dns_query_response_extraction_and_correlation(self):
        query = (IP(src="192.0.2.10", dst="8.8.8.8") / UDP(sport=53000, dport=53) /
                 DNS(id=42, qd=DNSQR(qname="example.test", qtype="A")))
        response = (IP(src="8.8.8.8", dst="192.0.2.10") / UDP(sport=53, dport=53000) /
                    DNS(id=42, qr=1, rcode=0, qd=DNSQR(qname="example.test", qtype="A"),
                        an=DNSRR(rrname="example.test", type="A", rdata="203.0.113.9")))
        analysis = analyze_packets(timed([query, response]))
        self.assertEqual(len(analysis.dns_activities), 1)
        activity = analysis.dns_activities[0]
        self.assertEqual(activity.domain, "example.test")
        self.assertEqual(activity.query_type, "A")
        self.assertEqual(activity.query_count, 1)
        self.assertEqual(activity.response_count, 1)
        self.assertEqual(activity.response_status, "No error")
        self.assertEqual(activity.resolved_ips, ("203.0.113.9",))
        self.assertEqual(activity.packet_numbers, (1, 2))

    def test_dns_query_without_response_is_retained(self):
        query = (IP(src="192.0.2.10", dst="8.8.8.8") / UDP(sport=53000, dport=53) /
                 DNS(id=7, qd=DNSQR(qname="missing.test", qtype="AAAA")))
        activity = analyze_packets(timed([query])).dns_activities[0]
        self.assertEqual(activity.query_type, "AAAA")
        self.assertEqual(activity.response_count, 0)
        self.assertEqual(activity.response_status, "No response observed")

    def test_dns_over_tcp_is_included_in_dns_and_conversation_views(self):
        query = (IP(src="192.0.2.11", dst="8.8.8.8") / TCP(sport=55000, dport=53, flags="PA") /
                 DNS(id=8, qd=DNSQR(qname="tcp.example.test", qtype="MX")))
        analysis = analyze_packets(timed([query]))
        self.assertEqual(analysis.dns_activities[0].query_type, "MX")
        self.assertEqual(analysis.conversations[0].protocol, "TCP")
        self.assertEqual(analysis.conversations[0].packet_numbers, (1,))

    def test_bidirectional_tcp_conversation_and_handshake_evidence(self):
        packets = timed([
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=443, flags="S"),
            IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=443, dport=50000, flags="SA"),
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=443, flags="A"),
        ])
        conversation = analyze_packets(packets).conversations[0]
        self.assertEqual(conversation.protocol, "TCP")
        self.assertEqual(conversation.packet_count, 3)
        self.assertEqual(conversation.packet_numbers, (1, 2, 3))
        self.assertIn("Three-way handshake observed", conversation.tcp_state)

    def test_ipv4_udp_and_incomplete_ipv6_tcp_conversations(self):
        packets = timed([
            IP(src="10.0.0.3", dst="10.0.0.4") / UDP(sport=1000, dport=2000),
            IP(src="10.0.0.4", dst="10.0.0.3") / UDP(sport=2000, dport=1000),
            IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=3000, dport=443, flags="S"),
        ])
        conversations = analyze_packets(packets).conversations
        self.assertEqual(len(conversations), 2)
        udp = next(item for item in conversations if item.protocol == "UDP")
        tcp = next(item for item in conversations if item.protocol == "TCP")
        self.assertEqual(udp.ip_version, 4)
        self.assertEqual(udp.packet_count, 2)
        self.assertEqual(tcp.ip_version, 6)
        self.assertIn("incomplete", tcp.tcp_state)

    def test_summary_uses_cached_capture_statistics(self):
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
        analysis = analyze_packets(timed([packet]))
        self.assertIn("1 packets across 1 network conversations", analysis.investigation_summary)
        self.assertIn("TCP connections", analysis.investigation_summary)
        self.assertIn("security observations", analysis.investigation_summary)

    def test_dns_observations_have_structured_evidence(self):
        packets = []
        long_domain = ("a" * 50) + ".test"
        for index in range(3):
            packets.extend((
                IP(src="192.0.2.20", dst="8.8.8.8") / UDP(sport=53000 + index, dport=53) /
                DNS(id=index, qd=DNSQR(qname=long_domain)),
                IP(src="8.8.8.8", dst="192.0.2.20") / UDP(sport=53, dport=53000 + index) /
                DNS(id=index, qr=1, rcode=3, qd=DNSQR(qname=long_domain)),
            ))
        analysis = analyze_packets(timed(packets))
        titles = {finding.title for finding in analysis.findings}
        self.assertIn("Repeated failed DNS lookups", titles)
        self.assertIn("Unusually long DNS label", titles)
        for finding in analysis.findings:
            self.assertTrue(finding.triggering_rule)
            self.assertTrue(finding.why_it_matters)
            self.assertIsInstance(finding.references, tuple)

    def test_high_dns_volume_uses_documented_conservative_threshold(self):
        packets = [IP(src="192.0.2.30", dst="8.8.8.8") /
                   UDP(sport=54000 + index, dport=53) /
                   DNS(id=index, qd=DNSQR(qname=f"host{index}.example.test"))
                   for index in range(100)]
        analysis = analyze_packets(timed(packets))
        finding = next(item for item in analysis.findings if item.title == "High DNS query volume")
        self.assertIn("100", finding.description)
        self.assertIn("At least 100", finding.triggering_rule)


if __name__ == "__main__":
    unittest.main()
