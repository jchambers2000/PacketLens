import unittest

from tests.packet_factory import (ARP, DNS, DNSQR, Ether, ICMP, IP, Raw, TCP,
                                  UDP, analyze_packets)


def describe_packet(packet):
    packet.time = 1.0
    return analyze_packets([packet]).packets[0].description


class PacketDescriptionTests(unittest.TestCase):
    def test_tcp_flag_descriptions(self):
        syn = IP() / TCP(dport=443, flags="S")
        syn_ack = IP() / TCP(dport=50000, flags="SA")
        push_ack = IP() / TCP(dport=443, flags="PA") / Raw(b"data")
        self.assertEqual(describe_packet(syn), "TCP connection request to port 443")
        self.assertEqual(describe_packet(syn_ack), "Server acknowledged a TCP connection request")
        self.assertIn("application data", describe_packet(push_ack))

    def test_dns_query_and_response_include_only_observed_name(self):
        query = IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="example.com"))
        response = IP() / UDP(sport=53) / DNS(qr=1, qd=DNSQR(qname="example.com"))
        self.assertEqual(describe_packet(query), "DNS lookup requested for example.com")
        self.assertEqual(describe_packet(response), "DNS response received for example.com")

    def test_common_protocol_descriptions(self):
        self.assertEqual(describe_packet(IP() / UDP(dport=443)),
                         "UDP datagram sent to destination port 443")
        self.assertEqual(describe_packet(IP() / ICMP(type=8)), "ICMP echo request")
        self.assertEqual(describe_packet(IP() / ICMP(type=0)), "ICMP echo reply")
        self.assertIn("requesting", describe_packet(Ether() / ARP(op=1, pdst="192.168.1.1")))

    def test_raw_summary_and_structured_details_are_preserved(self):
        packet = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(
            sport=1234, dport=443, flags="S", seq=42, ack=0, window=8192)
        packet.time = 100.0
        record = analyze_packets([packet]).packets[0]
        self.assertNotIn("IP / TCP", record.description)
        self.assertIn("TCP", record.raw_summary)
        self.assertEqual(record.details["Sequence number"], "42")
        self.assertEqual(record.details["Window size"], "8192")
        self.assertIn("does not establish", record.explanation)

    def test_incomplete_packet_is_handled_safely(self):
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / Raw(b"\x00\x01")
        packet.time = 1.0
        analysis = analyze_packets([packet])
        self.assertEqual(analysis.packets[0].description, "Unrecognized network frame")
        self.assertEqual(analysis.packets[0].source, "—")


if __name__ == "__main__":
    unittest.main()
