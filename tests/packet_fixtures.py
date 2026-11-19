"""Independent deterministic packet fixtures for PacketLens tests.

These builders use dpkt's public constructors and Python's socket module.
They do not depend on, copy, or adapt the former packet-library implementation.
"""

from __future__ import annotations

import socket
from pathlib import Path

import dpkt

from packetlens.analyzer import analyze_frames
from packetlens.capture_backend import CapturedFrame
from packetlens.capture_files import write_pcap_frames


MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")
TCP_FLAGS = {"F": 1, "S": 2, "R": 4, "P": 8, "A": 16,
             "U": 32, "E": 64, "C": 128}


def ethernet(payload, ethertype: int, *, src: bytes = MAC_A, dst: bytes = MAC_B) -> bytes:
    return bytes(dpkt.ethernet.Ethernet(src=src, dst=dst, type=ethertype, data=payload))


def _tcp(sport, dport, flags, seq, ack, window, payload):
    return dpkt.tcp.TCP(sport=sport, dport=dport,
                        flags=sum(TCP_FLAGS.get(flag, 0) for flag in flags),
                        seq=seq, ack=ack, win=window, data=payload)


def ipv4_tcp(src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=443,
             flags="", seq=0, ack=0, window=8192, payload=b"") -> bytes:
    tcp = _tcp(sport, dport, flags, seq, ack, window, payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    ip.len = len(ip)
    return ethernet(ip, dpkt.ethernet.ETH_TYPE_IP)


def ipv6_tcp(src="2001:db8::1", dst="2001:db8::2", sport=12345, dport=443,
             flags="", seq=0, ack=0, window=8192, payload=b"") -> bytes:
    tcp = _tcp(sport, dport, flags, seq, ack, window, payload)
    ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src),
                      dst=socket.inet_pton(socket.AF_INET6, dst),
                      nxt=dpkt.ip.IP_PROTO_TCP, hlim=64, plen=len(tcp), data=tcp)
    return ethernet(ip, dpkt.ethernet.ETH_TYPE_IP6)


def ipv4_udp(src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=53,
             payload=b"") -> bytes:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=udp)
    ip.len = len(ip)
    return ethernet(ip, dpkt.ethernet.ETH_TYPE_IP)


def ipv6_udp(src="2001:db8::1", dst="2001:db8::2", sport=12345, dport=5353,
             payload=b"") -> bytes:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src),
                      dst=socket.inet_pton(socket.AF_INET6, dst),
                      nxt=dpkt.ip.IP_PROTO_UDP, hlim=64, plen=len(udp), data=udp)
    return ethernet(ip, dpkt.ethernet.ETH_TYPE_IP6)


def dns_payload(name="example.test", *, identifier=1, response=False,
                qtype=dpkt.dns.DNS_A, rcode=0, answer=None) -> bytes:
    message = dpkt.dns.DNS(id=identifier,
                           qd=[dpkt.dns.DNS.Q(name=name, type=qtype)])
    if response:
        message.qr = dpkt.dns.DNS_R
        message.rcode = rcode
        if answer:
            rr = dpkt.dns.DNS.RR(name=name, type=qtype, ttl=60)
            if qtype == dpkt.dns.DNS_A:
                rr.ip = socket.inet_aton(answer)
            elif qtype == dpkt.dns.DNS_AAAA:
                rr.ip6 = socket.inet_pton(socket.AF_INET6, answer)
            message.an = [rr]
    return bytes(message)


def ipv4_dns(src="10.0.0.1", dst="8.8.8.8", sport=53000, dport=53,
             name="example.test", identifier=1, response=False,
             qtype=dpkt.dns.DNS_A, rcode=0, answer=None) -> bytes:
    payload = dns_payload(name, identifier=identifier, response=response,
                          qtype=qtype, rcode=rcode, answer=answer)
    return ipv4_udp(src, dst, sport, dport, payload)


def ipv4_dns_tcp(src="10.0.0.1", dst="8.8.8.8", sport=53000, dport=53,
                 name="example.test", identifier=1, response=False,
                 qtype=dpkt.dns.DNS_A, rcode=0, answer=None) -> bytes:
    payload = dns_payload(name, identifier=identifier, response=response,
                          qtype=qtype, rcode=rcode, answer=answer)
    return ipv4_tcp(src, dst, sport, dport, "PA",
                    payload=len(payload).to_bytes(2, "big") + payload)


def ipv4_icmp(src="10.0.0.1", dst="10.0.0.2", kind=8) -> bytes:
    message = dpkt.icmp.ICMP(type=kind, code=0,
                             data=dpkt.icmp.ICMP.Echo(id=1, seq=1))
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_ICMP, ttl=64, data=message)
    ip.len = len(ip)
    return ethernet(ip, dpkt.ethernet.ETH_TYPE_IP)


def ipv6_icmp(src="2001:db8::1", dst="2001:db8::2", kind=128) -> bytes:
    message = dpkt.icmp6.ICMP6(type=kind, code=0, data=b"\0\1\0\1")
    ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src),
                      dst=socket.inet_pton(socket.AF_INET6, dst),
                      nxt=dpkt.ip.IP_PROTO_ICMP6, hlim=64, plen=len(message), data=message)
    return ethernet(ip, dpkt.ethernet.ETH_TYPE_IP6)


def arp(src_ip="192.168.1.10", dst_ip="192.168.1.1", *, operation=1,
        src_mac=MAC_A, dst_mac=b"\0" * 6) -> bytes:
    packet = dpkt.arp.ARP(op=operation, sha=src_mac, spa=socket.inet_aton(src_ip),
                          tha=dst_mac, tpa=socket.inet_aton(dst_ip))
    return ethernet(packet, dpkt.ethernet.ETH_TYPE_ARP, src=src_mac,
                    dst=dst_mac if operation == 2 else b"\xff" * 6)


def unknown_frame(payload=b"\x00\x01") -> bytes:
    return ethernet(payload, 0x88B5)


def captured(raw: bytes, timestamp=1700000000.0, link_type=1,
             original_length=None) -> CapturedFrame:
    return CapturedFrame(timestamp, raw, len(raw), original_length or len(raw), link_type)


def frame_sequence(raw_packets, *, start=1700000000.0, step=0.01, link_type=1):
    return [captured(raw, start + index * step, link_type)
            for index, raw in enumerate(raw_packets)]


def analyze(raw_packets, path="capture.pcap", *, start=1700000000.0, step=0.01):
    return analyze_frames(frame_sequence(raw_packets, start=start, step=step), path)


def write_pcap(path: str | Path, raw_packets, *, start=1700000000.0, step=0.01):
    write_pcap_frames(path, frame_sequence(raw_packets, start=start, step=step), 1)
    return Path(path)


def write_pcapng(path: str | Path, raw_packets, *, start=1700000000.0, step=0.01):
    with Path(path).open("wb") as handle:
        writer = dpkt.pcapng.Writer(handle, linktype=dpkt.pcap.DLT_EN10MB)
        for index, raw in enumerate(raw_packets):
            writer.writepkt(raw, ts=start + index * step)
        writer.close()
    return Path(path)
