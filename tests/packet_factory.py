"""Small packet-construction DSL used only by deterministic tests.

It preserves the concise ``layer / layer`` notation used by older tests while
serializing packets independently with dpkt.  It is not a compatibility shim
for any external packet library.
"""

from __future__ import annotations

import socket
from pathlib import Path

import dpkt

from tests.packet_fixtures import (MAC_A, MAC_B, analyze as _analyze,
                                   arp as _arp, ethernet, ipv4_icmp,
                                   ipv4_tcp, ipv4_udp, ipv6_tcp, ipv6_udp,
                                   unknown_frame, write_pcap, write_pcapng)


class Layer:
    def __init__(self, **values):
        self.values = values
        self.time = 0.0

    def __truediv__(self, other):
        packet = Packet([self]) / other
        packet.time = self.time
        return packet

    def __bytes__(self):
        packet = Packet([self])
        packet.time = self.time
        return bytes(packet)

    def __len__(self):
        return len(bytes(self))


class Ether(Layer):
    pass


class IP(Layer):
    pass


class IPv6(Layer):
    pass


class TCP(Layer):
    pass


class UDP(Layer):
    pass


class ICMP(Layer):
    pass


class ARP(Layer):
    pass


class Raw(Layer):
    def __init__(self, payload=b""):
        super().__init__(payload=bytes(payload))


class DNSQR(Layer):
    pass


class DNSRR(Layer):
    pass


class DNS(Layer):
    pass


def _mac(value, default):
    return bytes.fromhex(value.replace(":", "")) if value else default


class Packet:
    def __init__(self, layers=None):
        self.layers = list(layers or ())
        self.time = 0.0

    def __truediv__(self, other):
        self.layers.append(other if isinstance(other, Layer) else Raw(other))
        return self

    def _layer(self, kind):
        return next((layer for layer in self.layers if isinstance(layer, kind)), None)

    def __bytes__(self):
        ether = self._layer(Ether)
        ip4, ip6 = self._layer(IP), self._layer(IPv6)
        tcp, udp = self._layer(TCP), self._layer(UDP)
        dns, icmp, arp = self._layer(DNS), self._layer(ICMP), self._layer(ARP)
        raw = self._layer(Raw)
        payload = raw.values["payload"] if raw is not None else b""
        if dns is not None:
            question = dns.values.get("qd")
            answer = dns.values.get("an")
            name = (question.values.get("qname", "example.test") if question is not None else "")
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            qtype = question.values.get("qtype", "A") if question is not None else "A"
            qtype = {"A": 1, "AAAA": 28, "MX": 15}.get(qtype, qtype)
            message = dpkt.dns.DNS(id=dns.values.get("id", 0),
                qd=[dpkt.dns.DNS.Q(name=name, type=qtype)] if question is not None else [])
            if dns.values.get("qr"):
                message.qr = dpkt.dns.DNS_R
                message.rcode = dns.values.get("rcode", 0)
                if answer is not None:
                    rr_type = {"A": 1, "AAAA": 28}.get(answer.values.get("type", "A"), 1)
                    rr = dpkt.dns.DNS.RR(name=answer.values.get("rrname", name), type=rr_type, ttl=60)
                    if rr_type == 1:
                        rr.ip = socket.inet_aton(answer.values.get("rdata", "0.0.0.0"))
                    else:
                        rr.ip6 = socket.inet_pton(socket.AF_INET6, answer.values.get("rdata", "::"))
                    message.an = [rr]
            payload = bytes(message)
            if tcp is not None:
                payload = len(payload).to_bytes(2, "big") + payload
        network = ip4 if ip4 is not None else ip6
        src = network.values.get("src", "10.0.0.1" if ip4 is not None else "2001:db8::1") if network is not None else None
        dst = network.values.get("dst", "10.0.0.2" if ip4 is not None else "2001:db8::2") if network is not None else None
        if tcp is not None:
            values = tcp.values
            maker = ipv4_tcp if ip4 is not None else ipv6_tcp
            result = maker(src, dst, values.get("sport", 20), values.get("dport", 80),
                           values.get("flags", ""), values.get("seq", 0), values.get("ack", 0),
                           values.get("window", 8192), payload)
        elif udp is not None:
            values = udp.values
            maker = ipv4_udp if ip4 is not None else ipv6_udp
            result = maker(src, dst, values.get("sport", 53), values.get("dport", 53), payload)
        elif icmp is not None and ip4 is not None:
            result = ipv4_icmp(src, dst, icmp.values.get("type", 8))
        elif arp is not None:
            result = _arp(arp.values.get("psrc", "0.0.0.0"), arp.values.get("pdst", "0.0.0.0"),
                          operation=arp.values.get("op", 1),
                          src_mac=_mac(arp.values.get("hwsrc"), MAC_A),
                          dst_mac=_mac(arp.values.get("hwdst"), b"\0" * 6))
        elif ether is not None:
            result = unknown_frame(payload)
        else:
            result = unknown_frame(payload)
        if ether is not None and len(result) >= 14:
            result = (_mac(ether.values.get("dst"), MAC_B) +
                      _mac(ether.values.get("src"), MAC_A) + result[12:])
        return result

    def __len__(self):
        return len(bytes(self))


def analyze_packets(packets, path="capture.pcap"):
    packets = list(packets)
    timestamps = [float(packet.time) for packet in packets]
    start = timestamps[0] if timestamps else 0.0
    step = (timestamps[1] - start) if len(timestamps) > 1 else 0.01
    return _analyze([bytes(packet) for packet in packets], path, start=start, step=step)


def wrpcap(path, packets):
    packets = list(packets)
    start = float(packets[0].time) if packets else 0.0
    step = float(packets[1].time) - start if len(packets) > 1 else 0.01
    return write_pcap(path, [bytes(packet) for packet in packets], start=start, step=step)


class PcapNgWriter:
    def __init__(self, path):
        self.path = Path(path)
        self.packets = []

    def __enter__(self):
        return self

    def write(self, packet):
        self.packets.append(packet)

    def __exit__(self, *_args):
        start = float(self.packets[0].time) if self.packets else 0.0
        write_pcapng(self.path, [bytes(packet) for packet in self.packets], start=start)
