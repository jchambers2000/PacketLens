"""Production offline parser backed by dpkt; no live device access."""

from __future__ import annotations

import socket
import struct
from pathlib import Path

import dpkt

from packetlens.capture_backend import BackendResult, CapturedFrame, CaptureBackendError
from packetlens.capture_files import iter_capture_frames
from packetlens.models import PacketRecord


DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
DNS_PORTS = {53, 5353}
MISSING = "—"


def _address(raw: bytes, family: int) -> str:
    return socket.inet_ntop(family, raw)


def _flags(value: int) -> str:
    values = ((dpkt.tcp.TH_FIN, "F"), (dpkt.tcp.TH_SYN, "S"), (dpkt.tcp.TH_RST, "R"),
              (dpkt.tcp.TH_PUSH, "P"), (dpkt.tcp.TH_ACK, "A"), (dpkt.tcp.TH_URG, "U"),
              (dpkt.tcp.TH_ECE, "E"), (dpkt.tcp.TH_CWR, "C"))
    return "".join(label for bit, label in values if value & bit)


def _wire_name(payload: bytes, offset: int, seen: set[int] | None = None) -> tuple[str, int]:
    labels: list[str] = []
    seen = set() if seen is None else seen
    while offset < len(payload):
        length = payload[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            if pointer in seen or pointer >= len(payload):
                raise ValueError("invalid DNS pointer")
            seen.add(pointer)
            suffix, _ = _wire_name(payload, pointer, seen)
            return ".".join(labels + ([suffix] if suffix else [])), offset + 2
        offset += 1
        if length == 0:
            return ".".join(labels), offset
        if length > 63 or offset + length > len(payload):
            raise ValueError("invalid DNS label")
        labels.append(payload[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    raise ValueError("truncated DNS name")


def _dns(transport):
    if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        return None
    if transport.sport not in DNS_PORTS and transport.dport not in DNS_PORTS:
        return None
    payload = bytes(transport.data)
    if isinstance(transport, dpkt.tcp.TCP):
        if len(payload) < 2:
            return None
        expected = int.from_bytes(payload[:2], "big")
        if expected > len(payload) - 2:
            return None
        payload = payload[2:2 + expected]
    try:
        return dpkt.dns.DNS(payload)
    except (dpkt.NeedData, dpkt.UnpackError, ValueError):
        return payload if len(payload) >= 12 else None


def _dns_metadata(dns):
    if dns is None:
        return None, "", "", False, None, ()
    if isinstance(dns, bytes):
        try:
            identifier, flags, questions, _an, _ns, _ar = struct.unpack("!HHHHHH", dns[:12])
            name, offset = _wire_name(dns, 12) if questions else ("", 12)
            qtype = struct.unpack("!H", dns[offset:offset + 2])[0] if questions and offset + 4 <= len(dns) else 0
            response = bool(flags & 0x8000)
            return identifier, name, DNS_TYPES.get(qtype, str(qtype)), response, flags & 15 if response else None, ()
        except (struct.error, ValueError):
            return None, "", "Unknown", False, None, ()
    question = dns.qd[0] if dns.qd else None
    name = str(question.name).rstrip(".") if question is not None else ""
    qtype = DNS_TYPES.get(int(question.type), str(question.type)) if question is not None else "Unknown"
    answers: list[str] = []
    for answer in dns.an:
        try:
            if answer.type == dpkt.dns.DNS_A:
                answers.append(_address(answer.ip, socket.AF_INET))
            elif answer.type == dpkt.dns.DNS_AAAA:
                answers.append(_address(answer.ip6, socket.AF_INET6))
        except (AttributeError, OSError, ValueError):
            continue
    response = bool(dns.qr)
    return dns.id, name, qtype, response, int(dns.rcode) if response else None, tuple(dict.fromkeys(answers))


def _network(frame: CapturedFrame):
    raw, link = frame.data, frame.link_type
    if link == dpkt.pcap.DLT_EN10MB:
        return dpkt.ethernet.Ethernet(raw).data
    if link in {dpkt.pcap.DLT_RAW, 101, 228, 229}:
        version = raw[0] >> 4 if raw else 0
        return dpkt.ip.IP(raw) if version == 4 else dpkt.ip6.IP6(raw) if version == 6 else None
    if link in {dpkt.pcap.DLT_NULL, dpkt.pcap.DLT_LOOP} and len(raw) >= 4:
        family = int.from_bytes(raw[:4], "big" if link == dpkt.pcap.DLT_LOOP else "little")
        payload = raw[4:]
        return dpkt.ip.IP(payload) if family == socket.AF_INET else dpkt.ip6.IP6(payload) if family in {24, 28, 30, socket.AF_INET6} else None
    if link == dpkt.pcap.DLT_LINUX_SLL:
        return dpkt.sll.SLL(raw).data
    if link == dpkt.pcap.DLT_LINUX_SLL2:
        return dpkt.sll2.SLL2(raw).data
    return None


def _description(protocol: str, destination_port: int | None, flags: str, dns_name: str,
                 dns_response: bool, control_type: int | None = None, arp_op: int | None = None) -> str:
    if protocol == "DNS":
        return f"DNS {'response received' if dns_response else 'lookup requested'}" + (f" for {dns_name}" if dns_name else "")
    if protocol == "TCP":
        if "S" in flags and "A" in flags: return "Server acknowledged a TCP connection request"
        if "S" in flags: return f"TCP connection request to port {destination_port}"
        if "R" in flags: return "TCP connection reset"
        if "F" in flags: return "TCP connection close request"
        if "P" in flags and "A" in flags: return "TCP application data transferred over an established connection"
        if flags == "A": return "TCP acknowledgment for an established connection"
        return f"TCP segment sent to destination port {destination_port}"
    if protocol == "UDP": return f"UDP datagram sent to destination port {destination_port}"
    if protocol == "ARP": return "Device requesting the MAC address for a local IP" if arp_op == 1 else "Device provided its MAC address for a local IP"
    if protocol == "ICMP": return "ICMP echo request" if control_type == 8 else "ICMP echo reply" if control_type == 0 else f"ICMP control message (type {control_type})"
    if protocol == "ICMPv6": return "ICMPv6 echo request" if control_type == 128 else "ICMPv6 echo reply" if control_type == 129 else f"ICMPv6 control message (type {control_type})"
    if protocol in {"IPv4", "IPv6"}: return f"{protocol} network packet"
    if protocol == "Malformed": return "Incomplete or malformed network packet"
    if protocol == "LLDP": return "Link Layer Discovery Protocol announcement"
    if protocol == "STP": return "Spanning Tree Protocol control frame"
    return "Unrecognized network frame"


class DpktCaptureBackend:
    name = "dpkt"

    def read(self, path: str | Path) -> BackendResult:
        return self.normalize_frames(iter_capture_frames(path))

    def normalize_frames(self, frames) -> BackendResult:
        """Normalize captured frames without a capture-file round trip."""
        records: list[PacketRecord] = []
        diagnostics: list[str] = []
        first_timestamp: float | None = None
        for number, frame in enumerate(frames, 1):
            if frame.timestamp is not None and first_timestamp is None:
                first_timestamp = frame.timestamp
            try:
                records.append(self._normalize(number, frame, first_timestamp or 0.0))
            except (dpkt.NeedData, dpkt.UnpackError, OSError, ValueError, struct.error) as exc:
                diagnostics.append(f"Packet {number}: {type(exc).__name__}: {exc}")
                timestamp = frame.timestamp if frame.timestamp is not None else 0.0
                base_timestamp = timestamp if first_timestamp is None else first_timestamp
                records.append(PacketRecord(number, timestamp, max(0.0, timestamp - base_timestamp),
                    MISSING, MISSING, "Malformed", frame.captured_length,
                    "Incomplete or malformed network packet", raw_summary="Malformed captured frame",
                    explanation="The frame was retained as evidence, but its available bytes could not be decoded.",
                    details={"Parsing note": "The frame was truncated, malformed, or unsupported."},
                    technical_details=frame.data[:512].hex(), raw_bytes=frame.data,
                    captured_length=frame.captured_length, original_length=frame.original_length,
                    link_type=frame.link_type))
        if not records:
            raise CaptureBackendError("The capture is empty or contains no readable packets.")
        return BackendResult(records, diagnostics)

    def _normalize(self, number: int, frame: CapturedFrame, first: float) -> PacketRecord:
        network = _network(frame)
        source = destination = MISSING
        version = 0
        transport = arp = None
        link_protocol = ("STP" if isinstance(network, dpkt.llc.LLC) and isinstance(network.data, dpkt.stp.STP)
                         else "LLDP" if frame.link_type == dpkt.pcap.DLT_EN10MB and len(frame.data) >= 14
                         and int.from_bytes(frame.data[12:14], "big") == 0x88CC else "")
        zero_length_ipv6_payload = False
        if isinstance(network, dpkt.ip.IP):
            source, destination, version, transport = _address(network.src, socket.AF_INET), _address(network.dst, socket.AF_INET), 4, network.data
        elif isinstance(network, dpkt.ip6.IP6):
            source, destination, version, transport = _address(network.src, socket.AF_INET6), _address(network.dst, socket.AF_INET6), 6, network.data
            # A zero payload length requires a Hop-by-Hop Jumbo Payload option.
            # Host offload captures sometimes contain trailing transport-looking
            # bytes without that option; retain them as IPv6 evidence but do not
            # invent ports or TCP state from an invalid length declaration.
            if network.plen == 0 and not network.all_extension_headers:
                transport = None
                zero_length_ipv6_payload = True
        elif isinstance(network, dpkt.arp.ARP):
            arp = network
            source, destination = _address(arp.spa, socket.AF_INET), _address(arp.tpa, socket.AF_INET)
        sport = dport = None
        flags = transport_name = ""
        if isinstance(transport, dpkt.tcp.TCP):
            sport, dport, flags, transport_name = transport.sport, transport.dport, _flags(transport.flags), "TCP"
        elif isinstance(transport, dpkt.udp.UDP):
            sport, dport, transport_name = transport.sport, transport.dport, "UDP"
        dns = _dns(transport)
        dns_id, dns_name, dns_type, dns_response, dns_rcode, dns_answers = _dns_metadata(dns)
        control_type = transport.type if isinstance(transport, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)) else None
        protocol = ("DNS" if dns is not None else "TCP" if isinstance(transport, dpkt.tcp.TCP)
                    else "UDP" if isinstance(transport, dpkt.udp.UDP) else "ICMP" if isinstance(transport, dpkt.icmp.ICMP)
                    else "ICMPv6" if isinstance(transport, dpkt.icmp6.ICMP6) else "ARP" if arp is not None
                    else f"IPv{version}" if version else link_protocol or "Other")
        description = _description(protocol, dport, flags, dns_name, dns_response, control_type,
                                   arp.op if arp is not None else None)
        details: dict[str, str] = {}
        if isinstance(transport, dpkt.tcp.TCP):
            details.update({"TCP flags": flags, "Sequence number": str(transport.seq), "Acknowledgment number": str(transport.ack), "Window size": str(transport.win)})
        if isinstance(transport, dpkt.udp.UDP): details["UDP datagram length"] = str(transport.ulen)
        if dns is not None: details.update({"Queried domain": dns_name or "Unavailable", "DNS query type": dns_type})
        if control_type is not None: details.update({f"{protocol} type": str(control_type), f"{protocol} code": str(transport.code)})
        if arp is not None: details.update({"ARP operation": "Request" if arp.op == 1 else "Reply", "Sender IP / MAC": f"{source} / {arp.sha.hex(':')}", "Target IP / MAC": f"{destination} / {arp.tha.hex(':')}"})
        if zero_length_ipv6_payload:
            details["Parsing note"] = "IPv6 declared a zero-length payload without a Jumbo Payload option; trailing bytes were not interpreted as transport fields."
        if frame.timestamp is None:
            details["Timestamp note"] = "This PCAPNG packet block did not contain a timestamp; 0 is used as an explicit unavailable sentinel."
        timestamp = frame.timestamp if frame.timestamp is not None else 0.0
        return PacketRecord(number, timestamp, max(0.0, timestamp - first), source, destination,
            protocol, frame.captured_length, description, sport, dport, flags,
            f"{source} > {destination}: {protocol}",
            f"{description}. This packet alone does not establish whether the traffic is malicious.",
            details, f"Raw frame ({frame.captured_length} captured / {frame.original_length} original bytes)\n{frame.data[:4096].hex()}",
            version, dns_id, dns_name, dns_type, dns_response, dns_rcode, dns_answers, transport_name,
            frame.data, frame.captured_length, frame.original_length, frame.link_type)
