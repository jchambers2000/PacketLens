"""Parser-neutral capture analysis and production dpkt entry points."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from packetlens.findings import generate_findings
from packetlens.investigation import (build_conversations, build_dns_activities,
                                      build_investigation_summary)
from packetlens.models import CaptureAnalysis, PacketRecord
from packetlens.capture_backend import CaptureBackendError
from packetlens.dpkt_backend import DpktCaptureBackend


DNS_RESPONSE_CODES = {0: "No error", 1: "Format error", 2: "Server failure",
                      3: "Name error", 4: "Not implemented", 5: "Refused"}


class CaptureError(Exception):
    """A capture could not be read or did not contain packets."""



def explain_packet(protocol: str, description: str, flags: str = "") -> str:
    if protocol == "TCP":
        if "S" in flags and "A" not in flags:
            context = "It begins a TCP connection attempt. A matching SYN-ACK would indicate a responding service."
        elif "S" in flags and "A" in flags:
            context = "It acknowledges a connection request. The packet alone does not prove the connection is safe."
        elif "P" in flags and "A" in flags:
            context = "PSH and ACK indicate application data delivery and acknowledgment on an established connection."
        else:
            context = "It is part of TCP connection state or data transfer."
    elif protocol == "DNS":
        context = "It is part of name resolution. DNS traffic is common and is not inherently suspicious."
    elif protocol in ("ICMP", "ICMPv6"):
        context = "It is a network control or reachability message and may be routine diagnostic traffic."
    elif protocol == "ARP":
        context = "It maps a local IPv4 address to a hardware address on the same network segment."
    elif protocol == "UDP":
        context = "UDP sends a datagram without establishing a connection or guaranteeing delivery."
    else:
        context = "The available fields do not identify a more specific purpose."
    return f"{description}. {context} This packet alone does not establish whether the traffic is malicious."



def analyze_records(records: list[PacketRecord], path: str | Path = "capture.pcap", *,
                    parser_backend: str = "normalized",
                    parser_diagnostics: list[str] | None = None) -> CaptureAnalysis:
    """Build all investigation products from parser-neutral packet records."""
    if not records:
        raise CaptureError("The capture is empty or contains no readable packets.")

    sources = {p.source for p in records if p.source != "—"}
    destinations = {p.destination for p in records if p.destination != "—"}
    protocol_counts = Counter(p.protocol for p in records)
    endpoints = Counter(address for packet in records
                        for address in {packet.source, packet.destination} if address != "—")
    endpoint_bytes = Counter()
    for packet in records:
        for address in {packet.source, packet.destination} - {"—"}:
            endpoint_bytes[address] += packet.length
    talker_stats = [(address, count, endpoint_bytes[address])
                    for address, count in endpoints.most_common(10)]
    start_time = min(p.timestamp for p in records)
    end_time = max(p.timestamp for p in records)
    analysis = CaptureAnalysis(
        path=Path(path), packets=records,
        duration=end_time - start_time,
        unique_sources=sources, unique_destinations=destinations,
        protocol_counts=dict(protocol_counts.most_common()),
        top_talkers=endpoints.most_common(10),
        total_bytes=sum(p.length for p in records),
        unique_ips=sources | destinations,
        top_talker_stats=talker_stats,
        start_time=start_time, end_time=end_time,
        parser_backend=parser_backend,
        parser_diagnostics=list(parser_diagnostics or ()),
    )
    analysis.conversations = build_conversations(records)
    analysis.dns_activities = build_dns_activities(records, DNS_RESPONSE_CODES)
    analysis.findings = generate_findings(
        records, analysis.dns_activities, analysis.conversations)
    analysis.investigation_summary = build_investigation_summary(analysis)
    return analysis


def analyze_frames(frames, path: str | Path = "live-capture.pcap") -> CaptureAnalysis:
    """Analyze copied native frames through the same dpkt normalization pipeline."""
    result = DpktCaptureBackend().normalize_frames(frames)
    return analyze_records(result.records, path, parser_backend="dpkt-live",
                           parser_diagnostics=result.diagnostics)


def analyze_capture(path: str | Path) -> CaptureAnalysis:
    """Analyze an offline capture with the production dpkt backend."""
    capture_path = Path(path)
    if capture_path.suffix.lower() not in {".pcap", ".pcapng"}:
        raise CaptureError("Choose a .pcap or .pcapng capture file.")
    try:
        if capture_path.stat().st_size == 0:
            raise CaptureError("The capture is empty or contains no readable packets.")
        result = DpktCaptureBackend().read(capture_path)
        return analyze_records(result.records, capture_path, parser_backend="dpkt",
                               parser_diagnostics=result.diagnostics)
    except CaptureError:
        raise
    except PermissionError as exc:
        raise CaptureError("PacketLens does not have permission to read this file.") from exc
    except (OSError, CaptureBackendError, ValueError, EOFError) as exc:
        raise CaptureError(f"The capture could not be parsed: {exc}") from exc
