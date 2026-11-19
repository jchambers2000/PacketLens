"""Cached conversation and DNS derivation from normalized packet records."""

from __future__ import annotations

from collections import defaultdict

from packetlens.models import Conversation, DNSActivity, PacketRecord


def _endpoint(address: str, port: int | None) -> tuple[str, int]:
    return address, port if port is not None else 0


def _endpoint_text(endpoint: tuple[str, int]) -> str:
    address, port = endpoint
    formatted = f"[{address}]" if ":" in address else address
    return f"{formatted}:{port}" if port else formatted


def build_conversations(packets: list[PacketRecord]) -> list[Conversation]:
    groups = defaultdict(list)
    for packet in packets:
        transport = packet.transport_protocol or packet.protocol
        if transport not in ("TCP", "UDP") or packet.ip_version not in (4, 6):
            continue
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        endpoint_a, endpoint_b = sorted((source, destination))
        groups[(packet.ip_version, transport, endpoint_a, endpoint_b)].append(packet)

    conversations = []
    for (version, protocol, endpoint_a, endpoint_b), records in groups.items():
        flags = []
        for record in records:
            if record.tcp_flags and record.tcp_flags not in flags:
                flags.append(record.tcp_flags)
        state = "Not applicable"
        if protocol == "TCP":
            state = _tcp_evidence(records)
        conversations.append(Conversation(
            _endpoint_text(endpoint_a), _endpoint_text(endpoint_b), protocol, version,
            len(records), sum(record.length for record in records),
            min(record.timestamp for record in records), max(record.timestamp for record in records),
            tuple(record.number for record in records), ", ".join(flags), state))
    return sorted(conversations, key=lambda item: (-item.packet_count, item.endpoint_a, item.endpoint_b))


def _tcp_evidence(records: list[PacketRecord]) -> str:
    for syn in records:
        if "S" not in syn.tcp_flags or "A" in syn.tcp_flags:
            continue
        syn_ack = next((record for record in records
                        if record.number > syn.number and "S" in record.tcp_flags
                        and "A" in record.tcp_flags and record.source == syn.destination
                        and record.destination == syn.source
                        and record.source_port == syn.destination_port
                        and record.destination_port == syn.source_port), None)
        if syn_ack:
            ack = next((record for record in records
                        if record.number > syn_ack.number and "A" in record.tcp_flags
                        and "S" not in record.tcp_flags and record.source == syn.source
                        and record.destination == syn.destination
                        and record.source_port == syn.source_port
                        and record.destination_port == syn.destination_port), None)
            if ack:
                closure = " Closure indicator observed." if any(
                    "F" in item.tcp_flags or "R" in item.tcp_flags for item in records) else ""
                return "Three-way handshake observed." + closure
            return "SYN and SYN-ACK observed; final ACK not observed."
    if any("S" in record.tcp_flags and "A" not in record.tcp_flags for record in records):
        return "Connection request observed; handshake incomplete in this capture."
    if any("F" in record.tcp_flags or "R" in record.tcp_flags for record in records):
        return "Closure indicator observed; connection establishment not observed."
    return "TCP packets observed; connection establishment not observed."


def build_dns_activities(packets: list[PacketRecord], response_codes: dict[int, str]) -> list[DNSActivity]:
    queries = {}
    groups = {}
    for packet in packets:
        if packet.protocol != "DNS" or not packet.dns_name:
            continue
        if not packet.dns_is_response:
            group_key = (packet.dns_name.casefold(), packet.dns_query_type,
                         packet.source, packet.destination)
            queries[(packet.dns_id, packet.source, packet.source_port,
                     packet.destination, packet.destination_port)] = group_key
            group = groups.setdefault(group_key, _dns_group(packet.dns_name, packet.dns_query_type,
                                                             packet.source, packet.destination))
            group["queries"] += 1
            group["packets"].append(packet.number)

    for packet in packets:
        if packet.protocol != "DNS" or not packet.dns_is_response or not packet.dns_name:
            continue
        query_key = (packet.dns_id, packet.destination, packet.destination_port,
                     packet.source, packet.source_port)
        group_key = queries.get(query_key)
        if group_key is None:
            group_key = (packet.dns_name.casefold(), packet.dns_query_type,
                         packet.destination, packet.source)
        group = groups.setdefault(group_key, _dns_group(packet.dns_name, packet.dns_query_type,
                                                         packet.destination, packet.source))
        group["responses"] += 1
        if packet.dns_response_code not in (None, 0):
            group["failed"] += 1
        group["packets"].append(packet.number)
        group["statuses"].add(response_codes.get(packet.dns_response_code,
                                                  f"Code {packet.dns_response_code}"))
        group["answers"].update(packet.dns_answers)

    result = []
    for group in groups.values():
        status = ", ".join(sorted(group["statuses"])) if group["responses"] else "No response observed"
        result.append(DNSActivity(
            group["domain"], group["type"], group["source"], group["destination"],
            group["queries"], group["responses"], status,
            tuple(sorted(group["answers"])), tuple(sorted(group["packets"])), group["failed"]))
    return sorted(result, key=lambda item: (-item.query_count, item.domain.casefold(), item.source))


def _dns_group(domain, query_type, source, destination):
    return {"domain": domain, "type": query_type or "Unknown", "source": source,
            "destination": destination, "queries": 0, "responses": 0,
            "failed": 0, "statuses": set(), "answers": set(), "packets": []}


def build_investigation_summary(analysis) -> str:
    conversation_count = len(analysis.conversations)
    dns_queries = sum(item.query_count for item in analysis.dns_activities)
    protocols = []
    if any(item.protocol == "TCP" for item in analysis.conversations):
        protocols.append("TCP connections")
    if dns_queries:
        protocols.append("DNS activity")
    activity = " and ".join(protocols) + " were observed" if protocols else "No TCP or DNS activity was identified"
    observation_word = "observation" if len(analysis.findings) == 1 else "observations"
    return (f"This capture contains {len(analysis.packets):,} packets across "
            f"{conversation_count:,} network conversations. {activity}. "
            f"{len(analysis.findings):,} security {observation_word} are available for review.")
