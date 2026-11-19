"""Conservative, explainable security observations."""

from __future__ import annotations

from collections import Counter, defaultdict

from packetlens.models import Conversation, DNSActivity, Finding, PacketRecord

COMMON_DESTINATION_PORTS = {20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123,
                            143, 161, 389, 443, 445, 465, 587, 636, 993, 995,
                            853, 1433, 1883, 1900, 3306, 3389, 3478, 5222, 5223,
                            5228, 5349, 5353, 5355, 5432, 8000, 8008, 8080, 8081,
                            8443, 8883, 8888}


def generate_findings(packets: list[PacketRecord],
                      dns_activities: list[DNSActivity] | None = None,
                      conversations: list[Conversation] | None = None) -> list[Finding]:
    """Return observations; heuristics are signals, never proof of an attack."""
    findings: list[Finding] = []
    dns_packets = [p for p in packets if p.protocol == "DNS" and p.destination_port == 53]
    if dns_packets:
        findings.append(Finding(
            "DNS query activity", "Informational",
            f"Observed {len(dns_packets)} packet(s) sent to DNS port 53. DNS is routine "
            "network behavior; review names in packet details if relevant.",
            tuple(p.number for p in dns_packets), "",
            "Inspect the queried domains and compare them with expected application activity.",
            "At least one outbound DNS query was observed.",
            "DNS establishes which names applications attempted to resolve; ordinary queries are expected.",
            tuple(dict.fromkeys(p.source for p in dns_packets if p.source != "—"))))

    activities = dns_activities or []
    for activity in activities:
        failed = activity.failed_response_count >= 3
        if failed:
            findings.append(Finding(
                "Repeated failed DNS lookups", "Review",
                f"{activity.failed_response_count} DNS responses for {activity.domain} reported "
                f"{activity.response_status}. Repeated failures may also result from stale configuration or typing errors.",
                activity.packet_numbers[:20], activity.source,
                "Review the requesting endpoint and confirm whether the domain is expected and correctly configured.",
                "Three or more non-success DNS responses were grouped for one domain and client.",
                "Persistent lookup failures can reveal configuration problems or repeated automated name generation.",
                (activity.source, activity.destination)))
        long_labels = [label for label in activity.domain.split(".") if len(label) >= 50]
        if long_labels:
            findings.append(Finding(
                "Unusually long DNS label", "Review",
                f"A label in {activity.domain} is {max(map(len, long_labels))} characters long. "
                "Long labels are permitted by DNS and may be legitimate.",
                activity.packet_numbers[:20], activity.source,
                "Inspect the full domain and identify the application responsible for the lookup.",
                "A DNS label contained at least 50 characters.",
                "Long labels can carry encoded identifiers, but length alone does not establish misuse.",
                (activity.source, activity.destination)))

    total_dns_queries = sum(activity.query_count for activity in activities)
    if total_dns_queries >= 100:
        references = tuple(number for activity in activities
                           for number in activity.packet_numbers)[:20]
        endpoints = tuple(dict.fromkeys(activity.source for activity in activities))[:10]
        findings.append(Finding(
            "High DNS query volume", "Review",
            f"Observed {total_dns_queries} DNS queries in this capture. Busy clients and DNS servers can legitimately exceed this threshold.",
            references, endpoints[0] if endpoints else "",
            "Compare query timing and domains with expected workload for the requesting endpoints.",
            "At least 100 DNS queries were observed in one capture.",
            "High volume can help prioritize DNS review but is not evidence of malicious behavior.", endpoints))

    unusual = _unusual_port_evidence(packets, conversations or [])
    if unusual:
        references = tuple(dict.fromkeys(number for item in unusual for number in item[4]))
        endpoints = tuple(dict.fromkeys(endpoint for item in unusual
                                        for endpoint in (item[1], item[2])))
        summaries = [f"{source} → {destination}:{port} ({len(refs)} packets, {protocol})"
                     for protocol, source, destination, port, refs in unusual]
        preview = "; ".join(summaries[:5])
        if len(summaries) > 5:
            preview += f"; plus {len(summaries) - 5} more grouped target(s)"
        title = (f"Repeated traffic to uncommon port {unusual[0][3]}" if len(unusual) == 1
                 else "Repeated traffic to uncommon service ports")
        findings.append(Finding(
            title, "Review",
            f"Observed direction-supported traffic to {len(unusual)} uncommon high-port target(s): {preview}. "
            "Custom services and peer-to-peer applications can legitimately use these ports.",
            references, unusual[0][2],
            "Validate the destination services and compare the supporting conversations with expected applications.",
            "At least five packets targeted an uncommon high port in an observed TCP client-SYN direction or a bidirectional UDP request/response direction.",
            "Direction evidence avoids treating normal server replies to client ephemeral ports as unusual service access.",
            endpoints))

    pair_counts = Counter((p.source, p.destination) for p in packets if p.source != "—")
    high_pairs = [((source, destination), count) for (source, destination), count in pair_counts.items()
                  if count >= 100]
    if high_pairs:
        refs = tuple(p.number for p in packets
                     if any(p.source == pair[0] and p.destination == pair[1]
                            for pair, _count in high_pairs))
        endpoints = tuple(dict.fromkeys(endpoint for pair, _count in high_pairs for endpoint in pair))
        pair_preview = "; ".join(f"{source} → {destination} ({count} packets)"
                                 for (source, destination), count in high_pairs[:5])
        findings.append(Finding(
            "High-volume endpoint relationships", "Informational",
            f"Observed {len(high_pairs)} directed endpoint relationship(s) above the volume threshold: {pair_preview}. "
            "This often reflects ordinary browsing, streaming, backups, or other bulk transfers.", refs,
            high_pairs[0][0][0],
            "Compare timing and endpoints with expected high-volume application activity.",
            "At least 100 packets shared a directed source and destination pair; related pairs are grouped.",
            "Packet volume prioritizes relationships for review but does not indicate suspicious behavior by itself.",
            endpoints))

    syn_groups: dict[tuple[str, int | None, str, int | None], list[int]] = defaultdict(list)
    responses: set[tuple[str, int | None, str, int | None]] = set()
    for packet in packets:
        if packet.protocol != "TCP":
            continue
        key = (packet.source, packet.source_port, packet.destination, packet.destination_port)
        if "S" in packet.tcp_flags and "A" not in packet.tcp_flags:
            syn_groups[key].append(packet.number)
        if "S" in packet.tcp_flags and "A" in packet.tcp_flags:
            responses.add((packet.destination, packet.destination_port,
                           packet.source, packet.source_port))
    for key, references in syn_groups.items():
        if len(references) >= 10 and key not in responses:
            source, _, destination, port = key
            findings.append(Finding(
                "Repeated TCP SYN packets without observed response", "Suspicious",
                f"Observed {len(references)} SYN packets from {source} to {destination}:{port} "
                "without a matching SYN-ACK in this capture. Packet loss, asymmetric capture, "
                "or an unavailable service can also explain this.",
                tuple(references), destination,
                "Review capture completeness and inspect the destination service and response path.",
                "Ten or more TCP SYN packets lacked a matching reversed SYN-ACK in the capture.",
                "Repeated unanswered connection attempts may indicate an unavailable service, packet loss, or asymmetric visibility.",
                (source, destination)))
    return findings


def _unusual_port_evidence(packets: list[PacketRecord], conversations: list[Conversation]):
    by_number = {packet.number: packet for packet in packets}
    evidence = []
    for conversation in conversations:
        records = [by_number[number] for number in conversation.packet_numbers if number in by_number]
        if conversation.protocol == "TCP":
            syn_packets = [packet for packet in records
                           if "S" in packet.tcp_flags and "A" not in packet.tcp_flags]
            if not syn_packets:
                continue
            initial = min(syn_packets, key=lambda packet: packet.number)
            port = initial.destination_port
            if port is None or port <= 1024 or port in COMMON_DESTINATION_PORTS:
                continue
            matching = [packet.number for packet in records
                        if packet.source == initial.source
                        and packet.destination == initial.destination
                        and packet.source_port == initial.source_port
                        and packet.destination_port == port]
            if len(matching) >= 5:
                evidence.append(("TCP", initial.source, initial.destination, port, matching))
        elif conversation.protocol == "UDP" and records:
            ordered = sorted(records, key=lambda packet: packet.number)
            initial = ordered[0]
            reverse_seen = any(
                packet.source == initial.destination and packet.destination == initial.source
                and packet.source_port == initial.destination_port
                and packet.destination_port == initial.source_port for packet in ordered[1:])
            if not reverse_seen:
                continue
            port = initial.destination_port
            if port is None or port <= 1024 or port in COMMON_DESTINATION_PORTS:
                continue
            matching = [packet.number for packet in ordered
                        if packet.source == initial.source and packet.destination == initial.destination
                        and packet.source_port == initial.source_port
                        and packet.destination_port == port]
            if len(matching) >= 5:
                evidence.append(("UDP", initial.source, initial.destination, port, matching))
    return evidence
