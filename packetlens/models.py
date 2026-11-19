"""Plain data models shared by the analyzer, UI, and report generator."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PacketRecord:
    number: int
    timestamp: float
    relative_time: float
    source: str
    destination: str
    protocol: str
    length: int
    description: str
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: str = ""
    raw_summary: str = ""
    explanation: str = ""
    details: dict[str, str] = field(default_factory=dict)
    technical_details: str = ""
    ip_version: int = 0
    dns_id: int | None = None
    dns_name: str = ""
    dns_query_type: str = ""
    dns_is_response: bool = False
    dns_response_code: int | None = None
    dns_answers: tuple[str, ...] = ()
    transport_protocol: str = ""
    raw_bytes: bytes = b""
    captured_length: int = 0
    original_length: int = 0
    link_type: int = 0


@dataclass(frozen=True, slots=True)
class Finding:
    title: str
    classification: str
    description: str
    references: tuple[int, ...] = ()
    related_ip: str = ""
    suggested_next_step: str = "Review the supporting packets in context."
    triggering_rule: str = "Rule-based observation"
    why_it_matters: str = "This pattern may provide useful investigative context."
    endpoints: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Conversation:
    endpoint_a: str
    endpoint_b: str
    protocol: str
    ip_version: int
    packet_count: int
    total_bytes: int
    first_seen: float
    last_seen: float
    packet_numbers: tuple[int, ...]
    tcp_flags: str = ""
    tcp_state: str = "Not applicable"

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)


@dataclass(frozen=True, slots=True)
class DNSActivity:
    domain: str
    query_type: str
    source: str
    destination: str
    query_count: int
    response_count: int
    response_status: str
    resolved_ips: tuple[str, ...]
    packet_numbers: tuple[int, ...]
    failed_response_count: int = 0


@dataclass(slots=True)
class CaptureAnalysis:
    path: Path
    packets: list[PacketRecord] = field(default_factory=list)
    duration: float = 0.0
    unique_sources: set[str] = field(default_factory=set)
    unique_destinations: set[str] = field(default_factory=set)
    protocol_counts: dict[str, int] = field(default_factory=dict)
    top_talkers: list[tuple[str, int]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    source_mode: str = "file"
    total_bytes: int = 0
    unique_ips: set[str] = field(default_factory=set)
    top_talker_stats: list[tuple[str, int, int]] = field(default_factory=list)
    start_time: float | None = None
    end_time: float | None = None
    capture_state: str = "Imported"
    conversations: list[Conversation] = field(default_factory=list)
    dns_activities: list[DNSActivity] = field(default_factory=list)
    investigation_summary: str = ""
    parser_backend: str = ""
    parser_diagnostics: list[str] = field(default_factory=list)

    @property
    def filename(self) -> str:
        return self.path.name
