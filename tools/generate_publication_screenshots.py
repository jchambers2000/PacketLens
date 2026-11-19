"""Generate deterministic, sanitized documentation screenshots without network I/O."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication, QMainWindow, QTextBrowser

from packetlens.app import PacketLensWindow
from packetlens.discovery import DiscoveredDevice
from packetlens.live_capture import NetworkInterface
from packetlens.models import CaptureAnalysis, Conversation, DNSActivity, Finding, PacketRecord
from packetlens.reports import build_html_report


OUTPUT = ROOT / "docs" / "screenshots"
BASE_TIME = 1_710_000_000.0


def record(number: int, source: str, destination: str, protocol: str, length: int,
           description: str, *, sport: int | None = None, dport: int | None = None,
           flags: str = "", dns_name: str = "") -> PacketRecord:
    return PacketRecord(
        number=number, timestamp=BASE_TIME + number / 10,
        relative_time=number / 10, source=source, destination=destination,
        protocol=protocol, length=length, description=description,
        source_port=sport, destination_port=dport, tcp_flags=flags,
        raw_summary=f"Synthetic {protocol} packet {number}",
        explanation=("Deterministic demonstration evidence generated for documentation. "
                     "It does not represent captured network traffic."),
        details={"Dataset": "Synthetic documentation fixture", "Evidence": description},
        technical_details=f"Synthetic packet {number}; no payload or real network identifier.",
        ip_version=4, dns_id=100 if dns_name else None, dns_name=dns_name,
        dns_query_type="A" if dns_name else "", transport_protocol="UDP" if protocol == "DNS" else protocol,
    )


def synthetic_analysis() -> CaptureAnalysis:
    packets = [
        record(1, "192.0.2.10", "198.51.100.20", "TCP", 74, "HTTPS connection request", sport=51000, dport=443, flags="S"),
        record(2, "198.51.100.20", "192.0.2.10", "TCP", 74, "HTTPS connection acknowledged", sport=443, dport=51000, flags="SA"),
        record(3, "192.0.2.10", "198.51.100.20", "TCP", 66, "TCP handshake completion", sport=51000, dport=443, flags="A"),
        record(4, "192.0.2.10", "198.51.100.20", "TCP", 517, "Encrypted application data", sport=51000, dport=443, flags="PA"),
        record(5, "198.51.100.20", "192.0.2.10", "TCP", 931, "Encrypted application response", sport=443, dport=51000, flags="PA"),
        record(6, "192.0.2.10", "203.0.113.53", "DNS", 86, "Query A portal.example.test", sport=53000, dport=53, dns_name="portal.example.test"),
        record(7, "203.0.113.53", "192.0.2.10", "DNS", 118, "Response A portal.example.test → 198.51.100.20", sport=53, dport=53000, dns_name="portal.example.test"),
        record(8, "192.0.2.10", "198.51.100.30", "UDP", 90, "Time synchronization request", sport=54000, dport=123),
        record(9, "198.51.100.30", "192.0.2.10", "UDP", 90, "Time synchronization response", sport=123, dport=54000),
        record(10, "192.0.2.10", "198.51.100.40", "ICMP", 98, "Echo request demonstration"),
        record(11, "198.51.100.40", "192.0.2.10", "ICMP", 98, "Echo reply demonstration"),
        record(12, "192.0.2.10", "198.51.100.20", "TCP", 66, "HTTPS session close", sport=51000, dport=443, flags="FA"),
    ]
    conversations = [
        Conversation("192.0.2.10:51000", "198.51.100.20:443", "TCP", 4, 6, 1728,
                     BASE_TIME + .1, BASE_TIME + 1.2, (1, 2, 3, 4, 5, 12),
                     "S SA A PA FA", "Three-way handshake observed"),
        Conversation("192.0.2.10:53000", "203.0.113.53:53", "UDP", 4, 2, 204,
                     BASE_TIME + .6, BASE_TIME + .7, (6, 7)),
        Conversation("192.0.2.10:54000", "198.51.100.30:123", "UDP", 4, 2, 180,
                     BASE_TIME + .8, BASE_TIME + .9, (8, 9)),
    ]
    dns = [DNSActivity("portal.example.test", "A", "192.0.2.10:53000", "203.0.113.53:53",
                       1, 1, "Successful response", ("198.51.100.20",), (6, 7))]
    findings = [
        Finding("DNS query activity", "Informational",
                "One DNS query and its response were observed in the synthetic demonstration dataset.",
                (6, 7), "192.0.2.10", "Confirm the domain is expected for the demonstration workflow.",
                "At least one outbound DNS query was observed.",
                "DNS shows which names an application attempted to resolve; ordinary queries are expected.",
                ("192.0.2.10", "203.0.113.53")),
        Finding("Repeated demonstration service traffic", "Review",
                "Several packets support one synthetic HTTPS relationship. This is a documentation example, not an incident.",
                (1, 2, 3, 4, 5, 12), "198.51.100.20",
                "Open the supporting packets and review the synthetic handshake evidence.",
                "The documentation fixture intentionally includes a complete TCP conversation.",
                "Grouped evidence demonstrates the investigation workflow without making a threat claim.",
                ("192.0.2.10", "198.51.100.20")),
    ]
    return CaptureAnalysis(
        path=Path("Synthetic-Demo-Capture.pcap"), packets=packets, duration=1.2,
        unique_sources={p.source for p in packets}, unique_destinations={p.destination for p in packets},
        protocol_counts={"TCP": 6, "DNS": 2, "UDP": 2, "ICMP": 2},
        top_talkers=[("192.0.2.10", 12), ("198.51.100.20", 6), ("203.0.113.53", 2)],
        findings=findings, total_bytes=sum(p.length for p in packets),
        unique_ips={p.source for p in packets} | {p.destination for p in packets},
        top_talker_stats=[("192.0.2.10", 12, 2312), ("198.51.100.20", 6, 2428),
                          ("203.0.113.53", 2, 204)],
        start_time=BASE_TIME, end_time=BASE_TIME + 1.2, capture_state="Synthetic demo",
        conversations=conversations, dns_activities=dns,
        investigation_summary=("Synthetic demonstration capture with documented TCP, DNS, UDP, and ICMP evidence. "
                               "No real network traffic is represented."),
    )


def save_window(window: PacketLensWindow, name: str) -> None:
    QCoreApplication.processEvents()
    if not window.grab().save(str(OUTPUT / name), "PNG"):
        raise RuntimeError(f"Unable to save {name}")


def configure_network_demo(window: PacketLensWindow) -> None:
    page = window.network
    interface = NetworkInterface("synthetic-ethernet", "Synthetic Ethernet",
                                 "Documentation-only adapter", "192.168.50.10",
                                 "255.255.255.0", "192.168.50.0/24", False)
    page.interfaces = [interface]
    page.capture_interface.clear()
    page.scan_interface.clear()
    page.capture_interface.addItem(interface.label, interface)
    page.scan_interface.addItem(f"{interface.name} — {interface.ipv4} ({interface.subnet})", interface)
    page.capture_state.setText("DEMO")
    page.capture_status.setText("Synthetic demonstration — no live capture was started.")
    page.begin_scan()
    for device in (
        DiscoveredDevice("192.168.50.1", "02:00:00:00:50:01", "demo-router.test",
                         "Responded (synthetic)", "Synthetic Demo Vendor"),
        DiscoveredDevice("192.168.50.25", "02:00:00:00:50:25", "demo-workstation.test",
                         "Responded (synthetic)", "Synthetic Demo Vendor"),
    ):
        page.add_device(device)
    page.set_scan_progress(254, 254)
    page.finish_scan(False)
    page.scan_status.setText("Synthetic demonstration — no ARP scan was performed.")
    page.select_device("192.168.50.25")


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("PacketLens Screenshot Generator")
    window = PacketLensWindow()
    window.resize(1440, 900)
    window._apply_analysis(synthetic_analysis())
    configure_network_demo(window)
    window.show()

    window.navigation.setCurrentRow(0)
    save_window(window, "overview.png")

    window.navigation.setCurrentRow(1)
    window.traffic.view_buttons.button(0).click()
    window.traffic.table.selectRow(3)
    save_window(window, "traffic-packet-inspection.png")

    window.traffic.view_buttons.button(1).click()
    save_window(window, "network-conversations.png")

    window.traffic.view_buttons.button(2).click()
    save_window(window, "dns-investigation.png")

    window.navigation.setCurrentRow(2)
    save_window(window, "network-discovery.png")

    window.navigation.setCurrentRow(3)
    save_window(window, "findings.png")
    window.close()

    report = QMainWindow()
    report.setWindowTitle("PacketLens — Synthetic HTML Report Preview")
    browser = QTextBrowser()
    browser.setHtml(build_html_report(
        synthetic_analysis(), datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)))
    report.setCentralWidget(browser)
    report.resize(1280, 900)
    report.show()
    QCoreApplication.processEvents()
    if not report.grab().save(str(OUTPUT / "html-report-preview.png"), "PNG"):
        raise RuntimeError("Unable to save report preview")
    report.close()
    print(f"Generated 7 sanitized screenshots in {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
