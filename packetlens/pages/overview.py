from datetime import datetime

from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QPushButton,
                               QProgressBar, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from packetlens.models import CaptureAnalysis


class OverviewPage(QWidget):
    open_requested = Signal()

    def __init__(self):
        super().__init__()
        self.discovered_device_count = 0
        self.capture_packet_count = 0
        self.capture_byte_count = 0
        self.capture_state = "No capture loaded"
        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        title = QLabel("Overview")
        title.setObjectName("pageTitle")
        self.open_button = QPushButton("Open Capture")
        self.open_button.clicked.connect(self.open_requested)
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.open_button)
        layout.addLayout(header)
        self.network_summary = QLabel()
        self.network_summary.setObjectName("summaryBanner")
        self.network_summary.setWordWrap(True)
        layout.addWidget(self.network_summary)
        self._update_network_summary()
        self.empty = QLabel("Open a PCAP or PCAPNG file to begin an offline investigation.")
        self.empty.setObjectName("emptyState")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.empty, 1)

        self.content = QWidget()
        content_layout = QVBoxLayout(self.content)
        self.filename = QLabel()
        self.filename.setObjectName("captureName")
        content_layout.addWidget(self.filename)
        self.context = QLabel()
        self.context.setWordWrap(True)
        self.context.setStyleSheet("color:#8fa0b7; margin-bottom:8px")
        content_layout.addWidget(self.context)
        metrics = QGridLayout()
        self.metric_labels = []
        for column, caption in enumerate(("Packets", "Duration", "Captured bytes", "Unique endpoints")):
            panel = QWidget()
            panel.setObjectName("card")
            panel_layout = QVBoxLayout(panel)
            value = QLabel("0")
            value.setObjectName("metric")
            panel_layout.addWidget(value)
            panel_layout.addWidget(QLabel(caption))
            metrics.addWidget(panel, 0, column)
            self.metric_labels.append(value)
        content_layout.addLayout(metrics)
        self.investigation_metrics = QLabel()
        self.investigation_metrics.setObjectName("summaryBanner")
        content_layout.addWidget(self.investigation_metrics)
        self.investigation_summary = QLabel()
        self.investigation_summary.setWordWrap(True)
        self.investigation_summary.setStyleSheet("color:#b9c9de; padding:4px 2px 8px 2px")
        content_layout.addWidget(self.investigation_summary)
        tables = QHBoxLayout()
        self.protocol_panel = QWidget()
        self.protocol_panel.setObjectName("card")
        protocol_layout = QVBoxLayout(self.protocol_panel)
        protocol_title = QLabel("Protocol distribution")
        protocol_title.setObjectName("sectionTitle")
        protocol_layout.addWidget(protocol_title)
        self.protocol_bars = {}
        for protocol in ("TCP", "UDP", "ICMP", "DNS", "ARP", "Other"):
            row = QHBoxLayout()
            name = QLabel(protocol)
            name.setFixedWidth(52)
            bar = QProgressBar()
            bar.setObjectName("protocolBar")
            bar.setRange(0, 1)
            bar.setTextVisible(True)
            row.addWidget(name)
            row.addWidget(bar, 1)
            protocol_layout.addLayout(row)
            self.protocol_bars[protocol] = bar
        protocol_layout.addStretch()
        self.talker_panel = QWidget()
        self.talker_panel.setObjectName("card")
        talker_layout = QVBoxLayout(self.talker_panel)
        talker_title = QLabel("Top network talkers")
        talker_title.setObjectName("sectionTitle")
        talker_layout.addWidget(talker_title)
        self.talkers = self._table("Top network talkers", ("IP address", "Packets", "Bytes"))
        talker_layout.addWidget(self.talkers)
        tables.addWidget(self.protocol_panel)
        tables.addWidget(self.talker_panel)
        content_layout.addLayout(tables, 1)
        layout.addWidget(self.content, 1)
        self.content.hide()

    @staticmethod
    def _table(title, headers):
        table = QTableWidget(0, len(headers))
        table.setProperty("sectionTitle", title)
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().hide()
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        return table

    def set_analysis(self, analysis: CaptureAnalysis):
        self.empty.hide()
        self.content.show()
        prefix = "LIVE  •  " if analysis.source_mode == "live" else "IMPORTED  •  "
        self.filename.setText(prefix + analysis.filename)
        self.capture_packet_count = len(analysis.packets)
        self.capture_byte_count = analysis.total_bytes
        self.capture_state = analysis.capture_state
        self._update_network_summary()
        values = (str(len(analysis.packets)), f"{analysis.duration:.3f} s",
                  f"{analysis.total_bytes:,}", str(len(analysis.unique_ips)))
        for label, value in zip(self.metric_labels, values):
            label.setText(value)
        start = self._format_time(analysis.start_time)
        end = self._format_time(analysis.end_time)
        self.context.setText(
            f"Mode: {analysis.source_mode.title()}    State: {analysis.capture_state}    "
            f"Start: {start}    End: {end}")
        tcp_conversations = sum(item.protocol == "TCP" for item in analysis.conversations)
        udp_conversations = sum(item.protocol == "UDP" for item in analysis.conversations)
        dns_queries = sum(item.query_count for item in analysis.dns_activities)
        self.investigation_metrics.setText(
            f"TCP conversations: {tcp_conversations:,}    •    UDP conversations: {udp_conversations:,}    •    "
            f"DNS queries: {dns_queries:,}    •    Security observations: {len(analysis.findings):,}")
        self.investigation_summary.setText(analysis.investigation_summary)
        categories = {name: 0 for name in self.protocol_bars}
        for protocol, count in analysis.protocol_counts.items():
            if protocol in ("TCP", "UDP", "DNS", "ARP"):
                categories[protocol] += count
            elif protocol in ("ICMP", "ICMPv6"):
                categories["ICMP"] += count
            else:
                categories["Other"] += count
        total = max(1, len(analysis.packets))
        for protocol, bar in self.protocol_bars.items():
            count = categories[protocol]
            bar.setRange(0, total)
            bar.setValue(count)
            bar.setFormat(f"{count:,}  ({count / total:.0%})")
        self._fill(self.talkers, analysis.top_talker_stats)

    @staticmethod
    def _format_time(timestamp):
        if timestamp is None:
            return "Unavailable"
        try:
            return datetime.fromtimestamp(timestamp).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        except (OSError, OverflowError, ValueError):
            return f"Unix {timestamp:.3f}"

    @staticmethod
    def _fill(table, rows):
        rows = list(rows)
        table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                text = f"{value:,}" if isinstance(value, int) else str(value)
                table.setItem(row, column, QTableWidgetItem(text))

    def clear_analysis(self, message="Open a capture or start a live capture to begin an investigation."):
        self.content.hide()
        self.empty.setText(message)
        self.empty.show()

    def set_discovered_device_count(self, count: int):
        self.discovered_device_count = max(0, count)
        self._update_network_summary()

    def set_capture_activity(self, state: str, packets: int = 0, captured_bytes: int = 0):
        self.capture_state = state
        self.capture_packet_count = packets
        self.capture_byte_count = captured_bytes
        self._update_network_summary()

    def _update_network_summary(self):
        self.network_summary.setText(
            f"Discovered devices: {self.discovered_device_count:,}    •    "
            f"Capture packets: {self.capture_packet_count:,}    •    "
            f"Captured bytes: {self.capture_byte_count:,}    •    "
            f"Capture state: {self.capture_state}")
