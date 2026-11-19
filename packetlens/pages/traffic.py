from datetime import datetime
import ipaddress

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt, Signal
from PySide6.QtGui import QFont, QIntValidator
from PySide6.QtWidgets import (QAbstractItemView, QFormLayout, QGroupBox, QHeaderView,
                               QComboBox, QLabel, QLineEdit, QScrollArea, QSplitter, QTableView,
                               QTextEdit, QToolButton, QVBoxLayout, QWidget, QHBoxLayout,
                               QPushButton, QButtonGroup, QStackedWidget, QTableWidget,
                               QTableWidgetItem)

from packetlens.models import CaptureAnalysis, PacketRecord


class PacketTableModel(QAbstractTableModel):
    headers = ("Number", "Time", "Source", "Destination", "Protocol", "Length", "Description")

    def __init__(self):
        super().__init__()
        self.packets: list[PacketRecord] = []

    def set_packets(self, packets):
        self.beginResetModel()
        self.packets = list(packets)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.packets)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.headers)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        packet = self.packets[index.row()]
        values = (packet.number, f"{packet.relative_time:.6f}", packet.source,
                  packet.destination, packet.protocol, packet.length, packet.description)
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.UserRole):
            return values[index.column()]
        if role == Qt.ItemDataRole.ToolTipRole and index.column() in (2, 3, 6):
            return str(values[index.column()])
        return None


class PacketFilter(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.device_ip = ""
        self.packet_numbers: set[int] = set()
        self.text_search = ""
        self.protocol = "All"
        self.ip_address = ""
        self.ip_valid = True
        self.port: int | None = None
        self.port_valid = True

    def _change(self, name, value):
        self.beginFilterChange()
        setattr(self, name, value)
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def set_device_ip(self, address: str):
        self._change("device_ip", address)

    def set_packet_numbers(self, packet_numbers):
        self._change("packet_numbers", set(packet_numbers))

    def set_text_search(self, text: str):
        self._change("text_search", text.strip().casefold())

    def set_protocol(self, protocol: str):
        self._change("protocol", protocol)

    def set_ip_filter(self, text: str):
        text = text.strip()
        try:
            normalized, valid = (str(ipaddress.ip_address(text)), True) if text else ("", True)
        except ValueError:
            normalized, valid = "", False
        self.beginFilterChange()
        self.ip_address, self.ip_valid = normalized, valid
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def set_port_filter(self, text: str):
        text = text.strip()
        valid = not text or (text.isdigit() and 0 <= int(text) <= 65535)
        self.beginFilterChange()
        self.port_valid = valid
        self.port = int(text) if valid and text else None
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def filterAcceptsRow(self, row, parent):
        model = self.sourceModel()
        packet = model.packets[row]
        if self.packet_numbers and packet.number not in self.packet_numbers:
            return False
        if self.device_ip and packet.source != self.device_ip and packet.destination != self.device_ip:
            return False
        if not self.ip_valid or not self.port_valid:
            return False
        if self.ip_address and packet.source != self.ip_address and packet.destination != self.ip_address:
            return False
        if self.port is not None and self.port not in (packet.source_port, packet.destination_port):
            return False
        protocol = packet.protocol.upper()
        requested = self.protocol.upper()
        if requested != "ALL":
            if requested == "ICMP":
                matches_protocol = protocol in ("ICMP", "ICMPV6")
            elif requested == "OTHER":
                matches_protocol = protocol not in ("TCP", "UDP", "DNS", "ICMP", "ICMPV6", "ARP")
            else:
                matches_protocol = protocol == requested
            if not matches_protocol:
                return False
        if self.text_search:
            searchable = " ".join((packet.source, packet.destination, packet.protocol,
                                   packet.description, packet.dns_name)).casefold()
            if self.text_search not in searchable:
                return False
        return True


class TrafficPage(QWidget):
    device_requested = Signal(str)
    filter_changed = Signal(int, int)

    def __init__(self):
        super().__init__()
        self.known_devices = {}
        layout = QVBoxLayout(self)
        title = QLabel("Traffic")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        segment_row = QHBoxLayout()
        self.view_buttons = QButtonGroup(self)
        self.view_buttons.setExclusive(True)
        for index, name in enumerate(("Packets", "Conversations", "DNS")):
            button = QPushButton(name)
            button.setCheckable(True)
            button.setObjectName("segmentButton")
            self.view_buttons.addButton(button, index)
            segment_row.addWidget(button)
        segment_row.addStretch()
        layout.addLayout(segment_row)
        self.view_stack = QStackedWidget()
        self.packet_page = QWidget()
        packet_layout = QVBoxLayout(self.packet_page)
        packet_layout.setContentsMargins(0, 0, 0, 0)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search traffic or domains…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(180)
        self.search.setToolTip("Search IP addresses, descriptions, protocols, and observed domains.")
        self.protocol_filter = QComboBox()
        self.protocol_filter.setObjectName("trafficProtocolFilter")
        self.protocol_filter.addItems(("All", "TCP", "UDP", "DNS", "ICMP", "ARP", "Other"))
        self.protocol_filter.setToolTip("Show only the selected protocol category.")
        self.ip_filter = QLineEdit()
        self.ip_filter.setPlaceholderText("Exact IP")
        self.ip_filter.setClearButtonEnabled(True)
        self.ip_filter.setMinimumWidth(150)
        self.ip_filter.setToolTip("Exact source or destination IPv4/IPv6 address.")
        self.port_filter = QLineEdit()
        self.port_filter.setPlaceholderText("Exact port")
        self.port_filter.setClearButtonEnabled(True)
        self.port_filter.setMinimumWidth(100)
        self.port_filter.setValidator(QIntValidator(0, 65535, self.port_filter))
        self.port_filter.setToolTip("Exact TCP/UDP source or destination port (0–65535).")
        self.clear_filters_button = QPushButton("Clear Filters")
        self.match_count = QLabel("Showing 0 of 0 packets")
        self.match_count.setObjectName("trafficMatchCount")
        filter_toolbar = QHBoxLayout()
        filter_toolbar.setSpacing(8)
        filter_toolbar.addWidget(self.search, 2)
        filter_toolbar.addWidget(self.protocol_filter)
        filter_toolbar.addWidget(self.ip_filter)
        filter_toolbar.addWidget(self.port_filter)
        filter_toolbar.addWidget(self.clear_filters_button)
        filter_toolbar.addStretch()
        filter_toolbar.addWidget(self.match_count)
        packet_layout.addLayout(filter_toolbar)
        self.device_filter_bar = QWidget()
        self.device_filter_bar.setObjectName("filterBanner")
        filter_layout = QHBoxLayout(self.device_filter_bar)
        filter_layout.setContentsMargins(10, 5, 8, 5)
        self.device_filter_label = QLabel()
        self.clear_device_filter_button = QPushButton("Clear Investigation Filter")
        self.clear_device_filter_button.clicked.connect(self.clear_device_filter)
        filter_layout.addWidget(self.device_filter_label)
        filter_layout.addStretch()
        filter_layout.addWidget(self.clear_device_filter_button)
        packet_layout.addWidget(self.device_filter_bar)
        self.device_filter_bar.hide()
        self.model = PacketTableModel()
        self.proxy = PacketFilter()
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(self.table.fontMetrics().height() + 14)
        self.table.horizontalHeader().setMinimumSectionSize(72)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column in (0, 1, 4, 5):
            self.table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        address_width = self.table.fontMetrics().horizontalAdvance("2001:db8:ffff:ffff:ffff:ffff")
        self.table.setColumnWidth(2, address_width)
        self.table.setColumnWidth(3, address_width)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.inspector = PacketInspector()
        self.inspector.device_requested.connect(self.device_requested)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.inspector)
        splitter.setSizes([500, 300])
        packet_layout.addWidget(splitter, 1)
        self.filter_empty = QLabel("No packets match the current filters.")
        self.filter_empty.setObjectName("emptyState")
        self.filter_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.filter_empty.setWordWrap(True)
        self.filter_empty.hide()
        packet_layout.addWidget(self.filter_empty)
        self.conversation_page = self._build_conversation_page()
        self.dns_page = self._build_dns_page()
        self.view_stack.addWidget(self.packet_page)
        self.view_stack.addWidget(self.conversation_page)
        self.view_stack.addWidget(self.dns_page)
        layout.addWidget(self.view_stack, 1)
        self.search.textChanged.connect(self._filters_changed)
        self.protocol_filter.currentTextChanged.connect(self._filters_changed)
        self.ip_filter.textChanged.connect(self._filters_changed)
        self.port_filter.textChanged.connect(self._filters_changed)
        self.clear_filters_button.clicked.connect(self.clear_general_filters)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        self.view_buttons.idClicked.connect(self.view_stack.setCurrentIndex)
        self.view_buttons.button(0).setChecked(True)

    def _build_conversation_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        note = QLabel("Bidirectional TCP and UDP packets are grouped by exact endpoints. Double-click a conversation to inspect its packets.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.conversation_table = QTableWidget(0, 9)
        self.conversation_table.setHorizontalHeaderLabels(
            ("Endpoint A", "Endpoint B", "Protocol", "Packets", "Bytes",
             "First seen", "Last seen", "Duration", "TCP evidence"))
        self._configure_summary_table(self.conversation_table)
        address_width = self.conversation_table.fontMetrics().horizontalAdvance(
            "[2001:db8:ffff:ffff:ffff:ffff]:65535")
        self.conversation_table.setColumnWidth(0, address_width)
        self.conversation_table.setColumnWidth(1, address_width)
        self.conversation_table.itemDoubleClicked.connect(self._open_conversation)
        layout.addWidget(self.conversation_table, 1)
        return page

    def _build_dns_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        note = QLabel("DNS queries and responses are correlated when transaction and endpoint evidence is available. Double-click an entry to inspect supporting packets.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.dns_table = QTableWidget(0, 8)
        self.dns_table.setHorizontalHeaderLabels(
            ("Domain", "Type", "Source", "Destination", "Queries", "Responses",
             "Response status / resolved IPs", "Packets"))
        self._configure_summary_table(self.dns_table)
        address_width = self.dns_table.fontMetrics().horizontalAdvance("2001:db8:ffff:ffff:ffff:ffff")
        self.dns_table.setColumnWidth(2, address_width)
        self.dns_table.setColumnWidth(3, address_width)
        self.dns_table.itemDoubleClicked.connect(self._open_dns)
        layout.addWidget(self.dns_table, 1)
        return page

    @staticmethod
    def _configure_summary_table(table):
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.verticalHeader().hide()
        table.verticalHeader().setDefaultSectionSize(table.fontMetrics().height() + 14)
        table.setSortingEnabled(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().setStretchLastSection(True)

    def set_packets(self, packets, clear_investigation=True):
        if clear_investigation:
            self.clear_investigation_filter()
        self.model.set_packets(packets)
        self.inspector.clear()
        self._update_filter_status()
        self._set_derived([], [])

    def set_analysis(self, analysis: CaptureAnalysis, clear_investigation=True):
        if clear_investigation:
            self.clear_investigation_filter()
        self.model.set_packets(analysis.packets)
        self.inspector.clear()
        self._update_filter_status()
        self._set_derived(analysis.conversations, analysis.dns_activities)

    def _set_derived(self, conversations, dns_activities):
        self.conversation_table.setSortingEnabled(False)
        self.conversation_table.setRowCount(len(conversations))
        for row, conversation in enumerate(conversations):
            first = self._summary_time(conversation.first_seen)
            last = self._summary_time(conversation.last_seen)
            tcp_evidence = conversation.tcp_state
            if conversation.protocol == "TCP" and conversation.tcp_flags:
                tcp_evidence += f" Flags: {conversation.tcp_flags}."
            values = (conversation.endpoint_a, conversation.endpoint_b, conversation.protocol,
                      conversation.packet_count, conversation.total_bytes, first, last,
                      f"{conversation.duration:.6f} s", tcp_evidence)
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, conversation.packet_numbers)
                self.conversation_table.setItem(row, column, item)
        self.conversation_table.setSortingEnabled(True)

        self.dns_table.setSortingEnabled(False)
        self.dns_table.setRowCount(len(dns_activities))
        for row, activity in enumerate(dns_activities):
            resolved = ", ".join(activity.resolved_ips) or "No resolved IP observed"
            status = f"{activity.response_status}; {resolved}"
            values = (activity.domain, activity.query_type, activity.source, activity.destination,
                      activity.query_count, activity.response_count, status,
                      ", ".join(map(str, activity.packet_numbers)))
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, activity.packet_numbers)
                self.dns_table.setItem(row, column, item)
        self.dns_table.setSortingEnabled(True)

    @staticmethod
    def _summary_time(timestamp):
        try:
            return datetime.fromtimestamp(timestamp).astimezone().strftime("%H:%M:%S.%f")[:-3]
        except (OSError, OverflowError, ValueError):
            return f"{timestamp:.6f}"

    def _open_conversation(self, item):
        references = self.conversation_table.item(item.row(), 0).data(Qt.ItemDataRole.UserRole) or ()
        self.filter_by_packet_numbers(references, "Conversation investigation")

    def _open_dns(self, item):
        domain = self.dns_table.item(item.row(), 0).text()
        references = self.dns_table.item(item.row(), 0).data(Qt.ItemDataRole.UserRole) or ()
        self.filter_by_packet_numbers(references, f"DNS investigation: {domain}")

    def set_known_devices(self, devices):
        self.known_devices = dict(devices)
        self.inspector.set_known_devices(self.known_devices)

    def filter_by_device(self, address: str) -> int:
        try:
            normalized = str(ipaddress.ip_address(address))
        except ValueError:
            self.clear_investigation_filter()
            return 0
        self.proxy.set_packet_numbers(())
        self.proxy.set_device_ip(normalized)
        self.device_filter_bar.show()
        available = sum(packet.source == normalized or packet.destination == normalized
                        for packet in self.model.packets)
        if available:
            self.device_filter_label.setText(
                f"Device investigation: {normalized} — {available:,} captured packet(s); "
                "general filters refine this set")
        else:
            self.device_filter_label.setText(
                f"No captured traffic matches device {normalized}. "
                "ARP discovery does not capture device traffic.")
        return self._update_filter_status()

    def clear_device_filter(self):
        self.clear_investigation_filter()

    def clear_investigation_filter(self):
        self.proxy.set_device_ip("")
        self.proxy.set_packet_numbers(())
        self.device_filter_bar.hide()
        self.device_filter_label.clear()
        self._update_filter_status()

    def filter_by_packet_numbers(self, packet_numbers, label: str) -> int:
        references = tuple(dict.fromkeys(int(number) for number in packet_numbers))
        self.proxy.set_device_ip("")
        self.proxy.set_packet_numbers(references)
        available = sum(packet.number in self.proxy.packet_numbers for packet in self.model.packets)
        self.device_filter_label.setText(
            f"{label} — {available:,} supporting packet(s); general filters refine this evidence set")
        self.device_filter_bar.show()
        self.view_buttons.button(0).setChecked(True)
        self.view_stack.setCurrentIndex(0)
        count = self._update_filter_status()
        if count:
            self.table.selectRow(0)
        return count

    @property
    def device_filter_ip(self):
        return self.proxy.device_ip

    def _filters_changed(self, _value=None):
        self.proxy.set_text_search(self.search.text())
        self.proxy.set_protocol(self.protocol_filter.currentText())
        self.proxy.set_ip_filter(self.ip_filter.text())
        self.proxy.set_port_filter(self.port_filter.text())
        self._update_filter_status()

    def _update_filter_status(self):
        count, total = self.proxy.rowCount(), self.model.rowCount()
        self.match_count.setText(f"Showing {count:,} of {total:,} packets")
        invalid = []
        if not self.proxy.ip_valid:
            invalid.append("Enter a complete IPv4 or IPv6 address.")
        if not self.proxy.port_valid:
            invalid.append("Port must be a number from 0 through 65535.")
        self.filter_empty.setText(" ".join(invalid) or "No packets match the current filters.")
        self.filter_empty.setVisible(total > 0 and count == 0)
        self.filter_changed.emit(count, total)
        return count

    def clear_general_filters(self):
        self.search.clear()
        self.protocol_filter.setCurrentText("All")
        self.ip_filter.clear()
        self.port_filter.clear()
        self._filters_changed()

    def _selection_changed(self):
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            self.inspector.clear()
            return
        source_index = self.proxy.mapToSource(indexes[0])
        packet = self.model.packets[source_index.row()]
        self.inspector.set_packet(packet)

    @property
    def selected_packet_number(self):
        return self.inspector.packet_number

    def select_packet_number(self, packet_number: int) -> bool:
        self.filter_by_packet_numbers((packet_number,), "Packet evidence")
        for row, packet in enumerate(self.model.packets):
            if packet.number == packet_number:
                source_index = self.model.index(row, 0)
                proxy_index = self.proxy.mapFromSource(source_index)
                if proxy_index.isValid():
                    self.table.selectRow(proxy_index.row())
                    self.table.scrollTo(proxy_index)
                    return True
        return False

    @property
    def investigation_active(self):
        return bool(self.proxy.device_ip or self.proxy.packet_numbers)


class PacketInspector(QScrollArea):
    device_requested = Signal(str)

    def __init__(self):
        super().__init__()
        self.packet_number: int | None = None
        self.current_packet: PacketRecord | None = None
        self.known_devices = {}
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        self.layout = QVBoxLayout(body)
        self.header = QLabel("Select a packet to inspect it.")
        self.header.setObjectName("inspectorHeader")
        self.header.setWordWrap(True)
        self.layout.addWidget(self.header)
        self.network_group, self.network_form, self.network_values = self._form_group("Network information")
        self.protocol_group, self.protocol_form, self.protocol_values = self._form_group("Protocol details")
        self.layout.addWidget(self.network_group)
        self.device_actions = QWidget()
        self.device_actions_layout = QHBoxLayout(self.device_actions)
        self.device_actions_layout.setContentsMargins(0, 0, 0, 0)
        self.layout.addWidget(self.device_actions)
        self.layout.addWidget(self.protocol_group)
        explanation_group = QGroupBox("What does this mean?")
        explanation_layout = QVBoxLayout(explanation_group)
        self.explanation = QLabel()
        self.explanation.setWordWrap(True)
        self.explanation.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        explanation_layout.addWidget(self.explanation)
        self.layout.addWidget(explanation_group)
        self.technical_toggle = QToolButton()
        self.technical_toggle.setText("Show technical details")
        self.technical_toggle.setCheckable(True)
        self.technical_toggle.toggled.connect(self._toggle_technical)
        self.layout.addWidget(self.technical_toggle)
        self.technical = QTextEdit()
        self.technical.setReadOnly(True)
        self.technical.setFont(QFont("Consolas", 9))
        self.technical.setMinimumHeight(220)
        self.technical.hide()
        self.layout.addWidget(self.technical)
        self.layout.addStretch()
        self.setWidget(body)
        self.clear()

    @staticmethod
    def _form_group(title):
        group = QGroupBox(title)
        form = QFormLayout(group)
        form.setHorizontalSpacing(24)
        return group, form, []

    @staticmethod
    def _plain_label(text):
        label = QLabel(str(text))
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        label.setWordWrap(True)
        return label

    @staticmethod
    def _clear_form(form, values):
        while form.rowCount():
            form.removeRow(0)
        values.clear()

    def _add_row(self, form, values, name, value):
        label = self._plain_label(value)
        values.append(label)
        form.addRow(name, label)

    def clear(self):
        self.packet_number = None
        self.current_packet = None
        self.header.setText("Select a packet to inspect it.")
        self._clear_form(self.network_form, self.network_values)
        self._clear_form(self.protocol_form, self.protocol_values)
        self.network_group.hide()
        self._clear_device_actions()
        self.protocol_group.hide()
        self.explanation.clear()
        self.explanation.parentWidget().hide()
        self.technical.clear()
        self.technical_toggle.hide()
        self.technical.hide()

    def set_packet(self, packet: PacketRecord):
        self.packet_number = packet.number
        self.current_packet = packet
        self.header.setText(f"Packet {packet.number}  •  {packet.protocol}\n{packet.description}")
        self._clear_form(self.network_form, self.network_values)
        try:
            timestamp = datetime.fromtimestamp(packet.timestamp).astimezone().strftime(
                "%Y-%m-%d %H:%M:%S.%f %Z")
        except (OSError, OverflowError, ValueError):
            timestamp = f"Unix timestamp {packet.timestamp:.6f}"
        rows = [("Source IP", packet.source), ("Destination IP", packet.destination)]
        if packet.source_port is not None:
            rows.extend((("Source port", packet.source_port), ("Destination port", packet.destination_port)))
        rows.extend((("Packet length", f"{packet.length:,} bytes"), ("Timestamp", timestamp)))
        for name, value in rows:
            self._add_row(self.network_form, self.network_values, name, value)
        self.network_group.show()
        self._clear_device_actions()
        for address in dict.fromkeys((packet.source, packet.destination)):
            if address in self.known_devices:
                button = QToolButton()
                button.setText(f"View discovered device {address}")
                button.clicked.connect(lambda _checked=False, ip=address: self.device_requested.emit(ip))
                self.device_actions_layout.addWidget(button)
        self.device_actions_layout.addStretch()
        self.device_actions.setVisible(self.device_actions_layout.count() > 1)

        self._clear_form(self.protocol_form, self.protocol_values)
        for name, value in packet.details.items():
            self._add_row(self.protocol_form, self.protocol_values, name, value)
        self.protocol_group.setVisible(bool(packet.details))
        self.explanation.setText(packet.explanation)
        self.explanation.parentWidget().show()
        self.technical.setPlainText(
            f"Normalized packet summary\n{'-' * 25}\n{packet.raw_summary}\n\n"
            f"Available protocol-layer information\n{'-' * 36}\n{packet.technical_details}")
        self.technical_toggle.setChecked(False)
        self.technical_toggle.setText("Show technical details")
        self.technical_toggle.show()

    def _toggle_technical(self, visible):
        self.technical.setVisible(visible)
        self.technical_toggle.setText("Hide technical details" if visible else "Show technical details")

    def set_known_devices(self, devices):
        self.known_devices = dict(devices)
        if self.current_packet is not None:
            self.set_packet(self.current_packet)

    def _clear_device_actions(self):
        while self.device_actions_layout.count():
            item = self.device_actions_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.device_actions.hide()
