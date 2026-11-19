from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFormLayout,
                               QFrame, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView,
                               QLabel, QProgressBar, QPushButton, QScrollArea, QSizePolicy,
                               QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from packetlens.discovery import DiscoveryError, validate_scan_target
from packetlens.live_capture import (LiveCaptureError, NetworkInterface,
                                     enumerate_interfaces, npcap_available)


class NetworkPage(QWidget):
    capture_start_requested = Signal(object)
    capture_stop_requested = Signal()
    capture_save_requested = Signal()
    scan_start_requested = Signal(object, str)
    scan_stop_requested = Signal()
    investigate_requested = Signal(str)

    def __init__(self):
        super().__init__()
        self.interfaces: list[NetworkInterface] = []
        self.discovered_devices = {}
        self._scan_has_run = False
        self._capture_running = False
        self._scan_running = False

        layout = QVBoxLayout(self)
        title_row = QHBoxLayout()
        title = QLabel("Network")
        title.setObjectName("pageTitle")
        self.refresh_button = QPushButton("Refresh Interfaces")
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        title_row.addWidget(title)
        title_row.addStretch()
        title_row.addWidget(self.refresh_button)
        layout.addLayout(title_row)

        controls = QHBoxLayout()
        controls.setSpacing(12)
        controls.addWidget(self._build_capture_section(), 1)
        controls.addWidget(self._build_discovery_section(), 1)
        layout.addLayout(controls)
        layout.addWidget(self._build_results_splitter(), 1)

        self.capture_start.clicked.connect(self._request_capture)
        self.capture_stop.clicked.connect(self.capture_stop_requested)
        self.capture_save.clicked.connect(self.capture_save_requested)
        self.capture_interface.currentIndexChanged.connect(self._capture_selection_changed)
        self.scan_interface.currentIndexChanged.connect(self._scan_selection_changed)
        self.confirm.toggled.connect(self._update_scan_enabled)
        self.scan_start.clicked.connect(self._request_scan)
        self.scan_stop.clicked.connect(self.scan_stop_requested)
        self.devices.itemSelectionChanged.connect(self._device_selection_changed)
        self.investigate_button.clicked.connect(self._request_investigation)
        self.refresh_interfaces()

    def _build_capture_section(self):
        box = QGroupBox("Live packet capture")
        box.setObjectName("networkControlCard")
        layout = QVBoxLayout(box)
        layout.setSpacing(8)
        selector = QHBoxLayout()
        selector.addWidget(QLabel("Capture adapter"))
        self.capture_interface = QComboBox()
        self.capture_interface.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        selector.addWidget(self.capture_interface, 1)
        self.capture_state = QLabel("READY")
        self.capture_state.setObjectName("networkStateBadge")
        layout.addLayout(selector)
        buttons = QHBoxLayout()
        self.capture_start = QPushButton("Start Capture")
        self.capture_stop = QPushButton("Stop Capture")
        self.capture_save = QPushButton("Save Capture")
        self.capture_stop.setEnabled(False)
        self.capture_save.setEnabled(False)
        buttons.addWidget(self.capture_start)
        buttons.addWidget(self.capture_stop)
        buttons.addWidget(self.capture_save)
        buttons.addWidget(self.capture_state)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.capture_status = QLabel("Select a capture adapter, then start capture explicitly.")
        self.capture_status.setObjectName("networkStatusText")
        self.capture_status.setWordWrap(True)
        layout.addWidget(self.capture_status)
        return box

    def _build_discovery_section(self):
        box = QGroupBox("Local network discovery")
        box.setObjectName("networkControlCard")
        layout = QVBoxLayout(box)
        layout.setSpacing(8)
        selector = QHBoxLayout()
        selector.addWidget(QLabel("Discovery adapter"))
        self.scan_interface = QComboBox()
        self.scan_interface.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        selector.addWidget(self.scan_interface, 1)
        layout.addLayout(selector)
        self.address_details = QLabel("No eligible private local subnet detected.")
        self.address_details.setObjectName("networkAddressText")
        self.address_details.setWordWrap(True)
        layout.addWidget(self.address_details)
        self.confirm = QCheckBox("I authorize scanning this selected local subnet")
        layout.addWidget(self.confirm)
        authorization_row = QHBoxLayout()
        self.scan_start = QPushButton("Start Scan")
        self.scan_stop = QPushButton("Stop Scan")
        self.scan_start.setEnabled(False)
        self.scan_stop.setEnabled(False)
        authorization_row.addWidget(self.scan_start)
        authorization_row.addWidget(self.scan_stop)
        layout.addLayout(authorization_row)
        progress_row = QHBoxLayout()
        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 100)
        self.scan_progress.setFormat("%p%")
        self.scan_progress.setValue(0)
        progress_row.addWidget(self.scan_progress, 1)
        self.results_count = QLabel("0 devices")
        self.results_count.setObjectName("networkResultsCount")
        progress_row.addWidget(self.results_count)
        layout.addLayout(progress_row)
        self.scan_status = QLabel("Discovery is opt-in and uses ARP only; no port scanning is performed.")
        self.scan_status.setObjectName("networkStatusText")
        self.scan_status.setWordWrap(True)
        layout.addWidget(self.scan_status)
        return box

    def _build_results_splitter(self):
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setObjectName("networkResultsSplitter")
        splitter.setChildrenCollapsible(False)

        left = QWidget()
        left.setObjectName("networkResultsPanel")
        left.setMinimumWidth(380)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(12, 10, 12, 12)
        heading = QHBoxLayout()
        title = QLabel("Discovered devices")
        title.setObjectName("sectionTitle")
        heading.addWidget(title)
        heading.addStretch()
        self.results_heading_count = QLabel("0")
        self.results_heading_count.setObjectName("networkResultsCount")
        heading.addWidget(self.results_heading_count)
        left_layout.addLayout(heading)
        self.results_stack = QStackedWidget()
        self.device_empty_state = QLabel("No discovery scan has been run.")
        self.device_empty_state.setObjectName("networkEmptyState")
        self.device_empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.device_empty_state.setWordWrap(True)
        self.results_stack.addWidget(self.device_empty_state)
        self.devices = QTableWidget(0, 4)
        self.devices.setObjectName("devicesTable")
        self.devices.setHorizontalHeaderLabels(("IP address", "MAC address", "Hostname", "Status"))
        self.devices.setSortingEnabled(True)
        self.devices.setAlternatingRowColors(True)
        self.devices.setWordWrap(False)
        self.devices.verticalHeader().hide()
        self.devices.verticalHeader().setDefaultSectionSize(self.devices.fontMetrics().height() + 12)
        self.devices.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.devices.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.devices.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        header = self.devices.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        address_width = self.devices.fontMetrics().horizontalAdvance("255.255.255.255") + 28
        self.devices.setColumnWidth(0, address_width)
        self.devices.setColumnWidth(1, self.devices.fontMetrics().horizontalAdvance("AA:BB:CC:DD:EE:FF") + 28)
        self.devices.setColumnWidth(2, self.devices.fontMetrics().horizontalAdvance("device-name.example.local") + 28)
        self.results_stack.addWidget(self.devices)
        left_layout.addWidget(self.results_stack, 1)
        splitter.addWidget(left)

        self.details_scroll = QScrollArea()
        self.details_scroll.setObjectName("networkDetailsScroll")
        self.details_scroll.setWidgetResizable(True)
        self.details_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.details_body = QWidget()
        self.details_body.setObjectName("networkDeviceDetails")
        details_layout = QVBoxLayout(self.details_body)
        details_layout.setContentsMargins(18, 14, 18, 18)
        details_title = QLabel("Selected device")
        details_title.setObjectName("sectionTitle")
        details_layout.addWidget(details_title)
        self.device_empty_selection = QLabel("Select a discovered device to view its details.")
        self.device_empty_selection.setObjectName("networkEmptyState")
        self.device_empty_selection.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.device_empty_selection.setWordWrap(True)
        details_layout.addWidget(self.device_empty_selection, 1)
        self.device_content = QWidget()
        self.device_content.setObjectName("networkDeviceContent")
        content_layout = QVBoxLayout(self.device_content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        self.device_form = QFormLayout()
        self.device_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.device_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.device_form.setVerticalSpacing(11)
        self.device_values = {}
        for key, caption in (("ip", "IP address"), ("mac", "MAC address"),
                             ("hostname", "Hostname"), ("vendor", "MAC manufacturer"),
                             ("method", "Discovery method"), ("status", "Status")):
            value = QLabel()
            value.setObjectName("networkDetailField")
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            caption_label = QLabel(caption)
            caption_label.setObjectName("networkDetailCaption")
            caption_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
            self.device_values[key] = value
            self.device_form.addRow(caption_label, value)
        content_layout.addLayout(self.device_form)
        note = QLabel(
            "ARP discovery confirms a local response only. It does not provide visibility into all traffic from this device.")
        note.setObjectName("networkStatusText")
        note.setWordWrap(True)
        content_layout.addWidget(note)
        self.investigate_button = QPushButton("Investigate Traffic")
        self.investigate_button.setEnabled(False)
        content_layout.addWidget(self.investigate_button, 0, Qt.AlignmentFlag.AlignLeft)
        content_layout.addStretch()
        details_layout.addWidget(self.device_content, 1)
        self.device_content.hide()
        self.details_scroll.setWidget(self.details_body)
        self.details_scroll.setMinimumWidth(320)
        splitter.addWidget(self.details_scroll)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([650, 430])
        self.results_splitter = splitter
        return splitter

    @staticmethod
    def _interface_id(interface):
        return getattr(interface, "identifier", "") if interface else ""

    def refresh_interfaces(self):
        previous_capture = self._interface_id(self.capture_interface.currentData())
        previous_scan = self._interface_id(self.scan_interface.currentData())
        enumeration_error = ""
        try:
            self.interfaces = enumerate_interfaces()
        except LiveCaptureError as exc:
            self.interfaces = []
            enumeration_error = str(exc)
        self.capture_interface.clear()
        self.scan_interface.clear()
        capture_index = scan_index = -1
        for interface in self.interfaces:
            self.capture_interface.addItem(interface.label, interface)
            if interface.identifier == previous_capture:
                capture_index = self.capture_interface.count() - 1
            if interface.subnet and not interface.is_virtual:
                try:
                    validate_scan_target(interface.subnet, interface)
                except DiscoveryError:
                    continue
                self.scan_interface.addItem(
                    f"{interface.name} — {interface.ipv4} ({interface.subnet})", interface)
                if interface.identifier == previous_scan:
                    scan_index = self.scan_interface.count() - 1
        if capture_index >= 0:
            self.capture_interface.setCurrentIndex(capture_index)
        elif previous_capture:
            self.capture_interface.setCurrentIndex(-1)
        if scan_index >= 0:
            self.scan_interface.setCurrentIndex(scan_index)

        available = npcap_available()
        self._capture_selection_changed()
        if not available:
            self.capture_state.setText("UNAVAILABLE")
            self.capture_status.setText(
                "Npcap was not detected. Live capture and ARP discovery require Npcap; offline analysis still works.")
        elif enumeration_error:
            self.capture_state.setText("UNAVAILABLE")
            self.capture_status.setText(enumeration_error)
        elif not self.interfaces:
            self.capture_state.setText("NO ADAPTER")
            self.capture_status.setText("No capture interfaces were detected.")
        else:
            self.capture_state.setText("READY")
        self.refresh_button.setEnabled(not self._capture_running and not self._scan_running)
        self._scan_selection_changed()

    def _capture_selection_changed(self):
        interface = self.capture_interface.currentData()
        usable = bool(interface and getattr(interface, "is_available", True))
        self.capture_start.setEnabled(
            usable and not self._capture_running and npcap_available())
        if interface is not None and not usable:
            self.capture_state.setText("UNAVAILABLE")
            self.capture_status.setText("The selected capture adapter is currently unavailable.")

    def _request_capture(self):
        interface = self.capture_interface.currentData()
        if interface:
            self.capture_start_requested.emit(interface)

    def _scan_selection_changed(self):
        interface = self.scan_interface.currentData()
        if interface:
            self.address_details.setText(
                f"IPv4: {interface.ipv4}    •    Mask: {interface.netmask}    •    Network: {interface.subnet}")
            self.address_details.setToolTip(
                f"IPv4 {interface.ipv4}; subnet mask {interface.netmask}; network {interface.subnet}")
        else:
            self.address_details.setText("No eligible private local subnet detected.")
            self.address_details.setToolTip("")
        self.confirm.setChecked(False)
        self._update_scan_enabled()

    def _update_scan_enabled(self):
        interface = self.scan_interface.currentData()
        valid = False
        if interface is not None:
            try:
                validate_scan_target(interface.subnet, interface)
                valid = True
            except DiscoveryError:
                pass
        self.scan_start.setEnabled(
            valid and self.confirm.isChecked() and not self.scan_stop.isEnabled() and npcap_available())

    def _request_scan(self):
        interface = self.scan_interface.currentData()
        if interface and self.confirm.isChecked():
            self.scan_start_requested.emit(interface, interface.subnet)

    def set_capture_running(self, running: bool, packet_count: int = 0):
        self._capture_running = running
        self.capture_interface.setEnabled(not running)
        interface = self.capture_interface.currentData()
        self.capture_start.setEnabled(
            not running and bool(interface) and getattr(interface, "is_available", True)
            and npcap_available())
        self.capture_stop.setEnabled(running)
        self.capture_save.setEnabled(not running and packet_count > 0)
        self.capture_state.setText("CAPTURING" if running else "STOPPED")
        self.capture_status.setText(
            f"Capturing on the selected adapter — {packet_count:,} packet(s), limit 10,000."
            if running else f"Capture stopped — {packet_count:,} packet(s) available in memory.")
        self.refresh_button.setEnabled(not self._capture_running and not self._scan_running)

    def set_capture_stopping(self):
        self.capture_stop.setEnabled(False)
        self.capture_state.setText("STOPPING")
        self.capture_status.setText("Stopping capture on the selected adapter…")

    def set_capture_error(self, message: str):
        self._capture_running = False
        self.capture_state.setText("ERROR")
        self.capture_status.setText(message)
        self.capture_interface.setEnabled(True)
        self.capture_stop.setEnabled(False)
        interface = self.capture_interface.currentData()
        self.capture_start.setEnabled(
            bool(interface) and getattr(interface, "is_available", True)
            and npcap_available())
        self.refresh_button.setEnabled(not self._scan_running)

    def begin_scan(self):
        self._scan_has_run = True
        self._scan_running = True
        self.devices.setSortingEnabled(False)
        self.devices.setRowCount(0)
        self.devices.setSortingEnabled(True)
        self.discovered_devices.clear()
        self._show_device(None)
        self.scan_progress.setValue(0)
        self.scan_start.setEnabled(False)
        self.scan_stop.setEnabled(True)
        self.scan_interface.setEnabled(False)
        self.confirm.setEnabled(False)
        self.scan_status.setText("Scanning the explicitly confirmed local subnet…")
        self.results_count.setText("0 devices")
        self.results_heading_count.setText("0")
        self._show_results_empty("Scanning… responding devices will appear here.")
        self.refresh_button.setEnabled(False)

    def add_device(self, device):
        selected_ip = self._selected_ip()
        self.discovered_devices[device.ip] = device
        self.devices.setSortingEnabled(False)
        for existing_row in range(self.devices.rowCount()):
            if self.devices.item(existing_row, 0).text() == device.ip:
                row = existing_row
                break
        else:
            row = self.devices.rowCount()
            self.devices.insertRow(row)
        for column, value in enumerate((device.ip, device.mac, device.hostname or "Unknown", device.status)):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            self.devices.setItem(row, column, item)
        self.devices.setSortingEnabled(True)
        count = len(self.discovered_devices)
        self.results_count.setText(f"{count:,} device" + ("" if count == 1 else "s"))
        self.results_heading_count.setText(str(count))
        self.results_stack.setCurrentWidget(self.devices)
        if selected_ip:
            self.select_device(selected_ip)
            if selected_ip == device.ip:
                self._show_device(device)

    def _selected_ip(self):
        rows = self.devices.selectionModel().selectedRows()
        if not rows:
            return ""
        item = self.devices.item(rows[0].row(), 0)
        return item.text() if item else ""

    def _device_selection_changed(self):
        device = self.discovered_devices.get(self._selected_ip())
        self._show_device(device)

    def _show_device(self, device):
        if device is None:
            self.device_content.hide()
            self.device_empty_selection.show()
            self.investigate_button.setEnabled(False)
            return
        self.device_empty_selection.hide()
        self.device_content.show()
        values = {
            "ip": device.ip or "Unknown", "mac": device.mac or "Unknown",
            "hostname": device.hostname or "Unknown", "vendor": device.vendor or "Unknown",
            "method": device.discovery_method or "Unknown", "status": device.status or "Unknown",
        }
        for key, value in values.items():
            self.device_values[key].setText(value)
            self.device_values[key].setToolTip(value)
        self.investigate_button.setEnabled(bool(device.ip))
        self.details_scroll.verticalScrollBar().setValue(0)

    def _request_investigation(self):
        selected_ip = self._selected_ip()
        if selected_ip:
            self.investigate_requested.emit(selected_ip)

    def select_device(self, ip: str) -> bool:
        for row in range(self.devices.rowCount()):
            item = self.devices.item(row, 0)
            if item and item.text() == ip:
                self.devices.selectRow(row)
                self.devices.scrollToItem(item)
                return True
        return False

    def set_scan_progress(self, completed: int, total: int):
        self.scan_progress.setValue(round(completed * 100 / total) if total else 0)
        count = len(self.discovered_devices)
        self.scan_status.setText(
            f"Checked {completed:,} of {total:,} local address(es); {count:,} device(s) responded.")

    def finish_scan(self, cancelled: bool = False):
        self._scan_running = False
        self.scan_stop.setEnabled(False)
        self.scan_interface.setEnabled(True)
        self.confirm.setEnabled(True)
        count = len(self.discovered_devices)
        self.scan_status.setText(
            ("Scan stopped" if cancelled else "Scan complete")
            + f" — {count:,} device(s) responded.")
        if count == 0:
            message = ("Scan stopped before any devices responded." if cancelled
                       else "No devices responded on the confirmed local subnet.")
            self._show_results_empty(message)
        self.refresh_button.setEnabled(not self._capture_running)
        self._update_scan_enabled()

    def set_scan_stopping(self):
        self.scan_stop.setEnabled(False)
        self.scan_status.setText("Stopping discovery after the current bounded ARP batch…")

    def set_scan_error(self, message: str):
        self.finish_scan(True)
        self.scan_status.setText(message)
        if not self.discovered_devices:
            self._show_results_empty("Discovery could not complete. Review the status message above.")

    def _show_results_empty(self, message: str):
        self.device_empty_state.setText(message)
        self.results_stack.setCurrentWidget(self.device_empty_state)
