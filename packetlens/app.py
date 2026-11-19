"""Main window, background parsing, and page coordination."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import (QObject, QSettings, QStandardPaths, QThread, QTimer,
                            Signal, Slot, Qt)
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QListWidget,
                               QListWidgetItem, QMainWindow, QMessageBox, QProgressBar,
                               QStackedWidget, QVBoxLayout, QWidget)

from packetlens.analyzer import analyze_capture, analyze_frames
from packetlens.discovery import DiscoveryEngine
from packetlens.display import (DISPLAY_PRESETS, apply_display_preset,
                                saved_display_preset)
from packetlens.live_capture import LiveCaptureEngine, LiveCaptureError
from packetlens.models import CaptureAnalysis
from packetlens.pages.findings import FindingsPage
from packetlens.pages.network import NetworkPage
from packetlens.pages.overview import OverviewPage
from packetlens.pages.reports import ReportsPage
from packetlens.pages.traffic import TrafficPage
from packetlens.reports import write_html_report


STYLE = """
QMainWindow, QWidget { background: #0f141d; color: #dce5f3; }
#sidebar { background: #121a26; border-right: 1px solid #253044; }
#brand { font-weight: 700; color: #f3f7ff; padding: 18px 14px; }
QListWidget#navigation { background: transparent; border: 0; outline: 0; }
QListWidget#navigation::item { padding: 13px 15px; margin: 3px 8px; border-radius: 8px; }
QListWidget#navigation::item:selected { background: #1b4f91; color: white; }
#pageTitle { font-weight: 650; color: #f5f8fd; margin: 4px 0 12px 0; }
#captureName { font-weight: 600; color: #f5f8fd; }
#emptyState { color: #8e9bad; border: 1px dashed #344258; border-radius: 12px; }
#summaryBanner, #filterBanner { background: #152235; color: #b9c9de; border: 1px solid #2b405d; border-radius: 8px; padding: 7px 10px; }
#card { background: #151e2b; border: 1px solid #273348; border-radius: 10px; }
#metric { font-weight: 650; color: #74adff; }
#sectionTitle { font-weight: 600; color: #dbe6f5; }
#inspectorHeader { font-weight: 600; color: #f2f7ff; padding: 5px 2px 9px 2px; }
QPushButton { background: #2466b8; color: white; border: 0; border-radius: 7px; padding: 8px 15px; min-height: 18px; font-weight: 600; }
QPushButton:hover { background: #2e78d2; } QPushButton:disabled { background: #303a49; color: #778294; }
QPushButton#segmentButton { background:#192536; color:#aebbd0; border:1px solid #2b3a50; min-width:100px; }
QPushButton#segmentButton:checked { background:#2466b8; color:white; border-color:#3479c7; }
QLineEdit, QTextEdit { background: #111925; border: 1px solid #2b3a50; border-radius: 7px; padding: 8px; selection-background-color: #2466b8; }
QComboBox { background: #111925; border: 1px solid #2b3a50; border-radius: 7px; padding: 7px; min-width: 220px; }
#displaySize, #trafficProtocolFilter { min-width: 100px; }
QComboBox QAbstractItemView { background: #151e2b; selection-background-color: #254f7d; }
QGroupBox { background: #151e2b; border: 1px solid #273348; border-radius: 10px; margin-top: 12px; padding-top: 12px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 5px; color: #b8c7dc; }
QCheckBox { spacing: 8px; }
QTableView, QTableWidget, QListWidget { background: #131c28; alternate-background-color: #162130; border: 1px solid #28364a; border-radius: 8px; gridline-color: #253247; }
QHeaderView::section { background: #192536; color: #aebbd0; padding: 8px; border: 0; border-bottom: 1px solid #304058; }
QTableView::item, QTableWidget::item { padding: 6px; } QTableView::item:selected, QListWidget::item:selected { background: #254f7d; }
QListWidget::item { border-bottom: 1px solid #273448; padding: 12px; }
QListWidget#findingsList::item { padding:10px 12px; margin:2px 0; border:0; border-bottom:1px solid #273448; }
QListWidget#findingsList::item:selected { background:#254f7d; color:white; border-radius:6px; }
#findingDetails { background:#151e2b; border:1px solid #29374b; border-radius:9px; }
#findingDetails QLabel, #findingDetailContent, #findingsMaster { background:transparent; }
#findingDetailTitle { font-weight:650; color:#f2f7ff; }
#findingDetailBadge { background:#254f7d; color:#dcecff; border-radius:8px; padding:4px 10px; font-weight:600; }
#findingDetailCaption { color:#91a4bd; font-weight:600; }
#findingDetailField { color:#dce5f3; }
#findingEmptyState { color:#8e9bad; padding:30px; }
#findingSeparator { color:#2d3d53; background:#2d3d53; max-height:1px; }
#findingsSplitter::handle { background:#273448; width:2px; }
#networkControlCard QLabel, #networkResultsPanel QLabel, #networkDeviceDetails QLabel, #networkDeviceContent { background:transparent; }
#networkStateBadge { background:#1f4f7d; color:#dcecff; border-radius:8px; padding:3px 9px; font-weight:600; }
#networkStatusText { color:#93a5bc; }
#networkAddressText { color:#c6d5e8; }
#networkResultsCount { color:#8fbaff; font-weight:600; }
#networkResultsPanel, #networkDeviceDetails { background:#151e2b; border:1px solid #29374b; border-radius:9px; }
#networkEmptyState { color:#8493a8; padding:24px; }
#networkDetailCaption { color:#91a4bd; font-weight:600; }
#networkDetailField { color:#dce5f3; }
#networkResultsSplitter::handle { background:#273448; width:2px; }
QProgressBar { background: #182231; border: 0; border-radius: 4px; min-height: 16px; text-align: center; } QProgressBar::chunk { background: #4d91e6; border-radius: 3px; }
QProgressBar#slimProgress { min-height: 6px; max-height: 6px; }
QProgressBar#protocolBar { min-height: 20px; max-height: 20px; color: #e8f1ff; }
QSplitter::handle { background: #273448; height: 2px; }
"""


class AnalysisWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, path: str):
        super().__init__()
        self.path = path

    @Slot()
    def run(self):
        try:
            self.completed.emit(analyze_capture(self.path))
        except Exception as exc:  # converted to a user-facing error at the UI boundary
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()


class CaptureWorker(QObject):
    failed = Signal(str)
    finished = Signal()

    def __init__(self, engine: LiveCaptureEngine):
        super().__init__()
        self.engine = engine

    @Slot()
    def run(self):
        try:
            self.engine.run()
        except LiveCaptureError as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()


class PacketAnalysisWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, packets, path: str):
        super().__init__()
        self.packets = packets
        self.path = path

    @Slot()
    def run(self):
        try:
            self.completed.emit(analyze_frames(self.packets, self.path))
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()


class DiscoveryWorker(QObject):
    device_found = Signal(object)
    progress = Signal(int, int)
    failed = Signal(str)
    finished = Signal(bool)

    def __init__(self, engine: DiscoveryEngine):
        super().__init__()
        self.engine = engine

    @Slot()
    def run(self):
        try:
            self.engine.run(self.device_found.emit, self.progress.emit)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit(self.engine.stopped)


class PacketLensWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("PacketLens", "PacketLens")
        self._page_status: dict[int, str] = {}
        self.analysis: CaptureAnalysis | None = None
        self._thread: QThread | None = None
        self._worker: AnalysisWorker | None = None
        self._capture_thread: QThread | None = None
        self._capture_worker: CaptureWorker | None = None
        self._capture_engine: LiveCaptureEngine | None = None
        self._capture_interface = None
        self._live_packets: list = []
        self._capture_error_message = ""
        self._live_analysis_thread: QThread | None = None
        self._live_analysis_worker: PacketAnalysisWorker | None = None
        self._live_analysis_pending = False
        self._discovery_thread: QThread | None = None
        self._discovery_worker: DiscoveryWorker | None = None
        self._discovery_engine: DiscoveryEngine | None = None
        self._discovery_error_message = ""
        self._discovered_devices = {}
        self.setWindowTitle("PacketLens — Network Security Analyzer")
        self.resize(1280, 800)
        self.setMinimumSize(980, 620)
        self.setStyleSheet(STYLE)

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.addWidget(self._label("PacketLens", "brand"))
        self.navigation = QListWidget()
        self.navigation.setObjectName("navigation")
        self.navigation.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.navigation.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        for name in ("Overview", "Traffic", "Network", "Findings", "Reports"):
            self.navigation.addItem(QListWidgetItem(name))
        sidebar_layout.addWidget(self.navigation)
        display_label = QLabel("Display size")
        display_label.setObjectName("displaySizeLabel")
        self.display_size = QComboBox()
        self.display_size.setObjectName("displaySize")
        self.display_size.addItems(DISPLAY_PRESETS)
        self.display_size.setToolTip("Adjust text and control sizing while preserving Windows DPI scaling.")
        self.display_size.setCurrentText(saved_display_preset(self.settings))
        sidebar_layout.addWidget(display_label)
        sidebar_layout.addWidget(self.display_size)
        self.privacy = QLabel("LOCAL ANALYSIS\nNo packet data leaves this device")
        self.privacy.setWordWrap(True)
        self.privacy.setStyleSheet("color:#6f7d91; padding:12px")
        sidebar_layout.addWidget(self.privacy)

        main = QWidget()
        main_layout = QVBoxLayout(main)
        main_layout.setContentsMargins(26, 22, 26, 18)
        self.pages = QStackedWidget()
        self.overview = OverviewPage()
        self.traffic = TrafficPage()
        self.network = NetworkPage()
        self.findings = FindingsPage()
        self.reports = ReportsPage()
        for page in (self.overview, self.traffic, self.network, self.findings, self.reports):
            self.pages.addWidget(page)
        main_layout.addWidget(self.pages, 1)
        self.progress = QProgressBar()
        self.progress.setObjectName("slimProgress")
        self.progress.setRange(0, 0)
        self.progress.hide()
        main_layout.addWidget(self.progress)
        self.status = QLabel("Ready")
        self.status.setStyleSheet("color:#7f8da1")
        main_layout.addWidget(self.status)
        root_layout.addWidget(sidebar)
        root_layout.addWidget(main, 1)
        self.setCentralWidget(root)

        self.navigation.currentRowChanged.connect(self._navigation_changed)
        self.overview.open_requested.connect(self.open_capture)
        self.reports.export_requested.connect(self.export_report)
        self.network.capture_start_requested.connect(self.start_live_capture)
        self.network.capture_stop_requested.connect(self.stop_live_capture)
        self.network.capture_save_requested.connect(self.save_live_capture)
        self.network.scan_start_requested.connect(self.start_discovery)
        self.network.scan_stop_requested.connect(self.stop_discovery)
        self.network.investigate_requested.connect(self.investigate_device)
        self.findings.packet_requested.connect(self.open_supporting_packet)
        self.findings.packets_requested.connect(self.open_supporting_packets)
        self.traffic.device_requested.connect(self.show_network_device)
        self.traffic.filter_changed.connect(self._traffic_filter_changed)
        self.display_size.currentTextChanged.connect(self.set_display_preset)
        self._live_refresh_timer = QTimer(self)
        self._live_refresh_timer.setInterval(1000)
        self._live_refresh_timer.timeout.connect(self._refresh_live_analysis)
        self.navigation.setCurrentRow(0)
        self.set_display_preset(self.display_size.currentText())

    @staticmethod
    def _label(text, name):
        label = QLabel(text)
        label.setObjectName(name)
        return label

    @staticmethod
    def _documents_directory() -> str:
        path = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DocumentsLocation)
        return path or str(Path.home() / "Documents")

    @Slot(str)
    def set_display_preset(self, preset: str):
        preset = apply_display_preset(self, preset, self.settings)
        if self.display_size.currentText() != preset:
            self.display_size.setCurrentText(preset)
        sidebar_width = {"Compact": 210, "Comfortable": 230, "Large": 270}[preset]
        self.navigation.parentWidget().setFixedWidth(sidebar_width)
        row_height = self.navigation.fontMetrics().height() + 38
        self.navigation.setMinimumHeight(self.navigation.count() * row_height + 8)
        self.navigation.setMaximumHeight(16777215)

    @Slot(int)
    def _navigation_changed(self, index: int):
        self.pages.setCurrentIndex(index)
        self.status.setText(self._page_status.get(index, self._default_page_status(index)))

    def _default_page_status(self, index: int) -> str:
        if self.analysis is None:
            defaults = ("Ready — open a capture or start live capture",
                        "No packet capture loaded", self.network.scan_status.text(),
                        "No observations available", "Open a capture to enable reports")
            return defaults[index] if 0 <= index < len(defaults) else "Ready"
        packet_count = len(self.analysis.packets)
        statuses = (
            f"{packet_count:,} packets analyzed — {len(self.analysis.findings):,} observations",
            f"Showing {self.traffic.proxy.rowCount():,} of {packet_count:,} packets",
            self.network.scan_status.text(),
            f"{len(self.analysis.findings):,} observations available",
            "Report ready for local export",
        )
        return statuses[index] if 0 <= index < len(statuses) else "Ready"

    def _set_page_status(self, index: int, message: str):
        self._page_status[index] = message
        if self.navigation.currentRow() == index:
            self.status.setText(message)

    @Slot(int, int)
    def _traffic_filter_changed(self, count: int, total: int):
        self._set_page_status(1, f"Showing {count:,} of {total:,} packets")

    @Slot()
    def open_capture(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open packet capture", self._documents_directory(),
            "Packet captures (*.pcap *.pcapng)")
        if path:
            self.load_capture(path)

    def load_capture(self, path: str):
        if (self._thread is not None or self._capture_thread is not None
                or self._live_analysis_thread is not None):
            return
        self.overview.open_button.setEnabled(False)
        self.traffic.clear_device_filter()
        self.overview.set_capture_activity("Loading", 0, 0)
        self.progress.show()
        self.status.setText(f"Analyzing {Path(path).name}…")
        self._set_page_status(0, f"Analyzing {Path(path).name}…")
        thread = QThread(self)
        worker = AnalysisWorker(path)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._analysis_ready)
        worker.failed.connect(self._analysis_failed)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._worker_finished)
        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(object)
    def _analysis_ready(self, analysis: CaptureAnalysis):
        self.traffic.clear_device_filter()
        self._apply_analysis(analysis, clear_investigation=True)
        self._set_page_status(
            0, f"{len(analysis.packets):,} packets analyzed — {len(analysis.findings):,} observations")

    def _apply_analysis(self, analysis: CaptureAnalysis, clear_investigation=True):
        self.analysis = analysis
        self.overview.set_analysis(analysis)
        self.traffic.set_analysis(analysis, clear_investigation=clear_investigation)
        self.findings.set_findings(analysis.findings)
        self.reports.set_ready(True)
        self._page_status[0] = (
            f"{len(analysis.packets):,} packets analyzed — {len(analysis.findings):,} observations")
        self._page_status[3] = f"{len(analysis.findings):,} observations available"
        self._page_status[4] = "Report ready for local export"
        current = self.navigation.currentRow()
        if current >= 0:
            self.status.setText(self._page_status.get(current, self._default_page_status(current)))

    @Slot(int)
    def open_supporting_packet(self, packet_number: int):
        if self.traffic.select_packet_number(packet_number):
            self.navigation.setCurrentRow(1)
            self._set_page_status(1, f"Showing supporting packet {packet_number}")

    @Slot(object)
    def open_supporting_packets(self, packet_numbers):
        references = tuple(packet_numbers)
        count = self.traffic.filter_by_packet_numbers(references, "Finding evidence")
        if count:
            self.navigation.setCurrentRow(1)
            self._set_page_status(1, f"Showing {count:,} filtered supporting packet(s)")

    @Slot(str)
    def investigate_device(self, address: str):
        count = self.traffic.filter_by_device(address)
        self.navigation.setCurrentRow(1)
        if count:
            self._set_page_status(1, f"Device investigation: {count:,} filtered packet(s) match {address}")
        else:
            self._set_page_status(1, f"No captured packets match discovered device {address}")

    @Slot(str)
    def show_network_device(self, address: str):
        if self.network.select_device(address):
            self.navigation.setCurrentRow(2)
            self._set_page_status(2, f"Showing discovered device {address}")

    @Slot(str)
    def _analysis_failed(self, message: str):
        self._set_page_status(0, f"Capture could not be loaded — {message}")
        self.overview.set_capture_activity("Load failed", 0, 0)
        QMessageBox.warning(self, "Unable to open capture", message)

    @Slot()
    def _worker_finished(self):
        self._thread = None
        self._worker = None
        self.progress.hide()
        self.overview.open_button.setEnabled(True)

    @Slot(object)
    def start_live_capture(self, interface):
        if (self._capture_thread is not None or self._thread is not None
                or self._live_analysis_thread is not None):
            return
        self.analysis = None
        self._live_packets = []
        self.traffic.clear_device_filter()
        self._capture_interface = interface
        self._capture_engine = LiveCaptureEngine(interface.identifier, max_packets=10_000)
        self._capture_error_message = ""
        self.overview.clear_analysis(f"Live capture is starting on {interface.name}…")
        self.overview.set_capture_activity("Starting", 0, 0)
        self.traffic.set_packets([])
        self.findings.set_findings([])
        self.reports.set_ready(False)
        self.network.set_capture_running(True, 0)
        self.overview.open_button.setEnabled(False)
        self._set_page_status(2, f"Live capture starting on {interface.name}")
        thread = QThread(self)
        worker = CaptureWorker(self._capture_engine)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.failed.connect(self._live_capture_failed)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._live_capture_finished)
        self._capture_thread = thread
        self._capture_worker = worker
        self._live_refresh_timer.start()
        thread.start()

    @Slot()
    def _refresh_live_analysis(self):
        if self._capture_engine is not None:
            self._live_packets = self._capture_engine.packets
        if not self._live_packets or self._capture_interface is None:
            return
        if self._live_analysis_thread is not None:
            self._live_analysis_pending = True
            return
        thread = QThread(self)
        worker = PacketAnalysisWorker(
            list(self._live_packets), f"Live capture - {self._capture_interface.name}.pcap")
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.completed.connect(self._live_analysis_ready)
        worker.failed.connect(lambda message: self.status.setText(f"Live analysis update failed: {message}"))
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._live_analysis_finished)
        self._live_analysis_thread = thread
        self._live_analysis_worker = worker
        thread.start()

    @Slot(object)
    def _live_analysis_ready(self, analysis: CaptureAnalysis):
        analysis.source_mode = "live"
        analysis.capture_state = "Capturing" if self._capture_thread is not None else "Stopped"
        self._apply_analysis(analysis, clear_investigation=False)
        self._set_page_status(
            2, f"Live capture on {self._capture_interface.name} — {len(analysis.packets):,} analyzed packets")
        if self._capture_thread is not None:
            self.network.set_capture_running(True, len(analysis.packets))

    @Slot()
    def _live_analysis_finished(self):
        self._live_analysis_thread = None
        self._live_analysis_worker = None
        if self._live_analysis_pending:
            self._live_analysis_pending = False
            QTimer.singleShot(0, self._refresh_live_analysis)

    @Slot()
    def stop_live_capture(self):
        if self._capture_engine is not None and self._capture_thread is not None:
            self._capture_engine.stop()
            self.network.set_capture_stopping()

    @Slot(str)
    def _live_capture_failed(self, message: str):
        self._capture_error_message = message
        self.network.set_capture_error(message)
        self.overview.set_capture_activity(
            "Unavailable", len(self._live_packets),
            sum(packet.captured_length for packet in self._live_packets))
        self._set_page_status(2, f"Live capture unavailable — {message}")

    @Slot()
    def _live_capture_finished(self):
        self._live_refresh_timer.stop()
        self._capture_thread = None
        self._refresh_live_analysis()
        count = len(self._live_packets)
        if self._capture_error_message:
            self.network.set_capture_error(self._capture_error_message)
        else:
            self.network.set_capture_running(False, count)
        self.overview.open_button.setEnabled(True)
        self._capture_worker = None
        if count:
            self._set_page_status(2, f"Live capture stopped — {count:,} packet(s)")
        elif not self._capture_error_message:
            self.overview.set_capture_activity("Stopped", 0, 0)

    @Slot()
    def save_live_capture(self):
        if self._capture_engine is None or not self._live_packets:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save live capture",
            str(Path(self._documents_directory()) / "PacketLens-capture.pcap"),
            "PCAP capture (*.pcap)")
        if not path:
            return
        if not path.lower().endswith(".pcap"):
            path += ".pcap"
        if Path(path).exists() and QMessageBox.question(
                self, "Replace capture?",
                f"A capture already exists at:\n{path}\n\nReplace it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        try:
            self._capture_engine.save(path)
            self._set_page_status(2, f"Saved capture to {path}")
        except LiveCaptureError as exc:
            self._set_page_status(2, f"Capture save failed — {exc}")
            QMessageBox.warning(self, "Unable to save capture", str(exc))

    @Slot(object, str)
    def start_discovery(self, interface, subnet: str):
        if self._discovery_thread is not None:
            return
        try:
            engine = DiscoveryEngine(interface, subnet)
        except Exception as exc:
            self.network.set_scan_error(str(exc))
            return
        self._discovery_engine = engine
        self._discovery_error_message = ""
        self._discovered_devices.clear()
        self.traffic.set_known_devices({})
        self.overview.set_discovered_device_count(0)
        self.network.begin_scan()
        self._set_page_status(2, f"Scanning confirmed local subnet {subnet}")
        thread = QThread(self)
        worker = DiscoveryWorker(engine)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.device_found.connect(self._device_discovered)
        worker.progress.connect(self.network.set_scan_progress)
        worker.failed.connect(self._discovery_failed)
        worker.finished.connect(self._discovery_worker_finished)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._discovery_finished)
        self._discovery_thread = thread
        self._discovery_worker = worker
        thread.start()

    @Slot()
    def stop_discovery(self):
        if self._discovery_engine is not None:
            self._discovery_engine.stop()
            self.network.set_scan_stopping()

    @Slot(object)
    def _device_discovered(self, device):
        self._discovered_devices[device.ip] = device
        self.network.add_device(device)
        self.traffic.set_known_devices(self._discovered_devices)
        self.overview.set_discovered_device_count(len(self._discovered_devices))

    @Slot(str)
    def _discovery_failed(self, message: str):
        self._discovery_error_message = message
        self.network.set_scan_error(message)
        self._set_page_status(2, f"Discovery failed — {message}")

    @Slot(bool)
    def _discovery_worker_finished(self, cancelled: bool):
        if self._discovery_error_message:
            self.network.set_scan_error(self._discovery_error_message)
        else:
            self.network.finish_scan(cancelled)
            count = len(self._discovered_devices)
            message = (f"Discovery stopped — {count:,} devices responded" if cancelled
                       else f"Discovery complete — {count:,} devices responded")
            self._set_page_status(2, message)

    @Slot()
    def _discovery_finished(self):
        self._discovery_thread = None
        self._discovery_worker = None
        self._discovery_engine = None

    def closeEvent(self, event):
        if self._capture_engine:
            self._capture_engine.stop()
        if self._discovery_engine:
            self._discovery_engine.stop()
        for thread in (self._capture_thread, self._live_analysis_thread,
                       self._discovery_thread, self._thread):
            if thread and thread.isRunning():
                thread.quit()
                thread.wait(2500)
        event.accept()

    @Slot()
    def export_report(self):
        if self.analysis is None:
            return
        suggested = str(Path(self._documents_directory()) /
                        f"{self.analysis.path.stem}-report.html")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export investigation report", suggested, "HTML report (*.html)")
        if not path:
            return
        if not path.lower().endswith(".html"):
            path += ".html"
        try:
            write_html_report(self.analysis, path)
            self._set_page_status(4, f"Report exported successfully — {path}")
            QMessageBox.information(self, "Report exported", f"Saved the local report to:\n{path}")
        except (OSError, PermissionError) as exc:
            self._set_page_status(4, f"Report export failed — {exc}")
            QMessageBox.warning(self, "Unable to export report", str(exc))
