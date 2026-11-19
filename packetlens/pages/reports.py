from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget


class ReportsPage(QWidget):
    export_requested = Signal()

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        title = QLabel("Reports")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        panel = QWidget()
        panel.setObjectName("card")
        panel_layout = QVBoxLayout(panel)
        heading = QLabel("HTML investigation report")
        heading.setObjectName("captureName")
        panel_layout.addWidget(heading)
        description = QLabel("Export capture statistics, protocol distribution, top endpoints, and security observations. Reports are generated locally and capture-derived text is HTML-escaped.")
        description.setWordWrap(True)
        panel_layout.addWidget(description)
        self.export_button = QPushButton("Export HTML Report")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_requested)
        panel_layout.addWidget(self.export_button)
        layout.addWidget(panel)
        layout.addStretch()

    def set_ready(self, ready: bool):
        self.export_button.setEnabled(ready)
