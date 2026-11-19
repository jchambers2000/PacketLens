from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QFormLayout, QFrame, QHBoxLayout, QLabel, QListWidget,
                               QListWidgetItem, QPushButton, QScrollArea, QSizePolicy,
                               QSplitter, QVBoxLayout, QWidget)

from packetlens.models import Finding


class FindingsPage(QWidget):
    """Compact findings master list with a single scrollable detail view."""

    packet_requested = Signal(int)
    packets_requested = Signal(object)

    def __init__(self):
        super().__init__()
        self._findings: list[Finding] = []
        layout = QVBoxLayout(self)
        title = QLabel("Findings")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        note = QLabel(
            "Rule-based observations are investigative leads, not proof of an attack. "
            "Select an observation for details or double-click it to inspect all supporting packets.")
        note.setWordWrap(True)
        layout.addWidget(note)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setObjectName("findingsSplitter")
        splitter.setChildrenCollapsible(False)

        master = QWidget()
        master.setObjectName("findingsMaster")
        master_layout = QVBoxLayout(master)
        master_layout.setContentsMargins(0, 0, 6, 0)
        master_heading = QLabel("Observations")
        master_heading.setObjectName("sectionTitle")
        master_layout.addWidget(master_heading)
        self.list = QListWidget()
        self.list.setObjectName("findingsList")
        self.list.setWordWrap(True)
        self.list.setVerticalScrollMode(QListWidget.ScrollMode.ScrollPerPixel)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list.currentItemChanged.connect(self._selection_changed)
        self.list.itemDoubleClicked.connect(self._open_supporting_packet)
        master_layout.addWidget(self.list, 1)
        splitter.addWidget(master)

        self.details_scroll = QScrollArea()
        self.details_scroll.setObjectName("findingDetailsScroll")
        self.details_scroll.setWidgetResizable(True)
        self.details_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.details_body = QWidget()
        self.details_body.setObjectName("findingDetails")
        self.details_layout = QVBoxLayout(self.details_body)
        self.details_layout.setContentsMargins(18, 14, 18, 18)
        self.details_layout.setSpacing(12)

        self.empty_state = QLabel("No findings to display. Open a capture to run the local observation rules.")
        self.empty_state.setObjectName("findingEmptyState")
        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state.setWordWrap(True)
        self.empty_state.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.details_layout.addWidget(self.empty_state, 1)

        self.detail_content = QWidget()
        self.detail_content.setObjectName("findingDetailContent")
        content_layout = QVBoxLayout(self.detail_content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(12)
        heading = QHBoxLayout()
        self.detail_title = self._text_label("findingDetailTitle")
        self.detail_classification = self._text_label("findingDetailBadge")
        self.detail_classification.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.detail_classification.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        heading.addWidget(self.detail_title, 1)
        heading.addWidget(self.detail_classification)
        content_layout.addLayout(heading)

        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setObjectName("findingSeparator")
        content_layout.addWidget(separator)

        form = QFormLayout()
        form.setObjectName("findingDetailForm")
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        form.setHorizontalSpacing(20)
        form.setVerticalSpacing(12)
        self.detail_description = self._add_detail_row(form, "Description")
        self.detail_endpoints = self._add_detail_row(form, "Relevant endpoints")
        self.detail_rule = self._add_detail_row(form, "Triggering rule")
        self.detail_why = self._add_detail_row(form, "Why it matters")
        self.detail_evidence = self._add_detail_row(form, "Supporting evidence")
        self.detail_next = self._add_detail_row(form, "Suggested next step")
        content_layout.addLayout(form)
        self.view_packets_button = QPushButton("View Supporting Packets")
        self.view_packets_button.clicked.connect(self._view_current_evidence)
        content_layout.addWidget(self.view_packets_button, 0, Qt.AlignmentFlag.AlignLeft)
        content_layout.addStretch()
        self.details_layout.addWidget(self.detail_content, 1)
        self.detail_content.hide()
        self.details_scroll.setWidget(self.details_body)
        splitter.addWidget(self.details_scroll)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([320, 720])
        layout.addWidget(splitter, 1)

        self.set_findings([])

    @staticmethod
    def _text_label(object_name=""):
        label = QLabel()
        if object_name:
            label.setObjectName(object_name)
        label.setWordWrap(True)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        return label

    def _add_detail_row(self, form: QFormLayout, caption: str):
        field = self._text_label("findingDetailField")
        caption_label = QLabel(caption)
        caption_label.setObjectName("findingDetailCaption")
        caption_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        form.addRow(caption_label, field)
        return field

    def set_findings(self, findings: list[Finding]):
        self._findings = list(findings)
        self.list.clear()
        for index, finding in enumerate(self._findings):
            packet_word = "packet" if len(finding.references) == 1 else "packets"
            compact_text = (f"{finding.title}\n{finding.classification.upper()}  •  "
                            f"{len(finding.references):,} supporting {packet_word}")
            legacy_text = (f"{compact_text}\nNext step: {finding.suggested_next_step}")
            item = FindingListItem(compact_text, legacy_text)
            item.setData(Qt.ItemDataRole.UserRole, index)
            item.setData(Qt.ItemDataRole.UserRole + 1, finding.references)
            item.setToolTip(finding.title)
            self.list.addItem(item)

        if self._findings:
            self.list.setCurrentRow(0)
        else:
            self._show_empty_state()

    def _selection_changed(self, current, _previous):
        if current is None:
            self._show_empty_state()
            return
        index = current.data(Qt.ItemDataRole.UserRole)
        if not isinstance(index, int) or not 0 <= index < len(self._findings):
            self._show_empty_state()
            return
        self._show_finding(self._findings[index])

    def _show_finding(self, finding: Finding):
        self.empty_state.hide()
        self.detail_content.show()
        self.detail_title.setText(finding.title)
        self.detail_classification.setText(finding.classification.upper())
        self.detail_classification.setProperty("classification", finding.classification.casefold())
        self.detail_classification.style().unpolish(self.detail_classification)
        self.detail_classification.style().polish(self.detail_classification)
        self.detail_description.setText(finding.description)
        self.detail_endpoints.setText(" → ".join(finding.endpoints) or "Not available")
        self.detail_rule.setText(finding.triggering_rule)
        self.detail_why.setText(finding.why_it_matters)
        packet_word = "packet" if len(finding.references) == 1 else "packets"
        self.detail_evidence.setText(
            f"{len(finding.references):,} supporting {packet_word}. "
            "The complete reference set opens in Traffic.")
        self.detail_next.setText(finding.suggested_next_step)
        self.view_packets_button.setEnabled(bool(finding.references))
        self.details_scroll.verticalScrollBar().setValue(0)

    def _show_empty_state(self):
        self.detail_content.hide()
        self.empty_state.show()

    def _current_references(self):
        item = self.list.currentItem()
        return tuple(item.data(Qt.ItemDataRole.UserRole + 1) or ()) if item else ()

    def _view_current_evidence(self):
        references = self._current_references()
        if references:
            self.packets_requested.emit(tuple(int(number) for number in references))

    def _open_supporting_packet(self, item):
        references = tuple(item.data(Qt.ItemDataRole.UserRole + 1) or ())
        if references:
            self.packets_requested.emit(tuple(int(number) for number in references))


class FindingListItem(QListWidgetItem):
    """Keep legacy Python text metadata while Qt paints only the compact display role."""

    def __init__(self, display_text: str, legacy_text: str):
        super().__init__()
        self._legacy_text = legacy_text
        self.setData(Qt.ItemDataRole.DisplayRole, display_text)

    def text(self):
        return self._legacy_text
