"""Central display-size preferences and DPI-friendly font application."""

from PySide6.QtCore import QSettings
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QTableView, QWidget

DISPLAY_PRESETS = {"Compact": 9.0, "Comfortable": 10.5, "Large": 12.5}
DEFAULT_DISPLAY_PRESET = "Comfortable"
SETTINGS_KEY = "display/size"

_FONT_ROLES = {
    "brand": (1.75, QFont.Weight.Bold),
    "pageTitle": (1.65, QFont.Weight.Bold),
    "captureName": (1.30, QFont.Weight.DemiBold),
    "metric": (1.65, QFont.Weight.DemiBold),
    "sectionTitle": (1.10, QFont.Weight.DemiBold),
    "inspectorHeader": (1.20, QFont.Weight.DemiBold),
    "findingDetailTitle": (1.40, QFont.Weight.DemiBold),
    "findingDetailBadge": (0.90, QFont.Weight.DemiBold),
    "findingDetailCaption": (0.95, QFont.Weight.DemiBold),
    "findingEmptyState": (1.05, QFont.Weight.Normal),
    "networkStateBadge": (0.90, QFont.Weight.DemiBold),
    "networkDetailCaption": (0.95, QFont.Weight.DemiBold),
    "networkEmptyState": (1.05, QFont.Weight.Normal),
}


def normalized_preset(value) -> str:
    value = str(value or "")
    return value if value in DISPLAY_PRESETS else DEFAULT_DISPLAY_PRESET


def saved_display_preset(settings: QSettings | None = None) -> str:
    return normalized_preset((settings or QSettings()).value(SETTINGS_KEY, DEFAULT_DISPLAY_PRESET))


def apply_display_preset(root: QWidget, preset: str, settings: QSettings | None = None) -> str:
    """Apply fonts without changing Qt/Windows DPI awareness or window geometry."""
    preset = normalized_preset(preset)
    point_size = DISPLAY_PRESETS[preset]
    base = QFont("Segoe UI")
    base.setPointSizeF(point_size)
    app = QApplication.instance()
    if app is not None:
        app.setFont(base)
    root.setFont(base)
    for widget in [root, *root.findChildren(QWidget)]:
        role = _FONT_ROLES.get(widget.objectName())
        font = QFont(base)
        if role:
            multiplier, weight = role
            font.setPointSizeF(point_size * multiplier)
            font.setWeight(weight)
        widget.setFont(font)
    for table in root.findChildren(QTableView):
        table.verticalHeader().setDefaultSectionSize(table.fontMetrics().height() + 14)
    if settings is not None:
        settings.setValue(SETTINGS_KEY, preset)
    return preset
