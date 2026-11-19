# -*- mode: python ; coding: utf-8 -*-
"""Maintained PyInstaller onedir/windowed build for PacketLens."""

from pathlib import Path
project_root = Path(SPECPATH)
optional_oui = project_root / "packetlens" / "data" / "oui.csv"
datas = [
    (str(project_root / "THIRD_PARTY_NOTICES.md"), "."),
    (str(project_root / "QT_LIBRARY_REPLACEMENT.md"), "."),
    (str(project_root / "QT_SOURCE_AVAILABILITY.md"), "."),
    (str(project_root / "THIRD_PARTY_LICENSES"), "THIRD_PARTY_LICENSES"),
]
if optional_oui.is_file():
    datas.append((str(optional_oui), "packetlens/data"))

hiddenimports = [
    "PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets",
]

# QtGui's hook collects whole plugin categories. Keep the Windows platform,
# Windows style, and common image support, then remove audited optional stacks.
excluded_qt_files = {
    "qt6network.dll", "qt6opengl.dll", "qt6pdf.dll", "qt6qml.dll",
    "qt6qmlmeta.dll", "qt6qmlmodels.dll", "qt6qmlworkerscript.dll",
    "qt6quick.dll", "qt6virtualkeyboard.dll",
}
excluded_qt_plugins = {
    "generic/qtuiotouchplugin.dll",
    "imageformats/qicns.dll", "imageformats/qpdf.dll", "imageformats/qtga.dll",
    "imageformats/qtiff.dll", "imageformats/qwbmp.dll",
    "networkinformation/qnetworklistmanager.dll",
    "platforminputcontexts/qtvirtualkeyboardplugin.dll",
    "platforms/qdirect2d.dll", "platforms/qminimal.dll", "platforms/qoffscreen.dll",
    "tls/qcertonlybackend.dll", "tls/qopensslbackend.dll", "tls/qschannelbackend.dll",
}


def keep_audited_binary(item):
    destination = item[0].replace("\\", "/").casefold()
    if destination.startswith("pyside6/plugins/"):
        plugin = destination.removeprefix("pyside6/plugins/")
        return plugin not in excluded_qt_plugins
    return destination.rsplit("/", 1)[-1] not in excluded_qt_files

a = Analysis(
    [str(project_root / "main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "pytest", "unittest.mock", "PySide6.QtNetwork",
    ],
    noarchive=False,
    optimize=1,
)
a.binaries = [item for item in a.binaries if keep_audited_binary(item)]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PacketLens",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(project_root / "packaging" / "PacketLens.version"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="PacketLens",
)
