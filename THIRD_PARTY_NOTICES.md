# Third-Party Notices — PacketLens 0.8.4 Windows candidate

The original PacketLens source code is licensed under Apache License 2.0 as
provided in the repository `LICENSE` file. That project license does not grant
ownership of, replace, or alter the licenses for the third-party components
listed here. PacketLens makes no ownership claim over third-party code.

This file also describes the audited `onedir` test distribution. It is not a
legal opinion. Complete third-party license texts named below are shipped in
`THIRD_PARTY_LICENSES`.

## Runtime components redistributed in the Windows folder

| Component | Exact version | Purpose / files | License expression or governing terms | Included text |
| --- | --- | --- | --- | --- |
| Python | 3.14.10 | `python314.dll`, `python3.dll`, standard-library archive and extension modules | Python Software Foundation License Version 2 plus incorporated notices | `Python-3.14.10-LICENSE.txt` |
| Qt for Python / PySide6 Essentials | 6.12.0 | `QtCore.pyd`, `QtGui.pyd`, `QtWidgets.pyd`, `pyside6.abi3.dll` | `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only` per installed wheel metadata | `LGPL-3.0.txt`, `GPL-3.0.txt` |
| Shiboken6 | 6.12.0 | `Shiboken.pyd`, `shiboken6.abi3.dll` | `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only` per installed wheel metadata | `LGPL-3.0.txt`, `GPL-3.0.txt` |
| Qt 6 runtime | 6.12.0 | Core, GUI, Widgets, SVG, Windows platform/style, SVG/icon and common image plugins | Open-source Qt modules are generally offered under LGPL-3.0-only or GPL-3.0-only; exact module files must be checked against the corresponding Qt source tree | `LGPL-3.0.txt`, `GPL-3.0.txt` |
| dpkt | 1.9.8 | PCAP/PCAPNG and packet parsing | BSD-3-Clause | `dpkt-1.9.8-LICENSE.txt`, `dpkt-1.9.8-AUTHORS.txt` |
| OpenSSL | 3.5.9 | `libcrypto-3.dll`, `libssl-3.dll`, used by CPython `_hashlib` and `_ssl` | Apache-2.0 | `OpenSSL-3.5.9-LICENSE.txt` |
| libffi | 3.4.4 | `libffi-8.dll`, used by CPython `ctypes` | MIT-like libffi license | `libffi-3.4.4-LICENSE.txt` |
| PyInstaller bootloader | 6.22.3 | Native `PacketLens.exe` bootloader | GPL-2.0-or-later with the PyInstaller bootloader exception | `PyInstaller-6.22.3-COPYING.txt` |
| Microsoft Visual C++ runtime | 14.51.36247.0 and 14.44.35211.0 | `VCRUNTIME140*.dll`, `MSVCP140*.dll` | Microsoft Visual Studio redistributable terms; proprietary, not an SPDX open-source license | See Microsoft's current Visual C++ redistribution documentation and the applicable Visual Studio license |

The audited Qt files are `Qt6Core.dll`, `Qt6Gui.dll`, `Qt6Widgets.dll`,
`Qt6Svg.dll`, `opengl32sw.dll`, and these plugins: `qwindows.dll`,
`qmodernwindowsstyle.dll`, `qsvgicon.dll`, `qgif.dll`, `qico.dll`, `qjpeg.dll`,
`qsvg.dll`, and `qwebp.dll`. Qt Quick, QML, Virtual Keyboard, PDF, Network,
WebEngine, TLS plugins, and alternative platform integrations are not in the
audited candidate.

PacketLens has not modified Qt, PySide6, Shiboken6, Python, OpenSSL, libffi,
dpkt, or the PyInstaller bootloader. The application communicates with Qt
through PySide6 and keeps Qt/PySide/Shiboken as separate replaceable DLL/PYD
files in its `onedir` layout. See `QT_LIBRARY_REPLACEMENT.md` and
`QT_SOURCE_AVAILABILITY.md`.

## Build-time tools not redistributed as importable packages

The build environment also contains PyInstaller 6.22.3, altgraph 0.17.5 (MIT),
packaging 26.3 (Apache-2.0 OR BSD-2-Clause), pefile 2024.8.26 (MIT),
pyinstaller-hooks-contrib 2026.10, pywin32-ctypes 0.2.3 (BSD-3-Clause), and
setuptools 84.2.1 (MIT). Their Python packages are build inputs and were not
found as importable packages in the frozen archive. The PyInstaller bootloader
is redistributed as described above.

## External system dependency: Npcap

Npcap is not bundled, downloaded, installed, or modified by PacketLens.
PacketLens loads an independently installed `wpcap.dll` through documented
libpcap-compatible APIs for interface enumeration, capture, cancellation, and
authorized local ARP discovery. The tested machine had Npcap 1.90 reporting
libpcap 1.10.7.

Npcap's free edition is not generally redistributable by third parties and its
free-use limits remain the user's or deployer's responsibility. Npcap states
that redistribution requires an OEM license. PacketLens documentation must not
present Npcap as included or automatically licensed.

## Source and upstream references

- Qt licensing: <https://doc.qt.io/qt-6/licensing.html>
- Qt for Python licensing: <https://doc.qt.io/qtforpython-6/licenses.html>
- Qt for Python 6.12.0 source: <https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-6.12.0-src/>
- Qt 6.12.0 source: <https://download.qt.io/official_releases/qt/6.12/6.12.0/>
- Python 3.14.10: <https://www.python.org/downloads/release/python-31410/>
- OpenSSL license: <https://www.openssl-library.org/source/license/>
- dpkt: <https://github.com/kbandla/dpkt>
- PyInstaller license: <https://pyinstaller.org/en/v6.22.0/license.html>
- Npcap licensing and guide: <https://npcap.com/> and <https://npcap.com/guide/npcap-users-guide.html>

Upstream links alone may not satisfy every source-provision obligation. The
release owner must complete the decisions in `FINAL_LICENSE_COMPLIANCE.md` and
`RELEASE_READINESS_CHECKLIST.md` before public redistribution.
