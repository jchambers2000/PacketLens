# Qt / PySide6 Source Availability Record

This record applies to the PacketLens 0.8.4 Windows compliance candidate. It
does not itself constitute a written source offer or legal advice.

## Exact corresponding upstream releases

- Qt framework: 6.12.0 — `qt-everywhere-src-6.12.0.tar.xz`,
  443,394,020 bytes, official SHA-256
  `98ff4f44bac6ec3e1e62ee2a4316ae0e3d15badb015d753cc0268a20db52f165`, at
  <https://download.qt.io/official_releases/qt/6.12/6.12.0/single/>
- Qt for Python (PySide6 and Shiboken6): 6.12.0 —
  <https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-6.12.0-src/>
- Qt for Python source archive: `pyside-setup-everywhere-src-6.12.0.tar.xz`,
  18,211,772 bytes, official SHA-256
  `099c1a597cf33c1b000e11cf68a0b82d216fb802bf81726efc720394f10c7751`.
  The equivalent ZIP is 23,393,479 bytes with official SHA-256
  `15b25c9e06f3acb8930c318192f3c20aee162f4b8d01bf4b4c60193c924cd847`.

The frozen candidate contains only Qt Core, GUI, Widgets, SVG and the explicitly
listed Windows/style/image plugins in `THIRD_PARTY_NOTICES.md`. It does not
contain Qt Virtual Keyboard or other Qt modules that Qt's licensing page lists
as GPL-only in the open-source option.

## Release-owner action required

Before a public binary release, the release owner should archive the exact Qt
6.12.0 and pyside-setup 6.12.0 corresponding source, their license files, and
checksums in durable release-controlled storage. A changing upstream URL alone
may not meet every obligation. Counsel should decide whether the chosen LGPLv3
compliance route also requires a written source offer, installation information,
or PacketLens application materials beyond the separate-DLL replacement method.

If any Qt/PySide/Shiboken file is patched, rebuilt, or configured differently,
preserve the complete corresponding source and build/configuration changes and
update this record. No such modifications were identified in the audited test
candidate.

## User modification and replacement

The onedir distribution leaves the Qt, PySide6, and Shiboken libraries as
separate DLL/PYD files. PacketLens does not impose a technical check that blocks
replacement, and its documentation does not prohibit reverse engineering for
debugging LGPL-covered modifications. A safe clone-and-probe procedure is in
`QT_LIBRARY_REPLACEMENT.md`.

Technical replaceability is not a legal conclusion. Arbitrary user builds must
remain ABI-compatible with CPython 3.14 x64, PySide6 6.12.0, Qt 6.12.0, and the
matching MSVC runtime; an ABI-incompatible replacement can legitimately fail.
