# Replacing Qt / PySide6 Libraries for Verification

PacketLens uses a PyInstaller `onedir` layout. Qt, PySide6, and Shiboken remain
separate files beneath `_internal`, so a recipient can test a compatible
replacement without changing the original distribution.

## Safe procedure

1. Obtain or build an x64 CPython 3.14-compatible PySide6/Shiboken 6.12.0 and
   Qt 6.12.0 runtime. Preserve its source, build configuration, and licenses.
2. Arrange the replacement as an `_internal` tree matching another PacketLens
   onedir distribution. Do not rename DLLs or mix Qt patch versions casually.
3. Run the repository script against a disposable clone:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass `
     -File .\tools\verify_qt_replacement.ps1 `
     -DistributionPath .\dist-v0.8.4-compliance-test\PacketLens `
     -ReplacementInternalPath C:\path\to\replacement\_internal
   ```

4. The script copies the distribution to a temporary directory, replaces only
   the audited Qt/PySide/Shiboken files, launches the non-networking packaging
   probe, reports its result, and deletes the temporary clone. It never edits
   the supplied distribution or replacement tree.

The probe validates application startup and creation of all five pages. It does
not prove every UI path or compatibility with arbitrary modified libraries.
Run the complete test suite and manual UI checks for a materially changed build.

No PacketLens term should prohibit reverse engineering needed to debug changes
to LGPL-covered libraries. Whether this procedure and the onedir structure meet
all legal requirements remains a question for qualified counsel.
