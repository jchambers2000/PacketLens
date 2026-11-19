"""Validation helpers shared by build automation and packaging tests."""

from __future__ import annotations

from pathlib import Path


FORBIDDEN_DIRECTORIES = {
    ".git", ".venv", "__pycache__", ".pytest_cache", "build", "captures", "tests"
}
FORBIDDEN_SUFFIXES = {".pcap", ".pcapng", ".env", ".key", ".pem", ".log"}
FORBIDDEN_DRIVER_FILES = {"wpcap.dll", "packet.dll", "npcap.dll", "npcaphelper.dll"}
CLEAN_BUILD_FORBIDDEN_FILES = {
    "qt6network.dll", "qt6opengl.dll", "qt6pdf.dll", "qt6qml.dll",
    "qt6qmlmeta.dll", "qt6qmlmodels.dll", "qt6qmlworkerscript.dll",
    "qt6quick.dll", "qt6virtualkeyboard.dll", "qtvirtualkeyboardplugin.dll",
    "qpdf.dll", "qtuiotouchplugin.dll",
}
CLEAN_BUILD_REQUIRED_FILES = {
    "qt6core.dll", "qt6gui.dll", "qt6svg.dll", "qt6widgets.dll",
    "qtcore.pyd", "qtgui.pyd", "qtwidgets.pyd", "qwindows.dll",
    "qmodernwindowsstyle.dll",
}


def distribution_issues(directory: str | Path) -> list[str]:
    root = Path(directory)
    issues: list[str] = []
    executable = root / "PacketLens.exe"
    if not executable.is_file():
        issues.append("PacketLens.exe is missing.")
    platform_plugins = list(root.glob("**/platforms/qwindows.dll"))
    if not platform_plugins:
        issues.append("The Qt Windows platform plugin qwindows.dll is missing.")
    if not root.is_dir():
        return issues
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part.casefold() in FORBIDDEN_DIRECTORIES for part in relative.parts):
            issues.append(f"Forbidden development/private directory: {relative}")
            continue
        if not path.is_file():
            continue
        if path.suffix.casefold() in FORBIDDEN_SUFFIXES:
            issues.append(f"Forbidden sensitive file: {relative}")
        if path.name.casefold() in FORBIDDEN_DRIVER_FILES:
            issues.append(f"Npcap/packet-capture driver file must not be bundled: {relative}")
        if path.name.casefold().endswith("-report.html"):
            issues.append(f"Generated report was bundled: {relative}")
        if path.name.startswith("PacketLens-v") and path.suffix.casefold() == ".png":
            issues.append(f"Debug screenshot was bundled: {relative}")
    return sorted(set(issues))


def assert_distribution_safe(directory: str | Path) -> None:
    issues = distribution_issues(directory)
    if issues:
        raise RuntimeError("Distribution validation failed:\n- " + "\n- ".join(issues))


def dependency_cleanup_issues(directory: str | Path) -> list[str]:
    """Validate the audited minimal Qt runtime without judging legal compliance."""
    root = Path(directory)
    names = {path.name.casefold() for path in root.rglob("*") if path.is_file()}
    issues = [f"Excluded optional dependency is present: {name}"
              for name in sorted(CLEAN_BUILD_FORBIDDEN_FILES & names)]
    issues.extend(f"Required runtime component is missing: {name}"
                  for name in sorted(CLEAN_BUILD_REQUIRED_FILES - names))
    return issues


def assert_dependency_cleanup(directory: str | Path) -> None:
    issues = dependency_cleanup_issues(directory)
    if issues:
        raise RuntimeError("Dependency cleanup validation failed:\n- " + "\n- ".join(issues))
