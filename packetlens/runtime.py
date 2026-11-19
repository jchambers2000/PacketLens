"""Frozen-application paths and privacy-conscious startup diagnostics."""

from __future__ import annotations

import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundle_root() -> Path:
    """Return the read-only source/bundle root without relying on the CWD."""
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(frozen_root).resolve()
    return Path(__file__).resolve().parent.parent


def resource_path(*parts: str) -> Path:
    return bundle_root().joinpath(*parts)


def user_data_directory() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        base = str(Path.home() / "AppData" / "Local")
    return Path(base) / "PacketLens"


def write_startup_diagnostic(version: str, error: BaseException) -> Path | None:
    """Write only on startup failure; never include packets or analysis state."""
    try:
        directory = user_data_directory() / "logs"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "startup-error.log"
        timestamp = datetime.now(timezone.utc).isoformat()
        details = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        path.write_text(
            f"PacketLens {version}\nStartup failure (UTC): {timestamp}\n"
            f"Frozen: {is_frozen()}\n\n{details}", encoding="utf-8")
        return path
    except OSError:
        return None
