"""Parser-neutral capture frames and backend interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from packetlens.models import PacketRecord


class CaptureBackendError(RuntimeError):
    """An offline backend could not read or normalize a capture."""


@dataclass(frozen=True, slots=True)
class CapturedFrame:
    timestamp: float | None
    data: bytes
    captured_length: int
    original_length: int
    link_type: int


@dataclass(slots=True)
class BackendResult:
    records: list[PacketRecord] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)


class CaptureBackend(Protocol):
    name: str

    def read(self, path: str | Path) -> BackendResult: ...
