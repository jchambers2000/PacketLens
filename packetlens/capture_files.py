"""Small streaming PCAP/PCAPNG container reader preserving capture metadata."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator

from packetlens.capture_backend import CapturedFrame, CaptureBackendError


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def iter_capture_frames(path: str | Path) -> Iterator[CapturedFrame]:
    capture_path = Path(path)
    try:
        with capture_path.open("rb") as handle:
            magic = handle.read(4)
            handle.seek(0)
            if magic in PCAP_MAGICS:
                yield from _iter_pcap(handle, magic)
            elif magic == PCAPNG_MAGIC:
                yield from _iter_pcapng(handle)
            else:
                raise CaptureBackendError("The capture has an unsupported or invalid file header.")
    except CaptureBackendError:
        raise
    except PermissionError as exc:
        raise CaptureBackendError("PacketLens does not have permission to read this file.") from exc
    except (OSError, EOFError, struct.error, ValueError) as exc:
        raise CaptureBackendError(f"The capture could not be parsed: {exc}") from exc


def write_pcap_frames(path: str | Path, frames: list[CapturedFrame], link_type: int):
    """Write classic little-endian, microsecond PCAP without changing frame metadata."""
    destination = Path(path)
    with destination.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
        for frame in frames:
            if frame.link_type != link_type:
                raise CaptureBackendError("A single PCAP file cannot contain multiple link-layer types.")
            if frame.captured_length != len(frame.data) or frame.original_length < frame.captured_length:
                raise CaptureBackendError("Captured packet length metadata is inconsistent.")
            if frame.timestamp is None:
                raise CaptureBackendError("A live packet without a timestamp cannot be saved faithfully.")
            seconds = int(frame.timestamp)
            microseconds = round((frame.timestamp - seconds) * 1_000_000)
            if microseconds >= 1_000_000:
                seconds += 1
                microseconds -= 1_000_000
            handle.write(struct.pack("<IIII", seconds, microseconds,
                                     frame.captured_length, frame.original_length))
            handle.write(frame.data)


def _read_exact(handle, size: int) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise EOFError("truncated capture block")
    return data


def _iter_pcap(handle, magic: bytes) -> Iterator[CapturedFrame]:
    endian, divisor = PCAP_MAGICS[magic]
    header = _read_exact(handle, 24)
    link_type = struct.unpack_from(endian + "I", header, 20)[0]
    while True:
        packet_header = handle.read(16)
        if not packet_header:
            break
        if len(packet_header) != 16:
            raise EOFError("truncated PCAP packet header")
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", packet_header)
        data = _read_exact(handle, captured)
        yield CapturedFrame(seconds + fraction / divisor, data, captured, original, link_type)


def _options(data: bytes, endian: str) -> dict[int, bytes]:
    found: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            break
        if offset + length > len(data):
            break
        found[code] = data[offset:offset + length]
        offset += (length + 3) & ~3
    return found


def _iter_pcapng(handle) -> Iterator[CapturedFrame]:
    endian: str | None = None
    interfaces: list[tuple[int, float, int, int]] = []  # link, divisor, offset, snaplen
    while True:
        prefix = handle.read(12)
        if not prefix:
            break
        if len(prefix) != 12:
            raise EOFError("truncated PCAPNG block header")
        if prefix[:4] == PCAPNG_MAGIC:
            bom = prefix[8:12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            if endian is None:
                raise CaptureBackendError("PCAPNG section has an invalid byte-order marker.")
            total = struct.unpack_from(endian + "I", prefix, 4)[0]
            _read_exact(handle, total - 12)
            interfaces = []
            continue
        if endian is None:
            raise CaptureBackendError("PCAPNG data appeared before a section header.")
        block_type, total = struct.unpack_from(endian + "II", prefix, 0)
        if total < 12 or total % 4:
            raise CaptureBackendError("PCAPNG block has an invalid length.")
        body_and_tail = prefix[8:] + _read_exact(handle, total - 12)
        body = body_and_tail[:-4]
        if struct.unpack_from(endian + "I", body_and_tail, len(body_and_tail) - 4)[0] != total:
            raise CaptureBackendError("PCAPNG block length fields do not match.")
        if block_type == 1:
            if len(body) < 8:
                raise EOFError("truncated PCAPNG interface block")
            link_type, _reserved, snaplen = struct.unpack_from(endian + "HHI", body, 0)
            opts = _options(body[8:], endian)
            resolution_data = opts.get(9) or b"\x06"
            resolution = resolution_data[0]
            divisor = float((2 if resolution & 0x80 else 10) ** (resolution & 0x7f))
            time_offset = struct.unpack(endian + "q", opts[14])[0] if len(opts.get(14, b"")) == 8 else 0
            interfaces.append((link_type, divisor, time_offset, snaplen))
        elif block_type in (2, 6):
            if len(body) < 20:
                raise EOFError("truncated PCAPNG packet block")
            if block_type == 6:
                interface_id, high, low, captured, original = struct.unpack_from(endian + "IIIII", body, 0)
            else:
                interface_id, _drops, high, low, captured, original = struct.unpack_from(endian + "HHIIII", body, 0)
            if interface_id >= len(interfaces) or 20 + captured > len(body):
                raise CaptureBackendError("PCAPNG packet references invalid interface or length metadata.")
            link_type, divisor, time_offset, _snaplen = interfaces[interface_id]
            timestamp = time_offset + (((high << 32) | low) / divisor)
            yield CapturedFrame(timestamp, body[20:20 + captured], captured, original, link_type)
        elif block_type == 3:
            if len(body) < 4 or not interfaces:
                raise EOFError("truncated PCAPNG simple packet block")
            original = struct.unpack_from(endian + "I", body, 0)[0]
            link_type, _divisor, _time_offset, snaplen = interfaces[0]
            available = len(body) - 4
            captured = min(original, snaplen or original, available)
            yield CapturedFrame(None, body[4:4 + captured], captured, original, link_type)
