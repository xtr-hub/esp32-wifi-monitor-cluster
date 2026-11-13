#!/usr/bin/env python3
"""Frame sources: read 802.11 frames from PCAP files or a live interface.

This module knows nothing about ESP32 nodes, telemetry, or the project layout.
It only turns "some source of captured frames" into a stream of frame bytes plus
a radiotap header, which is exactly what `pcap_dump.decode_frame` consumes. That
keeps the decoder and every viewer usable against any capture the host can
produce.

Supported sources:
  PcapTail   a PCAP file that may still be growing (polls for new records)
  static     a finished PCAP file read once
  live       a monitor-mode interface via scapy, when scapy is installed

Link types accepted: 127 (Radiotap) and 105 (raw 802.11 without radiotap).
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator

RADIOTAP = 127
IEEE80211 = 105

# Classic PCAP magic number, both byte orders.
_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
}

# Radiotap header with no fields would still work, but a real 802.11 capture
# encoded as link type 105 carries no radiotap preamble, so synthesise a minimal
# one (version 0, length 8, no present flags) to keep decode_frame's contract.
_EMPTY_RADIOTAP = struct.pack("<BBHI", 0, 0, 8, 0)


class PcapError(RuntimeError):
    pass


def _header(fp) -> tuple[str, int]:
    """Validate a PCAP global header and return (endian, linktype)."""
    raw = fp.read(24)
    if len(raw) < 24:
        raise PcapError("truncated PCAP header")
    endian = _MAGIC.get(raw[:4])
    if endian is None:
        raise PcapError("not a classic PCAP file (bad magic)")
    linktype = struct.unpack(endian + "I", raw[20:24])[0]
    if linktype not in (RADIOTAP, IEEE80211):
        raise PcapError(f"unsupported link type {linktype}; expected 127 or 105")
    return endian, linktype


def _normalise(linktype: int, body: bytes) -> bytes:
    """Return radiotap + 802.11 frame bytes, whatever the file stored."""
    if linktype == RADIOTAP:
        return body
    return _EMPTY_RADIOTAP + body


def read_records(path: Path) -> Iterator[bytes]:
    """Yield every frame in a finished PCAP file."""
    with open(path, "rb") as fp:
        endian, linktype = _header(fp)
        while True:
            header = fp.read(16)
            if len(header) < 16:
                return
            _sec, _usec, caplen, _orig = struct.unpack(endian + "IIII", header)
            if caplen > 262144:
                raise PcapError(f"implausible record length {caplen}")
            body = fp.read(caplen)
            if len(body) < caplen:
                return
            yield _normalise(linktype, body)


class PcapTail:
    """Poll a possibly-growing PCAP and return only newly completed records.

    Position is tracked internally at record boundaries, so this works on any
    PCAP whether or not the writer publishes a checkpoint file. A partially
    written record is left unread and retried on the next call.
    """

    def __init__(self, path: Path, from_start: bool = False) -> None:
        self.path = Path(path)
        self.endian: str | None = None
        self.linktype: int | None = None
        self.position = 0
        self._from_start = from_start

    def _open(self):
        fp = open(self.path, "rb")
        if self.endian is None:
            self.endian, self.linktype = _header(fp)
            self.position = 24 if self._from_start else self._end_of_complete_record(fp)
        return fp

    def _end_of_complete_record(self, fp) -> int:
        """Start at the file tail, rewinding if the last record is incomplete."""
        fp.seek(0, 2)
        size = fp.tell()
        if size < 24:
            return 24
        # Walk back at most one record: the writer may be mid-append.
        endian = self.endian or "<"
        position = 24
        candidate = 24
        while position + 16 <= size:
            fp.seek(position)
            header = fp.read(16)
            if len(header) < 16:
                break
            _sec, _usec, caplen, _orig = struct.unpack(endian + "IIII", header)
            if caplen > 262144 or position + 16 + caplen > size:
                break
            position += 16 + caplen
            candidate = position
        return candidate

    def read_new(self) -> list[bytes]:
        try:
            fp = self._open()
        except (OSError, PcapError):
            return []
        out: list[bytes] = []
        try:
            fp.seek(self.position)
            endian = self.endian or "<"
            while True:
                header = fp.read(16)
                if len(header) < 16:
                    break
                _sec, _usec, caplen, _orig = struct.unpack(endian + "IIII", header)
                if caplen > 262144:
                    break
                body = fp.read(caplen)
                if len(body) < caplen:
                    # Writer has not finished this record; retry next poll.
                    break
                out.append(_normalise(self.linktype or RADIOTAP, body))
                self.position += 16 + caplen
        finally:
            fp.close()
        return out


def live_frames(interface: str) -> Iterator[bytes]:
    """Yield frames from a monitor-mode interface.

    Requires scapy. The interface must already be in monitor mode; setting that
    up is platform specific and deliberately not attempted here.
    """
    try:
        from scapy.all import conf, sniff  # noqa: F401
    except ImportError as error:  # pragma: no cover - depends on the host
        raise PcapError(
            "live capture needs scapy (pip install scapy); "
            "PCAP sources work without it"
        ) from error

    from scapy.all import Raw, sniff

    def handle(packet):
        raw = bytes(packet)
        # Scapy may hand back the 802.11 body without radiotap depending on the
        # interface type, so synthesise the preamble when it is absent.
        if raw[:1] == b"\x00" and len(raw) >= 8:
            yield raw
        else:
            yield _EMPTY_RADIOTAP + raw

    for packet in sniff(iface=interface, store=False, monitor=True):
        for frame in handle(packet):
            yield frame
