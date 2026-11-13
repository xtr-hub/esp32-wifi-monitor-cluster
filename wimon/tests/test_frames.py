"""Tests for the frame source layer.

Run with plain Python; no test framework is required:

    py wimon/tests/test_frames.py

These cover the properties the live view depends on:

  - a tail reader never returns a partially written record
  - a tail reader resumes at the exact byte where it stopped
  - following a growing file delivers every record exactly once
  - finished PCAPs of both supported link types decode identically
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from frames import PcapError, PcapTail, read_records  # noqa: E402

RADIOTAP = 127
IEEE80211 = 105


def write_pcap(path: Path, records: list[bytes], linktype: int = RADIOTAP,
               truncate_last: int = 0) -> None:
    """Write a classic PCAP, optionally cutting the final record short."""
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for index, body in enumerate(records):
            record = (
                struct.pack("<IIII", 1_700_000_000 + index, 0, len(body), len(body))
                + body
            )
            if index == len(records) - 1 and truncate_last:
                handle.write(record[:truncate_last])
            else:
                handle.write(record)


class Case:
    def __init__(self, name: str) -> None:
        self.name = name

    def __enter__(self):
        self.path = Path(tempfile.mkdtemp()) / "test.pcap"
        return self

    def __exit__(self, *exc):
        self.path.unlink(missing_ok=True)
        try:
            self.path.parent.rmdir()
        except OSError:
            pass


def test_static_read() -> None:
    with Case("static") as case:
        bodies = [bytes(range(40)), bytes(range(60, 110))]
        write_pcap(case.path, bodies)
        got = list(read_records(case.path))
        assert len(got) == 2, f"expected 2 records, got {len(got)}"
        assert got[0] == bodies[0] and got[1] == bodies[1]
    print("ok  static read returns every record unchanged")


def test_linktype_105_gets_radiotap() -> None:
    with Case("linktype") as case:
        body = bytes(range(24))
        write_pcap(case.path, [body], linktype=IEEE80211)
        got = list(read_records(case.path))
        assert len(got) == 1
        assert got[0][:8] == struct.pack("<BBHI", 0, 0, 8, 0), "radiotap not prepended"
        assert got[0][8:] == body, "802.11 body altered"
    print("ok  raw 802.11 PCAPs get a synthesised radiotap header")


def test_partial_record_is_withheld() -> None:
    """The reader must stop before a record whose body is not fully written."""
    with Case("partial") as case:
        bodies = [bytes(range(40)), bytes(range(60, 110))]
        write_pcap(case.path, bodies, truncate_last=16)  # header only
        tail = PcapTail(case.path, from_start=True)
        got = tail.read_new()
        assert len(got) == 1, f"expected 1 complete record, got {len(got)}"
        boundary = tail.position

        # The writer finishes the record; the same reader must pick it up.
        write_pcap(case.path, bodies)
        got = tail.read_new()
        assert len(got) == 1, f"expected the finished record, got {len(got)}"
        assert tail.position > boundary
    print("ok  a partially written record is held back until it is complete")


def test_half_body_is_withheld() -> None:
    with Case("halfbody") as case:
        bodies = [bytes(range(40)), bytes(range(60, 110))]
        write_pcap(case.path, bodies, truncate_last=16 + 20)
        tail = PcapTail(case.path, from_start=True)
        got = tail.read_new()
        assert len(got) == 1, f"expected 1 complete record, got {len(got)}"
    print("ok  a half-written body is not returned")


def test_tail_resumes_at_boundary() -> None:
    """A second reader started at the tail must not replay old records."""
    with Case("resume") as case:
        bodies = [bytes(range(10))] * 5
        write_pcap(case.path, bodies)
        first = PcapTail(case.path, from_start=True)
        assert len(first.read_new()) == 5
        resume = PcapTail(case.path, from_start=False)
        assert resume.read_new() == [], "tail reader replayed existing records"
        # Append more data and confirm only the new records arrive.
        write_pcap(case.path, bodies + [b"new-record!"])
        got = resume.read_new()
        assert len(got) == 1, f"expected 1 appended record, got {len(got)}"
    print("ok  a tail reader resumes at the last complete record")


def test_no_record_is_lost_while_growing() -> None:
    """Repeated polling of a growing file must deliver every record once."""
    with Case("growing") as case:
        write_pcap(case.path, [])
        tail = PcapTail(case.path, from_start=True)
        written: list[bytes] = []
        delivered: list[bytes] = []
        for round_index in range(6):
            batch = [bytes([round_index, i]) * 8 for i in range(20)]
            written.extend(batch)
            # Rewrite the whole file each round, as an appending writer would.
            write_pcap(case.path, written)
            delivered.extend(tail.read_new())
        assert len(delivered) == len(written), (
            f"delivered {len(delivered)} of {len(written)} records"
        )
        assert delivered == written, "records arrived out of order or corrupted"
    print("ok  growing-file polling delivers every record exactly once")


def test_bad_magic_is_rejected() -> None:
    with Case("badmagic") as case:
        case.path.write_bytes(b"not a pcap at all" * 8)
        try:
            list(read_records(case.path))
        except PcapError:
            pass
        else:
            raise AssertionError("a non-PCAP file was accepted")
    print("ok  a non-PCAP file is rejected with PcapError")


def test_unsupported_linktype_is_rejected() -> None:
    with Case("linktype") as case:
        with open(case.path, "wb") as handle:
            # Ethernet (1) is not something this reader claims to handle.
            handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        try:
            list(read_records(case.path))
        except PcapError:
            pass
        else:
            raise AssertionError("an unsupported link type was accepted")
    print("ok  an unsupported link type is rejected with PcapError")


def main() -> int:
    tests = [
        test_static_read,
        test_linktype_105_gets_radiotap,
        test_partial_record_is_withheld,
        test_half_body_is_withheld,
        test_tail_resumes_at_boundary,
        test_no_record_is_lost_while_growing,
        test_bad_magic_is_rejected,
        test_unsupported_linktype_is_rejected,
    ]
    failures = 0
    for test in tests:
        try:
            test()
        except AssertionError as error:
            failures += 1
            print(f"FAIL {test.__name__}: {error}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
