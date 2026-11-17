"""Tests for the decoded-event database layer and the `events` commands.

Builds a small database through the real writer (`pcap_dump --sqlite`) so the
schema under test is the one the decoder actually produces, then exercises every
query path: info, summary, timeline, show, export, query and convert.

    py wimon/tests/test_events.py
"""

from __future__ import annotations

import contextlib
import io
import os
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "wimon"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _support import SkipTest  # noqa: E402

import cli  # noqa: E402
import events  # noqa: E402
import pcap_dump as pd  # noqa: E402
from frames import read_records  # noqa: E402


def write_pcap(path: Path, frames: list[bytes]) -> None:
    """Write frames as a Radiotap PCAP."""
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
        for index, body in enumerate(frames):
            record = struct.pack("<IIII", 1_700_000_000 + index, 0, len(body), len(body))
            handle.write(record + body)


def radiotap_wrap(frame: bytes, channel: int = 157, rssi: int = -40) -> bytes:
    """Radiotap header carrying channel and signal, as the collector writes it."""
    if 1 <= channel <= 14:
        frequency = 2484 if channel == 14 else 2412 + (channel - 1) * 5
        flags = 0x0080
    else:
        frequency = 5000 + channel * 5
        flags = 0x0100
    present = (1 << 1) | (1 << 3) | (1 << 5)   # flags, channel, dBm signal
    header = struct.pack("<BBHI", 0, 0, 15, present)
    header += struct.pack("<BBHHb", 0x10, 0, frequency, flags, rssi)
    return header + frame


def ethernet_data_frame(ethertype: int, l3: bytes, to_ds: bool = False) -> bytes:
    """802.11 data frame carrying an Ethernet payload.

    Kept simple and ToDS-clear so the decoder walks a three-address header; the
    real collector captures use the four-address QoS form, which is why the
    database tests below index a real capture frame instead of synthesising one.
    """
    fc = bytes([0x08, 0x02 if to_ds else 0x00])
    header = fc + b"\x00\x00" + b"\xff" * 6 + b"\x02" * 6 + b"\x03" * 6
    if to_ds:
        header += b"\x04" * 6
    llc = b"\xaa\xaa\x03\x00\x00\x00" + struct.pack(">H", ethertype)
    return header + b"\x00\x00" + llc + l3


CAPTURES = ROOT / "captures"


_FRAME_CACHE: dict[str, list[bytes]] = {}


def real_frames_by_protocol(wanted: list[str], limit_per: int = 1) -> list[bytes]:
    """Pull real frames from the checked-in capture for the given protocols.

    Synthesising 802.11 frames is error-prone: the collector writes the
    four-address QoS form and the decoder's offset maths depends on it. Using
    real bytes keeps these tests honest about what the decoder actually sees.

    Results are cached: scanning the whole capture takes seconds, and every test
    asks for the same few frames.
    """
    if os.environ.get("WIMON_SKIP_CAPTURE_TESTS", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }:
        raise SkipTest("WIMON_SKIP_CAPTURE_TESTS is set")

    key = ",".join(sorted(wanted))
    if key in _FRAME_CACHE:
        return list(_FRAME_CACHE[key])

    # Sort by size, smallest first: the captures include multi-gigabyte files
    # from earlier sessions, and these tests only need one frame of each kind.
    files = sorted(
        (p for p in CAPTURES.glob("*.pcap") if p.stat().st_size < 20 * 1_048_576),
        key=lambda p: p.stat().st_size,
    )
    if not files:
        raise SkipTest("no capture files; capture-dependent events tests need real input")
    wanted = list(wanted)
    found: list[bytes] = []
    counts: dict[str, int] = {name: 0 for name in wanted}
    for path in files:
        for frame in read_records(path):
            summary, _ = pd.decode_frame(frame)
            if not isinstance(summary, str):
                continue
            for name in wanted:
                if counts[name] >= limit_per:
                    continue
                if name in summary:
                    found.append(frame)
                    counts[name] += 1
        if all(value >= limit_per for value in counts.values()):
            break
    if not found:
        raise SkipTest("no matching frames in captures/; the test needs real input")
    _FRAME_CACHE[key] = list(found)
    return found


@contextlib.contextmanager
def sample_database():
    """Index a few real frames of different protocols into SQLite."""
    frames = real_frames_by_protocol(["UDP/3289", "UDP/22222", "UDP/10004"])

    directory = Path(tempfile.mkdtemp())
    pcap = directory / "sample.pcap"
    write_pcap(pcap, frames)

    database = directory / "events.sqlite"
    saved = sys.argv
    sys.argv = [
        "pcap_dump.py", str(pcap), "--decode", "--limit", "0",
        "--sqlite", str(database), "--source-label", "test-node",
    ]
    try:
        pd.main()
    finally:
        sys.argv = saved
    try:
        yield database
    finally:
        for path in directory.glob("*"):
            try:
                path.unlink(missing_ok=True)
            except PermissionError:
                pass
        try:
            directory.rmdir()
        except OSError:
            pass


def run_main(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exit_error:
            code = int(exit_error.code or 0)
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------
# query layer
# --------------------------------------------------------------------------
def test_database_lists_what_was_written() -> None:
    with sample_database() as database:
        with events.EventDatabase(database) as db:
            info = db.schema_summary()
            assert info["rows"] == 3, info["rows"]
            assert info["ring_mode"] is False
            assert info["first_capture"] and info["last_capture"]
            protocols = {protocol for _c, protocol, _n in db.counts_by_protocol()}
            assert any("3289" in p for p in protocols), protocols


def test_filters_narrow_the_result() -> None:
    with sample_database() as database:
        with events.EventDatabase(database) as db:
            total = db.count(events.EventFilter())
            only_one = db.count(events.EventFilter(protocol="3289"))
            assert 0 < only_one < total, (only_one, total)
            assert 0 < db.count(events.EventFilter(channel=157)) < total
            assert db.count(events.EventFilter(search="EPSONQ")) >= 1


def test_recent_is_newest_first() -> None:
    with sample_database() as database:
        with events.EventDatabase(database) as db:
            rows = db.recent(limit=10)
            times = [row["captured_at"] for row in rows]
            assert times == sorted(times, reverse=True), times


def test_stream_covers_every_row() -> None:
    with sample_database() as database:
        with events.EventDatabase(database) as db:
            streamed = list(db.stream())
            assert len(streamed) == db.count(events.EventFilter())


def test_histogram_totals_match_event_count() -> None:
    with sample_database() as database:
        with events.EventDatabase(database) as db:
            buckets = db.histogram(bucket_seconds=60)
            assert sum(count for _b, count in buckets) == db.count(events.EventFilter())


def test_missing_database_raises() -> None:
    try:
        events.EventDatabase(Path("definitely-not-here.sqlite"))
    except events.EventDatabaseError:
        return
    raise AssertionError("a missing database was accepted")


def test_non_database_file_raises() -> None:
    directory = Path(tempfile.mkdtemp())
    junk = directory / "junk.sqlite"
    junk.write_text("this is not sqlite")
    try:
        events.EventDatabase(junk)
    except events.EventDatabaseError:
        return
    finally:
        try:
            junk.unlink(missing_ok=True)
            directory.rmdir()
        except (PermissionError, OSError):
            pass
    raise AssertionError("a non-database file was accepted")


# --------------------------------------------------------------------------
# CLI commands
# --------------------------------------------------------------------------
def test_cli_events_info() -> None:
    with sample_database() as database:
        code, out, _ = run_main(["events", "info", str(database)])
    assert code == 0
    assert "events" in out and "test-node" in out


def test_cli_events_summary_by_category() -> None:
    with sample_database() as database:
        code, out, _ = run_main(["events", "summary", str(database), "--by", "category"])
    assert code == 0
    assert "udp" in out.lower(), out


def test_cli_events_timeline() -> None:
    with sample_database() as database:
        code, out, _ = run_main(["events", "timeline", str(database), "--bucket", "60"])
    assert code == 0
    assert "bucket(s)" in out


def test_cli_events_show_json() -> None:
    import json

    with sample_database() as database:
        code, out, _ = run_main(["events", "show", str(database), "--json", "--limit", "2"])
    assert code == 0
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 2
    for line in lines:
        row = json.loads(line)
        assert "summary" in row and "protocol" in row


def test_cli_events_show_fields() -> None:
    with sample_database() as database:
        code, out, _ = run_main([
            "events", "show", str(database), "--limit", "1",
            "--fields", "captured_at,protocol",
        ])
    assert code == 0
    assert "protocol=" in out


def test_cli_events_export_csv() -> None:
    with sample_database() as database:
        code, out, _ = run_main([
            "events", "export", str(database), "--fields", "captured_at,protocol",
        ])
    assert code == 0
    lines = out.strip().splitlines()
    assert lines[0] == "captured_at,protocol"
    # No blank lines between records.
    assert all(line.strip() for line in lines), lines


def test_cli_events_export_jsonl() -> None:
    with sample_database() as database:
        code, out, _ = run_main([
            "events", "export", str(database), "--format", "jsonl",
            "--fields", "protocol",
        ])
    assert code == 0
    assert out.count("\n") == 3


def test_cli_events_query_select() -> None:
    with sample_database() as database:
        code, out, _ = run_main([
            "events", "query", str(database),
            "SELECT COUNT(*) AS n FROM decoded_events",
        ])
    assert code == 0
    assert "3" in out


def test_cli_events_query_rejects_writes() -> None:
    with sample_database() as database:
        for statement in ("DELETE FROM decoded_events", "DROP TABLE decoded_events"):
            code, _out, err = run_main(["events", "query", str(database), statement])
            assert code == 2, (statement, code)
            assert "only SELECT" in err


def test_cli_events_query_survives_bad_sql() -> None:
    with sample_database() as database:
        code, _out, err = run_main(["events", "query", str(database), "SELECT nope FROM nothing"])
    assert code == 1
    assert "SQL error" in err


def test_cli_events_convert_roundtrip() -> None:
    """convert must produce a database that answers queries."""
    directory = Path(tempfile.mkdtemp())
    pcap = directory / "in.pcap"
    frames = real_frames_by_protocol(["UDP/3289"])
    assert frames, "no UDP/3289 frame available"
    write_pcap(pcap, frames)
    database = directory / "out.sqlite"
    code, out, err = run_main([
        "events", "convert", str(pcap), "--database", str(database),
        "--source-label", "converted",
    ])
    assert code == 0, (out, err)
    code, out, _ = run_main(["events", "info", str(database)])
    assert code == 0
    assert "converted" in out
    for path in directory.glob("*"):
        path.unlink(missing_ok=True)
    directory.rmdir()


def test_private_rows_are_hidden_by_default() -> None:
    """Rows written with show_private stay out of default listings."""
    directory = Path(tempfile.mkdtemp())
    pcap = directory / "private.pcap"
    frames = real_frames_by_protocol(["UDP/3289"])
    assert frames, "no UDP/3289 frame available"
    write_pcap(pcap, frames)
    database = directory / "private.sqlite"
    saved = sys.argv
    sys.argv = [
        "pcap_dump.py", str(pcap), "--decode", "--limit", "0",
        "--sqlite", str(database), "--show-private",
    ]
    try:
        pd.main()
    finally:
        sys.argv = saved

    with events.EventDatabase(database) as db:
        hidden = db.count(events.EventFilter())
        included = db.count(events.EventFilter(include_private=True))
        assert hidden == 0, f"private rows visible by default: {hidden}"
        assert included >= 1, "private rows missing even when requested"

    for path in directory.glob("*"):
        path.unlink(missing_ok=True)
    directory.rmdir()


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    skipped = 0
    for test in tests:
        try:
            test()
        except SkipTest as error:
            skipped += 1
            print(f"skip {test.__name__}: {error}")
        except AssertionError as error:
            failures += 1
            print(f"FAIL {test.__name__}: {error}")
        except Exception as error:
            failures += 1
            print(f"ERROR {test.__name__}: {type(error).__name__}: {error}")
        else:
            print(f"ok   {test.__name__}")
        finally:
            pd.SHOW_PRIVATE = False
    print(f"\n{len(tests) - failures - skipped}/{len(tests)} passed"
          f"{f', {skipped} skipped' if skipped else ''}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
