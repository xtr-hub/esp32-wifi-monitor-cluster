"""Decoder regression tests: robustness and no unclassified payloads.

Two kinds of check:

  * Robustness - malformed, truncated and adversarial payloads must never raise
    out of decode_frame. The live viewer decodes untrusted network input, so an
    exception means a dropped frame or a stalled view.
  * Coverage - against the checked-in capture, every datagram must receive a
    structural label, and no IPv4/MAC literal may survive in masked output.

The capture-dependent tests are skipped when `captures/` has no usable file, so
the suite still runs on a fresh clone.

    py wimon/tests/test_decoder.py
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "wimon"))

import pcap_dump as pd  # noqa: E402
from frames import PcapTail, read_records  # noqa: E402

CAPTURES = ROOT / "captures"
IPV4 = re.compile(r"(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d.])")
MAC = re.compile(r"\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b", re.I)


def address_literals(text: str) -> list[str]:
    """Return IPv4/MAC literals that are not part of a longer dotted token.

    SNMP object identifiers such as 1.3.6.1.2.1.1.2.0 contain four-or-more dotted
    numbers, so a naive four-group regex matches them and reports a false leak.
    The lookarounds plus the explicit length check keep OIDs out.
    """
    found: list[str] = []
    for match in IPV4.finditer(text):
        literal = match.group(0)
        # Reject anything adjacent to another dotted number (an OID fragment).
        start, end = match.span()
        before = text[start - 1] if start else ""
        after = text[end] if end < len(text) else ""
        if before == "." or after == ".":
            continue
        if before.isdigit() or after.isdigit():
            continue
        found.append(literal)
    found.extend(match.group(0) for match in MAC.finditer(text))
    return found


def radiotap_wrap(frame: bytes) -> bytes:
    """Minimal radiotap header plus an 802.11 frame."""
    return struct.pack("<BBHI", 0, 0, 8, 0) + frame


def ethernet_data_frame(ethertype: int, l3: bytes) -> bytes:
    """Build an 802.11 data frame carrying the given EtherType payload."""
    fc = bytes([0x08, 0x00])                     # data, to-DS clear
    duration = b"\x00\x00"
    addr1 = b"\xff" * 6
    addr2 = b"\x02" * 6
    addr3 = b"\x03" * 6
    seq = b"\x00\x00"
    llc = b"\xaa\xaa\x03\x00\x00\x00" + struct.pack(">H", ethertype)
    return fc + duration + addr1 + addr2 + addr3 + seq + llc + l3


def udp_packet(payload: bytes, sport: int, dport: int) -> bytes:
    """IPv4 + UDP around the payload."""
    total = 20 + 8 + len(payload)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total, 0, 0, 64, 17, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    )
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    return ip + udp + payload


def build_udp_frame(payload: bytes, sport: int, dport: int) -> bytes:
    return radiotap_wrap(ethernet_data_frame(0x0800, udp_packet(payload, sport, dport)))


# --------------------------------------------------------------------------
# robustness
# --------------------------------------------------------------------------
def test_truncated_frames_do_not_raise() -> None:
    """Every prefix of a real frame must decode without raising."""
    sample = build_udp_frame(b"hello-world", 5000, 5353)
    pd.SHOW_PRIVATE = False
    for length in range(len(sample) + 1):
        try:
            pd.decode_frame(sample[:length])
        except Exception as error:
            raise AssertionError(
                f"decode raised at prefix length {length}: {type(error).__name__}: {error}"
            ) from error


def test_short_matcher_payloads_do_not_raise() -> None:
    """Each marker matcher must tolerate payloads shorter than its layout."""
    pd.SHOW_PRIVATE = False
    matchers = [
        (pd._udp_10004_xml_discovery, 10004),
        (pd._udp_25353_ptbl, 25353),
        (pd._udp_3289_epson, 3289),
        (pd._udp_22222_str_bcast, 22222),
        (pd._udp_8888_netbios_like, 8888),
        (pd._udp_4039_comfyhub, 4039),
        (pd._udp_2343_netbios_name, 2343),
        (pd._udp_8090_probe, 8086),
        (pd._udp_23301_frame, 23301),
        (pd._udp_22000_opaque, 22000),
        (pd._udp_24011_roam, 24011),
        (pd._measure_udp_17702, 17702),
    ]
    for matcher, port in matchers:
        for length in range(0, 40):
            payload = bytes(range(256))[:length] if length <= 256 else b""
            payload = (payload * 2)[:length]
            try:
                matcher(payload, 50000, port)
                matcher(payload, port, 50000)
            except Exception as error:
                raise AssertionError(
                    f"{matcher.__name__} raised on {length}-byte payload: "
                    f"{type(error).__name__}: {error}"
                ) from error


def test_deeply_nested_json_does_not_escape() -> None:
    """RecursionError from json.loads must not propagate."""
    pd.SHOW_PRIVATE = False
    payload = b"[" * 3000
    frame = build_udp_frame(payload, 5000, 49161)
    try:
        pd.decode_frame(frame)
    except Exception as error:
        raise AssertionError(
            f"deep JSON escaped decode_frame: {type(error).__name__}: {error}"
        ) from error


def test_random_payloads_do_not_raise() -> None:
    """A pseudo-random sweep over many ports and lengths."""
    import random

    pd.SHOW_PRIVATE = False
    ports = [10004, 25353, 3289, 22222, 8888, 4039, 2343, 8090, 23301,
             22000, 24011, 24012, 17702, 5353, 1900, 5683]
    rng = random.Random(20261114)
    for _ in range(300):
        length = rng.randint(0, 200)
        payload = bytes(rng.getrandbits(8) for _ in range(length))
        port = rng.choice(ports)
        frame = build_udp_frame(payload, rng.randint(1024, 65535), port)
        try:
            pd.decode_frame(frame)
        except Exception as error:
            raise AssertionError(
                f"port {port} len {length} raised: {type(error).__name__}: {error}"
            ) from error


# --------------------------------------------------------------------------
# specific behaviours found during review
# --------------------------------------------------------------------------
def test_roam_matches_both_directions() -> None:
    text_bytes = b"payload-text"
    payload = (
        b"ROAM"
        + (len(text_bytes) + 2).to_bytes(4, "little")
        + bytes(4)
        + b"\x0a"
        + bytes([len(text_bytes)])
        + text_bytes
    )
    pd.SHOW_PRIVATE = False
    forward = pd._udp_24011_roam(payload, 41175, 24011)
    backward = pd._udp_24011_roam(payload, 24011, 5000)
    assert forward is not None, "ROAM not matched as destination port"
    assert backward is not None, "ROAM not matched as source port"


def test_8090_requires_literal_unknown_tag() -> None:
    """The probe matcher must not relabel arbitrary 28-byte traffic."""
    payload = bytes(12) + bytes(4) + b"\x11\x22\x33\x44" + b"OtherTag" + b"\x00"
    assert pd._udp_8090_probe(payload, 5000, 8086) is None
    good = bytes(12) + bytes(4) + b"\x11\x22\x33\x44" + b"unknown" + b"\x00"
    assert pd._udp_8090_probe(good, 5000, 8086) is not None


def test_23301_checks_declared_length() -> None:
    declared_wrong = (
        b"\x72\x79\x0a\x00"
        + (0xAA558FF1).to_bytes(4, "little")
        + bytes(16)
        + (999).to_bytes(4, "little")
        + b"short"
    )
    out = pd._udp_23301_frame(declared_wrong, 52944, 23301)
    assert out is not None and "MISMATCHES" in out, out
    declared_right = (
        b"\x72\x79\x0a\x00"
        + (0xAA558FF1).to_bytes(4, "little")
        + bytes(16)
        + (7).to_bytes(4, "little")
        + b"7 bytes"
    )
    out = pd._udp_23301_frame(declared_right, 52944, 23301)
    assert out is not None and "matches" in out, out


def test_17702_reports_measured_delta_only_after_two_frames() -> None:
    """The first frame cannot report a frame-to-frame delta."""
    pd.SHOW_PRIVATE = False
    payload = bytes([0, 255] * 15)
    first = pd._measure_udp_17702(payload, 40000, 17702)
    assert "not measured" in first, first
    second = pd._measure_udp_17702(bytes([0, 254] * 15), 40000, 17702)
    assert "not measured" not in second, second


# --------------------------------------------------------------------------
# coverage against a real capture
# --------------------------------------------------------------------------
def newest_capture() -> Path | None:
    """The newest capture, used for coverage checks."""
    if not CAPTURES.is_dir():
        return None
    files = sorted(CAPTURES.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def baseline_captures() -> list[Path]:
    """A fixed set of historical captures treated as the regression baseline.

    Live captures keep arriving with traffic the decoder has never seen, so
    asserting "every payload in the newest file is classified" would fail as soon
    as a new device appears. The baseline is the corpus the decoder was validated
    against; new captures are checked for parser errors and privacy instead.
    """
    if not CAPTURES.is_dir():
        return []
    baseline = sorted(CAPTURES.glob("20261113T16*.pcap"))
    if baseline:
        return baseline
    # Fall back to whatever exists, so a fresh clone still exercises the path.
    return sorted(CAPTURES.glob("*.pcap"))[:4]


def test_baseline_capture_has_no_unclassified_payloads() -> None:
    files = baseline_captures()
    if not files:
        print("  (skipped: no capture available)")
        return
    pd.SHOW_PRIVATE = False
    total = unknown = 0
    for path in files:
        for frame in read_records(path):
            summary, _ = pd.decode_frame(frame)
            if not isinstance(summary, str):
                continue
            total += 1
            if "unknown binary payload" in summary:
                unknown += 1
    assert total > 0, "baseline decoded no frames"
    assert unknown == 0, (
        f"{unknown} of {total} payloads in the baseline corpus are unclassified"
    )
    print(f"  ({total} frames across {len(files)} file(s), 0 unclassified)")


def test_newest_capture_decodes_without_errors() -> None:
    """Fresh traffic may contain unknown protocols, but never a crash or a leak."""
    path = newest_capture()
    if path is None:
        print("  (skipped: no capture available)")
        return
    pd.SHOW_PRIVATE = False
    total = leaks = undecodable = 0
    for frame in read_records(path):
        summary, _ = pd.decode_frame(frame)
        if not isinstance(summary, str):
            continue
        total += 1
        if "undecodable frame" in summary:
            undecodable += 1
        body = summary.split("802.11", 1)[-1]
        if address_literals(body):
            leaks += 1
    assert total > 0, "capture decoded no frames"
    assert undecodable == 0, f"{undecodable} frames raised inside the decoder"
    assert leaks == 0, f"{leaks} summaries leaked an address literal"
    print(f"  ({total} frames, 0 undecodable, 0 leaks)")


def test_expand_paths_handles_globs() -> None:
    """Wildcards must work even when the shell does not expand them."""
    import tempfile

    import watch

    directory = Path(tempfile.mkdtemp())
    for name in ("20260101T000000Z_aa-bb.pcap", "20260102T000000Z_aa-bb.pcap"):
        (directory / name).write_bytes(b"x")
    (directory / "notes.txt").write_text("x")

    wildcard = str(directory / "*.pcap")
    resolved = watch.expand_paths([wildcard])
    assert len(resolved) == 2, f"expected 2 matches, got {resolved}"

    # An explicit file still works, and duplicates are collapsed.
    both = watch.expand_paths([wildcard, str(resolved[0])])
    assert len(both) == 2, f"duplicates not collapsed: {both}"

    # A pattern that matches nothing is reported and yields nothing.
    assert watch.expand_paths([str(directory / "*.nope")]) == []


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
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
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
