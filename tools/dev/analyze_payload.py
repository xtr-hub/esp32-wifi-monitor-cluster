"""Structural analysis of a fixed-length UDP payload on one port.

Use this when a payload is unidentified. It answers the questions that decide
whether a layout exists at all, without printing values that identify a host:

  - length distribution and how many payloads are distinct
  - per-byte-value histogram and how many of the 256 values ever occur
  - whether the frame behaves like signed bytes or like multi-byte integers,
    using frame-to-frame smoothness (a real numeric array changes little)
  - fixed versus variable byte offsets across samples
  - bit-level 0/1 probability, which exposes constant header bits
  - whether any position behaves as a counter or timestamp

Example:
    py tools/dev/analyze_payload.py --port 17702 --length 30
    py tools/dev/analyze_payload.py --port 24011 --pcap captures/<file>.pcap
"""

from __future__ import annotations

import argparse
import collections
import math
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from payload_scan import (  # noqa: E402
    parse_dot11,
    parse_ipv4,
    parse_ports,
    records,
    strip_radiotap,
)

CAPTURES = Path(__file__).resolve().parents[2] / "captures"


def gather(port: int, length: int | None, limit: int, pcap: Path | None) -> list[bytes]:
    if pcap is not None:
        paths = [pcap]
    else:
        paths = sorted(
            CAPTURES.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True
        )
    out: list[bytes] = []
    for path in paths:
        for _ts, data in records(path):
            frame = strip_radiotap(data)
            if not frame:
                continue
            info = parse_dot11(frame)
            if not info or info[5] != 0x0800:
                continue
            ip = parse_ipv4(info[6])
            if not ip or ip[0] != 17:
                continue
            ports = parse_ports(ip[0], ip[1])
            if not ports:
                continue
            _sport, dport, payload = ports
            if dport != port or not payload:
                continue
            if length is not None and len(payload) != length:
                continue
            out.append(payload)
            if len(out) >= limit:
                return out
    return out


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True, help="destination UDP port")
    ap.add_argument("--length", type=int, default=None, help="only keep this payload length")
    ap.add_argument("--pcap", type=Path, default=None, help="single PCAP instead of the newest files")
    ap.add_argument("--limit", type=int, default=400, help="max payloads to analyse")
    args = ap.parse_args()

    rows = gather(args.port, args.length, args.limit, args.pcap)
    print(f"UDP/{args.port}: {len(rows)} payloads, {len(set(rows))} distinct")
    if not rows:
        return

    lens = collections.Counter(len(r) for r in rows)
    print(f"lengths: {dict(sorted(lens.items()))}")
    n = lens.most_common(1)[0][0]
    group = [r for r in rows if len(r) == n]
    print(f"analysing {len(group)} payloads of {n} bytes")

    flat = bytes(b for r in group for b in r)
    hist = collections.Counter(flat)
    total = len(flat)
    print(f"\nbyte values used: {len(hist)}/256")
    print(f"  0x00={100*hist[0]/total:.1f}%  0xff={100*hist[255]/total:.1f}%")
    print(f"  pooled entropy: {entropy(flat):.2f} bits/byte")

    print("\nfixed vs variable offsets:")
    variable = [i for i in range(n) if len({r[i] for r in group}) > 1]
    print(f"  fixed={n-len(variable)}  variable={len(variable)}")
    if variable and len(variable) < n:
        print(f"  variable offsets: {variable[:20]}{'...' if len(variable) > 20 else ''}")

    print("\nsmoothness (decides 8-bit channels vs multi-byte integers):")
    byte_delta = [
        abs(a - b) for x, y in zip(group, group[1:]) for a, b in zip(x, y)
    ]
    print(f"  as independent bytes: mean |delta| = {sum(byte_delta)/len(byte_delta):.1f}")
    for endian in ("<", ">"):
        deltas = []
        for x, y in zip(group, group[1:]):
            try:
                vx = struct.unpack(endian + f"{n//2}h", x[: n // 2 * 2])
                vy = struct.unpack(endian + f"{n//2}h", y[: n // 2 * 2])
            except struct.error:
                continue
            deltas.extend(abs(a - b) for a, b in zip(vx, vy))
        if deltas:
            print(f"  as {endian}int16 pairs: mean |delta| = {sum(deltas)/len(deltas):.1f}")

    print("\nper-bit 1-probability (near 0 or 1 means a constant field bit):")
    probs = []
    for pos in range(n * 8):
        byte_i, bit_i = divmod(pos, 8)
        mask = 0x80 >> bit_i
        ones = sum(1 for r in group if r[byte_i] & mask)
        probs.append(ones / len(group))
    flagged = [(i, p) for i, p in enumerate(probs) if p < 0.1 or p > 0.9]
    print(f"  constant-ish bits: {len(flagged)}/{n*8}")
    for i, p in flagged[:12]:
        print(f"    bit {i} (byte {i//8}, bit {i%8}): {p:.3f}")

    print("\ncounter / timestamp test (monotonic 16- and 32-bit reads):")
    for width, fmt in ((2, "<H"), (4, "<I")):
        for offset in range(0, min(n - width + 1, 5)):
            vals = [
                struct.unpack(fmt, r[offset:offset + width])[0]
                for r in group
                if len(r) >= offset + width
            ]
            if len(vals) < 10:
                continue
            ups = sum(1 for a, b in zip(vals, vals[1:]) if b > a)
            downs = sum(1 for a, b in zip(vals, vals[1:]) if b < a)
            if ups > 0.9 * (len(vals) - 1):
                print(f"  offset {offset} width {width}: monotonic increasing ({ups} ups)")

    print("\nfirst 3 payloads:")
    for r in group[:3]:
        print("   ", r.hex(" "))


if __name__ == "__main__":
    main()
