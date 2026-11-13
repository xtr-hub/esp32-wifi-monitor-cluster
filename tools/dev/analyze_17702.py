"""Test integer/float interpretations for the UDP/17702 30-byte payloads."""

from __future__ import annotations

import collections
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from payload_scan import records, strip_radiotap, parse_dot11, parse_ipv4, parse_ports  # noqa: E402

CAP = Path(__file__).resolve().parents[2] / "captures"


def gather(port: int, length: int, limit: int = 2000):
    p = sorted(CAP.glob("*a5-0c.pcap"), key=lambda x: x.stat().st_mtime, reverse=True)[0]
    out = []
    for _ts, data in records(p):
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
        _s, dport, payload = ports
        if dport == port and len(payload) == length:
            out.append(payload)
        if len(out) >= limit:
            break
    return out


def padding_score(rows, width, offset, signed=True):
    """Fraction of values whose high byte is 0x00 or 0xff (small magnitude)."""
    hits = 0
    total = 0
    for payload in rows:
        for start in range(offset, len(payload) - width + 1, width):
            chunk = payload[start:start + width]
            if len(chunk) < width:
                continue
            total += 1
            if chunk[-1] in (0x00, 0xFF):
                hits += 1
    return hits / total if total else 0.0


def main() -> None:
    rows = gather(17702, 30)
    print(f"samples={len(rows)} distinct={len(set(rows))}")
    if not rows:
        return

    flat = collections.Counter(b for r in rows for b in r)
    total = sum(flat.values())
    print(f"00={100*flat[0]/total:.1f}% ff={100*flat[255]/total:.1f}% "
          f"combined={100*(flat[0]+flat[255])/total:.1f}%")

    print("\nhigh-byte padding score per (width, offset):")
    for width in (2, 4):
        for offset in range(0, min(width + 1, 5)):
            score = padding_score(rows, width, offset)
            print(f"  width={width} offset={offset}: {100*score:.1f}% of high bytes in 00/ff")

    print("\nfloat32 finite/sane fraction (offset 0 and 1):")
    for offset in (0, 1, 2):
        sane = 0
        count = 0
        for payload in rows:
            for start in range(offset, len(payload) - 3, 4):
                value = struct.unpack("<f", payload[start:start + 4])[0]
                count += 1
                if value == value and abs(value) < 1e6 and abs(value) > 1e-9:
                    sane += 1
        print(f"  offset={offset}: {100*sane/count:.1f}% plausible (n={count})")

    print("\nfirst 6 samples:")
    for r in rows[:6]:
        print("  ", r.hex(" "))


if __name__ == "__main__":
    main()
